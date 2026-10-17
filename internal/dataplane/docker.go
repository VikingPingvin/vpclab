//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"

	"github.com/VikingPingvin/vpclab/internal/naming"
	"github.com/VikingPingvin/vpclab/internal/plan"
)

const idleCmd = plan.IdleCmd

func docker(ctx context.Context, args ...string) (string, error) {
	var out, errb bytes.Buffer
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(out.String()), nil
}

type containerState struct {
	exists  bool
	running bool
	pid     int
	spec    string
}

func inspect(ctx context.Context, name string) (containerState, error) {
	out, err := docker(ctx, "ps", "-a", "--filter", "name=^"+name+"$", "--format", "{{.Names}}")
	if err != nil || out == "" {
		return containerState{}, err
	}
	out, err = docker(ctx, "inspect", "-f",
		`{{.State.Running}} {{.State.Pid}} {{index .Config.Labels "`+naming.LabelSpec+`"}}`, name)
	if err != nil {
		return containerState{}, err
	}
	f := strings.Fields(out)
	pid, _ := strconv.Atoi(f[1])
	st := containerState{exists: true, running: f[0] == "true", pid: pid}
	if len(f) > 2 {
		st.spec = f[2]
	}
	return st, nil
}

// ensure starts the container if needed and returns its PID. The run
// arguments are hashed into a label; a container created with different
// arguments (e.g. by an older vpcsim) is recreated.
func ensure(ctx context.Context, name string, runArgs []string) (int, error) {
	sum := sha256.Sum256([]byte(strings.Join(runArgs, "\x00")))
	spec := hex.EncodeToString(sum[:8])
	runArgs = append([]string{"--label", naming.LabelSpec + "=" + spec}, runArgs...)

	st, err := inspect(ctx, name)
	if err != nil {
		return 0, err
	}
	if st.exists && st.spec != spec {
		slog.Info("recreating container with changed spec", "name", name)
		if err := remove(ctx, name); err != nil {
			return 0, err
		}
		st = containerState{}
	}
	switch {
	case !st.exists:
		if _, err := docker(ctx, append([]string{"run", "-d", "--name", name}, runArgs...)...); err != nil {
			return 0, err
		}
	case !st.running:
		if _, err := docker(ctx, "start", name); err != nil {
			return 0, err
		}
	default:
		return st.pid, nil
	}
	st, err = inspect(ctx, name)
	if err != nil {
		return 0, err
	}
	if !st.running || st.pid == 0 {
		return 0, fmt.Errorf("container %s is not running", name)
	}
	return st.pid, nil
}

// forwarderSysctls configure a namespace that forwards packets: no reverse
// path filter, no ICMP redirects, and no arp_filter. arp_filter (on by
// default on some kernels) only answers ARP when the route back to the
// sender uses the same interface; the IGW links have no such route because
// both ends use the same link-local next hop in every VPC.
var forwarderSysctls = []string{
	"--sysctl", "net.ipv4.ip_forward=1",
	"--sysctl", "net.ipv4.conf.all.rp_filter=0",
	"--sysctl", "net.ipv4.conf.default.rp_filter=0",
	"--sysctl", "net.ipv4.conf.all.send_redirects=0",
	"--sysctl", "net.ipv4.conf.default.send_redirects=0",
	"--sysctl", "net.ipv4.conf.all.arp_filter=0",
	"--sysctl", "net.ipv4.conf.default.arp_filter=0",
}

// ensureRouter starts the container that owns a VPC router's namespace. The
// sysctls are set before any interface exists, so every interface vpcsim adds
// later inherits them from "default".
func ensureRouter(ctx context.Context, r plan.Router, image string) (int, error) {
	args := []string{
		"--label", naming.LabelRole + "=" + naming.RoleRouter,
		"--label", naming.LabelVPC + "=" + r.VPCID,
		"--network", "none",
		"--hostname", r.VPCID,
		"--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW", // for debugging with nft/tcpdump via docker exec
		"--sysctl", "net.ipv4.conf.default.proxy_arp=1",
	}
	args = append(args, forwarderSysctls...)
	return ensure(ctx, r.Container, append(args, "--entrypoint", "sh", image, "-c", idleCmd))
}

// ensureInstance starts an instance container without any network; vpcsim
// plugs its ENIs in afterwards. NET_ADMIN lets the learner manage the OS
// network config as root on EC2 can; filtering happens outside, in the router.
func ensureInstance(ctx context.Context, in plan.Instance) (int, error) {
	args := []string{
		"--label", naming.LabelRole + "=" + naming.RoleInstance,
		"--label", naming.LabelVPC + "=" + in.VPCID,
		"--label", naming.LabelInstance + "=" + in.ID,
		"--network", "none",
		"--hostname", in.Hostname,
		"--cap-add", "NET_ADMIN",
	}
	for _, ns := range in.DNS {
		args = append(args, "--dns", ns)
	}
	return ensure(ctx, in.Container, append(args, "--entrypoint", "sh", in.Image, "-c", idleCmd))
}

// stopInstance stops the container of a stopped instance and keeps it, so
// its files survive until the instance starts again. A stopped instance
// without a container (e.g. stopped before vpcsim ran) gets none.
func stopInstance(ctx context.Context, in plan.Instance) error {
	st, err := inspect(ctx, in.Container)
	if err != nil || !st.running {
		return err
	}
	slog.Info("stopping container", "name", in.Container)
	_, err = docker(ctx, "stop", "-t", "5", in.Container)
	return err
}

// ensureNetwork creates the Docker bridge network that connects the internet
// namespace to the host. Containers on it cannot talk to each other.
func ensureNetwork(ctx context.Context, name string) error {
	if _, err := docker(ctx, "network", "inspect", name); err == nil {
		return nil
	}
	slog.Info("creating network", "name", name)
	_, err := docker(ctx, "network", "create", "--driver", "bridge",
		"--label", naming.LabelRole+"="+naming.RoleUplink,
		"--opt", "com.docker.network.bridge.enable_icc=false", name)
	return err
}

// ensureInternet starts the container that owns the internet namespace. Its
// eth0 is on the uplink network, with Docker's default route to the host.
func ensureInternet(ctx context.Context, in *plan.Internet, image string) (int, error) {
	if err := ensureNetwork(ctx, in.Uplink); err != nil {
		return 0, err
	}
	args := []string{
		"--label", naming.LabelRole + "=" + naming.RoleInternet,
		"--network", in.Uplink,
		"--hostname", "internet",
		"--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW",
	}
	args = append(args, forwarderSysctls...)
	return ensure(ctx, in.Container, append(args, "--entrypoint", "sh", image, "-c", idleCmd))
}

// ensureHost starts a machine on the internet, e.g. the operator box.
func ensureHost(ctx context.Context, h plan.Host) (int, error) {
	return ensure(ctx, h.Container, []string{
		"--label", naming.LabelRole + "=" + naming.RoleInternetHost,
		"--network", "none",
		"--hostname", h.Name,
		"--cap-add", "NET_ADMIN",
		"--entrypoint", "sh",
		h.Image, "-c", h.Command,
	})
}

// managed lists all containers vpcsim created.
func managed(ctx context.Context) ([]string, error) {
	out, err := docker(ctx, "ps", "-a", "--filter", "label="+naming.LabelRole, "--format", "{{.Names}}")
	if err != nil || out == "" {
		return nil, err
	}
	return strings.Split(out, "\n"), nil
}

func remove(ctx context.Context, name string) error {
	_, err := docker(ctx, "rm", "-f", name)
	return err
}
