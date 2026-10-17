package exercise

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ec2"

	"github.com/VikingPingvin/vpclab/internal/naming"
	"github.com/VikingPingvin/vpclab/internal/plan"
	"github.com/VikingPingvin/vpclab/internal/snapshot"
)

// Result is the outcome of one check.
type Result struct {
	Check  Check
	Pass   bool
	Detail string // why it failed, for the learner
}

// Address is where an instance or internet host can be reached.
type Address struct {
	Container string
	Private   netip.Addr // zero for a stopped or terminated instance
	Public    netip.Addr // zero without a public IPv4 (or for internet hosts)
	State     string     // instance state; "running" for internet hosts
}

// Addresses resolves every instance of the exercise and the internet hosts.
// Public IPs come from the same planner vpcsim uses, so auto-assigned
// addresses resolve too.
func Addresses(ctx context.Context, c *ec2.Client, ex *Exercise, s *State) (map[string]Address, error) {
	snap, err := snapshot.Fetch(ctx, c)
	if err != nil {
		return nil, err
	}
	p, err := plan.Build(snap, plan.Options{})
	if err != nil {
		return nil, err
	}
	enis := map[string]snapshot.ENI{}
	for _, e := range snap.ENIs {
		enis[e.ID] = e
	}
	instances := map[string]snapshot.Instance{}
	for _, in := range snap.Instances {
		instances[in.ID] = in
	}

	out := map[string]Address{
		plan.OperatorName: {Container: "vpcsim-" + plan.OperatorName, Private: plan.OperatorIP, State: "running"},
		plan.EchoName:     {Container: "vpcsim-" + plan.EchoName, Private: plan.EchoIP, State: "running"},
	}
	for _, in := range ex.Resources.Instances {
		id := s.IDs[in.Name]
		a := Address{Container: naming.InstanceContainer(id), State: "terminated"}
		if si, ok := instances[id]; ok {
			a.State = si.State
			for _, eniID := range si.ENIs {
				if e := enis[eniID]; e.DeviceIndex == 0 && len(e.PrivateIPs) > 0 {
					a.Private, _ = netip.ParseAddr(e.PrivateIPs[0])
				}
			}
			for _, r := range p.Routers {
				if r.VPCID != si.VPCID {
					continue
				}
				for _, n := range r.NAT {
					if n.Private == a.Private {
						a.Public = n.Public
					}
				}
			}
		}
		out[in.Name] = a
	}
	return out, nil
}

// Verify runs every check with real traffic. It does not wait for vpcsim:
// the caller makes sure the data plane matches Floci first.
func Verify(ctx context.Context, c *ec2.Client, ex *Exercise, s *State) ([]Result, error) {
	addrs, err := Addresses(ctx, c, ex, s)
	if err != nil {
		return nil, err
	}
	var results []Result
	for _, chk := range ex.Checks {
		results = append(results, runCheck(ctx, chk, addrs))
	}
	return results, nil
}

func runCheck(ctx context.Context, chk Check, addrs map[string]Address) Result {
	res := Result{Check: chk}
	open, detail := probe(ctx, chk, addrs)
	res.Pass = open == (chk.Expect == "open")
	if !res.Pass {
		if detail == "" {
			if open {
				detail = fmt.Sprintf("the connection to port %d works, but it must be blocked", chk.Port)
			} else {
				detail = fmt.Sprintf("the connection to port %d fails (timeout or refused)", chk.Port)
			}
		}
		res.Detail = detail
	}
	return res
}

// probe reports whether a TCP connection from chk.From to chk.To succeeds.
// The detail explains a failure that is not the network's doing.
func probe(ctx context.Context, chk Check, addrs map[string]Address) (bool, string) {
	from := addrs[chk.From]
	if from.State != "running" {
		return false, fmt.Sprintf("%s is %s, so the check cannot run from it", chk.From, from.State)
	}
	toName, public := strings.CutSuffix(chk.To, publicSuffix)
	to := addrs[toName]
	if to.State != "running" {
		return false, fmt.Sprintf("%s is %s", toName, to.State)
	}
	ip := to.Private
	if public {
		if !to.Public.IsValid() {
			return false, fmt.Sprintf("%s has no public IPv4 address", toName)
		}
		ip = to.Public
	}
	if toName != plan.OperatorName && toName != plan.EchoName {
		if err := ensureListener(ctx, to.Container, chk.Port); err != nil {
			return false, fmt.Sprintf("cannot start a test listener on %s: %v", toName, err)
		}
	}
	_, err := dockerSh(ctx, from.Container, fmt.Sprintf("socat -u OPEN:/dev/null TCP:%s:%d,connect-timeout=3", ip, chk.Port))
	return err == nil, ""
}

// ensureListener starts a TCP server on the port unless something already
// listens there, e.g. the learner's own web server.
func ensureListener(ctx context.Context, container string, port int) error {
	script := fmt.Sprintf(`ss -ltnH | grep -q ':%d ' || { nohup socat TCP-LISTEN:%d,fork,reuseaddr SYSTEM:'echo ok' >/dev/null 2>&1 & sleep 0.3; }`, port, port)
	_, err := dockerSh(ctx, container, script)
	return err
}

func dockerSh(ctx context.Context, container, script string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, "docker", "exec", container, "sh", "-c", script)
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	if err != nil {
		return out.String(), fmt.Errorf("%w: %s", err, strings.TrimSpace(out.String()))
	}
	return out.String(), nil
}
