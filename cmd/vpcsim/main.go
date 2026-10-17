// Command vpcsim renders the AWS networking state stored in Floci into a
// packet-level Linux network. See docs/vpcsim/architecture.md.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/VikingPingvin/vpclab/internal/dataplane"
	"github.com/VikingPingvin/vpclab/internal/floci"
	"github.com/VikingPingvin/vpclab/internal/plan"
	"github.com/VikingPingvin/vpclab/internal/snapshot"
)

const usage = `usage: vpcsim <command> [flags]

commands:
  snapshot   print the networking state read from Floci as JSON
  plan       print the desired data plane (routes, rules, nftables) without applying it
  apply      reconcile the data plane once (needs root and --pid=host)
  run        reconcile continuously (needs root and --pid=host)

environment:
  FLOCI_ENDPOINT          Floci URL (default http://localhost:4566)
  VPCSIM_INSTANCE_IMAGE   image for EC2 instances (default nicolaka/netshoot:latest)
  VPCSIM_RUNTIME_IMAGE    image for router and internet containers (default vpcsim-runtime:dev)
  VPCSIM_DNS              comma-separated resolvers for instances (default 1.1.1.1,8.8.8.8)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "snapshot":
		err = runSnapshot(ctx)
	case "plan":
		err = runPlan(ctx)
	case "apply":
		err = reconcile(ctx)
	case "run":
		fs := flag.NewFlagSet("run", flag.ExitOnError)
		interval := fs.Duration("interval", 2*time.Second, "time between reconciles")
		_ = fs.Parse(os.Args[2:])
		err = runLoop(ctx, *interval)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "vpcsim:", err)
		os.Exit(1)
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func fetch(ctx context.Context) (*snapshot.Snapshot, error) {
	client, err := floci.EC2(ctx)
	if err != nil {
		return nil, err
	}
	return snapshot.Fetch(ctx, client)
}

func buildPlan(ctx context.Context) (*plan.Plan, error) {
	snap, err := fetch(ctx)
	if err != nil {
		return nil, err
	}
	var dns []string
	if v := os.Getenv("VPCSIM_DNS"); v != "" {
		dns = strings.Split(v, ",")
	}
	return plan.Build(snap, plan.Options{
		InstanceImage: env("VPCSIM_INSTANCE_IMAGE", "nicolaka/netshoot:latest"),
		DNS:           dns,
	})
}

func runSnapshot(ctx context.Context) error {
	snap, err := fetch(ctx)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(snap)
}

func runPlan(ctx context.Context) error {
	p, err := buildPlan(ctx)
	if err != nil {
		return err
	}
	for _, w := range p.Warnings {
		fmt.Println("warning:", w)
	}
	for _, in := range p.Instances {
		state := "running"
		if !in.Running {
			state = "stopped"
		}
		fmt.Printf("instance %s -> container %s (%s, %s, dns %v)\n", in.ID, in.Container, in.Image, state, in.DNS)
	}
	for _, r := range p.Routers {
		fmt.Printf("\n=== router %s (container %s)\n", r.VPCID, r.Container)
		fmt.Printf("gateway addresses: %v\n", r.Gateway)
		for _, e := range r.ENIs {
			fmt.Printf("eni %s: %s <-> %s:%s mac=%s ips=%v subnet=%s gw=%s srcdst=%t\n",
				e.ID, e.RouterIf, e.InstanceID, e.InstanceIf, e.MAC, e.IPs, e.Subnet, e.Gateway, e.SrcDstCheck)
		}
		if r.IGW != nil {
			fmt.Printf("internet gateway %s\n", r.IGW.ID)
		}
		for _, n := range r.NAT {
			src := "Floci"
			if n.Auto {
				src = "auto-assigned by vpcsim (Floci does not report it)"
			}
			fmt.Printf("public ip %s -> %s (%s)\n", n.Public, n.Private, src)
		}
		for _, rule := range r.Rules {
			iif := rule.IifName
			if iif == "" {
				iif = "all"
			}
			fmt.Printf("rule %d: iif %s lookup %d\n", rule.Priority, iif, rule.Table)
		}
		for _, t := range r.Tables {
			fmt.Printf("table %d (%s):\n", t.ID, t.Name)
			for _, rt := range t.Routes {
				fmt.Printf("  %s %s %s\n", rt.Kind, rt.Dst, rt.Dev)
			}
		}
		fmt.Println("nftables:")
		fmt.Print(r.Ruleset)
	}
	if in := p.Internet; in != nil {
		fmt.Printf("\n=== internet (container %s, uplink network %s)\n", in.Container, in.Uplink)
		for _, h := range in.Hosts {
			fmt.Printf("host %s: %s (container %s)\n", h.Name, h.IP, h.Container)
		}
		for _, l := range in.Links {
			fmt.Printf("%s (%s): %v\n", l.IGWID, l.VPCID, l.Public)
		}
		fmt.Println("nftables:")
		fmt.Print(in.Ruleset)
	}
	return nil
}

func reconcile(ctx context.Context) error {
	p, err := buildPlan(ctx)
	if err != nil {
		return err
	}
	for _, w := range p.Warnings {
		slog.Warn(w)
	}
	return dataplane.Apply(ctx, p, dataplane.Options{RouterImage: env("VPCSIM_RUNTIME_IMAGE", "vpcsim-runtime:dev")})
}

func runLoop(ctx context.Context, interval time.Duration) error {
	slog.Info("vpcsim running", "endpoint", floci.Endpoint(), "interval", interval)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if err := reconcile(ctx); err != nil && ctx.Err() == nil {
			slog.Error("reconcile failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}
