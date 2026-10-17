//go:build linux

// Package dataplane makes the Linux data plane match a plan: containers for
// routers and instances, veth pairs for ENIs, routes, ip rules and nftables.
// It needs root and --pid=host; it normally runs inside the vpcsim container.
package dataplane

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/VikingPingvin/vpclab/internal/plan"
)

type Options struct {
	// RouterImage is the image for router containers. It must contain sh.
	RouterImage string
}

// Apply reconciles the data plane with the plan. It is idempotent.
func Apply(ctx context.Context, p *plan.Plan, opt Options) error {
	desired := map[string]bool{}
	for _, r := range p.Routers {
		desired[r.Container] = true
	}
	for _, in := range p.Instances {
		desired[in.Container] = true
	}
	if p.Internet != nil {
		desired[p.Internet.Container] = true
		for _, h := range p.Internet.Hosts {
			desired[h.Container] = true
		}
	}
	existing, err := managed(ctx)
	if err != nil {
		return err
	}
	for _, name := range existing {
		if !desired[name] {
			slog.Info("removing container", "name", name)
			if err := remove(ctx, name); err != nil {
				return err
			}
		}
	}

	internetPID := 0
	if p.Internet != nil {
		if internetPID, err = ensureInternet(ctx, p.Internet, opt.RouterImage); err != nil {
			return fmt.Errorf("internet: %w", err)
		}
		hostPIDs := map[string]int{}
		for _, h := range p.Internet.Hosts {
			if hostPIDs[h.Name], err = ensureHost(ctx, h); err != nil {
				return fmt.Errorf("internet host %s: %w", h.Name, err)
			}
		}
		if err := applyInternetBase(p.Internet, internetPID, hostPIDs); err != nil {
			return fmt.Errorf("internet: %w", err)
		}
		if err := nftApply(ctx, internetPID, p.Internet.Ruleset); err != nil {
			return fmt.Errorf("internet nftables: %w", err)
		}
	}

	routerPIDs := map[string]int{}
	for _, r := range p.Routers {
		pid, err := ensureRouter(ctx, r, opt.RouterImage)
		if err != nil {
			return fmt.Errorf("router %s: %w", r.VPCID, err)
		}
		routerPIDs[r.VPCID] = pid
	}
	instancePIDs := map[string]int{}
	for _, in := range p.Instances {
		if !in.Running {
			// Stopping the container destroys its namespace and with it the
			// ENI veths; the router's ends disappear with them.
			if err := stopInstance(ctx, in); err != nil {
				return fmt.Errorf("instance %s: %w", in.ID, err)
			}
			continue
		}
		pid, err := ensureInstance(ctx, in)
		if err != nil {
			return fmt.Errorf("instance %s: %w", in.ID, err)
		}
		instancePIDs[in.ID] = pid
	}
	for _, r := range p.Routers {
		if err := applyRouter(ctx, r, routerPIDs[r.VPCID], internetPID, instancePIDs); err != nil {
			return fmt.Errorf("router %s: %w", r.VPCID, err)
		}
	}
	if p.Internet != nil {
		if err := syncInternetRoutes(p.Internet, internetPID); err != nil {
			return fmt.Errorf("internet routes: %w", err)
		}
	}
	return nil
}
