//go:build linux

package dataplane

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/VikingPingvin/vpclab/internal/plan"
)

const gatewayIf = "gw0"

type nsHandle struct {
	ns netns.NsHandle
	h  *netlink.Handle
}

// openNS opens the network namespace of a process. vpcsim runs with
// --pid=host, so /proc shows the PIDs of other containers.
func openNS(pid int) (*nsHandle, error) {
	ns, err := netns.GetFromPath(fmt.Sprintf("/proc/%d/ns/net", pid))
	if err != nil {
		return nil, fmt.Errorf("open netns of pid %d: %w", pid, err)
	}
	h, err := netlink.NewHandleAt(ns)
	if err != nil {
		ns.Close()
		return nil, err
	}
	return &nsHandle{ns: ns, h: h}, nil
}

func (n *nsHandle) Close() {
	n.h.Close()
	n.ns.Close()
}

func isNotFound(err error) bool {
	var lnf netlink.LinkNotFoundError
	return errors.As(err, &lnf)
}

// liveVeth returns the veth called name in h's namespace if its peer is in
// the target namespace. A veth whose peer is elsewhere is stale: the kernel
// destroys a dead container's namespace asynchronously, so the old end can
// linger for a moment after the container is replaced. Stale links are
// deleted, and (nil, nil) means "create it".
func liveVeth(h *netlink.Handle, name string, target netns.NsHandle) (netlink.Link, error) {
	link, err := h.LinkByName(name)
	if isNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	id, err := h.GetNetNsIdByFd(int(target))
	if err == nil && id >= 0 && link.Attrs().NetNsID == id {
		return link, nil
	}
	if err := h.LinkDel(link); err != nil && !isNotFound(err) {
		return nil, fmt.Errorf("remove stale %s: %w", name, err)
	}
	return nil, nil
}

// applyRouter brings one VPC router namespace to the planned state.
// eniPIDs maps the containers that hold the other end of ENIs to their PIDs.
func applyRouter(ctx context.Context, r plan.Router, routerPID, internetPID int, eniPIDs map[string]int) error {
	rt, err := openNS(routerPID)
	if err != nil {
		return err
	}
	defer rt.Close()

	if err := ensureDummy(rt.h, gatewayIf, r.Gateway); err != nil {
		return fmt.Errorf("gateway addresses: %w", err)
	}
	if err := ensureIGW(rt.h, r.IGW, internetPID); err != nil {
		return fmt.Errorf("internet gateway: %w", err)
	}

	want := map[string]bool{}
	for _, e := range r.ENIs {
		want[e.RouterIf] = true
		pid, ok := eniPIDs[e.Container]
		if !ok {
			return fmt.Errorf("%s: container %s is not running", e.ID, e.Container)
		}
		if err := ensureENI(rt.h, e, pid); err != nil {
			return fmt.Errorf("%s: %w", e.ID, err)
		}
	}
	// Peering and TGW links were created before, in ensurePeering and applyTGW.
	for _, p := range r.Peerings {
		want[p.Ifname] = true
	}
	for _, a := range r.Attachments {
		want[a.Ifname] = true
	}
	if err := removeStaleLinks(rt.h, want, "v", "p", "a"); err != nil {
		return err
	}
	if err := syncRoutes(rt.h, r.Tables); err != nil {
		return fmt.Errorf("routes: %w", err)
	}
	if err := syncRules(rt.h, r.Rules); err != nil {
		return fmt.Errorf("rules: %w", err)
	}
	if err := nftApply(ctx, routerPID, r.Ruleset); err != nil {
		return fmt.Errorf("nftables: %w", err)
	}
	return nil
}

// ensureDummy puts /32 addresses on a dummy interface. The namespace then
// answers ARP for them on every link (arp_ignore=0 answers for any local
// address). Routers use it for the .1 address of every subnet, like the AWS
// VPC router.
func ensureDummy(h *netlink.Handle, name string, gws []netip.Addr) error {
	link, err := h.LinkByName(name)
	if isNotFound(err) {
		if err := h.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name}}); err != nil {
			return err
		}
		link, err = h.LinkByName(name)
	}
	if err != nil {
		return err
	}
	if err := h.LinkSetUp(link); err != nil {
		return err
	}
	want := map[netip.Addr]bool{}
	for _, gw := range gws {
		want[gw] = true
		if err := h.AddrReplace(link, &netlink.Addr{IPNet: hostNet(gw)}); err != nil {
			return err
		}
	}
	addrs, err := h.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	for _, a := range addrs {
		if ip, ok := netip.AddrFromSlice(a.IP.To4()); ok && !want[ip] {
			if err := h.AddrDel(link, &a); err != nil {
				return err
			}
		}
	}
	return nil
}

// ensureENI creates the veth pair for an ENI if it does not exist yet. A veth
// pair dies with either namespace, so a missing router end means the instance
// end is gone too and both are rebuilt.
func ensureENI(rh *netlink.Handle, e plan.ENI, instancePID int) error {
	inst, err := openNS(instancePID)
	if err != nil {
		return err
	}
	link, err := liveVeth(rh, e.RouterIf, inst.ns)
	inst.Close()
	if err == nil && link == nil {
		link, err = createENI(rh, e, instancePID)
	}
	if err != nil {
		return err
	}
	if err := rh.LinkSetUp(link); err != nil {
		return err
	}
	// The router knows every ENI's MAC, like the AWS mapping service, so it
	// never needs to ARP for instances.
	for _, ip := range e.IPs {
		if err := rh.NeighSet(&netlink.Neigh{
			LinkIndex:    link.Attrs().Index,
			Family:       netlink.FAMILY_V4,
			State:        netlink.NUD_PERMANENT,
			IP:           net.IP(ip.AsSlice()),
			HardwareAddr: e.MAC,
		}); err != nil {
			return fmt.Errorf("neighbor %s: %w", ip, err)
		}
	}
	return nil
}

func createENI(rh *netlink.Handle, e plan.ENI, instancePID int) (netlink.Link, error) {
	inst, err := openNS(instancePID)
	if err != nil {
		return nil, err
	}
	defer inst.Close()

	veth := &netlink.Veth{
		LinkAttrs:     netlink.LinkAttrs{Name: e.RouterIf, MTU: plan.ENIMTU},
		PeerName:      e.TempIf,
		PeerNamespace: netlink.NsFd(int(inst.ns)),
	}
	if err := rh.LinkAdd(veth); err != nil {
		return nil, fmt.Errorf("create veth: %w", err)
	}

	// Configure the instance end: name, MAC, MTU, addresses, default route.
	ih := inst.h
	peer, err := ih.LinkByName(e.TempIf)
	if err != nil {
		return nil, err
	}
	steps := []func() error{
		func() error { return ih.LinkSetName(peer, e.InstanceIf) },
		func() error { return ih.LinkSetHardwareAddr(peer, e.MAC) },
		func() error { return ih.LinkSetMTU(peer, plan.ENIMTU) },
	}
	for _, step := range steps {
		if err := step(); err != nil {
			return nil, err
		}
	}
	for _, ip := range e.IPs {
		addr := &netlink.Addr{IPNet: &net.IPNet{IP: net.IP(ip.AsSlice()), Mask: net.CIDRMask(e.Subnet.Bits(), 32)}}
		if err := ih.AddrAdd(peer, addr); err != nil {
			return nil, fmt.Errorf("instance address %s: %w", ip, err)
		}
	}
	if err := ih.LinkSetUp(peer); err != nil {
		return nil, err
	}
	if e.DefaultGW {
		if err := ih.RouteReplace(&netlink.Route{
			LinkIndex: peer.Attrs().Index,
			Gw:        net.IP(e.Gateway.AsSlice()),
		}); err != nil {
			return nil, fmt.Errorf("instance default route: %w", err)
		}
	}
	return rh.LinkByName(e.RouterIf)
}

func ownedTable(t int) bool {
	return t == plan.TableDelivery || t == plan.TableBlackhole || (t >= plan.TableRTBase && t < plan.TableRTBase+10000)
}

func routeKey(table int, dst netip.Prefix, typ int, linkIndex int, gw net.IP, metric int) string {
	return fmt.Sprintf("%d|%s|%d|%d|%s|%d", table, dst, typ, linkIndex, gw, metric)
}

// syncRoutes makes the routes in every vpcsim-owned table match the plan.
func syncRoutes(h *netlink.Handle, tables []plan.Table) error {
	var desired []*netlink.Route
	want := map[string]bool{}
	for _, t := range tables {
		for _, r := range t.Routes {
			nr := &netlink.Route{Table: t.ID, Dst: prefixNet(r.Dst), Priority: r.Metric}
			switch r.Kind {
			case plan.RouteThrow:
				nr.Type = unix.RTN_THROW
			case plan.RouteBlackhole:
				nr.Type = unix.RTN_BLACKHOLE
			case plan.RouteDev:
				link, err := h.LinkByName(r.Dev)
				if err != nil {
					return fmt.Errorf("route %s dev %s: %w", r.Dst, r.Dev, err)
				}
				nr.Type = unix.RTN_UNICAST
				nr.LinkIndex = link.Attrs().Index
				nr.Scope = netlink.SCOPE_LINK
			case plan.RouteVia:
				link, err := h.LinkByName(r.Dev)
				if err != nil {
					return fmt.Errorf("route %s via %s dev %s: %w", r.Dst, r.Via, r.Dev, err)
				}
				nr.Type = unix.RTN_UNICAST
				nr.LinkIndex = link.Attrs().Index
				nr.Gw = net.IP(r.Via.AsSlice())
				nr.Flags = int(netlink.FLAG_ONLINK)
			}
			desired = append(desired, nr)
			want[routeKey(t.ID, r.Dst, nr.Type, nr.LinkIndex, nr.Gw, nr.Priority)] = true
		}
	}

	existing, err := h.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return err
	}
	for _, r := range existing {
		if !ownedTable(r.Table) {
			continue
		}
		if !want[routeKey(r.Table, netPrefix(r.Dst), r.Type, r.LinkIndex, r.Gw, r.Priority)] {
			if err := h.RouteDel(&r); err != nil {
				return fmt.Errorf("delete route %s table %d: %w", r.Dst, r.Table, err)
			}
		}
	}
	for _, r := range desired {
		if err := h.RouteReplace(r); err != nil {
			return fmt.Errorf("route %s table %d: %w", r.Dst, r.Table, err)
		}
	}
	return nil
}

// syncRules makes the ip rules in vpcsim's priority range match the plan.
func syncRules(h *netlink.Handle, rules []plan.Rule) error {
	key := func(prio int, iif string, table int) string { return fmt.Sprintf("%d|%s|%d", prio, iif, table) }
	want := map[string]bool{}
	for _, r := range rules {
		want[key(r.Priority, r.IifName, r.Table)] = true
	}
	existing, err := h.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return err
	}
	have := map[string]bool{}
	for _, r := range existing {
		if r.Priority < plan.PrioritySubnetRT || r.Priority > plan.PriorityBlackhole {
			continue
		}
		k := key(r.Priority, r.IifName, r.Table)
		if !want[k] || have[k] {
			if err := h.RuleDel(&r); err != nil {
				return fmt.Errorf("delete rule %s: %w", k, err)
			}
			continue
		}
		have[k] = true
	}
	for _, r := range rules {
		k := key(r.Priority, r.IifName, r.Table)
		if have[k] {
			continue
		}
		nr := netlink.NewRule()
		nr.Family = netlink.FAMILY_V4
		nr.Priority = r.Priority
		nr.Table = r.Table
		nr.IifName = r.IifName
		if err := h.RuleAdd(nr); err != nil {
			return fmt.Errorf("add rule %s: %w", k, err)
		}
	}
	return nil
}

// nftApply loads a ruleset into the router namespace in one transaction.
func nftApply(ctx context.Context, pid int, ruleset string) error {
	var errb bytes.Buffer
	cmd := exec.CommandContext(ctx, "nsenter", "--net=/proc/"+strconv.Itoa(pid)+"/ns/net", "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(errb.String()))
	}
	return nil
}

func hostNet(a netip.Addr) *net.IPNet {
	return &net.IPNet{IP: net.IP(a.AsSlice()), Mask: net.CIDRMask(32, 32)}
}

func prefixNet(p netip.Prefix) *net.IPNet {
	return &net.IPNet{IP: net.IP(p.Addr().AsSlice()), Mask: net.CIDRMask(p.Bits(), 32)}
}

// netPrefix converts a netlink destination; netlink reports default routes
// as a nil Dst.
func netPrefix(n *net.IPNet) netip.Prefix {
	if n == nil {
		return netip.MustParsePrefix("0.0.0.0/0")
	}
	a, _ := netip.AddrFromSlice(n.IP.To4())
	ones, _ := n.Mask.Size()
	return netip.PrefixFrom(a, ones)
}
