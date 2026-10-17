//go:build linux

package dataplane

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/vishvananda/netlink"

	"github.com/VikingPingvin/vpclab/internal/naming"
	"github.com/VikingPingvin/vpclab/internal/plan"
)

// ensurePair creates a veth called name in both namespaces, unless a live
// pair exists. The MACs are fixed, so the permanent neighbour entries of the
// other end stay valid when the pair is rebuilt.
func ensurePair(ah *netlink.Handle, b *nsHandle, name string, aMAC, bMAC net.HardwareAddr, mtu int) (netlink.Link, netlink.Link, error) {
	link, err := liveVeth(ah, name, b.ns)
	if err != nil {
		return nil, nil, err
	}
	if link == nil {
		// The other end of a replaced namespace may still exist.
		if old, err := b.h.LinkByName(name); err == nil {
			if err := b.h.LinkDel(old); err != nil && !isNotFound(err) {
				return nil, nil, fmt.Errorf("remove stale %s: %w", name, err)
			}
		}
		if err := ah.LinkAdd(&netlink.Veth{
			LinkAttrs:        netlink.LinkAttrs{Name: name, MTU: mtu, HardwareAddr: aMAC},
			PeerName:         name,
			PeerHardwareAddr: bMAC,
			PeerNamespace:    netlink.NsFd(int(b.ns)),
		}); err != nil {
			return nil, nil, fmt.Errorf("create veth %s: %w", name, err)
		}
		if link, err = ah.LinkByName(name); err != nil {
			return nil, nil, err
		}
	}
	peer, err := b.h.LinkByName(name)
	if err != nil {
		return nil, nil, err
	}
	return link, peer, nil
}

// upWithNextHop brings a link end up and maps plan.LinkNextHop to the MAC of
// the other end. Link state changes (e.g. joining a VRF) flush neighbours,
// so this runs last.
func upWithNextHop(h *netlink.Handle, link netlink.Link, peerMAC net.HardwareAddr) error {
	if err := h.LinkSetUp(link); err != nil {
		return err
	}
	return h.NeighSet(&netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		Family:       netlink.FAMILY_V4,
		State:        netlink.NUD_PERMANENT,
		IP:           net.IP(plan.LinkNextHop.AsSlice()),
		HardwareAddr: peerMAC,
	})
}

// ensurePeering connects two VPC routers.
func ensurePeering(pc plan.Peering, routerPIDs map[string]int) error {
	a, err := openNS(routerPIDs[pc.A.VPCID])
	if err != nil {
		return err
	}
	defer a.Close()
	b, err := openNS(routerPIDs[pc.B.VPCID])
	if err != nil {
		return err
	}
	defer b.Close()
	la, lb, err := ensurePair(a.h, b, pc.Ifname, pc.A.MAC, pc.B.MAC, plan.ENIMTU)
	if err != nil {
		return err
	}
	if err := upWithNextHop(a.h, la, pc.B.MAC); err != nil {
		return err
	}
	return upWithNextHop(b.h, lb, pc.A.MAC)
}

// ensureTGW starts the container that owns a transit gateway's namespace.
func ensureTGW(ctx context.Context, g plan.TransitGateway, image string) (int, error) {
	args := []string{
		"--label", naming.LabelRole + "=" + naming.RoleTGW,
		"--network", "none",
		"--hostname", g.ID,
		"--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW", // for debugging with ip/tcpdump via docker exec
	}
	args = append(args, forwarderSysctls...)
	return ensure(ctx, g.Container, append(args, "--entrypoint", "sh", image, "-c", idleCmd))
}

// applyTGW builds a transit gateway's VRFs, its attachment links to the VPC
// routers and the routes of every VRF.
func applyTGW(g plan.TransitGateway, tgwPID int, routerPIDs map[string]int) error {
	tg, err := openNS(tgwPID)
	if err != nil {
		return err
	}
	defer tg.Close()

	vrfs := map[string]netlink.Link{}
	for _, v := range g.VRFs {
		link, err := ensureVRF(tg.h, v)
		if err != nil {
			return fmt.Errorf("VRF %s: %w", v.RouteTableID, err)
		}
		vrfs[v.Ifname] = link
	}

	want := map[string]bool{}
	for _, v := range g.VRFs {
		want[v.Ifname] = true
	}
	for _, a := range g.Attachments {
		want[a.Ifname] = true
		if err := ensureAttachment(tg, a, vrfs, routerPIDs); err != nil {
			return fmt.Errorf("%s: %w", a.ID, err)
		}
	}
	if err := removeStaleLinks(tg.h, want, "a", "r"); err != nil {
		return err
	}
	return syncRoutes(tg.h, g.Tables)
}

func ensureVRF(h *netlink.Handle, v plan.VRF) (netlink.Link, error) {
	link, err := h.LinkByName(v.Ifname)
	if err == nil {
		if vrf, ok := link.(*netlink.Vrf); !ok || vrf.Table != uint32(v.Table) {
			// Route table IDs are assigned by position; a deleted table
			// shifts the others.
			if err := h.LinkDel(link); err != nil {
				return nil, err
			}
			err = netlink.LinkNotFoundError{}
		}
	}
	if isNotFound(err) {
		if err := h.LinkAdd(&netlink.Vrf{LinkAttrs: netlink.LinkAttrs{Name: v.Ifname}, Table: uint32(v.Table)}); err != nil {
			return nil, err
		}
		link, err = h.LinkByName(v.Ifname)
	}
	if err != nil {
		return nil, err
	}
	return link, h.LinkSetUp(link)
}

func ensureAttachment(tg *nsHandle, a plan.TGWAttachment, vrfs map[string]netlink.Link, routerPIDs map[string]int) error {
	rt, err := openNS(routerPIDs[a.VPCID])
	if err != nil {
		return err
	}
	defer rt.Close()
	lt, lr, err := ensurePair(tg.h, rt, a.Ifname, a.TGWMAC, a.RouterMAC, plan.TGWMTU)
	if err != nil {
		return err
	}
	master := 0
	if v, ok := vrfs[a.VRF]; ok {
		master = v.Attrs().Index
	}
	if lt.Attrs().MasterIndex != master {
		if master == 0 {
			err = tg.h.LinkSetNoMaster(lt)
		} else {
			err = tg.h.LinkSetMasterByIndex(lt, master)
		}
		if err != nil {
			return fmt.Errorf("VRF: %w", err)
		}
	}
	if err := upWithNextHop(tg.h, lt, a.RouterMAC); err != nil {
		return err
	}
	return upWithNextHop(rt.h, lr, a.TGWMAC)
}

// removeStaleLinks deletes veths and VRFs whose names start with one of the
// prefixes and that the plan no longer has. Deleting one end of a veth
// removes the pair.
func removeStaleLinks(h *netlink.Handle, want map[string]bool, prefixes ...string) error {
	links, err := h.LinkList()
	if err != nil {
		return err
	}
	for _, l := range links {
		name := l.Attrs().Name
		if (l.Type() != "veth" && l.Type() != "vrf") || want[name] {
			continue
		}
		for _, p := range prefixes {
			if strings.HasPrefix(name, p) {
				if err := h.LinkDel(l); err != nil && !isNotFound(err) {
					return fmt.Errorf("remove %s: %w", name, err)
				}
				break
			}
		}
	}
	return nil
}
