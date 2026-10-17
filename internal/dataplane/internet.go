//go:build linux

package dataplane

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"github.com/VikingPingvin/vpclab/internal/plan"
)

// routeProtocol tags the routes vpcsim owns in the internet namespace's main
// table, so stale ones can be found and removed.
const routeProtocol = netlink.RouteProtocol(99)

const edgeIf = "edge0"

// applyInternetBase sets up the internet namespace and its hosts. The
// namespace owns EdgeInternetAddr on a dummy interface, so it answers ARP for
// that address on every link: VPC routers and hosts use it as next hop.
func applyInternetBase(in *plan.Internet, internetPID int, hostPIDs map[string]int) error {
	inet, err := openNS(internetPID)
	if err != nil {
		return err
	}
	defer inet.Close()

	if err := ensureDummy(inet.h, edgeIf, []netip.Addr{plan.EdgeInternetAddr}); err != nil {
		return fmt.Errorf("edge address: %w", err)
	}
	for _, h := range in.Hosts {
		if err := ensureHostLink(inet.h, h, hostPIDs[h.Name]); err != nil {
			return fmt.Errorf("host %s: %w", h.Name, err)
		}
	}
	return nil
}

func ensureHostLink(ih *netlink.Handle, h plan.Host, hostPID int) error {
	host, err := openNS(hostPID)
	if err != nil {
		return err
	}
	defer host.Close()
	if link, err := liveVeth(ih, h.Ifname, host.ns); err != nil || link != nil {
		return err
	}

	temp := "t" + h.Ifname[1:]
	if err := ih.LinkAdd(&netlink.Veth{
		LinkAttrs:     netlink.LinkAttrs{Name: h.Ifname, MTU: plan.InternetMTU},
		PeerName:      temp,
		PeerNamespace: netlink.NsFd(int(host.ns)),
	}); err != nil {
		return fmt.Errorf("create veth: %w", err)
	}
	link, err := ih.LinkByName(h.Ifname)
	if err != nil {
		return err
	}
	if err := ih.LinkSetUp(link); err != nil {
		return err
	}

	hh := host.h
	peer, err := hh.LinkByName(temp)
	if err != nil {
		return err
	}
	if err := hh.LinkSetName(peer, "eth0"); err != nil {
		return err
	}
	if err := hh.LinkSetMTU(peer, plan.InternetMTU); err != nil {
		return err
	}
	if err := hh.AddrAdd(peer, &netlink.Addr{IPNet: hostNet(h.IP)}); err != nil {
		return err
	}
	if err := hh.LinkSetUp(peer); err != nil {
		return err
	}
	return hh.RouteReplace(&netlink.Route{
		LinkIndex: peer.Attrs().Index,
		Gw:        net.IP(plan.EdgeInternetAddr.AsSlice()),
		Flags:     int(netlink.FLAG_ONLINK),
	})
}

// ensureIGW creates or removes the link between a VPC router and the internet
// namespace. The router end owns EdgeRouterAddr, the internet end routes the
// VPC's public IPs to it (see syncInternetRoutes).
func ensureIGW(rh *netlink.Handle, igw *plan.IGW, internetPID int) error {
	if igw == nil {
		link, err := rh.LinkByName(plan.IGWIf)
		if err == nil {
			return rh.LinkDel(link)
		}
		if isNotFound(err) {
			return nil
		}
		return err
	}
	inet, err := openNS(internetPID)
	if err != nil {
		return err
	}
	link, err := liveVeth(rh, plan.IGWIf, inet.ns)
	inet.Close()
	if err == nil && link == nil {
		link, err = createIGWLink(rh, igw, internetPID)
	}
	if err != nil {
		return err
	}
	if err := rh.AddrReplace(link, &netlink.Addr{IPNet: hostNet(plan.EdgeRouterAddr)}); err != nil {
		return err
	}
	return rh.LinkSetUp(link)
}

func createIGWLink(rh *netlink.Handle, igw *plan.IGW, internetPID int) (netlink.Link, error) {
	inet, err := openNS(internetPID)
	if err != nil {
		return nil, err
	}
	defer inet.Close()
	// The internet end of a replaced router may still exist under this name.
	if old, err := inet.h.LinkByName(igw.InternetIf); err == nil {
		if err := inet.h.LinkDel(old); err != nil && !isNotFound(err) {
			return nil, fmt.Errorf("remove stale %s: %w", igw.InternetIf, err)
		}
	}
	if err := rh.LinkAdd(&netlink.Veth{
		LinkAttrs:     netlink.LinkAttrs{Name: plan.IGWIf, MTU: plan.InternetMTU},
		PeerName:      igw.InternetIf,
		PeerNamespace: netlink.NsFd(int(inet.ns)),
	}); err != nil {
		return nil, fmt.Errorf("create IGW veth: %w", err)
	}
	peer, err := inet.h.LinkByName(igw.InternetIf)
	if err != nil {
		return nil, err
	}
	if err := inet.h.LinkSetUp(peer); err != nil {
		return nil, err
	}
	return rh.LinkByName(plan.IGWIf)
}

// syncInternetRoutes makes the internet namespace route every host address and
// every public IP to the right link.
func syncInternetRoutes(in *plan.Internet, internetPID int) error {
	inet, err := openNS(internetPID)
	if err != nil {
		return err
	}
	defer inet.Close()
	h := inet.h

	var desired []*netlink.Route
	for _, host := range in.Hosts {
		link, err := h.LinkByName(host.Ifname)
		if err != nil {
			return err
		}
		desired = append(desired, &netlink.Route{
			Dst: hostNet(host.IP), LinkIndex: link.Attrs().Index, Scope: netlink.SCOPE_LINK, Protocol: routeProtocol,
		})
	}
	for _, l := range in.Links {
		link, err := h.LinkByName(l.Ifname)
		if err != nil {
			return fmt.Errorf("IGW link of %s: %w", l.VPCID, err)
		}
		for _, pub := range l.Public {
			desired = append(desired, &netlink.Route{
				Dst: hostNet(pub), LinkIndex: link.Attrs().Index, Protocol: routeProtocol,
				Gw: net.IP(plan.EdgeRouterAddr.AsSlice()), Flags: int(netlink.FLAG_ONLINK),
			})
		}
	}

	want := map[string]bool{}
	for _, r := range desired {
		want[fmt.Sprintf("%s|%d", r.Dst, r.LinkIndex)] = true
	}
	existing, err := h.RouteListFiltered(netlink.FAMILY_V4,
		&netlink.Route{Table: unix.RT_TABLE_MAIN, Protocol: routeProtocol},
		netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL)
	if err != nil {
		return err
	}
	for _, r := range existing {
		if !want[fmt.Sprintf("%s|%d", r.Dst, r.LinkIndex)] {
			if err := h.RouteDel(&r); err != nil {
				return fmt.Errorf("delete route %s: %w", r.Dst, err)
			}
		}
	}
	for _, r := range desired {
		if err := h.RouteReplace(r); err != nil {
			return fmt.Errorf("route %s: %w", r.Dst, err)
		}
	}
	return nil
}
