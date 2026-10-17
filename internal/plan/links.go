package plan

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/VikingPingvin/vpclab/internal/naming"
	"github.com/VikingPingvin/vpclab/internal/snapshot"
)

// LinkNextHop is the next hop on every peering and transit gateway link. No
// namespace owns the address: each end has a permanent neighbour entry that
// maps it to the other end's MAC, so the links never need ARP and the same
// address works on every link.
var LinkNextHop = netip.MustParseAddr("169.254.1.1")

// TGWMTU is the largest packet a transit gateway forwards between VPCs.
const TGWMTU = 8500

// catchAllMetric puts a table's catch-all blackhole behind every real route
// with the same prefix.
const catchAllMetric = 4278198272

// Peering is a veth between two VPC routers. The interface has the same name
// in both namespaces. A is the VPC with the lower ID; its namespace creates
// the pair.
type Peering struct {
	ID     string
	Ifname string
	A, B   LinkEnd
}

type LinkEnd struct {
	VPCID string
	MAC   net.HardwareAddr
}

// RouterPeering is one VPC router's side of an active peering connection.
// The router accepts traffic from the link only if it comes from the peer
// VPC and goes to its own VPC: peering is not transitive, and the peer
// cannot use this VPC's gateways (no edge-to-edge routing).
type RouterPeering struct {
	ID         string
	Ifname     string
	PeerVPCID  string
	LocalCIDRs []netip.Prefix
	PeerCIDRs  []netip.Prefix
}

// TransitGateway is a namespace with one VRF per TGW route table. Each VPC
// attachment is a veth from a VPC router into the VRF of the route table it
// is associated with. Routes in a VRF may point to an attachment in another
// VRF; the reply uses that attachment's own route table, as in AWS.
type TransitGateway struct {
	ID          string
	Container   string
	VRFs        []VRF
	Attachments []TGWAttachment
	Tables      []Table // one per VRF
}

type VRF struct {
	RouteTableID string
	Ifname       string
	Table        int
}

type TGWAttachment struct {
	ID        string
	VPCID     string
	Ifname    string // same name in the router and the TGW namespace
	VRF       string // VRF interface; empty when not associated (traffic is dropped)
	RouterMAC net.HardwareAddr
	TGWMAC    net.HardwareAddr
}

// RouterAttachment is one VPC router's side of a TGW attachment.
type RouterAttachment struct {
	ID     string
	TGWID  string
	Ifname string
	// Subnet is the first attachment subnet. Traffic from the TGW is routed
	// with its route table, so a middlebox route there applies.
	Subnet string
	// Uncovered lists the router interfaces of ENIs in Availability Zones
	// without an attachment subnet. The TGW cannot reach them, and they
	// cannot reach the TGW.
	Uncovered []string
}

// linkSet holds the peerings and TGW attachments that get a link: both
// sides must have a namespace, so the VPCs need running instances.
type linkSet struct {
	peerings    map[string]snapshot.Peering       // by ID
	attachments map[string]snapshot.TGWAttachment // by ID
	cidrs       map[string][2][]netip.Prefix      // peering ID -> requester, accepter CIDRs
}

func usableLinks(s *snapshot.Snapshot, idx *indexes, routed map[string]bool) (*linkSet, []string) {
	var warns []string
	ls := &linkSet{
		peerings:    map[string]snapshot.Peering{},
		attachments: map[string]snapshot.TGWAttachment{},
		cidrs:       map[string][2][]netip.Prefix{},
	}
	for _, pc := range s.Peerings {
		if pc.Status != "active" || !routed[pc.RequesterVPCID] || !routed[pc.AccepterVPCID] {
			continue
		}
		req := peerCIDRs(idx, pc.RequesterCIDRs, pc.RequesterVPCID)
		acc := peerCIDRs(idx, pc.AccepterCIDRs, pc.AccepterVPCID)
		if overlaps(req, acc) {
			warns = append(warns, fmt.Sprintf("%s: the CIDRs of %s and %s overlap; AWS rejects such a peering; it is not simulated",
				pc.ID, pc.RequesterVPCID, pc.AccepterVPCID))
			continue
		}
		ls.peerings[pc.ID] = pc
		ls.cidrs[pc.ID] = [2][]netip.Prefix{req, acc}
	}
	tgwUp := map[string]bool{}
	for _, g := range s.TransitGateways {
		tgwUp[g.ID] = g.State == "available" || g.State == "pending"
	}
	for _, a := range s.TGWAttachments {
		if tgwUp[a.TGWID] && routed[a.VPCID] && (a.State == "available" || a.State == "pending") {
			ls.attachments[a.ID] = a
		}
	}
	return ls, warns
}

// peerCIDRs returns the CIDRs a peering covers; Floci may only report the
// primary CIDR, so the VPC's CIDRs are the fallback.
func peerCIDRs(idx *indexes, cidrs []string, vpcID string) []netip.Prefix {
	if len(cidrs) == 0 {
		cidrs = idx.vpc[vpcID].CIDRs
	}
	return collapse(cidrs)
}

func overlaps(a, b []netip.Prefix) bool {
	for _, x := range a {
		for _, y := range b {
			if x.Overlaps(y) {
				return true
			}
		}
	}
	return false
}

// buildRouterLinks adds the router's side of its peerings and attachments.
// It runs after the ENIs are known.
func buildRouterLinks(s *snapshot.Snapshot, idx *indexes, ls *linkSet, r *Router) {
	for _, pc := range s.Peerings {
		if _, ok := ls.peerings[pc.ID]; !ok {
			continue
		}
		c := ls.cidrs[pc.ID]
		switch r.VPCID {
		case pc.RequesterVPCID:
			r.Peerings = append(r.Peerings, RouterPeering{ID: pc.ID, Ifname: naming.PeeringIf(pc.ID), PeerVPCID: pc.AccepterVPCID, LocalCIDRs: c[0], PeerCIDRs: c[1]})
		case pc.AccepterVPCID:
			r.Peerings = append(r.Peerings, RouterPeering{ID: pc.ID, Ifname: naming.PeeringIf(pc.ID), PeerVPCID: pc.RequesterVPCID, LocalCIDRs: c[1], PeerCIDRs: c[0]})
		}
	}
	for _, a := range s.TGWAttachments {
		if _, ok := ls.attachments[a.ID]; !ok || a.VPCID != r.VPCID {
			continue
		}
		azs := map[string]bool{}
		for _, sn := range a.SubnetIDs {
			azs[idx.subnet[sn].AZ] = true
		}
		ra := RouterAttachment{ID: a.ID, TGWID: a.TGWID, Ifname: naming.AttachmentIf(a.ID)}
		if len(a.SubnetIDs) > 0 {
			ra.Subnet = a.SubnetIDs[0]
		}
		for _, e := range r.ENIs {
			if !azs[idx.subnet[e.SubnetID].AZ] {
				ra.Uncovered = append(ra.Uncovered, e.RouterIf)
			}
		}
		r.Attachments = append(r.Attachments, ra)
	}
}

// linkRoute resolves a route to a peering connection or transit gateway.
// ok is false when the route is a blackhole; warn explains why, if useful.
func linkRoute(s *snapshot.Snapshot, r *Router, rte snapshot.Route) (dev string, ok bool, warn string) {
	switch rte.TargetKind {
	case snapshot.TargetPeering:
		for _, p := range r.Peerings {
			if p.ID == rte.TargetID {
				return p.Ifname, true, ""
			}
		}
		for _, pc := range s.Peerings {
			if pc.ID != rte.TargetID {
				continue
			}
			if pc.RequesterVPCID != r.VPCID && pc.AccepterVPCID != r.VPCID {
				return "", false, fmt.Sprintf("peering connection %s does not include %s", pc.ID, r.VPCID)
			}
			if pc.Status != "active" {
				return "", false, fmt.Sprintf("peering connection %s is %s, not active", pc.ID, pc.Status)
			}
			return "", false, "" // the peer VPC has no running instances
		}
		return "", false, fmt.Sprintf("peering connection %s not found", rte.TargetID)
	case snapshot.TargetTGW:
		for _, a := range r.Attachments {
			if a.TGWID == rte.TargetID {
				return a.Ifname, true, ""
			}
		}
		return "", false, fmt.Sprintf("%s has no available attachment to %s", r.VPCID, rte.TargetID)
	}
	return "", false, ""
}

// flociTGWRoute reports whether a route without a target is a route to the
// VPC's transit gateway. Floci 2.3.0 drops TransitGatewayId from routes in
// DescribeRouteTables; with exactly one TGW attachment in the VPC, the
// target is unambiguous.
func flociTGWRoute(s *snapshot.Snapshot, vpcID string, rte snapshot.Route) (string, bool) {
	if rte.TargetKind != snapshot.TargetUnknown || rte.TargetID != "" {
		return "", false
	}
	var tgw string
	n := 0
	for _, a := range s.TGWAttachments {
		if a.VPCID == vpcID {
			tgw = a.TGWID
			n++
		}
	}
	return tgw, n == 1
}

// buildTransitGateways plans the TGW namespaces. A TGW gets one when at
// least one of its attachments has a link.
func buildTransitGateways(s *snapshot.Snapshot, idx *indexes, ls *linkSet) ([]TransitGateway, []string) {
	var out []TransitGateway
	var warns []string
	for _, g := range s.TransitGateways {
		var atts []snapshot.TGWAttachment
		for _, a := range s.TGWAttachments {
			if _, ok := ls.attachments[a.ID]; ok && a.TGWID == g.ID {
				atts = append(atts, a)
			}
		}
		if len(atts) == 0 {
			continue
		}
		tg := TransitGateway{ID: g.ID, Container: naming.TGWContainer(g.ID)}
		vrfOf := map[string]string{}
		var rts []snapshot.TGWRouteTable
		for _, rt := range s.TGWRouteTables {
			if rt.TGWID != g.ID {
				continue
			}
			v := VRF{RouteTableID: rt.ID, Ifname: naming.VRFIf(rt.ID), Table: TableRTBase + len(tg.VRFs)}
			tg.VRFs = append(tg.VRFs, v)
			vrfOf[rt.ID] = v.Ifname
			rts = append(rts, rt)
		}
		attIf := map[string]string{}
		for _, a := range atts {
			attIf[a.ID] = naming.AttachmentIf(a.ID)
			tg.Attachments = append(tg.Attachments, TGWAttachment{
				ID:        a.ID,
				VPCID:     a.VPCID,
				Ifname:    attIf[a.ID],
				VRF:       vrfOf[a.RouteTable],
				RouterMAC: naming.MAC(a.ID + "/vpc"),
				TGWMAC:    naming.MAC(a.ID + "/tgw"),
			})
		}
		for i, rt := range rts {
			t, w := tgwTable(s, idx, g, rt, attIf)
			t.ID = tg.VRFs[i].Table
			tg.Tables = append(tg.Tables, t)
			warns = append(warns, w...)
		}
		out = append(out, tg)
	}
	return out, warns
}

// tgwTable renders one TGW route table. Static routes win over propagated
// routes for the same prefix, as in AWS.
func tgwTable(s *snapshot.Snapshot, idx *indexes, g snapshot.TransitGateway, rt snapshot.TGWRouteTable, attIf map[string]string) (Table, []string) {
	var warns []string
	byDst := map[netip.Prefix]Route{}
	from := map[netip.Prefix]string{}

	props := slices.Clone(rt.Propagations)
	if g.DefaultPropagation && rt.ID == g.DefaultPropagationRT {
		// AWS propagates every new attachment into this table; Floci does
		// not record those propagations.
		for _, a := range s.TGWAttachments {
			if a.TGWID == g.ID && !slices.Contains(props, a.ID) {
				props = append(props, a.ID)
			}
		}
	}
	slices.Sort(props)
	for _, id := range props {
		dev, ok := attIf[id]
		if !ok {
			continue // the attachment's VPC has no running instances
		}
		var vpcID string
		for _, a := range s.TGWAttachments {
			if a.ID == id {
				vpcID = a.VPCID
			}
		}
		for _, dst := range collapse(idx.vpc[vpcID].CIDRs) {
			if other, dup := from[dst]; dup {
				warns = append(warns, fmt.Sprintf("%s: %s is propagated by %s and %s; %s is used", rt.ID, dst, other, id, other))
				continue
			}
			byDst[dst] = Route{Dst: dst, Kind: RouteVia, Dev: dev, Via: LinkNextHop}
			from[dst] = id
		}
	}
	for _, sr := range rt.Routes {
		p, err := netip.ParsePrefix(sr.DestinationCIDR)
		if err != nil {
			warns = append(warns, fmt.Sprintf("%s: route %q: %v", rt.ID, sr.DestinationCIDR, err))
			continue
		}
		dst := p.Masked()
		dev, ok := attIf[sr.AttachmentID]
		if sr.Blackhole || !ok {
			byDst[dst] = Route{Dst: dst, Kind: RouteBlackhole}
			continue
		}
		byDst[dst] = Route{Dst: dst, Kind: RouteVia, Dev: dev, Via: LinkNextHop}
	}

	t := Table{Name: rt.ID}
	for _, r := range byDst {
		t.Routes = append(t.Routes, r)
	}
	slices.SortFunc(t.Routes, func(a, b Route) int {
		if c := a.Dst.Addr().Compare(b.Dst.Addr()); c != 0 {
			return c
		}
		return a.Dst.Bits() - b.Dst.Bits()
	})
	// Without a match the kernel would leave the VRF and try the main table.
	t.Routes = append(t.Routes, Route{Dst: netip.MustParsePrefix("0.0.0.0/0"), Kind: RouteBlackhole, Metric: catchAllMetric})
	return t, warns
}

// renderLinkFilters renders the forward-chain rules for peering and TGW
// links.
func renderLinkFilters(w func(string, ...any), r *Router) {
	for _, p := range r.Peerings {
		w("\t\tiifname %q ip saddr != %s counter drop comment %q", p.Ifname, prefixSet(p.PeerCIDRs), p.ID+": source is not in the peer VPC")
		w("\t\tiifname %q ip daddr != %s counter drop comment %q", p.Ifname, prefixSet(p.LocalCIDRs), p.ID+": destination is not in this VPC")
	}
	for _, a := range r.Attachments {
		if len(a.Uncovered) == 0 {
			continue
		}
		set := "{ " + quoteJoin(a.Uncovered) + " }"
		w("\t\toifname %q iifname %s counter drop comment %q", a.Ifname, set, a.ID+": no attachment subnet in the source's Availability Zone")
		w("\t\tiifname %q oifname %s counter drop comment %q", a.Ifname, set, a.ID+": no attachment subnet in the destination's Availability Zone")
	}
}

// buildPeerings lists the peering links of the plan.
func buildPeerings(ls *linkSet) []Peering {
	var out []Peering
	for id, pc := range ls.peerings {
		a, b := pc.RequesterVPCID, pc.AccepterVPCID
		if b < a {
			a, b = b, a
		}
		out = append(out, Peering{
			ID:     id,
			Ifname: naming.PeeringIf(id),
			A:      LinkEnd{VPCID: a, MAC: naming.MAC(id + "/" + a)},
			B:      LinkEnd{VPCID: b, MAC: naming.MAC(id + "/" + b)},
		})
	}
	slices.SortFunc(out, func(x, y Peering) int { return strings.Compare(x.ID, y.ID) })
	return out
}
