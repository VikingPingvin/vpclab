package plan

import (
	"slices"
	"strings"
	"testing"

	"github.com/VikingPingvin/vpclab/internal/naming"
	"github.com/VikingPingvin/vpclab/internal/snapshot"
)

// multiVPC: vpc-1 (fixture) plus vpc-2 (10.1.0.0/16) and vpc-3
// (10.2.0.0/16), one instance each.
func multiVPC() *snapshot.Snapshot {
	s := fixture()
	allEgress := []snapshot.SGRule{{Protocol: "-1", CIDRs: []string{"0.0.0.0/0"}}}
	for _, v := range []struct{ n, cidr, ip, az string }{{"2", "10.1.0.0/16", "10.1.1.10", "az-a"}, {"3", "10.2.0.0/16", "10.2.1.10", "az-b"}} {
		vpc, sn := "vpc-"+v.n, "subnet-"+v.n
		s.VPCs = append(s.VPCs, snapshot.VPC{ID: vpc, CIDRs: []string{v.cidr}})
		s.Subnets = append(s.Subnets, snapshot.Subnet{ID: sn, VPCID: vpc, CIDR: strings.Replace(v.cidr, "0.0/16", "1.0/24", 1), AZ: v.az})
		s.RouteTables = append(s.RouteTables, snapshot.RouteTable{ID: "rtb-" + v.n, VPCID: vpc, Main: true, Routes: []snapshot.Route{
			{DestinationCIDR: v.cidr, TargetKind: snapshot.TargetLocal},
		}})
		s.SecurityGroups = append(s.SecurityGroups, snapshot.SecurityGroup{ID: "sg-" + v.n, VPCID: vpc, Egress: allEgress})
		s.ENIs = append(s.ENIs, snapshot.ENI{ID: "eni-" + v.n, SubnetID: sn, VPCID: vpc, PrivateIPs: []string{v.ip}, Groups: []string{"sg-" + v.n}, SourceDestCheck: true, InstanceID: "i-" + v.n})
		s.Instances = append(s.Instances, snapshot.Instance{ID: "i-" + v.n, State: "running", SourceDestCheck: true, SubnetID: sn, VPCID: vpc, ENIs: []string{"eni-" + v.n}})
	}
	for i := range s.Subnets {
		if s.Subnets[i].AZ == "" {
			s.Subnets[i].AZ = "az-a"
		}
	}
	return s
}

// linkWarnings drops the fixture's own warning about igw-1.
func linkWarnings(p *Plan) []string {
	var out []string
	for _, w := range p.Warnings {
		if !strings.Contains(w, "igw-1") {
			out = append(out, w)
		}
	}
	return out
}

func router(t *testing.T, p *Plan, vpc string) Router {
	t.Helper()
	for _, r := range p.Routers {
		if r.VPCID == vpc {
			return r
		}
	}
	t.Fatalf("no router for %s", vpc)
	return Router{}
}

func addRoute(s *snapshot.Snapshot, rt string, r snapshot.Route) {
	for i := range s.RouteTables {
		if s.RouteTables[i].ID == rt {
			s.RouteTables[i].Routes = append(s.RouteTables[i].Routes, r)
		}
	}
}

func withPeering(s *snapshot.Snapshot, status string) *snapshot.Snapshot {
	s.Peerings = []snapshot.Peering{{
		ID: "pcx-1", Status: status,
		RequesterVPCID: "vpc-1", RequesterCIDRs: []string{"10.0.0.0/16"},
		AccepterVPCID: "vpc-2", // Floci may omit the CIDRs
	}}
	addRoute(s, "rtb-main", snapshot.Route{DestinationCIDR: "10.1.0.0/16", TargetKind: snapshot.TargetPeering, TargetID: "pcx-1"})
	addRoute(s, "rtb-2", snapshot.Route{DestinationCIDR: "10.0.0.0/16", TargetKind: snapshot.TargetPeering, TargetID: "pcx-1"})
	// Transitive use is not possible: vpc-2 routes vpc-3's CIDR to the peering.
	addRoute(s, "rtb-2", snapshot.Route{DestinationCIDR: "10.2.0.0/16", TargetKind: snapshot.TargetPeering, TargetID: "pcx-1"})
	return s
}

func TestPeering(t *testing.T) {
	p := build2(t, withPeering(multiVPC(), "active"))
	ifname := naming.PeeringIf("pcx-1")
	if len(p.Peerings) != 1 || p.Peerings[0].Ifname != ifname || p.Peerings[0].A.VPCID != "vpc-1" || p.Peerings[0].B.VPCID != "vpc-2" {
		t.Fatalf("peerings = %+v", p.Peerings)
	}
	if p.Peerings[0].A.MAC.String() == p.Peerings[0].B.MAC.String() {
		t.Error("both ends of the peering link have the same MAC")
	}

	r1, r2 := router(t, p, "vpc-1"), router(t, p, "vpc-2")
	if rt := route(t, r1, "rtb-main", "10.1.0.0/16"); rt.Kind != RouteVia || rt.Dev != ifname || rt.Via != LinkNextHop {
		t.Errorf("vpc-1 route to the peer = %+v", rt)
	}
	if rt := route(t, r2, "rtb-2", "10.0.0.0/16"); rt.Kind != RouteVia || rt.Dev != ifname {
		t.Errorf("vpc-2 route to the peer = %+v", rt)
	}

	// The receiver accepts only peer source -> own destination. The accepter
	// CIDRs come from the VPC because the peering does not list them.
	assertInOrder(t, r2.Ruleset, []string{
		`iifname "` + ifname + `" ip saddr != { 10.0.0.0/16 } counter drop`,
		`iifname "` + ifname + `" ip daddr != { 10.1.0.0/16 } counter drop`,
		"iifname vmap",
	})
	if !strings.Contains(r1.Ruleset, `iifname "`+ifname+`" ip saddr != { 10.1.0.0/16 }`) {
		t.Errorf("vpc-1 does not filter the peer's source:\n%s", r1.Ruleset)
	}
	// Peering traffic only goes to local addresses: no ip rule for the link.
	for _, rule := range r1.Rules {
		if rule.IifName == ifname {
			t.Errorf("ip rule for the peering link: %+v", rule)
		}
	}
	if w := linkWarnings(p); len(w) != 0 {
		t.Errorf("warnings = %v", w)
	}
}

func TestPeeringNotActive(t *testing.T) {
	p := build2(t, withPeering(multiVPC(), "pending-acceptance"))
	if len(p.Peerings) != 0 {
		t.Errorf("peerings = %+v, want none", p.Peerings)
	}
	if rt := route(t, router(t, p, "vpc-1"), "rtb-main", "10.1.0.0/16"); rt.Kind != RouteBlackhole {
		t.Errorf("route to an inactive peering = %+v, want blackhole", rt)
	}
	if !slices.ContainsFunc(p.Warnings, func(w string) bool { return strings.Contains(w, "pending-acceptance") }) {
		t.Errorf("warnings = %v, want one about the pending peering", p.Warnings)
	}
}

func TestPeeringOverlap(t *testing.T) {
	s := withPeering(multiVPC(), "active")
	s.VPCs[1].CIDRs = []string{"10.0.0.0/8"}
	p := build2(t, s)
	if len(p.Peerings) != 0 || !slices.ContainsFunc(p.Warnings, func(w string) bool { return strings.Contains(w, "overlap") }) {
		t.Errorf("peerings = %+v, warnings = %v; want no peering and an overlap warning", p.Peerings, p.Warnings)
	}
}

// withTGW attaches all three VPCs to tgw-1. vpc-1 and vpc-2 use the default
// route table rt-a; vpc-3 is associated with rt-b, which only has a static
// route to vpc-1.
func withTGW(s *snapshot.Snapshot) *snapshot.Snapshot {
	s.TransitGateways = []snapshot.TransitGateway{{ID: "tgw-1", State: "available", DefaultPropagation: true, DefaultPropagationRT: "rt-a"}}
	s.TGWAttachments = []snapshot.TGWAttachment{
		{ID: "att-1", TGWID: "tgw-1", VPCID: "vpc-1", State: "available", SubnetIDs: []string{"subnet-b"}, RouteTable: "rt-a"},
		{ID: "att-2", TGWID: "tgw-1", VPCID: "vpc-2", State: "available", SubnetIDs: []string{"subnet-2"}, RouteTable: "rt-a"},
		{ID: "att-3", TGWID: "tgw-1", VPCID: "vpc-3", State: "available", SubnetIDs: []string{"subnet-3"}, RouteTable: "rt-b"},
	}
	s.TGWRouteTables = []snapshot.TGWRouteTable{
		{ID: "rt-a", TGWID: "tgw-1", Routes: []snapshot.TGWRoute{{DestinationCIDR: "10.9.0.0/16", Blackhole: true}}},
		{ID: "rt-b", TGWID: "tgw-1", Routes: []snapshot.TGWRoute{{DestinationCIDR: "10.0.0.0/16", AttachmentID: "att-1"}}},
	}
	addRoute(s, "rtb-main", snapshot.Route{DestinationCIDR: "10.1.0.0/16", TargetKind: snapshot.TargetTGW, TargetID: "tgw-1"})
	// Floci drops the target of TGW routes.
	addRoute(s, "rtb-2", snapshot.Route{DestinationCIDR: "10.0.0.0/8", TargetKind: snapshot.TargetUnknown})
	return s
}

func TestTransitGateway(t *testing.T) {
	p := build2(t, withTGW(multiVPC()))
	if w := linkWarnings(p); len(w) != 0 {
		t.Errorf("warnings = %v", w)
	}
	if len(p.TransitGateways) != 1 {
		t.Fatalf("transit gateways = %+v", p.TransitGateways)
	}
	g := p.TransitGateways[0]
	if g.Container != "vpcsim-tgw-1" || len(g.VRFs) != 2 || len(g.Attachments) != 3 || len(g.Tables) != 2 {
		t.Fatalf("transit gateway = %+v", g)
	}
	if g.Attachments[0].VRF != naming.VRFIf("rt-a") || g.Attachments[2].VRF != naming.VRFIf("rt-b") {
		t.Errorf("attachment VRFs = %s, %s", g.Attachments[0].VRF, g.Attachments[2].VRF)
	}

	// rt-a: implicit default propagation of all three VPCs, a static
	// blackhole and the catch-all.
	var dsts []string
	for _, r := range g.Tables[0].Routes {
		dsts = append(dsts, r.Dst.String()+" "+string(r.Kind)+" "+r.Dev)
	}
	want := []string{
		"10.0.0.0/16 via " + naming.AttachmentIf("att-1"),
		"10.1.0.0/16 via " + naming.AttachmentIf("att-2"),
		"10.2.0.0/16 via " + naming.AttachmentIf("att-3"),
		"10.9.0.0/16 blackhole ",
		"0.0.0.0/0 blackhole ",
	}
	if !slices.Equal(dsts, want) {
		t.Errorf("rt-a routes:\n got %q\nwant %q", dsts, want)
	}
	if last := g.Tables[0].Routes[4]; last.Metric != catchAllMetric {
		t.Errorf("catch-all metric = %d", last.Metric)
	}
	if n := len(g.Tables[1].Routes); n != 2 || g.Tables[1].Routes[0].Dev != naming.AttachmentIf("att-1") {
		t.Errorf("rt-b routes = %+v", g.Tables[1].Routes)
	}

	r1, r2 := router(t, p, "vpc-1"), router(t, p, "vpc-2")
	att1 := naming.AttachmentIf("att-1")
	if rt := route(t, r1, "rtb-main", "10.1.0.0/16"); rt.Kind != RouteVia || rt.Dev != att1 || rt.Via != LinkNextHop {
		t.Errorf("vpc-1 route to the TGW = %+v", rt)
	}
	if rt := route(t, r2, "rtb-2", "10.0.0.0/8"); rt.Kind != RouteVia || rt.Dev != naming.AttachmentIf("att-2") {
		t.Errorf("vpc-2 route without a target (Floci) = %+v, want the TGW attachment", rt)
	}
	// Traffic from the TGW uses the attachment subnet's route table: rtb-b.
	found := false
	for _, rule := range r1.Rules {
		if rule.IifName == att1 {
			found = rule.Table == TableRTBase+1
		}
	}
	if !found {
		t.Errorf("no ip rule from %s to rtb-b: %+v", att1, r1.Rules)
	}
}

// AWS: a TGW only reaches ENIs in Availability Zones where the attachment
// has a subnet.
func TestTransitGatewayAvailabilityZones(t *testing.T) {
	s := withTGW(multiVPC())
	for i := range s.Subnets {
		if s.Subnets[i].ID == "subnet-a" {
			s.Subnets[i].AZ = "az-c"
		}
	}
	r := router(t, build2(t, s), "vpc-1")
	att := naming.AttachmentIf("att-1")
	var uncovered []string
	for _, e := range r.ENIs {
		if e.SubnetID == "subnet-a" {
			uncovered = append(uncovered, e.RouterIf)
		}
	}
	if len(r.Attachments) != 1 || !slices.Equal(r.Attachments[0].Uncovered, uncovered) {
		t.Fatalf("attachments = %+v, want uncovered %v", r.Attachments, uncovered)
	}
	if !strings.Contains(r.Ruleset, `oifname "`+att+`" iifname { "`) {
		t.Errorf("no AZ filter for %s:\n%s", att, r.Ruleset)
	}
}

func TestTransitGatewayRouteWithoutAttachment(t *testing.T) {
	s := withTGW(multiVPC())
	s.TGWAttachments = s.TGWAttachments[1:] // vpc-1 is not attached
	p := build2(t, s)
	if rt := route(t, router(t, p, "vpc-1"), "rtb-main", "10.1.0.0/16"); rt.Kind != RouteBlackhole {
		t.Errorf("route = %+v, want blackhole", rt)
	}
	if !slices.ContainsFunc(p.Warnings, func(w string) bool { return strings.Contains(w, "no available attachment") }) {
		t.Errorf("warnings = %v", p.Warnings)
	}
	// rt-b's static route to att-1 has no target now.
	if r := p.TransitGateways[0].Tables[1].Routes[0]; r.Kind != RouteBlackhole {
		t.Errorf("static route to a missing attachment = %+v, want blackhole", r)
	}
}
