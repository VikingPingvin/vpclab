package plan

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/VikingPingvin/vpclab/internal/naming"
	"github.com/VikingPingvin/vpclab/internal/snapshot"
)

// fixture: one VPC, two subnets, web/app/other instances.
// sg-web allows tcp/443 from sg-app only.
func fixture() *snapshot.Snapshot {
	allEgress := []snapshot.SGRule{{Protocol: "-1", CIDRs: []string{"0.0.0.0/0"}}}
	return &snapshot.Snapshot{
		VPCs: []snapshot.VPC{{ID: "vpc-1", CIDRs: []string{"10.0.0.0/16"}}},
		Subnets: []snapshot.Subnet{
			{ID: "subnet-a", VPCID: "vpc-1", CIDR: "10.0.1.0/24"},
			{ID: "subnet-b", VPCID: "vpc-1", CIDR: "10.0.2.0/24"},
		},
		RouteTables: []snapshot.RouteTable{
			{ID: "rtb-main", VPCID: "vpc-1", Main: true, Routes: []snapshot.Route{
				{DestinationCIDR: "10.0.0.0/16", TargetKind: snapshot.TargetLocal},
			}},
			{ID: "rtb-b", VPCID: "vpc-1", Subnets: []string{"subnet-b"}, Routes: []snapshot.Route{
				{DestinationCIDR: "10.0.0.0/16", TargetKind: snapshot.TargetLocal},
				{DestinationCIDR: "0.0.0.0/0", TargetKind: snapshot.TargetIGW, TargetID: "igw-1"},
				{DestinationCIDR: "192.168.0.0/16", TargetKind: snapshot.TargetNAT, TargetID: "nat-1", Blackhole: true},
			}},
		},
		SecurityGroups: []snapshot.SecurityGroup{
			{ID: "sg-web", VPCID: "vpc-1", Egress: allEgress, Ingress: []snapshot.SGRule{
				{Protocol: "tcp", FromPort: 443, ToPort: 443, Groups: []string{"sg-app"}},
				{Protocol: "icmp", FromPort: 3, ToPort: 4, CIDRs: []string{"0.0.0.0/0"}},
			}},
			{ID: "sg-app", VPCID: "vpc-1", Egress: allEgress},
			{ID: "sg-other", VPCID: "vpc-1", Egress: allEgress},
		},
		ENIs: []snapshot.ENI{
			{ID: "eni-web", SubnetID: "subnet-a", VPCID: "vpc-1", PrivateIPs: []string{"10.0.1.10"}, Groups: []string{"sg-web"}, SourceDestCheck: true, InstanceID: "i-web"},
			{ID: "eni-app", SubnetID: "subnet-b", VPCID: "vpc-1", PrivateIPs: []string{"10.0.2.10", "10.0.2.11"}, Groups: []string{"sg-app"}, SourceDestCheck: true, InstanceID: "i-app"},
			{ID: "eni-other", SubnetID: "subnet-a", VPCID: "vpc-1", PrivateIPs: []string{"10.0.1.20"}, Groups: []string{"sg-other"}, SourceDestCheck: false, InstanceID: "i-other"},
		},
		Instances: []snapshot.Instance{
			{ID: "i-web", State: "running", SourceDestCheck: true, SubnetID: "subnet-a", VPCID: "vpc-1", ENIs: []string{"eni-web"}},
			{ID: "i-app", State: "running", SourceDestCheck: true, SubnetID: "subnet-b", VPCID: "vpc-1", ENIs: []string{"eni-app"}},
			{ID: "i-other", State: "running", SourceDestCheck: true, SubnetID: "subnet-a", VPCID: "vpc-1", ENIs: []string{"eni-other"}},
			{ID: "i-gone", State: "terminated", SubnetID: "subnet-a", VPCID: "vpc-1"},
		},
	}
}

func build(t *testing.T) *Plan {
	t.Helper()
	p, err := Build(fixture(), Options{InstanceImage: "img"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestBuildSkipsNonRunningInstances(t *testing.T) {
	p := build(t)
	if len(p.Instances) != 3 {
		t.Fatalf("instances = %d, want 3", len(p.Instances))
	}
	if p.Instances[0].Hostname != "ip-10-0-1-10" {
		t.Errorf("hostname = %q", p.Instances[0].Hostname)
	}
	if got := fmt.Sprint(p.Instances[0].DNS); got != fmt.Sprint(DefaultDNS) {
		t.Errorf("DNS = %s, want %s", got, fmt.Sprint(DefaultDNS))
	}
}

// A stopped instance keeps its container but has no ENIs on the router.
func TestStoppedInstanceKeepsContainer(t *testing.T) {
	for _, state := range []string{"stopping", "stopped"} {
		s := fixture()
		s.Instances[0].State = state // i-web
		p, err := Build(s, Options{InstanceImage: "img"})
		if err != nil {
			t.Fatal(err)
		}
		if len(p.Instances) != 3 || p.Instances[0].ID != "i-web" || p.Instances[0].Running {
			t.Errorf("%s: instances = %+v, want i-web kept and not running", state, p.Instances)
		}
		if !p.Instances[1].Running {
			t.Errorf("%s: %s is not running", state, p.Instances[1].ID)
		}
		for _, e := range p.Routers[0].ENIs {
			if e.ID == "eni-web" {
				t.Errorf("%s: router still plugs in eni-web", state)
			}
		}
	}
}

func TestRouterGatewaysAndDelivery(t *testing.T) {
	r := build(t).Routers[0]
	want := []netip.Addr{netip.MustParseAddr("10.0.1.1"), netip.MustParseAddr("10.0.2.1")}
	if len(r.Gateway) != 2 || r.Gateway[0] != want[0] || r.Gateway[1] != want[1] {
		t.Errorf("gateways = %v, want %v", r.Gateway, want)
	}
	delivery := r.Tables[0]
	if delivery.ID != TableDelivery || len(delivery.Routes) != 4 {
		t.Fatalf("delivery table = %+v", delivery)
	}
}

func TestSubnetRouteTableAssociation(t *testing.T) {
	r := build(t).Routers[0]
	tableByIf := map[string]int{}
	for _, rule := range r.Rules {
		if rule.IifName != "" {
			tableByIf[rule.IifName] = rule.Table
		}
	}
	tables := map[int]Table{}
	for _, tb := range r.Tables {
		tables[tb.ID] = tb
	}
	if got := tables[tableByIf[naming.RouterIf("eni-web")]].Name; got != "rtb-main" {
		t.Errorf("subnet-a uses %s, want implicit main rtb-main", got)
	}
	if got := tables[tableByIf[naming.RouterIf("eni-app")]].Name; got != "rtb-b" {
		t.Errorf("subnet-b uses %s, want explicit rtb-b", got)
	}
}

func TestUnsupportedTargetsBlackholeWithWarning(t *testing.T) {
	p := build(t)
	if len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "igw-1") {
		t.Errorf("warnings = %v, want one about igw-1", p.Warnings)
	}
	for _, tb := range p.Routers[0].Tables {
		if tb.Name != "rtb-b" {
			continue
		}
		for _, rt := range tb.Routes {
			if rt.Dst.String() == "10.0.0.0/16" && rt.Kind != RouteThrow {
				t.Errorf("local route kind = %s, want throw", rt.Kind)
			}
			if rt.Dst.String() != "10.0.0.0/16" && rt.Kind != RouteBlackhole {
				t.Errorf("%s kind = %s, want blackhole", rt.Dst, rt.Kind)
			}
		}
	}
}

func TestNftSecurityGroups(t *testing.T) {
	rs := build(t).Routers[0].Ruleset
	for _, want := range []string{
		"delete table inet vpcsim",
		// sg-web ingress references sg-app members, including secondary IPs
		"set members_sg_app {",
		"elements = { 10.0.2.10, 10.0.2.11 }",
		`ip saddr @members_sg_app tcp dport 443 return comment "sg-web ingress"`,
		`icmp type 3 icmp code 4 return comment "sg-web ingress"`,
		// all-traffic egress to 0.0.0.0/0 renders as a bare return
		`return comment "sg-web egress"`,
		// source/destination check on eni-web, not on eni-other
		"ip saddr { 10.0.1.10 } return",
		"ct state established accept",
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("ruleset missing %q\n%s", want, rs)
		}
	}
	if strings.Contains(rs, "ip saddr { 10.0.1.20 } return") {
		t.Error("eni-other has source/destination check disabled but got a source check")
	}
}

func withInternet(s *snapshot.Snapshot) *snapshot.Snapshot {
	s.IGWs = []snapshot.IGW{{ID: "igw-1", VPCID: "vpc-1"}}
	s.Subnets[0].MapPublicIPOnLaunch = true // subnet-a: web, other
	s.ElasticIPs = []snapshot.ElasticIP{{AllocationID: "eipalloc-1", PublicIP: "54.1.1.1", ENIID: "eni-app", PrivateIP: "10.0.2.10"}}
	return s
}

func TestInternetGateway(t *testing.T) {
	p, err := Build(withInternet(fixture()), Options{InstanceImage: "img"})
	if err != nil {
		t.Fatal(err)
	}
	r := p.Routers[0]
	if r.IGW == nil || r.IGW.ID != "igw-1" {
		t.Fatalf("IGW = %+v", r.IGW)
	}
	for _, tb := range r.Tables {
		if tb.Name != "rtb-b" {
			continue
		}
		for _, rt := range tb.Routes {
			if rt.Dst.String() == "0.0.0.0/0" && (rt.Kind != RouteVia || rt.Dev != IGWIf || rt.Via != EdgeInternetAddr) {
				t.Errorf("default route = %+v, want via %s dev %s", rt, EdgeInternetAddr, IGWIf)
			}
		}
	}

	// EIP for app (secondary IP 10.0.2.11 has none), auto-assigned IPs for
	// the primary ENIs in subnet-a.
	if len(r.NAT) != 3 {
		t.Fatalf("NAT = %+v, want 3 entries", r.NAT)
	}
	for _, n := range r.NAT {
		switch n.Private.String() {
		case "10.0.2.10":
			if n.Public.String() != "54.1.1.1" || n.Auto {
				t.Errorf("app NAT = %+v, want EIP 54.1.1.1", n)
			}
		case "10.0.1.10", "10.0.1.20":
			if !n.Auto || !autoPublicPool.Contains(n.Public) {
				t.Errorf("%s NAT = %+v, want auto-assigned from %s", n.Private, n, autoPublicPool)
			}
		default:
			t.Errorf("unexpected NAT %+v", n)
		}
	}
	for _, want := range []string{
		`iifname "igw0" dnat ip to ip daddr map {`,
		"54.1.1.1 : 10.0.2.10",
		`oifname "igw0" ip saddr != @public_private counter drop`,
	} {
		if !strings.Contains(r.Ruleset, want) {
			t.Errorf("ruleset missing %q", want)
		}
	}

	if p.Internet == nil || len(p.Internet.Links) != 1 || len(p.Internet.Links[0].Public) != 3 {
		t.Fatalf("internet = %+v", p.Internet)
	}
	again, _ := Build(withInternet(fixture()), Options{InstanceImage: "img"})
	if fmt.Sprint(again.Routers[0].NAT) != fmt.Sprint(r.NAT) {
		t.Error("auto-assigned public IPs are not deterministic")
	}
}

func TestInternetUplink(t *testing.T) {
	in := build(t).Internet
	if in == nil || in.Uplink != UplinkNetwork {
		t.Fatalf("internet = %+v, want uplink %s", in, UplinkNetwork)
	}
	for _, want := range []string{
		"delete table ip vpcsim",
		`oifname "eth0" ip daddr @not_routable counter drop`,
		`oifname "eth0" masquerade`,
		`iifname "eth0" ct state established,related accept`,
		"172.16.0.0/12",         // the WSL host's Docker networks and Floci
		autoPublicPool.String(), // simulated public IPs never leak
		"203.0.113.0/24",        // simulated internet hosts
	} {
		if !strings.Contains(in.Ruleset, want) {
			t.Errorf("internet ruleset missing %q\n%s", want, in.Ruleset)
		}
	}
}

// Two VPCs may use the same CIDR; an EIP must stay with its own ENI.
func TestOverlappingVPCsKeepTheirEIPs(t *testing.T) {
	s := withInternet(fixture())
	s.VPCs = append(s.VPCs, snapshot.VPC{ID: "vpc-2", CIDRs: []string{"10.0.0.0/16"}})
	s.Subnets = append(s.Subnets, snapshot.Subnet{ID: "subnet-2", VPCID: "vpc-2", CIDR: "10.0.2.0/24"})
	s.RouteTables = append(s.RouteTables, snapshot.RouteTable{ID: "rtb-2", VPCID: "vpc-2", Main: true})
	s.IGWs = append(s.IGWs, snapshot.IGW{ID: "igw-2", VPCID: "vpc-2"})
	s.ENIs = append(s.ENIs, snapshot.ENI{ID: "eni-twin", SubnetID: "subnet-2", VPCID: "vpc-2", PrivateIPs: []string{"10.0.2.10"}, SourceDestCheck: true, InstanceID: "i-twin"})
	s.Instances = append(s.Instances, snapshot.Instance{ID: "i-twin", State: "running", VPCID: "vpc-2", ENIs: []string{"eni-twin"}, SourceDestCheck: true})
	s.ElasticIPs = append(s.ElasticIPs, snapshot.ElasticIP{AllocationID: "eipalloc-2", PublicIP: "54.2.2.2", ENIID: "eni-twin", PrivateIP: "10.0.2.10"})

	p := build2(t, s)
	got := map[string]string{}
	for _, r := range p.Routers {
		for _, n := range r.NAT {
			if n.Private.String() == "10.0.2.10" {
				got[r.VPCID] = n.Public.String()
			}
		}
	}
	if got["vpc-1"] != "54.1.1.1" || got["vpc-2"] != "54.2.2.2" {
		t.Errorf("public IPs for 10.0.2.10 = %v, want vpc-1: 54.1.1.1, vpc-2: 54.2.2.2", got)
	}
}

func TestNetworkACL(t *testing.T) {
	s := fixture()
	icmpAll := int32(-1)
	s.NetworkACLs = []snapshot.NetworkACL{
		{ID: "acl-default", VPCID: "vpc-1", Default: true, Subnets: []string{"subnet-b"}, Entries: []snapshot.ACLEntry{
			{RuleNumber: 100, Allow: true, Protocol: "-1", CIDR: "0.0.0.0/0"},
			{RuleNumber: 100, Egress: true, Allow: true, Protocol: "-1", CIDR: "0.0.0.0/0"},
		}},
		{ID: "acl-a", VPCID: "vpc-1", Subnets: []string{"subnet-a"}, Entries: []snapshot.ACLEntry{
			{RuleNumber: 90, Allow: false, Protocol: "6", CIDR: "10.0.2.0/24", FromPort: 22, ToPort: 22},
			{RuleNumber: 100, Allow: true, Protocol: "6", CIDR: "0.0.0.0/0", FromPort: 443, ToPort: 443},
			{RuleNumber: 110, Allow: true, Protocol: "1", CIDR: "0.0.0.0/0", ICMPType: &icmpAll, ICMPCode: &icmpAll},
			{RuleNumber: 100, Egress: true, Allow: true, Protocol: "6", CIDR: "0.0.0.0/0", FromPort: 1024, ToPort: 65535},
		}},
	}
	rs := build2(t, s).Routers[0].Ruleset

	in := chainBody(t, rs, "nacl_in_subnet_a")
	want := []string{
		// traffic from the same subnet skips the ACL
		`iifname { "` + naming.RouterIf("eni-other") + `", "` + naming.RouterIf("eni-web") + `" } return`,
		`ip saddr { 10.0.2.0/24 } tcp dport 22 counter drop comment "acl-a #90"`,
		`tcp dport 443 return comment "acl-a #100"`,
		`meta l4proto icmp return comment "acl-a #110"`,
		`counter drop comment "network ACL in: implicit deny"`,
	}
	assertInOrder(t, in, want)
	assertInOrder(t, chainBody(t, rs, "nacl_out_subnet_a"), []string{`tcp dport 1024-65535 return comment "acl-a #100"`})
	assertInOrder(t, chainBody(t, rs, "nacl_in_subnet_b"), []string{`return comment "acl-default #100"`})
	if !strings.Contains(rs, `oifname vmap { "`+naming.RouterIf("eni-app")+`" : jump nacl_in_subnet_b`) {
		t.Error("forward chain does not dispatch eni-app to subnet-b's ACL")
	}
}

func build2(t *testing.T, s *snapshot.Snapshot) *Plan {
	t.Helper()
	p, err := Build(s, Options{InstanceImage: "img"})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func chainBody(t *testing.T, ruleset, chain string) string {
	t.Helper()
	start := strings.Index(ruleset, "\tchain "+chain+" {")
	if start < 0 {
		t.Fatalf("chain %s not found in\n%s", chain, ruleset)
	}
	end := strings.Index(ruleset[start:], "\n\t}")
	return ruleset[start : start+end]
}

func assertInOrder(t *testing.T, body string, lines []string) {
	t.Helper()
	pos := 0
	for _, l := range lines {
		i := strings.Index(body[pos:], l)
		if i < 0 {
			t.Errorf("missing or out of order: %q\nin:\n%s", l, body)
			return
		}
		pos += i + len(l)
	}
}

func TestCollapse(t *testing.T) {
	got := collapse([]string{"10.0.1.0/24", "10.0.0.0/16", "10.0.1.5", "192.168.1.1/32", "192.168.1.1", "bad"})
	if s := fmt.Sprint(got); s != "[10.0.0.0/16 192.168.1.1/32]" {
		t.Errorf("collapse = %s", s)
	}
}

func TestMACIsLocallyAdministeredUnicast(t *testing.T) {
	m := naming.MAC("eni-c9e8a40f0aee152c2")
	if m[0]&0x02 == 0 || m[0]&0x01 != 0 {
		t.Errorf("mac %s is not locally administered unicast", m)
	}
	if naming.MAC("eni-c9e8a40f0aee152c2").String() != m.String() {
		t.Error("mac is not deterministic")
	}
}
