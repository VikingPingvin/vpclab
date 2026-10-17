// Package plan turns a Floci snapshot into the complete desired state of the
// data plane. It is pure: no I/O, no root, so every rendering decision is
// unit-testable with hand-built snapshots.
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

// AWS ENIs use jumbo frames inside a VPC.
const ENIMTU = 9001

// Routing table IDs and ip rule priorities inside a router namespace.
const (
	TableDelivery  = 100  // /32 routes to every ENI address in the VPC
	TableBlackhole = 999  // final catch-all: AWS drops traffic with no route
	TableRTBase    = 1000 // AWS route table N maps to TableRTBase+N

	PrioritySubnetRT  = 1000
	PriorityDelivery  = 31000
	PriorityBlackhole = 32000
)

type Plan struct {
	Instances       []Instance
	Routers         []Router
	Peerings        []Peering
	TransitGateways []TransitGateway
	Internet        *Internet // nil when no VPC has a running instance
	Warnings        []string
}

type Instance struct {
	ID        string
	Name      string // Name tag
	VPCID     string
	Container string
	Image     string
	Hostname  string
	DNS       []string // resolvers in the instance's /etc/resolv.conf
	// Running is false for a stopped instance: its container is kept but
	// stopped, so files survive like on an EBS root volume.
	Running bool
	State   string // EC2 state from Floci
	// PrivateIP and PublicIP belong to the primary ENI. PublicIP includes
	// addresses vpcsim assigns itself (PublicAuto), which the AWS API does
	// not show.
	PrivateIP  string
	PublicIP   string
	PublicAuto bool
}

type Router struct {
	VPCID     string
	Container string
	// Gateway holds the .1 address of every subnet. The router answers ARP for
	// them because they are local addresses.
	Gateway []netip.Addr
	ENIs    []ENI
	IGW     *IGW  // nil when no internet gateway is attached
	NAT     []NAT // 1:1 mappings the IGW applies, sorted by private IP
	Tables  []Table
	Rules   []Rule
	Ruleset string // complete nftables ruleset, applied atomically
	// NATGateways run in their own namespaces; their ENIs are in ENIs.
	NATGateways []NATGateway
	Peerings    []RouterPeering
	Attachments []RouterAttachment
}

// NATGateway is a NAT gateway's namespace. It rewrites the source of
// forwarded traffic to its private IP and sends it back to the router, which
// routes it with the route table of the NAT gateway's subnet. The IGW then
// maps the private IP to the gateway's Elastic IP, as in AWS.
type NATGateway struct {
	ID        string
	VPCID     string
	Container string
	Ruleset   string // nftables ruleset of the NAT gateway's namespace
}

// IGW is an attached internet gateway: a veth between the router (IGWIf) and
// the internet namespace (InternetIf).
type IGW struct {
	ID         string
	InternetIf string
}

type ENI struct {
	ID         string
	InstanceID string
	// NATGatewayID is set for a NAT gateway's ENI; InstanceID is empty then.
	// NAT gateways have no security groups.
	NATGatewayID string
	Container    string // container whose netns holds the instance end
	SubnetID     string
	RouterIf     string
	TempIf       string
	InstanceIf   string
	MAC          net.HardwareAddr
	IPs          []netip.Addr // primary first
	Subnet       netip.Prefix
	Gateway      netip.Addr
	DefaultGW    bool // only device index 0 gets a default route
	SrcDstCheck  bool
	Groups       []string
}

type RouteKind string

const (
	RouteThrow     RouteKind = "throw"     // continue with the next ip rule
	RouteBlackhole RouteKind = "blackhole" // drop silently, like AWS
	RouteDev       RouteKind = "dev"       // deliver out of a router interface
	RouteVia       RouteKind = "via"       // send to a next hop on Dev (onlink)
)

type Route struct {
	Dst    netip.Prefix
	Kind   RouteKind
	Dev    string
	Via    netip.Addr // RouteVia only
	Metric int        // 0 for every route except a table's catch-all
}

type Table struct {
	ID     int
	Name   string // AWS ID or purpose, for humans
	Routes []Route
}

type Rule struct {
	Priority int
	IifName  string // empty: any
	Table    int
}

// Options configures plan generation.
type Options struct {
	InstanceImage string
	// DNS lists the resolvers instances use. There is no VPC resolver at .2
	// yet, so these are public resolvers, reached through the IGW.
	DNS []string
}

// DefaultDNS are the resolvers instances use when Options.DNS is empty.
var DefaultDNS = []string{"1.1.1.1", "8.8.8.8"}

// Build computes the desired data plane from a snapshot.
func Build(s *snapshot.Snapshot, opt Options) (*Plan, error) {
	idx := index(s)
	p := &Plan{}

	dns := opt.DNS
	if len(dns) == 0 {
		dns = DefaultDNS
	}
	public := publicIPs(s, idx)
	running := map[string][]snapshot.Instance{} // by VPC
	for _, in := range s.Instances {
		var isRunning bool
		switch in.State {
		case "running", "pending":
			isRunning = true
			running[in.VPCID] = append(running[in.VPCID], in)
		case "stopping", "stopped":
		default:
			continue // terminated: the container is removed
		}
		pi := Instance{
			ID:        in.ID,
			Name:      in.Name,
			VPCID:     in.VPCID,
			Container: naming.InstanceContainer(in.ID),
			Image:     opt.InstanceImage,
			Hostname:  naming.Hostname(idx.primaryIP(in)),
			DNS:       dns,
			Running:   isRunning,
			State:     in.State,
		}
		if eni, ip, ok := idx.primaryENI(in); ok {
			pi.PrivateIP = ip
			if a, err := netip.ParseAddr(ip); err == nil {
				if n, ok := public[natKey{eni, a}]; ok {
					pi.PublicIP, pi.PublicAuto = n.Public.String(), n.Auto
				}
			}
		}
		p.Instances = append(p.Instances, pi)
	}

	// Only VPCs with running instances need a router.
	routed := map[string]bool{}
	for _, vpc := range s.VPCs {
		routed[vpc.ID] = len(running[vpc.ID]) > 0
	}
	links, warns := usableLinks(s, idx, routed)
	p.Warnings = append(p.Warnings, warns...)
	for _, vpc := range s.VPCs {
		if !routed[vpc.ID] {
			continue
		}
		r, warns, err := buildRouter(s, idx, links, vpc, running[vpc.ID], public)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", vpc.ID, err)
		}
		p.Routers = append(p.Routers, *r)
		p.Warnings = append(p.Warnings, warns...)
	}
	p.Peerings = buildPeerings(links)
	p.TransitGateways, warns = buildTransitGateways(s, idx, links)
	p.Warnings = append(p.Warnings, warns...)
	if len(p.Routers) > 0 {
		buildInternet(p, opt.InstanceImage)
	}
	return p, nil
}

func buildRouter(s *snapshot.Snapshot, idx *indexes, links *linkSet, vpc snapshot.VPC, insts []snapshot.Instance, public map[natKey]NAT) (*Router, []string, error) {
	var warns []string
	r := &Router{VPCID: vpc.ID, Container: naming.RouterContainer(vpc.ID)}
	for _, g := range s.IGWs {
		if g.VPCID == vpc.ID {
			r.IGW = &IGW{ID: g.ID, InternetIf: naming.InternetIf(vpc.ID)}
		}
	}

	for _, sn := range s.Subnets {
		if sn.VPCID != vpc.ID {
			continue
		}
		pfx, err := netip.ParsePrefix(sn.CIDR)
		if err != nil {
			return nil, nil, fmt.Errorf("subnet %s: %w", sn.ID, err)
		}
		r.Gateway = append(r.Gateway, firstHost(pfx))
	}

	for _, in := range insts {
		for _, eniID := range in.ENIs {
			e, ok := idx.eni[eniID]
			if !ok {
				warns = append(warns, fmt.Sprintf("%s: ENI %s not found", in.ID, eniID))
				continue
			}
			sn, ok := idx.subnet[e.SubnetID]
			if !ok {
				return nil, nil, fmt.Errorf("ENI %s: subnet %s not found", e.ID, e.SubnetID)
			}
			pfx, err := netip.ParsePrefix(sn.CIDR)
			if err != nil {
				return nil, nil, err
			}
			var ips []netip.Addr
			for _, s := range e.PrivateIPs {
				a, err := netip.ParseAddr(s)
				if err != nil {
					return nil, nil, fmt.Errorf("ENI %s: %w", e.ID, err)
				}
				ips = append(ips, a)
			}
			r.ENIs = append(r.ENIs, ENI{
				ID:          e.ID,
				InstanceID:  in.ID,
				Container:   naming.InstanceContainer(in.ID),
				SubnetID:    e.SubnetID,
				RouterIf:    naming.RouterIf(e.ID),
				TempIf:      naming.TempIf(e.ID),
				InstanceIf:  naming.InstanceIf(e.DeviceIndex),
				MAC:         naming.MAC(e.ID),
				IPs:         ips,
				Subnet:      pfx.Masked(),
				Gateway:     firstHost(pfx),
				DefaultGW:   e.DeviceIndex == 0,
				SrcDstCheck: e.SourceDestCheck && (e.DeviceIndex != 0 || in.SourceDestCheck),
				Groups:      e.Groups,
			})
		}
	}
	for _, n := range s.NATGateways {
		if n.VPCID != vpc.ID || (n.State != "available" && n.State != "pending") {
			continue
		}
		e, err := natGatewayENI(idx, n)
		if err != nil {
			warns = append(warns, fmt.Sprintf("%s: %v; the NAT gateway is not simulated", n.ID, err))
			continue
		}
		r.ENIs = append(r.ENIs, e)
		r.NATGateways = append(r.NATGateways, NATGateway{
			ID:        n.ID,
			VPCID:     vpc.ID,
			Container: e.Container,
			Ruleset:   renderNATGatewayNft(e.IPs[0]),
		})
	}
	slices.SortFunc(r.ENIs, func(a, b ENI) int { return strings.Compare(a.ID, b.ID) })

	// Duplicate addresses break delivery: only one ENI gets the traffic.
	owner := map[netip.Addr]string{}
	for _, e := range r.ENIs {
		for _, ip := range e.IPs {
			if other, ok := owner[ip]; ok {
				warns = append(warns, fmt.Sprintf("%s and %s both use %s; only one of them receives traffic", other, e.ID, ip))
			}
			owner[ip] = e.ID
		}
	}

	for _, e := range r.ENIs {
		for _, ip := range e.IPs {
			if n, ok := public[natKey{e.ID, ip}]; ok {
				r.NAT = append(r.NAT, n)
			}
		}
	}
	slices.SortFunc(r.NAT, func(a, b NAT) int { return a.Private.Compare(b.Private) })

	buildRouterLinks(s, idx, links, r)
	tw, err := buildRouting(s, idx, vpc, r)
	if err != nil {
		return nil, nil, err
	}
	warns = append(warns, tw...)
	r.Ruleset = renderNft(idx, r)
	return r, warns, nil
}

// natGatewayENI builds the ENI of a NAT gateway. Floci reports the ENI only
// in the NAT gateway's addresses, not in DescribeNetworkInterfaces.
func natGatewayENI(idx *indexes, n snapshot.NATGateway) (ENI, error) {
	if n.ENIID == "" {
		return ENI{}, fmt.Errorf("no network interface")
	}
	ip, err := netip.ParseAddr(n.Private)
	if err != nil {
		return ENI{}, fmt.Errorf("private IP %q: %w", n.Private, err)
	}
	sn, ok := idx.subnet[n.SubnetID]
	if !ok {
		return ENI{}, fmt.Errorf("subnet %s not found", n.SubnetID)
	}
	pfx, err := netip.ParsePrefix(sn.CIDR)
	if err != nil {
		return ENI{}, err
	}
	return ENI{
		ID:           n.ENIID,
		NATGatewayID: n.ID,
		Container:    naming.NATGatewayContainer(n.ID),
		SubnetID:     n.SubnetID,
		RouterIf:     naming.RouterIf(n.ENIID),
		TempIf:       naming.TempIf(n.ENIID),
		InstanceIf:   naming.InstanceIf(0),
		MAC:          naming.MAC(n.ENIID),
		IPs:          []netip.Addr{ip},
		Subnet:       pfx.Masked(),
		Gateway:      firstHost(pfx),
		DefaultGW:    true,
		// The NAT gateway forwards traffic for other addresses.
		SrcDstCheck: false,
	}, nil
}

// renderNATGatewayNft renders a NAT gateway's ruleset: forwarded traffic
// leaves with the gateway's private IP. Nothing may open a connection to the
// gateway itself, so traffic from the internet to its Elastic IP ends here.
func renderNATGatewayNft(ip netip.Addr) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	w("table ip vpcsim {}")
	w("delete table ip vpcsim")
	w("table ip vpcsim {")
	w("\tchain input {")
	w("\t\ttype filter hook input priority filter; policy drop;")
	w("\t}")
	w("\tchain postrouting {")
	w("\t\ttype nat hook postrouting priority srcnat; policy accept;")
	w("\t\tsnat ip to %s", ip)
	w("\t}")
	w("}")
	return b.String()
}

// targetENI finds the ENI a NAT gateway, instance or ENI route sends to. An
// instance route uses the instance's primary ENI. ok is false when the
// target has no ENI on this router, e.g. a stopped instance; AWS shows such
// routes as blackhole.
func (r *Router) targetENI(rte snapshot.Route) (ENI, bool) {
	for _, e := range r.ENIs {
		switch {
		case rte.TargetKind == snapshot.TargetNAT && e.NATGatewayID == rte.TargetID,
			rte.TargetKind == snapshot.TargetInstance && e.InstanceID == rte.TargetID && e.DefaultGW,
			rte.TargetKind == snapshot.TargetENI && e.ID == rte.TargetID:
			return e, len(e.IPs) > 0
		}
	}
	return ENI{}, false
}

func buildRouting(s *snapshot.Snapshot, idx *indexes, vpc snapshot.VPC, r *Router) ([]string, error) {
	var warns []string

	delivery := Table{ID: TableDelivery, Name: "delivery"}
	for _, e := range r.ENIs {
		for _, ip := range e.IPs {
			delivery.Routes = append(delivery.Routes, Route{Dst: netip.PrefixFrom(ip, 32), Kind: RouteDev, Dev: e.RouterIf})
		}
	}
	r.Tables = append(r.Tables, delivery)

	tableOf := map[string]int{} // route table ID -> Linux table
	var mainRT string
	n := 0
	for _, rt := range s.RouteTables {
		if rt.VPCID != vpc.ID {
			continue
		}
		id := TableRTBase + n
		n++
		tableOf[rt.ID] = id
		if rt.Main {
			mainRT = rt.ID
		}
		t := Table{ID: id, Name: rt.ID}
		for _, rte := range rt.Routes {
			dsts, err := routeDestinations(idx, rte)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", rt.ID, err)
			}
			for _, dst := range dsts {
				switch {
				case rte.TargetKind == snapshot.TargetLocal:
					// "local" continues to the delivery table; more specific
					// routes in this table still win by longest prefix.
					t.Routes = append(t.Routes, Route{Dst: dst, Kind: RouteThrow})
				case rte.Blackhole:
					t.Routes = append(t.Routes, Route{Dst: dst, Kind: RouteBlackhole})
				case rte.TargetKind == snapshot.TargetIGW:
					if r.IGW == nil || r.IGW.ID != rte.TargetID {
						// AWS shows such a route as "blackhole".
						warns = append(warns, fmt.Sprintf("%s: route %s -> %s: gateway is not attached to %s; traffic is dropped",
							rt.ID, dst, rte.TargetID, vpc.ID))
						t.Routes = append(t.Routes, Route{Dst: dst, Kind: RouteBlackhole})
						continue
					}
					t.Routes = append(t.Routes, Route{Dst: dst, Kind: RouteVia, Dev: IGWIf, Via: EdgeInternetAddr})
				case rte.TargetKind == snapshot.TargetNAT, rte.TargetKind == snapshot.TargetInstance, rte.TargetKind == snapshot.TargetENI:
					e, ok := r.targetENI(rte)
					if !ok {
						warns = append(warns, fmt.Sprintf("%s: route %s -> %s: target is not running in %s; traffic is dropped",
							rt.ID, dst, rte.TargetID, vpc.ID))
						t.Routes = append(t.Routes, Route{Dst: dst, Kind: RouteBlackhole})
						continue
					}
					t.Routes = append(t.Routes, Route{Dst: dst, Kind: RouteVia, Dev: e.RouterIf, Via: e.IPs[0]})
				case rte.TargetKind == snapshot.TargetPeering, rte.TargetKind == snapshot.TargetTGW:
					t.Routes = append(t.Routes, linkRouteFor(s, r, rt.ID, dst, rte, &warns))
				default:
					if tgw, ok := flociTGWRoute(s, vpc.ID, rte); ok {
						t.Routes = append(t.Routes, linkRouteFor(s, r, rt.ID, dst,
							snapshot.Route{TargetKind: snapshot.TargetTGW, TargetID: tgw}, &warns))
						continue
					}
					if rte.TargetKind == snapshot.TargetUnknown && rte.TargetID == "" {
						warns = append(warns, fmt.Sprintf("%s: route %s has no target in Floci (Floci drops transit gateway targets, "+
							"and the VPC does not have exactly one TGW attachment); traffic is dropped", rt.ID, dst))
						t.Routes = append(t.Routes, Route{Dst: dst, Kind: RouteBlackhole})
						continue
					}
					warns = append(warns, fmt.Sprintf("%s: route %s -> %s %s is not simulated yet; traffic is dropped",
						rt.ID, dst, rte.TargetKind, rte.TargetID))
					t.Routes = append(t.Routes, Route{Dst: dst, Kind: RouteBlackhole})
				}
			}
		}
		r.Tables = append(r.Tables, t)
	}
	if mainRT == "" {
		return nil, fmt.Errorf("no main route table")
	}

	explicit := map[string]string{} // subnet -> route table
	for _, rt := range s.RouteTables {
		for _, sn := range rt.Subnets {
			explicit[sn] = rt.ID
		}
	}
	for _, e := range r.ENIs {
		rt, ok := explicit[e.SubnetID]
		if !ok {
			rt = mainRT // implicit association
		}
		r.Rules = append(r.Rules, Rule{Priority: PrioritySubnetRT, IifName: e.RouterIf, Table: tableOf[rt]})
	}
	// Traffic from a transit gateway enters through the attachment subnet
	// and uses its route table. Traffic from a peering connection only goes
	// to local addresses (delivery table).
	for _, a := range r.Attachments {
		rt, ok := explicit[a.Subnet]
		if !ok {
			rt = mainRT
		}
		r.Rules = append(r.Rules, Rule{Priority: PrioritySubnetRT, IifName: a.Ifname, Table: tableOf[rt]})
	}
	r.Rules = append(r.Rules,
		Rule{Priority: PriorityDelivery, Table: TableDelivery},
		Rule{Priority: PriorityBlackhole, Table: TableBlackhole},
	)
	r.Tables = append(r.Tables, Table{ID: TableBlackhole, Name: "blackhole", Routes: []Route{
		{Dst: netip.MustParsePrefix("0.0.0.0/0"), Kind: RouteBlackhole},
	}})
	return warns, nil
}

// linkRouteFor renders a route to a peering connection or transit gateway.
func linkRouteFor(s *snapshot.Snapshot, r *Router, rtID string, dst netip.Prefix, rte snapshot.Route, warns *[]string) Route {
	dev, ok, warn := linkRoute(s, r, rte)
	if !ok {
		if warn != "" {
			*warns = append(*warns, fmt.Sprintf("%s: route %s -> %s: %s; traffic is dropped", rtID, dst, rte.TargetID, warn))
		}
		return Route{Dst: dst, Kind: RouteBlackhole}
	}
	return Route{Dst: dst, Kind: RouteVia, Dev: dev, Via: LinkNextHop}
}

func routeDestinations(idx *indexes, r snapshot.Route) ([]netip.Prefix, error) {
	if r.DestinationPrefixList != "" {
		pl, ok := idx.prefixList[r.DestinationPrefixList]
		if !ok {
			return nil, fmt.Errorf("prefix list %s not found", r.DestinationPrefixList)
		}
		return collapse(pl.CIDRs), nil
	}
	p, err := netip.ParsePrefix(r.DestinationCIDR)
	if err != nil {
		return nil, err
	}
	return []netip.Prefix{p.Masked()}, nil
}

type indexes struct {
	vpc        map[string]snapshot.VPC
	eni        map[string]snapshot.ENI
	subnet     map[string]snapshot.Subnet
	sg         map[string]snapshot.SecurityGroup
	prefixList map[string]snapshot.PrefixList
	sgMembers  map[string][]string // SG ID -> private IPs of member ENIs

	naclBySubnet map[string]snapshot.NetworkACL
	defaultNACL  map[string]snapshot.NetworkACL // by VPC
}

func index(s *snapshot.Snapshot) *indexes {
	idx := &indexes{
		vpc:        map[string]snapshot.VPC{},
		eni:        map[string]snapshot.ENI{},
		subnet:     map[string]snapshot.Subnet{},
		sg:         map[string]snapshot.SecurityGroup{},
		prefixList: map[string]snapshot.PrefixList{},
		sgMembers:  map[string][]string{},

		naclBySubnet: map[string]snapshot.NetworkACL{},
		defaultNACL:  map[string]snapshot.NetworkACL{},
	}
	for _, a := range s.NetworkACLs {
		if a.Default {
			idx.defaultNACL[a.VPCID] = a
		}
		for _, sn := range a.Subnets {
			idx.naclBySubnet[sn] = a
		}
	}
	for _, e := range s.ENIs {
		idx.eni[e.ID] = e
		for _, g := range e.Groups {
			idx.sgMembers[g] = append(idx.sgMembers[g], e.PrivateIPs...)
		}
	}
	for _, sn := range s.Subnets {
		idx.subnet[sn.ID] = sn
	}
	for _, v := range s.VPCs {
		idx.vpc[v.ID] = v
	}
	for _, g := range s.SecurityGroups {
		idx.sg[g.ID] = g
	}
	for _, pl := range s.PrefixLists {
		idx.prefixList[pl.ID] = pl
	}
	return idx
}

func (idx *indexes) primaryIP(in snapshot.Instance) string {
	if _, ip, ok := idx.primaryENI(in); ok {
		return ip
	}
	return in.ID
}

// primaryENI returns the ID and primary private IP of the instance's
// device-index-0 ENI.
func (idx *indexes) primaryENI(in snapshot.Instance) (string, string, bool) {
	for _, id := range in.ENIs {
		if e, ok := idx.eni[id]; ok && e.DeviceIndex == 0 && len(e.PrivateIPs) > 0 {
			return e.ID, e.PrivateIPs[0], true
		}
	}
	return "", "", false
}
