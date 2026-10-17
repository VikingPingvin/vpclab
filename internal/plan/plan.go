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
	Instances []Instance
	Routers   []Router
	Internet  *Internet // nil when no VPC has a running instance
	Warnings  []string
}

type Instance struct {
	ID        string
	VPCID     string
	Container string
	Image     string
	Hostname  string
	DNS       []string // resolvers in the instance's /etc/resolv.conf
	// Running is false for a stopped instance: its container is kept but
	// stopped, so files survive like on an EBS root volume.
	Running bool
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
}

// IGW is an attached internet gateway: a veth between the router (IGWIf) and
// the internet namespace (InternetIf).
type IGW struct {
	ID         string
	InternetIf string
}

type ENI struct {
	ID          string
	InstanceID  string
	Container   string // instance container whose netns holds the instance end
	SubnetID    string
	RouterIf    string
	TempIf      string
	InstanceIf  string
	MAC         net.HardwareAddr
	IPs         []netip.Addr // primary first
	Subnet      netip.Prefix
	Gateway     netip.Addr
	DefaultGW   bool // only device index 0 gets a default route
	SrcDstCheck bool
	Groups      []string
}

type RouteKind string

const (
	RouteThrow     RouteKind = "throw"     // continue with the next ip rule
	RouteBlackhole RouteKind = "blackhole" // drop silently, like AWS
	RouteDev       RouteKind = "dev"       // deliver out of a router interface
	RouteVia       RouteKind = "via"       // send to a next hop on Dev (onlink)
)

type Route struct {
	Dst  netip.Prefix
	Kind RouteKind
	Dev  string
	Via  netip.Addr // RouteVia only
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
		p.Instances = append(p.Instances, Instance{
			ID:        in.ID,
			VPCID:     in.VPCID,
			Container: naming.InstanceContainer(in.ID),
			Image:     opt.InstanceImage,
			Hostname:  naming.Hostname(idx.primaryIP(in)),
			DNS:       dns,
			Running:   isRunning,
		})
	}

	public := publicIPs(s, idx)

	// Only VPCs with running instances need a router.
	for _, vpc := range s.VPCs {
		if len(running[vpc.ID]) == 0 {
			continue
		}
		r, warns, err := buildRouter(s, idx, vpc, running[vpc.ID], public)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", vpc.ID, err)
		}
		p.Routers = append(p.Routers, *r)
		p.Warnings = append(p.Warnings, warns...)
	}
	if len(p.Routers) > 0 {
		buildInternet(p, opt.InstanceImage)
	}
	return p, nil
}

func buildRouter(s *snapshot.Snapshot, idx *indexes, vpc snapshot.VPC, insts []snapshot.Instance, public map[natKey]NAT) (*Router, []string, error) {
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
	slices.SortFunc(r.ENIs, func(a, b ENI) int { return strings.Compare(a.ID, b.ID) })

	for _, e := range r.ENIs {
		for _, ip := range e.IPs {
			if n, ok := public[natKey{e.ID, ip}]; ok {
				r.NAT = append(r.NAT, n)
			}
		}
	}
	slices.SortFunc(r.NAT, func(a, b NAT) int { return a.Private.Compare(b.Private) })

	tw, err := buildRouting(s, idx, vpc, r)
	if err != nil {
		return nil, nil, err
	}
	warns = append(warns, tw...)
	r.Ruleset = renderNft(idx, r)
	return r, warns, nil
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
				default:
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
	r.Rules = append(r.Rules,
		Rule{Priority: PriorityDelivery, Table: TableDelivery},
		Rule{Priority: PriorityBlackhole, Table: TableBlackhole},
	)
	r.Tables = append(r.Tables, Table{ID: TableBlackhole, Name: "blackhole", Routes: []Route{
		{Dst: netip.MustParsePrefix("0.0.0.0/0"), Kind: RouteBlackhole},
	}})
	return warns, nil
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
	for _, g := range s.SecurityGroups {
		idx.sg[g.ID] = g
	}
	for _, pl := range s.PrefixLists {
		idx.prefixList[pl.ID] = pl
	}
	return idx
}

func (idx *indexes) primaryIP(in snapshot.Instance) string {
	for _, id := range in.ENIs {
		if e, ok := idx.eni[id]; ok && e.DeviceIndex == 0 && len(e.PrivateIPs) > 0 {
			return e.PrivateIPs[0]
		}
	}
	return in.ID
}
