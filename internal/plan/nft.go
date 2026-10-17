package plan

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/VikingPingvin/vpclab/internal/naming"
	"github.com/VikingPingvin/vpclab/internal/snapshot"
)

// renderNft renders the complete nftables ruleset of one VPC router.
//
// Evaluation order for a forwarded packet (see docs/vpcsim/architecture.md):
//
//	source/destination check -> conntrack shortcut -> SG egress (source ENI) -> SG ingress (destination ENI)
//
// NACLs (phase 2) will slot in before the conntrack shortcut because they are
// stateless and must see every packet.
//
// The ruleset starts by creating and deleting the table, so `nft -f` replaces
// the previous ruleset in a single atomic transaction.
func renderNft(idx *indexes, r *Router) string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }

	referenced := map[string]bool{}
	var chains strings.Builder
	cw := func(format string, args ...any) { fmt.Fprintf(&chains, format+"\n", args...) }

	for _, e := range r.ENIs {
		id := naming.NftID(e.ID)

		cw("\tchain src_%s {", id)
		if e.SrcDstCheck {
			cw("\t\tip saddr %s return", addrSet(e.IPs))
			cw("\t\tcounter drop comment %q", e.ID+" source/destination check")
		}
		cw("\t}")
		cw("\tchain dst_%s {", id)
		if e.SrcDstCheck {
			cw("\t\tip daddr %s return", addrSet(e.IPs))
			cw("\t\tcounter drop comment %q", e.ID+" source/destination check")
		}
		cw("\t}")

		for _, dir := range []string{"egress", "ingress"} {
			cw("\tchain sg_%s_%s {", dir, id)
			// NAT gateways have no security groups: their chains are empty.
			if e.NATGatewayID == "" {
				for _, g := range e.Groups {
					sg, ok := idx.sg[g]
					if !ok {
						continue
					}
					rules := sg.Egress
					if dir == "ingress" {
						rules = sg.Ingress
					}
					for _, rule := range rules {
						for _, line := range sgRuleLines(idx, rule, dir == "ingress", referenced) {
							cw("\t\t%s return comment %q", line, sg.ID+" "+dir)
						}
					}
				}
				cw("\t\tcounter drop comment %q", e.ID+" "+dir+": no security group rule matched")
			}
			cw("\t}")
		}
	}

	// Network ACLs, one pair of chains per subnet that has ENIs.
	subnetIfs := map[string][]string{}
	var subnets []string
	for _, e := range r.ENIs {
		if _, ok := subnetIfs[e.SubnetID]; !ok {
			subnets = append(subnets, e.SubnetID)
		}
		subnetIfs[e.SubnetID] = append(subnetIfs[e.SubnetID], e.RouterIf)
	}
	slices.Sort(subnets)
	for _, sn := range subnets {
		acl, ok := idx.naclFor(sn, r.VPCID)
		renderNACLChain(cw, acl, ok, sn, true, subnetIfs[sn])
		renderNACLChain(cw, acl, ok, sn, false, subnetIfs[sn])
	}
	naclVmap := func(dir string) string {
		parts := make([]string, 0, len(r.ENIs))
		for _, e := range r.ENIs {
			parts = append(parts, fmt.Sprintf("%q : jump %s", e.RouterIf, naclChain(dir, e.SubnetID)))
		}
		return "{ " + strings.Join(parts, ", ") + " }"
	}

	w("table inet vpcsim {}")
	w("delete table inet vpcsim")
	w("table inet vpcsim {")

	groups := make([]string, 0, len(referenced))
	for g := range referenced {
		groups = append(groups, g)
	}
	slices.Sort(groups)
	for _, g := range groups {
		w("\tset %s {", memberSet(g))
		w("\t\ttype ipv4_addr")
		if ips := collapse(idx.sgMembers[g]); len(ips) > 0 {
			w("\t\telements = %s", prefixSet(ips))
		}
		w("\t}")
	}

	// Internet gateway: 1:1 NAT between private and public addresses.
	if r.IGW != nil && len(r.NAT) > 0 {
		var priv []string
		var dnat, snat []string
		for _, n := range r.NAT {
			priv = append(priv, n.Private.String())
			dnat = append(dnat, n.Public.String()+" : "+n.Private.String())
			snat = append(snat, n.Private.String()+" : "+n.Public.String())
		}
		w("\tset public_private {")
		w("\t\ttype ipv4_addr")
		w("\t\telements = { %s }", strings.Join(priv, ", "))
		w("\t}")
		w("\tchain prerouting {")
		w("\t\ttype nat hook prerouting priority dstnat; policy accept;")
		w("\t\tiifname %q dnat ip to ip daddr map { %s }", IGWIf, strings.Join(dnat, ", "))
		w("\t}")
		w("\tchain postrouting {")
		w("\t\ttype nat hook postrouting priority srcnat; policy accept;")
		w("\t\toifname %q snat ip to ip saddr map { %s }", IGWIf, strings.Join(snat, ", "))
		w("\t}")
	}

	w("\tchain input {")
	w("\t\ttype filter hook input priority filter; policy drop;")
	w("\t}")

	w("\tchain forward {")
	w("\t\ttype filter hook forward priority filter; policy drop;")
	w("\t\tmeta nfproto != ipv4 drop")
	if len(r.ENIs) > 0 {
		renderLinkFilters(w, r)
		w("\t\tiifname vmap %s", ifVmap(r.ENIs, "src"))
		w("\t\toifname vmap %s", ifVmap(r.ENIs, "dst"))
		w("\t\tiifname vmap %s", naclVmap("out"))
		w("\t\toifname vmap %s", naclVmap("in"))
		if r.IGW != nil {
			// The IGW only forwards traffic from addresses with a public IPv4.
			if len(r.NAT) > 0 {
				w("\t\toifname %q ip saddr != @public_private counter drop comment %q", IGWIf, "IGW: source has no public IPv4")
			} else {
				w("\t\toifname %q counter drop comment %q", IGWIf, "IGW: source has no public IPv4")
			}
		}
		w("\t\tct state established accept")
		w("\t\tiifname vmap %s", ifVmap(r.ENIs, "sg_egress"))
		w("\t\toifname vmap %s", ifVmap(r.ENIs, "sg_ingress"))
		w("\t\taccept")
	}
	w("\t}")

	b.WriteString(chains.String())
	w("}")
	return b.String()
}

// sgRuleLines renders one IpPermission as nft match expressions, one per
// source kind. The caller appends the verdict.
func sgRuleLines(idx *indexes, r snapshot.SGRule, ingress bool, referenced map[string]bool) []string {
	field := "ip daddr"
	if ingress {
		field = "ip saddr"
	}
	proto := protoMatch(r)

	join := func(parts ...string) string {
		var nonEmpty []string
		for _, p := range parts {
			if p != "" {
				nonEmpty = append(nonEmpty, p)
			}
		}
		return strings.Join(nonEmpty, " ")
	}

	var lines []string
	cidrs := slices.Clone(r.CIDRs)
	for _, pl := range r.PrefixLists {
		cidrs = append(cidrs, idx.prefixList[pl].CIDRs...)
	}
	if ps := collapse(cidrs); len(ps) > 0 {
		addr := field + " " + prefixSet(ps)
		if len(ps) == 1 && ps[0].Bits() == 0 {
			addr = "" // 0.0.0.0/0 matches everything
		}
		lines = append(lines, join(addr, proto))
	}
	for _, g := range r.Groups {
		referenced[g] = true
		lines = append(lines, join(field+" @"+memberSet(g), proto))
	}
	return lines
}

func protoMatch(r snapshot.SGRule) string {
	switch strings.ToLower(r.Protocol) {
	case "-1", "all":
		return ""
	case "tcp", "6":
		return portMatch("tcp", r.FromPort, r.ToPort)
	case "udp", "17":
		return portMatch("udp", r.FromPort, r.ToPort)
	case "icmp", "1":
		switch {
		case r.FromPort < 0:
			return "meta l4proto icmp"
		case r.ToPort < 0:
			return fmt.Sprintf("icmp type %d", r.FromPort)
		default:
			return fmt.Sprintf("icmp type %d icmp code %d", r.FromPort, r.ToPort)
		}
	}
	if n, err := strconv.Atoi(r.Protocol); err == nil {
		return fmt.Sprintf("meta l4proto %d", n)
	}
	return "meta l4proto " + r.Protocol
}

func portMatch(proto string, from, to int32) string {
	switch {
	case from < 0 || (from == 0 && to >= 65535):
		return "meta l4proto " + proto
	case from == to:
		return fmt.Sprintf("%s dport %d", proto, from)
	default:
		return fmt.Sprintf("%s dport %d-%d", proto, from, to)
	}
}

func memberSet(sgID string) string { return "members_" + naming.NftID(sgID) }

func ifVmap(enis []ENI, chainPrefix string) string {
	parts := make([]string, 0, len(enis))
	for _, e := range enis {
		parts = append(parts, fmt.Sprintf("%q : jump %s_%s", e.RouterIf, chainPrefix, naming.NftID(e.ID)))
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}

func addrSet(as []netip.Addr) string {
	parts := make([]string, 0, len(as))
	for _, a := range as {
		parts = append(parts, a.String())
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}

func prefixSet(ps []netip.Prefix) string {
	parts := make([]string, 0, len(ps))
	for _, p := range ps {
		if p.Bits() == 32 {
			parts = append(parts, p.Addr().String())
		} else {
			parts = append(parts, p.String())
		}
	}
	return "{ " + strings.Join(parts, ", ") + " }"
}
