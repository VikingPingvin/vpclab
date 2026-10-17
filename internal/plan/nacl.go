package plan

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/VikingPingvin/vpclab/internal/naming"
	"github.com/VikingPingvin/vpclab/internal/snapshot"
)

// naclFor returns the network ACL of a subnet: its explicit association, or
// the VPC's default ACL.
func (idx *indexes) naclFor(subnetID, vpcID string) (snapshot.NetworkACL, bool) {
	if a, ok := idx.naclBySubnet[subnetID]; ok {
		return a, true
	}
	a, ok := idx.defaultNACL[vpcID]
	return a, ok
}

func naclChain(dir, subnetID string) string {
	return "nacl_" + dir + "_" + naming.NftID(subnetID)
}

// renderNACLChain renders one direction of a subnet's network ACL.
//
// NACLs are stateless and evaluated in rule-number order; the first match
// decides. They only apply when traffic crosses the subnet boundary, so the
// chain first returns for traffic to (egress) or from (ingress) an interface
// in the same subnet. Ingress rules match the source CIDR, egress rules the
// destination CIDR; port ranges always match the destination port.
func renderNACLChain(w func(string, ...any), acl snapshot.NetworkACL, ok bool, subnetID string, egress bool, subnetIfs []string) {
	dir, sameSubnet, field := "in", "iifname", "ip saddr"
	if egress {
		dir, sameSubnet, field = "out", "oifname", "ip daddr"
	}
	w("\tchain %s {", naclChain(dir, subnetID))
	w("\t\t%s { %s } return", sameSubnet, quoteJoin(subnetIfs))
	if ok {
		for _, e := range acl.Entries {
			if e.Egress != egress {
				continue
			}
			verdict := "return"
			if !e.Allow {
				verdict = "counter drop"
			}
			match := naclMatch(e, field)
			w("\t\t%s comment %q", strings.TrimSpace(match+" "+verdict), fmt.Sprintf("%s #%d", acl.ID, e.RuleNumber))
		}
	}
	w("\t\tcounter drop comment %q", "network ACL "+dir+": implicit deny")
	w("\t}")
}

func naclMatch(e snapshot.ACLEntry, field string) string {
	var parts []string
	if ps := collapse([]string{e.CIDR}); len(ps) == 1 && ps[0].Bits() > 0 {
		parts = append(parts, field+" "+prefixSet(ps))
	}
	proto := strings.ToLower(e.Protocol)
	switch proto {
	case "-1", "all":
	case "6", "tcp", "17", "udp":
		name := "tcp"
		if proto == "17" || proto == "udp" {
			name = "udp"
		}
		switch {
		case e.FromPort == 0 && e.ToPort == 0, e.FromPort == 0 && e.ToPort >= 65535:
			parts = append(parts, "meta l4proto "+name)
		case e.FromPort == e.ToPort:
			parts = append(parts, fmt.Sprintf("%s dport %d", name, e.FromPort))
		default:
			parts = append(parts, fmt.Sprintf("%s dport %d-%d", name, e.FromPort, e.ToPort))
		}
	case "1", "icmp":
		switch {
		case e.ICMPType == nil || *e.ICMPType < 0:
			parts = append(parts, "meta l4proto icmp")
		case e.ICMPCode == nil || *e.ICMPCode < 0:
			parts = append(parts, fmt.Sprintf("icmp type %d", *e.ICMPType))
		default:
			parts = append(parts, fmt.Sprintf("icmp type %d icmp code %d", *e.ICMPType, *e.ICMPCode))
		}
	default:
		if n, err := strconv.Atoi(proto); err == nil {
			parts = append(parts, fmt.Sprintf("meta l4proto %d", n))
		}
	}
	return strings.Join(parts, " ")
}

func quoteJoin(ss []string) string {
	q := make([]string, len(ss))
	for i, s := range ss {
		q[i] = strconv.Quote(s)
	}
	return strings.Join(q, ", ")
}
