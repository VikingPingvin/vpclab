package plan

import (
	"net/netip"
	"slices"
)

// collapse parses CIDRs/addresses, removes duplicates and prefixes contained
// in other prefixes, and returns them sorted. nftables rejects overlapping
// elements in one set, so every set goes through this.
func collapse(in []string) []netip.Prefix {
	var ps []netip.Prefix
	for _, s := range in {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, aerr := netip.ParseAddr(s)
			if aerr != nil || !a.Is4() {
				continue
			}
			p = netip.PrefixFrom(a, 32)
		}
		if !p.Addr().Is4() {
			continue
		}
		ps = append(ps, p.Masked())
	}
	slices.SortFunc(ps, func(a, b netip.Prefix) int {
		if c := a.Bits() - b.Bits(); c != 0 {
			return c // broader prefixes first
		}
		return a.Addr().Compare(b.Addr())
	})
	var out []netip.Prefix
	for _, p := range ps {
		covered := false
		for _, q := range out {
			if q.Contains(p.Addr()) && q.Bits() <= p.Bits() {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, p)
		}
	}
	slices.SortFunc(out, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	return out
}

// firstHost returns the subnet's .1 address, which AWS reserves for the VPC
// router.
func firstHost(p netip.Prefix) netip.Addr {
	return p.Masked().Addr().Next()
}
