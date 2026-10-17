package plan

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/VikingPingvin/vpclab/internal/snapshot"

	"github.com/VikingPingvin/vpclab/internal/naming"
)

// The link between a VPC router and the internet namespace uses the same two
// link-local addresses in every VPC; each router has its own namespace.
var (
	EdgeRouterAddr   = netip.MustParseAddr("169.254.0.1")
	EdgeInternetAddr = netip.MustParseAddr("169.254.0.2")
)

const (
	IGWIf = "igw0"
	// Traffic leaving a VPC through an internet gateway is limited to 1500.
	InternetMTU = 1500
)

// Floci does not auto-assign public IPv4 addresses, so vpcsim assigns them
// from the benchmarking range, which never appears on the real internet.
var autoPublicPool = netip.MustParsePrefix("198.18.0.0/15")

// The internet namespace reaches the real internet through a Docker bridge
// network. Docker masquerades the namespace's bridge address on the host;
// the namespace masquerades public IPs to that address first.
const (
	UplinkNetwork = "vpcsim-uplink"
	UplinkIf      = "eth0"
)

// notRoutable lists destinations the internet namespace never sends to the
// real internet: private and special-purpose ranges (on the real internet
// they go nowhere; here they would reach the WSL host and its Docker
// networks, including Floci), plus the simulated public ranges.
var notRoutable = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
	autoPublicPool.String(), "203.0.113.0/24",
}

// Internet is the namespace that stands in for the public internet: it
// routes public /32s to VPC routers, hosts a few well-known machines and
// forwards everything else to the real internet.
type Internet struct {
	Container string
	Uplink    string // Docker network that connects the namespace to the host
	Links     []InternetLink
	Hosts     []Host
	Ruleset   string // nftables ruleset of the internet namespace
}

// InternetLink is the internet side of one VPC's internet gateway.
type InternetLink struct {
	VPCID  string
	IGWID  string
	Ifname string       // interface in the internet namespace
	Public []netip.Addr // public IPs routed to this VPC
}

// Host is a machine on the internet.
type Host struct {
	Name      string
	Container string
	Image     string
	IP        netip.Addr
	Ifname    string // interface in the internet namespace
	Command   string // shell command the container runs
}

// NAT is the 1:1 mapping the internet gateway applies.
type NAT struct {
	Private netip.Addr
	Public  netip.Addr
	// Auto is true when vpcsim assigned the address because Floci does not
	// report auto-assigned public IPs.
	Auto bool
}

// Well-known internet hosts. Addresses come from TEST-NET-3.
const (
	OperatorName = "operator"
	EchoName     = "echo"
)

var (
	OperatorIP = netip.MustParseAddr("203.0.113.10")
	EchoIP     = netip.MustParseAddr("203.0.113.20")
)

// echoCmd answers HTTP on port 80 with the caller's source address, so
// learners can see which public IP their traffic leaves with. The responder
// reads the request headers first; closing with unread data would send a RST.
const echoCmd = `cat > /usr/local/bin/echo-ip <<'EOF'
#!/bin/bash
while IFS= read -r line; do line=${line%$'\r'}; [ -z "$line" ] && break; done
printf 'HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n%s\n' "$SOCAT_PEERADDR"
EOF
chmod +x /usr/local/bin/echo-ip
exec socat TCP-LISTEN:80,fork,reuseaddr EXEC:/usr/local/bin/echo-ip`

// IdleCmd keeps a container alive and exits promptly on SIGTERM.
const IdleCmd = `trap 'exit 0' TERM; while :; do sleep 3600 & wait; done`

func internetHosts(image string) []Host {
	return []Host{
		{Name: OperatorName, Container: "vpcsim-" + OperatorName, Image: image, IP: OperatorIP, Ifname: "h" + naming.Short(OperatorName, 11), Command: IdleCmd},
		{Name: EchoName, Container: "vpcsim-" + EchoName, Image: image, IP: EchoIP, Ifname: "h" + naming.Short(EchoName, 11), Command: echoCmd},
	}
}

// natKey identifies an ENI address. Private IPs alone are not unique: VPCs
// may use overlapping CIDRs.
type natKey struct {
	eni string
	ip  netip.Addr
}

// publicIPs computes the private -> public mapping for every ENI address.
// Sources, in order: Elastic IP associations, the ENI's own association, NAT
// gateways, and an auto-assigned address for the primary ENI in a
// MapPublicIpOnLaunch subnet.
func publicIPs(s *snapshot.Snapshot, idx *indexes) map[natKey]NAT {
	out := map[natKey]NAT{}
	used := map[netip.Addr]bool{}
	add := func(eni, priv, pub string, auto bool) {
		pa, err1 := netip.ParseAddr(priv)
		pb, err2 := netip.ParseAddr(pub)
		if err1 != nil || err2 != nil || eni == "" {
			return
		}
		k := natKey{eni, pa}
		if _, ok := out[k]; ok {
			return
		}
		out[k] = NAT{Private: pa, Public: pb, Auto: auto}
		used[pb] = true
	}
	for _, eip := range s.ElasticIPs {
		add(eip.ENIID, eip.PrivateIP, eip.PublicIP, false)
	}
	for _, e := range s.ENIs {
		if e.PublicIP != "" && len(e.PrivateIPs) > 0 {
			add(e.ID, e.PrivateIPs[0], e.PublicIP, false)
		}
	}
	// Floci shows a NAT gateway's Elastic IP only on the NAT gateway, not
	// in DescribeAddresses. Private NAT gateways have none.
	for _, n := range s.NATGateways {
		if n.Public {
			add(n.ENIID, n.Private, n.PublicIP, false)
		}
	}
	// s.ENIs is sorted by ID, so auto-assignment is deterministic.
	for _, e := range s.ENIs {
		if e.DeviceIndex != 0 || len(e.PrivateIPs) == 0 || !idx.subnet[e.SubnetID].MapPublicIPOnLaunch {
			continue
		}
		pa, err := netip.ParseAddr(e.PrivateIPs[0])
		if err != nil {
			continue
		}
		k := natKey{e.ID, pa}
		if _, ok := out[k]; ok {
			continue
		}
		pub := autoPublic(e.ID, used)
		out[k] = NAT{Private: pa, Public: pub, Auto: true}
		used[pub] = true
	}
	return out
}

func autoPublic(eniID string, used map[netip.Addr]bool) netip.Addr {
	sum := sha256.Sum256([]byte(eniID))
	size := uint32(1) << (32 - autoPublicPool.Bits())
	base := binary.BigEndian.Uint32(autoPublicPool.Addr().AsSlice())
	off := binary.BigEndian.Uint32(sum[:4]) % size
	for {
		if off == 0 || off == size-1 {
			off = 1
		}
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], base+off)
		a := netip.AddrFrom4(b)
		if !used[a] {
			return a
		}
		off = (off + 1) % size
	}
}

func buildInternet(p *Plan, image string) {
	in := &Internet{Container: "vpcsim-internet", Uplink: UplinkNetwork, Hosts: internetHosts(image), Ruleset: renderInternetNft()}
	for _, r := range p.Routers {
		if r.IGW == nil {
			continue
		}
		link := InternetLink{VPCID: r.VPCID, IGWID: r.IGW.ID, Ifname: r.IGW.InternetIf}
		for _, n := range r.NAT {
			link.Public = append(link.Public, n.Public)
		}
		slices.SortFunc(link.Public, func(a, b netip.Addr) int { return a.Compare(b) })
		in.Links = append(in.Links, link)
	}
	slices.SortFunc(in.Links, func(a, b InternetLink) int { return strings.Compare(a.VPCID, b.VPCID) })
	p.Internet = in
}

// renderInternetNft renders the internet namespace's ruleset. Traffic to the
// real internet leaves through the uplink with the namespace's own address;
// the real internet cannot open connections into the simulation.
func renderInternetNft() string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	w("table ip vpcsim {}")
	w("delete table ip vpcsim")
	w("table ip vpcsim {")
	w("\tset not_routable {")
	w("\t\ttype ipv4_addr")
	w("\t\tflags interval")
	w("\t\telements = { %s }", strings.Join(notRoutable, ", "))
	w("\t}")
	w("\tchain forward {")
	w("\t\ttype filter hook forward priority filter; policy accept;")
	w("\t\toifname %q ip daddr @not_routable counter drop comment %q", UplinkIf, "not routable on the internet")
	w("\t\tiifname %q ct state established,related accept", UplinkIf)
	w("\t\tiifname %q counter drop comment %q", UplinkIf, "unsolicited traffic from the real internet")
	w("\t}")
	w("\tchain postrouting {")
	w("\t\ttype nat hook postrouting priority srcnat; policy accept;")
	w("\t\toifname %q masquerade", UplinkIf)
	w("\t}")
	w("}")
	return b.String()
}
