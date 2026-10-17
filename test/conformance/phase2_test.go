//go:build conformance

package conformance

import (
	"testing"
)

// TestInternetGateway covers public and private subnets behind an IGW.
//
// Expected AWS behaviour (VPC user guide, "Internet gateways"):
//   - The IGW performs 1:1 NAT between an instance's private IP and its
//     public IPv4 (EIP or auto-assigned).
//   - An instance without a public IPv4 cannot use the IGW.
//   - A subnet is only public if its route table routes to the IGW.
//   - Security groups still apply to internet traffic.
func TestInternetGateway(t *testing.T) {
	e := newEnv(t)
	vpc := e.vpc("10.40.0.0/16")
	pub := e.subnet(vpc, "10.40.1.0/24")
	priv := e.subnet(vpc, "10.40.2.0/24")
	igw := e.igw(vpc)
	e.publicRouteTable(vpc, igw, pub)

	sg := e.sg(vpc, "web")
	e.allowIngress(sg, fromCIDR(tcp(80), "0.0.0.0/0"))

	web := e.instance(pub, sg)
	webIP := e.eip(web)
	noPublic := e.instance(pub, sg)
	private := e.instance(priv, sg)
	privateIP := e.eip(private)
	e.apply()

	e.listenTCP(web, "80")
	e.listenTCP(web, "22")
	e.listenTCP(private, "80")

	t.Run("outbound leaves with the public IP", func(t *testing.T) {
		got, ok := e.echo(web)
		if !ok || got != webIP {
			t.Errorf("echo host saw %q (ok=%t), want the EIP %s", got, ok, webIP)
		}
	})
	t.Run("inbound to the public IP", func(t *testing.T) {
		if !e.operatorCanTCP(webIP, "80") {
			t.Errorf("operator cannot reach %s:80", webIP)
		}
	})
	t.Run("security groups apply to internet traffic", func(t *testing.T) {
		if e.operatorCanTCP(webIP, "22") {
			t.Errorf("operator reached %s:22, which sg-web does not allow", webIP)
		}
	})
	t.Run("no public IP means no internet", func(t *testing.T) {
		if got, ok := e.echo(noPublic); ok {
			t.Errorf("instance without public IP reached the internet as %q", got)
		}
	})
	t.Run("no route to the IGW means no internet", func(t *testing.T) {
		if got, ok := e.echo(private); ok {
			t.Errorf("instance in a subnet without IGW route reached the internet as %q", got)
		}
		if e.operatorCanTCP(privateIP, "80") {
			t.Errorf("operator reached %s:80 although the subnet has no route to the IGW", privateIP)
		}
	})
}

// TestNetworkACLs covers stateless subnet filtering.
//
// Expected AWS behaviour (VPC user guide, "Network ACLs"):
//   - NACLs are stateless: return traffic needs its own rule, usually for
//     the ephemeral ports 1024-65535.
//   - Rules are evaluated in rule-number order; the first match decides.
//   - NACLs filter traffic entering and leaving the subnet, not traffic
//     between instances in the same subnet.
func TestNetworkACLs(t *testing.T) {
	e := newEnv(t)
	vpc := e.vpc("10.50.0.0/16")
	pub := e.subnet(vpc, "10.50.1.0/24")
	igw := e.igw(vpc)
	e.publicRouteTable(vpc, igw, pub)

	sg := e.sg(vpc, "web")
	e.allowIngress(sg, fromCIDR(tcp(80), "0.0.0.0/0"), fromCIDR(tcp(9090), "10.50.0.0/16"))
	web := e.instance(pub, sg)
	webIP := e.eip(web)
	peer := e.instance(pub, sg)

	acl := e.nacl(vpc, pub)
	e.aclEntry(acl, aclRule{number: 100, allow: true, cidr: "0.0.0.0/0", from: 80, to: 80})
	e.aclEntry(acl, aclRule{number: 100, egress: true, allow: true, cidr: "0.0.0.0/0", from: 80, to: 80})
	e.apply()
	e.listenTCP(web, "80")
	e.listenTCP(web, "9090")

	t.Run("return traffic needs an outbound ephemeral rule", func(t *testing.T) {
		if e.operatorCanTCP(webIP, "80") {
			t.Fatal("inbound 80 worked although outbound only allows port 80, not the client's ephemeral port")
		}
		e.aclEntry(acl, aclRule{number: 110, egress: true, allow: true, cidr: "0.0.0.0/0", from: 1024, to: 65535})
		e.apply()
		if !e.operatorCanTCP(webIP, "80") {
			t.Error("inbound 80 still fails after allowing outbound 1024-65535")
		}
	})
	t.Run("outbound replies need an inbound ephemeral rule", func(t *testing.T) {
		if got, ok := e.echo(web); ok {
			t.Fatalf("outbound HTTP worked (%q) although inbound does not allow ephemeral ports", got)
		}
		e.aclEntry(acl, aclRule{number: 120, allow: true, cidr: "0.0.0.0/0", from: 1024, to: 65535})
		e.apply()
		if got, ok := e.echo(web); !ok || got != webIP {
			t.Errorf("outbound HTTP after allowing inbound 1024-65535: %q (ok=%t)", got, ok)
		}
	})
	t.Run("lowest rule number wins", func(t *testing.T) {
		e.aclEntry(acl, aclRule{number: 90, allow: false, cidr: "203.0.113.10/32", from: 80, to: 80})
		e.apply()
		if e.operatorCanTCP(webIP, "80") {
			t.Error("deny #90 did not override allow #100")
		}
		e.deleteACLEntry(acl, 90, false)
		e.apply()
		if !e.operatorCanTCP(webIP, "80") {
			t.Error("access did not return after removing deny #90")
		}
	})
	t.Run("same subnet is not filtered", func(t *testing.T) {
		if !e.canTCP(peer, web.IP, "9090") {
			t.Error("same-subnet traffic on port 9090 was blocked; the ACL has no rule for 9090 but must not apply inside the subnet")
		}
	})
}
