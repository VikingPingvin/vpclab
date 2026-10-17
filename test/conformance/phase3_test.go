//go:build conformance

package conformance

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/VikingPingvin/vpclab/internal/plan"
)

// TestNATGateway covers outbound internet access from private subnets.
//
// Expected AWS behaviour (VPC user guide, "NAT gateways"):
//   - A public NAT gateway in a public subnet gives instances in private
//     subnets outbound access; traffic leaves with the gateway's EIP.
//   - Nothing on the internet can open a connection through it.
//   - The NAT gateway sends traffic with the route table of its own subnet,
//     so a NAT gateway in a private subnet gives no internet.
//   - A private NAT gateway cannot use an internet gateway.
//   - The network ACL of the NAT gateway's subnet applies; it has no SG.
//   - A route to a deleted NAT gateway becomes a blackhole.
func TestNATGateway(t *testing.T) {
	e := newEnv(t)
	vpc := e.vpc("10.60.0.0/16")
	pub := e.subnet(vpc, "10.60.1.0/24")
	priv := e.subnet(vpc, "10.60.2.0/24")
	other := e.subnet(vpc, "10.60.3.0/24") // no route to the IGW
	igw := e.igw(vpc)
	e.publicRouteTable(vpc, igw, pub)

	nat, natIP := e.natGateway(pub, true)
	privRT := e.routeTable(vpc, priv)
	e.route(privRT, "0.0.0.0/0", func(in *ec2.CreateRouteInput) { in.NatGatewayId = &nat })

	sg := e.sg(vpc, "app")
	e.allowIngress(sg, fromCIDR(tcp(80), "0.0.0.0/0"))
	app := e.instance(priv, sg)
	e.apply()
	e.listenTCP(app, "80")

	t.Run("outbound leaves with the NAT gateway's EIP", func(t *testing.T) {
		if got, ok := e.echo(app); !ok || got != natIP {
			t.Errorf("echo host saw %q (ok=%t), want the NAT gateway's EIP %s", got, ok, natIP)
		}
	})
	t.Run("no inbound through the NAT gateway", func(t *testing.T) {
		if e.operatorCanTCP(natIP, "80") {
			t.Errorf("operator reached %s:80 through the NAT gateway", natIP)
		}
	})
	t.Run("private NAT gateway has no internet", func(t *testing.T) {
		pnat, _ := e.natGateway(pub, false)
		e.replaceRoute(privRT, "0.0.0.0/0", func(in *ec2.ReplaceRouteInput) { in.NatGatewayId = &pnat })
		e.apply()
		if got, ok := e.echo(app); ok {
			t.Errorf("traffic through a private NAT gateway reached the internet as %q", got)
		}
	})
	t.Run("NAT gateway in a subnet without IGW route", func(t *testing.T) {
		bad, _ := e.natGateway(other, true)
		e.replaceRoute(privRT, "0.0.0.0/0", func(in *ec2.ReplaceRouteInput) { in.NatGatewayId = &bad })
		e.apply()
		if got, ok := e.echo(app); ok {
			t.Errorf("NAT gateway in a subnet without IGW route reached the internet as %q", got)
		}
		e.replaceRoute(privRT, "0.0.0.0/0", func(in *ec2.ReplaceRouteInput) { in.NatGatewayId = &nat })
		e.apply()
		if got, ok := e.echo(app); !ok || got != natIP {
			t.Errorf("after routing back to %s: echo %q (ok=%t)", nat, got, ok)
		}
	})
	t.Run("network ACL of the NAT gateway's subnet applies", func(t *testing.T) {
		acl := e.nacl(vpc, pub)
		e.aclEntry(acl, aclRule{number: 100, allow: true, cidr: "10.60.0.0/16", from: 80, to: 80})
		e.aclEntry(acl, aclRule{number: 100, egress: true, allow: true, cidr: "0.0.0.0/0", from: 80, to: 80})
		e.aclEntry(acl, aclRule{number: 110, egress: true, allow: true, cidr: "10.60.0.0/16", from: 1024, to: 65535})
		e.apply()
		if got, ok := e.echo(app); ok {
			t.Fatalf("outbound HTTP worked (%q) although the NAT subnet's ACL does not allow inbound ephemeral ports", got)
		}
		e.aclEntry(acl, aclRule{number: 120, allow: true, cidr: "0.0.0.0/0", from: 1024, to: 65535})
		e.apply()
		if got, ok := e.echo(app); !ok || got != natIP {
			t.Errorf("after allowing inbound 1024-65535 on the NAT subnet: echo %q (ok=%t)", got, ok)
		}
	})
	t.Run("route to a deleted NAT gateway is a blackhole", func(t *testing.T) {
		if _, err := e.ec2.DeleteNatGateway(e.ctx, &ec2.DeleteNatGatewayInput{NatGatewayId: &nat}); err != nil {
			t.Fatal(err)
		}
		e.apply()
		if got, ok := e.echo(app); ok {
			t.Errorf("traffic still reached the internet as %q after the NAT gateway was deleted", got)
		}
	})
}

// TestNATInstance covers an EC2 instance that does NAT for a private subnet.
//
// Expected AWS behaviour (VPC user guide, "NAT instances"):
//   - A route can send traffic to an instance.
//   - The instance only forwards traffic after its source/destination check
//     is disabled.
//   - Unlike a NAT gateway, the instance's security groups apply.
func TestNATInstance(t *testing.T) {
	e := newEnv(t)
	vpc := e.vpc("10.70.0.0/16")
	pub := e.subnet(vpc, "10.70.1.0/24")
	priv := e.subnet(vpc, "10.70.2.0/24")
	igw := e.igw(vpc)
	e.publicRouteTable(vpc, igw, pub)

	sgNAT := e.sg(vpc, "nat")
	fromVPC := fromCIDR(types.IpPermission{IpProtocol: aws.String("-1")}, "10.70.0.0/16")
	e.allowIngress(sgNAT, fromVPC)
	natInst := e.instance(pub, sgNAT)
	natIP := e.eip(natInst)
	app := e.instance(priv, e.sg(vpc, "app"))

	privRT := e.routeTable(vpc, priv)
	e.route(privRT, "0.0.0.0/0", func(in *ec2.CreateRouteInput) { in.InstanceId = &natInst.ID })
	e.apply()
	e.mustSh(natInst, "iptables -t nat -A POSTROUTING -o eth0 -s 10.70.2.0/24 -j MASQUERADE")

	t.Run("source/destination check blocks forwarding", func(t *testing.T) {
		if got, ok := e.echo(app); ok {
			t.Errorf("traffic through the NAT instance reached the internet as %q with the check enabled", got)
		}
	})
	t.Run("forwarding works without the check", func(t *testing.T) {
		if _, err := e.ec2.ModifyInstanceAttribute(e.ctx, &ec2.ModifyInstanceAttributeInput{
			InstanceId: &natInst.ID, SourceDestCheck: &types.AttributeBooleanValue{Value: aws.Bool(false)},
		}); err != nil {
			t.Skipf("Floci cannot disable the source/destination check: %v", err)
		}
		e.apply()
		if got, ok := e.echo(app); !ok || got != natIP {
			t.Errorf("echo host saw %q (ok=%t), want the NAT instance's EIP %s", got, ok, natIP)
		}
	})
	t.Run("the NAT instance's security group applies", func(t *testing.T) {
		if _, err := e.ec2.RevokeSecurityGroupIngress(e.ctx, &ec2.RevokeSecurityGroupIngressInput{
			GroupId: &sgNAT, IpPermissions: []types.IpPermission{fromVPC},
		}); err != nil {
			t.Fatal(err)
		}
		e.apply()
		if got, ok := e.echo(app); ok {
			t.Errorf("traffic reached the internet as %q although the NAT instance's SG allows no inbound traffic", got)
		}
	})
}

// TestRouteTables covers route selection.
//
// Expected AWS behaviour (VPC user guide, "Route priority"):
//   - The most specific route that matches the destination wins.
//   - A route whose target is gone stays in the table as a blackhole and
//     still wins over less specific routes: traffic is dropped, not sent to
//     the default route.
func TestRouteTables(t *testing.T) {
	e := newEnv(t)
	vpc := e.vpc("10.80.0.0/16")
	pub := e.subnet(vpc, "10.80.1.0/24")
	igw := e.igw(vpc)
	rt := e.publicRouteTable(vpc, igw, pub)
	web := e.instance(pub, e.sg(vpc, "web"))
	e.eip(web)

	// A private NAT gateway cannot reach the internet: the /32 to the echo
	// host leads nowhere, everything else uses the IGW.
	pnat, _ := e.natGateway(pub, false)
	e.route(rt, plan.EchoIP.String()+"/32", func(in *ec2.CreateRouteInput) { in.NatGatewayId = &pnat })
	e.apply()
	if _, err := e.hostSh(plan.OperatorName, "nohup socat TCP-LISTEN:8080,fork,reuseaddr SYSTEM:'echo ok' >/dev/null 2>&1 &"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)

	t.Run("longest prefix wins", func(t *testing.T) {
		if got, ok := e.echo(web); ok {
			t.Errorf("echo host reached as %q; the /32 route should win over 0.0.0.0/0", got)
		}
		if !e.canTCP(web, plan.OperatorIP.String(), "8080") {
			t.Error("operator unreachable; 0.0.0.0/0 to the IGW should still apply to it")
		}
	})
	t.Run("route to a deleted target is a blackhole", func(t *testing.T) {
		if _, err := e.ec2.DeleteNatGateway(e.ctx, &ec2.DeleteNatGatewayInput{NatGatewayId: &pnat}); err != nil {
			t.Fatal(err)
		}
		e.apply()
		if got, ok := e.echo(web); ok {
			t.Errorf("echo host reached as %q; the blackhole /32 must not fall back to 0.0.0.0/0", got)
		}
	})
}

// TestPrefixLists covers customer-managed prefix lists in routes and
// security group rules.
func TestPrefixLists(t *testing.T) {
	e := newEnv(t)
	out, err := e.ec2.CreateManagedPrefixList(e.ctx, &ec2.CreateManagedPrefixListInput{
		PrefixListName: aws.String("internet-hosts"), AddressFamily: aws.String("IPv4"), MaxEntries: aws.Int32(5),
		Entries: []types.AddPrefixListEntry{{Cidr: aws.String("203.0.113.0/24")}},
	})
	if err != nil {
		t.Skipf("Floci cannot create prefix lists: %v", err)
	}
	pl := aws.ToString(out.PrefixList.PrefixListId)
	e.defer_(func() { e.ec2.DeleteManagedPrefixList(e.ctx, &ec2.DeleteManagedPrefixListInput{PrefixListId: &pl}) })

	vpc := e.vpc("10.90.0.0/16")
	pub := e.subnet(vpc, "10.90.1.0/24")
	igw := e.igw(vpc)
	rt := e.routeTable(vpc, pub) // no default route: only the prefix list goes to the IGW
	e.route(rt, "", func(in *ec2.CreateRouteInput) {
		in.DestinationCidrBlock, in.DestinationPrefixListId, in.GatewayId = nil, &pl, &igw
	})
	sg := e.sg(vpc, "web")
	e.allowIngress(sg, types.IpPermission{
		IpProtocol: aws.String("tcp"), FromPort: aws.Int32(80), ToPort: aws.Int32(80),
		PrefixListIds: []types.PrefixListId{{PrefixListId: &pl}},
	})
	web := e.instance(pub, sg)
	webIP := e.eip(web)
	e.apply()
	e.listenTCP(web, "80")
	e.listenTCP(web, "81")

	t.Run("route to a prefix list", func(t *testing.T) {
		if got, ok := e.echo(web); !ok || got != webIP {
			t.Errorf("echo host saw %q (ok=%t), want %s through the prefix-list route", got, ok, webIP)
		}
	})
	t.Run("security group rule with a prefix list", func(t *testing.T) {
		if !e.operatorCanTCP(webIP, "80") {
			t.Errorf("operator (in the prefix list) cannot reach %s:80", webIP)
		}
		if e.operatorCanTCP(webIP, "81") {
			t.Errorf("operator reached %s:81, which no rule allows", webIP)
		}
	})
}

// natGateway creates a NAT gateway in the subnet. A public one gets a new
// Elastic IP, which is returned.
func (e *env) natGateway(subnet string, public bool) (id, publicIP string) {
	e.t.Helper()
	in := &ec2.CreateNatGatewayInput{SubnetId: &subnet, ConnectivityType: types.ConnectivityTypePrivate}
	if public {
		a, err := e.ec2.AllocateAddress(e.ctx, &ec2.AllocateAddressInput{Domain: types.DomainTypeVpc})
		if err != nil {
			e.t.Fatal(err)
		}
		alloc := aws.ToString(a.AllocationId)
		e.defer_(func() { e.ec2.ReleaseAddress(e.ctx, &ec2.ReleaseAddressInput{AllocationId: &alloc}) })
		in.AllocationId, in.ConnectivityType, publicIP = &alloc, types.ConnectivityTypePublic, aws.ToString(a.PublicIp)
	}
	out, err := e.ec2.CreateNatGateway(e.ctx, in)
	if err != nil {
		e.t.Fatal(err)
	}
	id = aws.ToString(out.NatGateway.NatGatewayId)
	e.defer_(func() { e.ec2.DeleteNatGateway(e.ctx, &ec2.DeleteNatGatewayInput{NatGatewayId: &id}) })
	return id, publicIP
}

// routeTable creates a route table without extra routes and associates it
// with the subnets.
func (e *env) routeTable(vpc string, subnets ...string) string {
	e.t.Helper()
	out, err := e.ec2.CreateRouteTable(e.ctx, &ec2.CreateRouteTableInput{VpcId: &vpc})
	if err != nil {
		e.t.Fatal(err)
	}
	id := aws.ToString(out.RouteTable.RouteTableId)
	e.defer_(func() { e.ec2.DeleteRouteTable(e.ctx, &ec2.DeleteRouteTableInput{RouteTableId: &id}) })
	for _, sn := range subnets {
		a, err := e.ec2.AssociateRouteTable(e.ctx, &ec2.AssociateRouteTableInput{RouteTableId: &id, SubnetId: aws.String(sn)})
		if err != nil {
			e.t.Fatal(err)
		}
		assoc := aws.ToString(a.AssociationId)
		e.defer_(func() { e.ec2.DisassociateRouteTable(e.ctx, &ec2.DisassociateRouteTableInput{AssociationId: &assoc}) })
	}
	return id
}

// route adds a route to dst; target sets the target field.
func (e *env) route(rt, dst string, target func(*ec2.CreateRouteInput)) {
	e.t.Helper()
	in := &ec2.CreateRouteInput{RouteTableId: &rt, DestinationCidrBlock: &dst}
	target(in)
	if _, err := e.ec2.CreateRoute(e.ctx, in); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) replaceRoute(rt, dst string, target func(*ec2.ReplaceRouteInput)) {
	e.t.Helper()
	in := &ec2.ReplaceRouteInput{RouteTableId: &rt, DestinationCidrBlock: &dst}
	target(in)
	if _, err := e.ec2.ReplaceRoute(e.ctx, in); err != nil {
		e.t.Fatal(err)
	}
}
