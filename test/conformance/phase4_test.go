//go:build conformance

package conformance

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// TestVPCPeering covers traffic between peered VPCs.
//
// Expected AWS behaviour (VPC peering guide, "How VPC peering works" and
// "Unsupported VPC peering configurations"):
//   - Both VPCs need a route to the peering connection; without the return
//     route the reply is dropped.
//   - Security groups can reference a group in the peer VPC.
//   - Peering is not transitive: A cannot reach C through B.
//   - No edge-to-edge routing: A cannot use B's internet gateway.
//   - Routes to a deleted peering connection become blackholes.
func TestVPCPeering(t *testing.T) {
	e := newEnv(t)
	vpcA, vpcB, vpcC := e.vpc("10.110.0.0/16"), e.vpc("10.111.0.0/16"), e.vpc("10.112.0.0/16")
	snA, snB, snC := e.subnet(vpcA, "10.110.1.0/24"), e.subnet(vpcB, "10.111.1.0/24"), e.subnet(vpcC, "10.112.1.0/24")
	rtA, rtB, rtC := e.mainRouteTable(vpcA), e.mainRouteTable(vpcB), e.mainRouteTable(vpcC)

	sgA, sgB, sgC := e.sg(vpcA, "a"), e.sg(vpcB, "b"), e.sg(vpcC, "c")
	for _, sg := range []string{sgA, sgB, sgC} {
		e.allowIngress(sg, fromCIDR(tcp(80), "10.0.0.0/8"))
	}
	a, b, c := e.instance(snA, sgA), e.instance(snB, sgB), e.instance(snC, sgC)

	ab := e.peering(vpcA, vpcB)
	bc := e.peering(vpcB, vpcC)
	toPeer := func(id string) func(*ec2.CreateRouteInput) {
		return func(in *ec2.CreateRouteInput) { in.VpcPeeringConnectionId = &id }
	}
	e.route(rtA, "10.111.0.0/16", toPeer(ab))
	e.route(rtB, "10.112.0.0/16", toPeer(bc))
	e.route(rtC, "10.111.0.0/16", toPeer(bc))
	e.apply()
	for _, in := range []instance{a, b, c} {
		e.listenTCP(in, "80")
		e.listenTCP(in, "81")
	}

	t.Run("both VPCs need a route", func(t *testing.T) {
		e.expectTCP(a, b, "80", false, "vpc B has no route back to vpc A")
		e.route(rtB, "10.110.0.0/16", toPeer(ab))
		e.apply()
		e.expectTCP(a, b, "80", true, "routes to the peering in both VPCs")
		e.expectTCP(b, a, "80", true, "routes to the peering in both VPCs")
	})
	t.Run("security group references a group in the peer VPC", func(t *testing.T) {
		e.expectTCP(a, b, "81", false, "no rule allows port 81 yet")
		if _, err := e.ec2.AuthorizeSecurityGroupIngress(e.ctx, &ec2.AuthorizeSecurityGroupIngressInput{
			GroupId: &sgB, IpPermissions: []types.IpPermission{fromGroup(tcp(81), sgA)},
		}); err != nil {
			t.Skipf("Floci rejects a reference to a peer VPC's group: %v", err)
		}
		e.apply()
		e.expectTCP(a, b, "81", true, "sg-b allows port 81 from sg-a in the peer VPC")
		e.expectTCP(c, b, "81", false, "c is not in sg-a")
	})
	t.Run("peering is not transitive", func(t *testing.T) {
		e.expectTCP(b, c, "80", true, "b and c are peered")
		e.route(rtA, "10.112.0.0/16", toPeer(ab))
		e.route(rtC, "10.110.0.0/16", toPeer(bc))
		e.apply()
		e.expectTCP(a, c, "80", false, "a reaches c only through b; peering is not transitive")
		e.expectTCP(c, a, "80", false, "c reaches a only through b; peering is not transitive")
	})
	t.Run("no edge-to-edge routing through the peer's internet gateway", func(t *testing.T) {
		igw := e.igw(vpcB)
		e.publicRouteTable(vpcB, igw, snB)
		// The new table replaces B's main table for snB: route back to A again.
		e.mustRouteForSubnet(vpcB, snB, "10.110.0.0/16", toPeer(ab))
		e.eip(b)
		e.route(rtA, "0.0.0.0/0", toPeer(ab))
		e.apply()
		if _, ok := e.echo(b); !ok {
			t.Fatal("b cannot reach the internet through its own IGW")
		}
		e.expectTCP(a, b, "80", true, "a still reaches b")
		if got, ok := e.echo(a); ok {
			t.Errorf("a reached the internet as %q through vpc B's internet gateway", got)
		}
	})
	t.Run("route to a deleted peering connection is a blackhole", func(t *testing.T) {
		if _, err := e.ec2.DeleteVpcPeeringConnection(e.ctx, &ec2.DeleteVpcPeeringConnectionInput{VpcPeeringConnectionId: &ab}); err != nil {
			t.Fatal(err)
		}
		e.apply()
		e.expectTCP(a, b, "80", false, "the peering connection is deleted")
	})
}

// TestTransitGateway covers routing through a transit gateway.
//
// Expected AWS behaviour (Transit Gateways guide, "How transit gateways work"):
//   - Attachments are associated with, and propagate into, the default route
//     table: all attached VPCs reach each other (transitive).
//   - An attachment associated with another route table only reaches what
//     that table routes to; replies need a route as well.
//   - A static route wins over a propagated route; a blackhole route drops.
//   - The TGW only reaches resources in Availability Zones where the
//     attachment has a subnet.
func TestTransitGateway(t *testing.T) {
	e := newEnv(t)
	vpcA, vpcB, vpcC := e.vpc("10.120.0.0/16"), e.vpc("10.121.0.0/16"), e.vpc("10.122.0.0/16")
	snA := e.subnetAZ(vpcA, "10.120.1.0/24", "us-east-1a")
	snA2 := e.subnetAZ(vpcA, "10.120.2.0/24", "us-east-1b")
	snB := e.subnetAZ(vpcB, "10.121.1.0/24", "us-east-1a")
	snC := e.subnetAZ(vpcC, "10.122.1.0/24", "us-east-1a")

	var ins []instance
	for _, v := range []struct{ vpc, subnet, name string }{{vpcA, snA, "a"}, {vpcA, snA2, "a2"}, {vpcB, snB, "b"}, {vpcC, snC, "c"}} {
		sg := e.sg(v.vpc, v.name)
		e.allowIngress(sg, fromCIDR(tcp(80), "10.0.0.0/8"))
		ins = append(ins, e.instance(v.subnet, sg))
	}
	a, a2, b, c := ins[0], ins[1], ins[2], ins[3]

	tgw, defaultRT := e.transitGateway()
	attA := e.tgwAttachment(tgw, vpcA, snA) // no subnet in us-east-1b
	e.tgwAttachment(tgw, vpcB, snB)
	attC := e.tgwAttachment(tgw, vpcC, snC)
	for _, vpc := range []string{vpcA, vpcB, vpcC} {
		e.route(e.mainRouteTable(vpc), "10.0.0.0/8", func(in *ec2.CreateRouteInput) { in.TransitGatewayId = &tgw })
	}
	e.apply()
	for _, in := range ins {
		e.listenTCP(in, "80")
	}

	t.Run("default route table connects all attachments", func(t *testing.T) {
		e.expectTCP(a, b, "80", true, "both attachments propagate into the default route table")
		e.expectTCP(b, c, "80", true, "both attachments propagate into the default route table")
		e.expectTCP(c, a, "80", true, "both attachments propagate into the default route table")
	})
	t.Run("no attachment subnet in the Availability Zone", func(t *testing.T) {
		e.expectTCP(b, a2, "80", false, "the attachment of vpc A has no subnet in us-east-1b")
		e.expectTCP(a2, b, "80", false, "the attachment of vpc A has no subnet in us-east-1b")
	})
	t.Run("static blackhole route wins over the propagated route", func(t *testing.T) {
		e.tgwRoute(defaultRT, "10.120.0.0/16", "")
		e.apply()
		e.expectTCP(b, a, "80", false, "blackhole route for vpc A in the default route table")
		if _, err := e.ec2.DeleteTransitGatewayRoute(e.ctx, &ec2.DeleteTransitGatewayRouteInput{
			TransitGatewayRouteTableId: &defaultRT, DestinationCidrBlock: aws.String("10.120.0.0/16"),
		}); err != nil {
			t.Fatal(err)
		}
		e.apply()
		e.expectTCP(b, a, "80", true, "the propagated route applies again")
	})
	t.Run("isolated route table", func(t *testing.T) {
		rt := e.tgwRouteTable(tgw)
		if _, err := e.ec2.DisassociateTransitGatewayRouteTable(e.ctx, &ec2.DisassociateTransitGatewayRouteTableInput{
			TransitGatewayRouteTableId: &defaultRT, TransitGatewayAttachmentId: &attC,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := e.ec2.AssociateTransitGatewayRouteTable(e.ctx, &ec2.AssociateTransitGatewayRouteTableInput{
			TransitGatewayRouteTableId: &rt, TransitGatewayAttachmentId: &attC,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := e.ec2.EnableTransitGatewayRouteTablePropagation(e.ctx, &ec2.EnableTransitGatewayRouteTablePropagationInput{
			TransitGatewayRouteTableId: &rt, TransitGatewayAttachmentId: &attA,
		}); err != nil {
			t.Fatal(err)
		}
		e.apply()
		e.expectTCP(c, a, "80", true, "vpc C's route table has vpc A's propagation")
		e.expectTCP(a, c, "80", true, "the default route table still routes to vpc C")
		e.expectTCP(c, b, "80", false, "vpc C's route table has no route to vpc B")
		e.expectTCP(b, c, "80", false, "the reply from vpc C has no route to vpc B")
	})
	t.Run("deleted attachment", func(t *testing.T) {
		if _, err := e.ec2.DeleteTransitGatewayVpcAttachment(e.ctx, &ec2.DeleteTransitGatewayVpcAttachmentInput{TransitGatewayAttachmentId: &attA}); err != nil {
			t.Fatal(err)
		}
		e.apply()
		e.expectTCP(b, a, "80", false, "vpc A is no longer attached")
	})
}

// peering creates and accepts a peering connection.
func (e *env) peering(requester, accepter string) string {
	e.t.Helper()
	out, err := e.ec2.CreateVpcPeeringConnection(e.ctx, &ec2.CreateVpcPeeringConnectionInput{VpcId: &requester, PeerVpcId: &accepter})
	if err != nil {
		e.t.Fatal(err)
	}
	id := aws.ToString(out.VpcPeeringConnection.VpcPeeringConnectionId)
	e.defer_(func() {
		e.ec2.DeleteVpcPeeringConnection(e.ctx, &ec2.DeleteVpcPeeringConnectionInput{VpcPeeringConnectionId: &id})
	})
	if _, err := e.ec2.AcceptVpcPeeringConnection(e.ctx, &ec2.AcceptVpcPeeringConnectionInput{VpcPeeringConnectionId: &id}); err != nil {
		e.t.Fatal(err)
	}
	return id
}

// mustRouteForSubnet adds a route to the route table associated with the
// subnet.
func (e *env) mustRouteForSubnet(vpc, subnet, dst string, target func(*ec2.CreateRouteInput)) {
	e.t.Helper()
	out, err := e.ec2.DescribeRouteTables(e.ctx, &ec2.DescribeRouteTablesInput{
		Filters: []types.Filter{{Name: aws.String("association.subnet-id"), Values: []string{subnet}}},
	})
	if err != nil || len(out.RouteTables) != 1 {
		e.t.Fatalf("route table of %s: %v (%d tables)", subnet, err, len(out.RouteTables))
	}
	e.route(aws.ToString(out.RouteTables[0].RouteTableId), dst, target)
}

func (e *env) subnetAZ(vpc, cidr, az string) string {
	e.t.Helper()
	out, err := e.ec2.CreateSubnet(e.ctx, &ec2.CreateSubnetInput{VpcId: &vpc, CidrBlock: &cidr, AvailabilityZone: &az})
	if err != nil {
		e.t.Fatal(err)
	}
	id := aws.ToString(out.Subnet.SubnetId)
	e.defer_(func() { e.ec2.DeleteSubnet(e.ctx, &ec2.DeleteSubnetInput{SubnetId: &id}) })
	return id
}

// transitGateway creates a TGW with the default route table settings and
// returns its ID and default route table.
func (e *env) transitGateway() (id, routeTable string) {
	e.t.Helper()
	out, err := e.ec2.CreateTransitGateway(e.ctx, &ec2.CreateTransitGatewayInput{})
	if err != nil {
		e.t.Fatal(err)
	}
	g := out.TransitGateway
	id = aws.ToString(g.TransitGatewayId)
	e.defer_(func() { e.ec2.DeleteTransitGateway(e.ctx, &ec2.DeleteTransitGatewayInput{TransitGatewayId: &id}) })
	if g.Options == nil || g.Options.AssociationDefaultRouteTableId == nil {
		e.t.Fatal("the new transit gateway has no default route table")
	}
	return id, aws.ToString(g.Options.AssociationDefaultRouteTableId)
}

func (e *env) tgwAttachment(tgw, vpc string, subnets ...string) string {
	e.t.Helper()
	out, err := e.ec2.CreateTransitGatewayVpcAttachment(e.ctx, &ec2.CreateTransitGatewayVpcAttachmentInput{
		TransitGatewayId: &tgw, VpcId: &vpc, SubnetIds: subnets,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	id := aws.ToString(out.TransitGatewayVpcAttachment.TransitGatewayAttachmentId)
	e.defer_(func() {
		e.ec2.DeleteTransitGatewayVpcAttachment(e.ctx, &ec2.DeleteTransitGatewayVpcAttachmentInput{TransitGatewayAttachmentId: &id})
	})
	return id
}

func (e *env) tgwRouteTable(tgw string) string {
	e.t.Helper()
	out, err := e.ec2.CreateTransitGatewayRouteTable(e.ctx, &ec2.CreateTransitGatewayRouteTableInput{TransitGatewayId: &tgw})
	if err != nil {
		e.t.Fatal(err)
	}
	id := aws.ToString(out.TransitGatewayRouteTable.TransitGatewayRouteTableId)
	e.defer_(func() {
		e.ec2.DeleteTransitGatewayRouteTable(e.ctx, &ec2.DeleteTransitGatewayRouteTableInput{TransitGatewayRouteTableId: &id})
	})
	return id
}

// tgwRoute adds a static route; an empty attachment makes it a blackhole.
func (e *env) tgwRoute(rt, dst, attachment string) {
	e.t.Helper()
	in := &ec2.CreateTransitGatewayRouteInput{TransitGatewayRouteTableId: &rt, DestinationCidrBlock: &dst}
	if attachment == "" {
		in.Blackhole = aws.Bool(true)
	} else {
		in.TransitGatewayAttachmentId = &attachment
	}
	if _, err := e.ec2.CreateTransitGatewayRoute(e.ctx, in); err != nil {
		e.t.Fatal(err)
	}
}
