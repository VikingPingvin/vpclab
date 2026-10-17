//go:build conformance

package conformance

import (
	"bytes"
	"os/exec"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/VikingPingvin/vpclab/internal/plan"
)

func (e *env) igw(vpc string) string {
	e.t.Helper()
	out, err := e.ec2.CreateInternetGateway(e.ctx, &ec2.CreateInternetGatewayInput{})
	if err != nil {
		e.t.Fatal(err)
	}
	id := aws.ToString(out.InternetGateway.InternetGatewayId)
	if _, err := e.ec2.AttachInternetGateway(e.ctx, &ec2.AttachInternetGatewayInput{InternetGatewayId: &id, VpcId: &vpc}); err != nil {
		e.t.Fatal(err)
	}
	e.defer_(func() {
		e.ec2.DetachInternetGateway(e.ctx, &ec2.DetachInternetGatewayInput{InternetGatewayId: &id, VpcId: &vpc})
		e.ec2.DeleteInternetGateway(e.ctx, &ec2.DeleteInternetGatewayInput{InternetGatewayId: &id})
	})
	return id
}

// publicRouteTable creates a route table with 0.0.0.0/0 -> igw and associates
// it with the subnets.
func (e *env) publicRouteTable(vpc, igw string, subnets ...string) string {
	e.t.Helper()
	out, err := e.ec2.CreateRouteTable(e.ctx, &ec2.CreateRouteTableInput{VpcId: &vpc})
	if err != nil {
		e.t.Fatal(err)
	}
	id := aws.ToString(out.RouteTable.RouteTableId)
	e.defer_(func() { e.ec2.DeleteRouteTable(e.ctx, &ec2.DeleteRouteTableInput{RouteTableId: &id}) })
	if _, err := e.ec2.CreateRoute(e.ctx, &ec2.CreateRouteInput{
		RouteTableId: &id, DestinationCidrBlock: aws.String("0.0.0.0/0"), GatewayId: &igw,
	}); err != nil {
		e.t.Fatal(err)
	}
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

// eip allocates an Elastic IP, associates it with the instance and returns
// the public address.
func (e *env) eip(in instance) string {
	e.t.Helper()
	out, err := e.ec2.AllocateAddress(e.ctx, &ec2.AllocateAddressInput{Domain: types.DomainTypeVpc})
	if err != nil {
		e.t.Fatal(err)
	}
	alloc := aws.ToString(out.AllocationId)
	e.defer_(func() { e.ec2.ReleaseAddress(e.ctx, &ec2.ReleaseAddressInput{AllocationId: &alloc}) })
	a, err := e.ec2.AssociateAddress(e.ctx, &ec2.AssociateAddressInput{AllocationId: &alloc, InstanceId: &in.ID})
	if err != nil {
		e.t.Fatal(err)
	}
	assoc := aws.ToString(a.AssociationId)
	e.defer_(func() { e.ec2.DisassociateAddress(e.ctx, &ec2.DisassociateAddressInput{AssociationId: &assoc}) })
	return aws.ToString(out.PublicIp)
}

// nacl creates a network ACL, associates it with the subnet and restores
// the default association on cleanup.
func (e *env) nacl(vpc, subnet string) string {
	e.t.Helper()
	out, err := e.ec2.CreateNetworkAcl(e.ctx, &ec2.CreateNetworkAclInput{VpcId: &vpc})
	if err != nil {
		e.t.Fatal(err)
	}
	id := aws.ToString(out.NetworkAcl.NetworkAclId)
	e.defer_(func() { e.ec2.DeleteNetworkAcl(e.ctx, &ec2.DeleteNetworkAclInput{NetworkAclId: &id}) })

	cur, err := e.ec2.DescribeNetworkAcls(e.ctx, &ec2.DescribeNetworkAclsInput{
		Filters: []types.Filter{{Name: aws.String("association.subnet-id"), Values: []string{subnet}}},
	})
	if err != nil || len(cur.NetworkAcls) == 0 {
		e.t.Fatalf("find current ACL of %s: %v", subnet, err)
	}
	prev := aws.ToString(cur.NetworkAcls[0].NetworkAclId)
	var assoc string
	for _, a := range cur.NetworkAcls[0].Associations {
		if aws.ToString(a.SubnetId) == subnet {
			assoc = aws.ToString(a.NetworkAclAssociationId)
		}
	}
	r, err := e.ec2.ReplaceNetworkAclAssociation(e.ctx, &ec2.ReplaceNetworkAclAssociationInput{AssociationId: &assoc, NetworkAclId: &id})
	if err != nil {
		e.t.Fatal(err)
	}
	newAssoc := aws.ToString(r.NewAssociationId)
	e.defer_(func() {
		e.ec2.ReplaceNetworkAclAssociation(e.ctx, &ec2.ReplaceNetworkAclAssociationInput{AssociationId: &newAssoc, NetworkAclId: &prev})
	})
	return id
}

type aclRule struct {
	number   int32
	egress   bool
	allow    bool
	cidr     string
	from, to int32 // TCP port range
}

func (e *env) aclEntry(acl string, r aclRule) {
	e.t.Helper()
	action := types.RuleActionDeny
	if r.allow {
		action = types.RuleActionAllow
	}
	if _, err := e.ec2.CreateNetworkAclEntry(e.ctx, &ec2.CreateNetworkAclEntryInput{
		NetworkAclId: &acl, RuleNumber: aws.Int32(r.number), Egress: aws.Bool(r.egress),
		RuleAction: action, Protocol: aws.String("6"), CidrBlock: aws.String(r.cidr),
		PortRange: &types.PortRange{From: aws.Int32(r.from), To: aws.Int32(r.to)},
	}); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) deleteACLEntry(acl string, number int32, egress bool) {
	e.t.Helper()
	if _, err := e.ec2.DeleteNetworkAclEntry(e.ctx, &ec2.DeleteNetworkAclEntryInput{
		NetworkAclId: &acl, RuleNumber: aws.Int32(number), Egress: aws.Bool(egress),
	}); err != nil {
		e.t.Fatal(err)
	}
}

// hostSh runs a shell command on an internet host, e.g. the operator box.
func (e *env) hostSh(host, script string) (string, error) {
	var out bytes.Buffer
	cmd := exec.Command("docker", "exec", "vpcsim-"+host, "sh", "-c", script)
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}

// operatorCanTCP reports whether the operator box on the internet can reach
// ip:port and read the reply.
func (e *env) operatorCanTCP(ip, port string) bool {
	out, err := e.hostSh(plan.OperatorName, "socat -T2 - TCP:"+ip+":"+port+",connect-timeout=2 </dev/null")
	return err == nil && strings.Contains(out, "ok")
}

// echo asks the internet echo host which source address it sees. ok is false
// when the request fails.
func (e *env) echo(from instance) (string, bool) {
	out, err := e.sh(from, "curl -s --max-time 3 http://"+plan.EchoIP.String()+"/")
	return strings.TrimSpace(out), err == nil
}
