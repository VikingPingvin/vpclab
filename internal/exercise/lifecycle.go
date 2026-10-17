package exercise

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// TagExercise marks every resource an exercise creates.
const TagExercise = "cap:exercise"

// State is the running exercise: the AWS IDs of its resources and what Stop
// must undo.
type State struct {
	Exercise   string            `json:"exercise"`
	IDs        map[string]string `json:"ids"`     // resource name -> AWS ID
	Created    []Created         `json:"created"` // in creation order
	HintsShown int               `json:"hintsShown"`
}

// Created is one step that Stop reverses.
type Created struct {
	Kind string `json:"kind"`
	ID   string `json:"id"`
	// Ref is a second ID the reversal needs: the VPC of an IGW attachment,
	// the allocation of an EIP association, the previous ACL of a subnet.
	Ref string `json:"ref,omitempty"`
}

const (
	kindVPC        = "vpc"
	kindSubnet     = "subnet"
	kindIGW        = "igw"
	kindIGWAttach  = "igw-attachment"
	kindRouteTable = "route-table"
	kindRTAssoc    = "route-table-association"
	kindSG         = "security-group"
	kindNACL       = "network-acl"
	kindNACLAssoc  = "network-acl-association"
	kindInstance   = "instance"
	kindEIP        = "elastic-ip"
	kindEIPAssoc   = "elastic-ip-association"
)

func (s *State) add(kind, id, ref string) { s.Created = append(s.Created, Created{kind, id, ref}) }

// SaveState writes the state as JSON, creating the directory if needed.
func SaveState(path string, s *State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// LoadState reads the state file. A missing file returns (nil, nil).
func LoadState(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	s := &State{}
	return s, json.Unmarshal(data, s)
}

// Start creates the exercise's resources in Floci. If a step fails, it
// removes what it created and returns the error.
func Start(ctx context.Context, c *ec2.Client, ex *Exercise) (*State, error) {
	s := &State{Exercise: ex.Name, IDs: map[string]string{}}
	if err := create(ctx, c, ex, s); err != nil {
		if errs := Stop(ctx, c, s); len(errs) > 0 {
			err = fmt.Errorf("%w (cleanup: %v)", err, errors.Join(errs...))
		}
		return nil, err
	}
	return s, nil
}

func tags(kind types.ResourceType, ex *Exercise, name string) []types.TagSpecification {
	return []types.TagSpecification{{ResourceType: kind, Tags: []types.Tag{
		{Key: aws.String("Name"), Value: aws.String(name)},
		{Key: aws.String(TagExercise), Value: aws.String(ex.Name)},
	}}}
}

func create(ctx context.Context, c *ec2.Client, ex *Exercise, s *State) error {
	r := ex.Resources
	id := func(name string) *string { return aws.String(s.IDs[name]) }

	for _, v := range r.VPCs {
		out, err := c.CreateVpc(ctx, &ec2.CreateVpcInput{CidrBlock: &v.CIDR, TagSpecifications: tags(types.ResourceTypeVpc, ex, v.Name)})
		if err != nil {
			return fmt.Errorf("vpc %s: %w", v.Name, err)
		}
		s.IDs[v.Name] = aws.ToString(out.Vpc.VpcId)
		s.add(kindVPC, s.IDs[v.Name], "")
	}
	for _, sn := range r.Subnets {
		out, err := c.CreateSubnet(ctx, &ec2.CreateSubnetInput{VpcId: id(sn.VPC), CidrBlock: &sn.CIDR, TagSpecifications: tags(types.ResourceTypeSubnet, ex, sn.Name)})
		if err != nil {
			return fmt.Errorf("subnet %s: %w", sn.Name, err)
		}
		s.IDs[sn.Name] = aws.ToString(out.Subnet.SubnetId)
		s.add(kindSubnet, s.IDs[sn.Name], "")
	}
	for _, g := range r.InternetGateways {
		out, err := c.CreateInternetGateway(ctx, &ec2.CreateInternetGatewayInput{TagSpecifications: tags(types.ResourceTypeInternetGateway, ex, g.Name)})
		if err != nil {
			return fmt.Errorf("internet gateway %s: %w", g.Name, err)
		}
		s.IDs[g.Name] = aws.ToString(out.InternetGateway.InternetGatewayId)
		s.add(kindIGW, s.IDs[g.Name], "")
		if _, err := c.AttachInternetGateway(ctx, &ec2.AttachInternetGatewayInput{InternetGatewayId: id(g.Name), VpcId: id(g.VPC)}); err != nil {
			return fmt.Errorf("attach %s: %w", g.Name, err)
		}
		s.add(kindIGWAttach, s.IDs[g.Name], s.IDs[g.VPC])
	}
	for _, rt := range r.RouteTables {
		out, err := c.CreateRouteTable(ctx, &ec2.CreateRouteTableInput{VpcId: id(rt.VPC), TagSpecifications: tags(types.ResourceTypeRouteTable, ex, rt.Name)})
		if err != nil {
			return fmt.Errorf("route table %s: %w", rt.Name, err)
		}
		s.IDs[rt.Name] = aws.ToString(out.RouteTable.RouteTableId)
		s.add(kindRouteTable, s.IDs[rt.Name], "")
		for _, rte := range rt.Routes {
			if _, err := c.CreateRoute(ctx, &ec2.CreateRouteInput{RouteTableId: id(rt.Name), DestinationCidrBlock: &rte.Destination, GatewayId: id(rte.Gateway)}); err != nil {
				return fmt.Errorf("route table %s: route %s: %w", rt.Name, rte.Destination, err)
			}
		}
		for _, sn := range rt.Subnets {
			a, err := c.AssociateRouteTable(ctx, &ec2.AssociateRouteTableInput{RouteTableId: id(rt.Name), SubnetId: id(sn)})
			if err != nil {
				return fmt.Errorf("route table %s: associate %s: %w", rt.Name, sn, err)
			}
			s.add(kindRTAssoc, aws.ToString(a.AssociationId), "")
		}
	}
	// Create all groups first: rules may refer to any of them.
	for _, sg := range r.SecurityGroups {
		out, err := c.CreateSecurityGroup(ctx, &ec2.CreateSecurityGroupInput{
			VpcId: id(sg.VPC), GroupName: aws.String(sg.Name), Description: aws.String(ex.Name + ": " + sg.Name),
			TagSpecifications: tags(types.ResourceTypeSecurityGroup, ex, sg.Name),
		})
		if err != nil {
			return fmt.Errorf("security group %s: %w", sg.Name, err)
		}
		s.IDs[sg.Name] = aws.ToString(out.GroupId)
		s.add(kindSG, s.IDs[sg.Name], "")
	}
	for _, sg := range r.SecurityGroups {
		if len(sg.Ingress) == 0 {
			continue
		}
		var perms []types.IpPermission
		for _, rule := range sg.Ingress {
			from, to, _ := parsePorts(rule.Protocol, rule.Ports)
			proto := rule.Protocol
			if proto == "all" {
				proto = "-1"
			}
			p := types.IpPermission{IpProtocol: aws.String(proto), FromPort: aws.Int32(from), ToPort: aws.Int32(to)}
			if rule.CIDR != "" {
				p.IpRanges = []types.IpRange{{CidrIp: aws.String(rule.CIDR)}}
			} else {
				p.UserIdGroupPairs = []types.UserIdGroupPair{{GroupId: id(rule.Group)}}
			}
			perms = append(perms, p)
		}
		if _, err := c.AuthorizeSecurityGroupIngress(ctx, &ec2.AuthorizeSecurityGroupIngressInput{GroupId: id(sg.Name), IpPermissions: perms}); err != nil {
			return fmt.Errorf("security group %s: ingress: %w", sg.Name, err)
		}
	}
	for _, acl := range r.NetworkACLs {
		if err := createNACL(ctx, c, ex, s, acl); err != nil {
			return fmt.Errorf("network ACL %s: %w", acl.Name, err)
		}
	}
	for _, in := range r.Instances {
		var groups []string
		for _, g := range in.SecurityGroups {
			groups = append(groups, s.IDs[g])
		}
		out, err := c.RunInstances(ctx, &ec2.RunInstancesInput{
			ImageId: aws.String("ami-12345678"), InstanceType: types.InstanceTypeT3Micro,
			MinCount: aws.Int32(1), MaxCount: aws.Int32(1),
			SubnetId: id(in.Subnet), SecurityGroupIds: groups,
			TagSpecifications: tags(types.ResourceTypeInstance, ex, in.Name),
		})
		if err != nil {
			return fmt.Errorf("instance %s: %w", in.Name, err)
		}
		s.IDs[in.Name] = aws.ToString(out.Instances[0].InstanceId)
		s.add(kindInstance, s.IDs[in.Name], "")
		if !in.ElasticIP {
			continue
		}
		eip, err := c.AllocateAddress(ctx, &ec2.AllocateAddressInput{Domain: types.DomainTypeVpc})
		if err != nil {
			return fmt.Errorf("instance %s: elastic IP: %w", in.Name, err)
		}
		alloc := aws.ToString(eip.AllocationId)
		s.add(kindEIP, alloc, "")
		a, err := c.AssociateAddress(ctx, &ec2.AssociateAddressInput{AllocationId: &alloc, InstanceId: id(in.Name)})
		if err != nil {
			return fmt.Errorf("instance %s: associate elastic IP: %w", in.Name, err)
		}
		s.add(kindEIPAssoc, aws.ToString(a.AssociationId), alloc)
	}
	return nil
}

func createNACL(ctx context.Context, c *ec2.Client, ex *Exercise, s *State, acl NetworkACL) error {
	out, err := c.CreateNetworkAcl(ctx, &ec2.CreateNetworkAclInput{VpcId: aws.String(s.IDs[acl.VPC]), TagSpecifications: tags(types.ResourceTypeNetworkAcl, ex, acl.Name)})
	if err != nil {
		return err
	}
	aclID := aws.ToString(out.NetworkAcl.NetworkAclId)
	s.IDs[acl.Name] = aclID
	s.add(kindNACL, aclID, "")
	for _, e := range acl.Entries {
		from, to, _ := parsePorts(e.Protocol, e.Ports)
		in := &ec2.CreateNetworkAclEntryInput{
			NetworkAclId: &aclID, RuleNumber: aws.Int32(e.Rule), Egress: aws.Bool(e.Direction == "outbound"),
			RuleAction: types.RuleAction(e.Action), Protocol: aws.String(protocolNumber(e.Protocol)), CidrBlock: aws.String(e.CIDR),
		}
		if from >= 0 {
			in.PortRange = &types.PortRange{From: aws.Int32(from), To: aws.Int32(to)}
		}
		if _, err := c.CreateNetworkAclEntry(ctx, in); err != nil {
			return fmt.Errorf("rule %d: %w", e.Rule, err)
		}
	}
	// A subnet always has exactly one ACL: replace its current association.
	for _, sn := range acl.Subnets {
		cur, err := c.DescribeNetworkAcls(ctx, &ec2.DescribeNetworkAclsInput{
			Filters: []types.Filter{{Name: aws.String("association.subnet-id"), Values: []string{s.IDs[sn]}}},
		})
		if err != nil || len(cur.NetworkAcls) == 0 {
			return fmt.Errorf("find the current ACL of %s: %v", sn, err)
		}
		prev := aws.ToString(cur.NetworkAcls[0].NetworkAclId)
		var assoc string
		for _, a := range cur.NetworkAcls[0].Associations {
			if aws.ToString(a.SubnetId) == s.IDs[sn] {
				assoc = aws.ToString(a.NetworkAclAssociationId)
			}
		}
		r, err := c.ReplaceNetworkAclAssociation(ctx, &ec2.ReplaceNetworkAclAssociationInput{AssociationId: &assoc, NetworkAclId: &aclID})
		if err != nil {
			return fmt.Errorf("associate %s: %w", sn, err)
		}
		s.add(kindNACLAssoc, aws.ToString(r.NewAssociationId), prev)
	}
	return nil
}

// Stop removes the exercise's resources in reverse creation order. It goes
// on after an error and returns all of them. Resources the learner created
// are not tracked and stay.
func Stop(ctx context.Context, c *ec2.Client, s *State) []error {
	var errs []error
	for _, r := range slices.Backward(s.Created) {
		if err := undo(ctx, c, r); err != nil {
			errs = append(errs, fmt.Errorf("%s %s: %w", r.Kind, r.ID, err))
		}
	}
	return errs
}

func undo(ctx context.Context, c *ec2.Client, r Created) error {
	id := aws.String(r.ID)
	var err error
	switch r.Kind {
	case kindVPC:
		_, err = c.DeleteVpc(ctx, &ec2.DeleteVpcInput{VpcId: id})
	case kindSubnet:
		_, err = c.DeleteSubnet(ctx, &ec2.DeleteSubnetInput{SubnetId: id})
	case kindIGW:
		_, err = c.DeleteInternetGateway(ctx, &ec2.DeleteInternetGatewayInput{InternetGatewayId: id})
	case kindIGWAttach:
		_, err = c.DetachInternetGateway(ctx, &ec2.DetachInternetGatewayInput{InternetGatewayId: id, VpcId: aws.String(r.Ref)})
	case kindRouteTable:
		// The learner may have associated the table with subnets.
		if out, derr := c.DescribeRouteTables(ctx, &ec2.DescribeRouteTablesInput{RouteTableIds: []string{r.ID}}); derr == nil {
			for _, rt := range out.RouteTables {
				for _, a := range rt.Associations {
					if a.SubnetId != nil && !aws.ToBool(a.Main) {
						c.DisassociateRouteTable(ctx, &ec2.DisassociateRouteTableInput{AssociationId: a.RouteTableAssociationId})
					}
				}
			}
		}
		_, err = c.DeleteRouteTable(ctx, &ec2.DeleteRouteTableInput{RouteTableId: id})
	case kindRTAssoc:
		_, err = c.DisassociateRouteTable(ctx, &ec2.DisassociateRouteTableInput{AssociationId: id})
	case kindSG:
		_, err = c.DeleteSecurityGroup(ctx, &ec2.DeleteSecurityGroupInput{GroupId: id})
	case kindNACL:
		_, err = c.DeleteNetworkAcl(ctx, &ec2.DeleteNetworkAclInput{NetworkAclId: id})
	case kindNACLAssoc:
		_, err = c.ReplaceNetworkAclAssociation(ctx, &ec2.ReplaceNetworkAclAssociationInput{AssociationId: id, NetworkAclId: aws.String(r.Ref)})
	case kindInstance:
		_, err = c.TerminateInstances(ctx, &ec2.TerminateInstancesInput{InstanceIds: []string{r.ID}})
	case kindEIP:
		_, err = c.ReleaseAddress(ctx, &ec2.ReleaseAddressInput{AllocationId: id})
	case kindEIPAssoc:
		_, err = c.DisassociateAddress(ctx, &ec2.DisassociateAddressInput{AssociationId: id})
	default:
		err = fmt.Errorf("unknown kind")
	}
	return err
}
