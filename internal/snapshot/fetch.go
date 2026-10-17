package snapshot

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// EC2API is the subset of the EC2 client used by Fetch.
type EC2API interface {
	ec2.DescribeVpcsAPIClient
	ec2.DescribeSubnetsAPIClient
	ec2.DescribeRouteTablesAPIClient
	ec2.DescribeNetworkAclsAPIClient
	ec2.DescribeSecurityGroupsAPIClient
	ec2.DescribeNetworkInterfacesAPIClient
	ec2.DescribeInstancesAPIClient
	ec2.DescribeInternetGatewaysAPIClient
	ec2.DescribeNatGatewaysAPIClient
	ec2.DescribeVpcPeeringConnectionsAPIClient
	ec2.DescribeManagedPrefixListsAPIClient
	ec2.GetManagedPrefixListEntriesAPIClient
	ec2.DescribeTransitGatewaysAPIClient
	ec2.DescribeTransitGatewayVpcAttachmentsAPIClient
	ec2.DescribeTransitGatewayAttachmentsAPIClient
	ec2.DescribeTransitGatewayRouteTablesAPIClient
	ec2.GetTransitGatewayRouteTablePropagationsAPIClient
	SearchTransitGatewayRoutes(context.Context, *ec2.SearchTransitGatewayRoutesInput, ...func(*ec2.Options)) (*ec2.SearchTransitGatewayRoutesOutput, error)
	DescribeAddresses(context.Context, *ec2.DescribeAddressesInput, ...func(*ec2.Options)) (*ec2.DescribeAddressesOutput, error)
}

type pager[O any] interface {
	HasMorePages() bool
	NextPage(context.Context, ...func(*ec2.Options)) (O, error)
}

func collect[O, T any](ctx context.Context, p pager[O], items func(O) []T) ([]T, error) {
	var out []T
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		out = append(out, items(page)...)
	}
	return out, nil
}

// Fetch reads the full networking state from the EC2 API.
func Fetch(ctx context.Context, c EC2API) (*Snapshot, error) {
	s := &Snapshot{}
	steps := []struct {
		name string
		fn   func(context.Context, EC2API, *Snapshot) error
	}{
		{"vpcs", fetchVPCs},
		{"subnets", fetchSubnets},
		{"route tables", fetchRouteTables},
		{"network acls", fetchNetworkACLs},
		{"security groups", fetchSecurityGroups},
		{"network interfaces", fetchENIs},
		{"instances", fetchInstances},
		{"internet gateways", fetchIGWs},
		{"nat gateways", fetchNATGateways},
		{"elastic ips", fetchElasticIPs},
		{"peering connections", fetchPeerings},
		{"prefix lists", fetchPrefixLists},
		{"transit gateways", fetchTransitGateways},
	}
	for _, st := range steps {
		if err := st.fn(ctx, c, s); err != nil {
			return nil, fmt.Errorf("fetch %s: %w", st.name, err)
		}
	}
	return s, nil
}

func fetchVPCs(ctx context.Context, c EC2API, s *Snapshot) error {
	vpcs, err := collect(ctx, ec2.NewDescribeVpcsPaginator(c, &ec2.DescribeVpcsInput{}),
		func(o *ec2.DescribeVpcsOutput) []types.Vpc { return o.Vpcs })
	if err != nil {
		return err
	}
	for _, v := range vpcs {
		cidrs := []string{aws.ToString(v.CidrBlock)}
		for _, a := range v.CidrBlockAssociationSet {
			cidr := aws.ToString(a.CidrBlock)
			if cidr == cidrs[0] || !cidrActive(a.CidrBlockState) {
				continue
			}
			cidrs = append(cidrs, cidr)
		}
		s.VPCs = append(s.VPCs, VPC{ID: aws.ToString(v.VpcId), CIDRs: cidrs})
	}
	sortByID(s.VPCs, func(v VPC) string { return v.ID })
	return nil
}

func cidrActive(st *types.VpcCidrBlockState) bool {
	return st == nil || st.State == "" || st.State == types.VpcCidrBlockStateCodeAssociated
}

func fetchSubnets(ctx context.Context, c EC2API, s *Snapshot) error {
	subnets, err := collect(ctx, ec2.NewDescribeSubnetsPaginator(c, &ec2.DescribeSubnetsInput{}),
		func(o *ec2.DescribeSubnetsOutput) []types.Subnet { return o.Subnets })
	if err != nil {
		return err
	}
	for _, sn := range subnets {
		s.Subnets = append(s.Subnets, Subnet{
			ID:                  aws.ToString(sn.SubnetId),
			VPCID:               aws.ToString(sn.VpcId),
			CIDR:                aws.ToString(sn.CidrBlock),
			AZ:                  aws.ToString(sn.AvailabilityZone),
			MapPublicIPOnLaunch: aws.ToBool(sn.MapPublicIpOnLaunch),
		})
	}
	sortByID(s.Subnets, func(v Subnet) string { return v.ID })
	return nil
}

func fetchRouteTables(ctx context.Context, c EC2API, s *Snapshot) error {
	rts, err := collect(ctx, ec2.NewDescribeRouteTablesPaginator(c, &ec2.DescribeRouteTablesInput{}),
		func(o *ec2.DescribeRouteTablesOutput) []types.RouteTable { return o.RouteTables })
	if err != nil {
		return err
	}
	for _, rt := range rts {
		out := RouteTable{ID: aws.ToString(rt.RouteTableId), VPCID: aws.ToString(rt.VpcId)}
		for _, a := range rt.Associations {
			if aws.ToBool(a.Main) {
				out.Main = true
			}
			if id := aws.ToString(a.SubnetId); id != "" {
				out.Subnets = append(out.Subnets, id)
			}
		}
		for _, r := range rt.Routes {
			if r.DestinationIpv6CidrBlock != nil && r.DestinationCidrBlock == nil && r.DestinationPrefixListId == nil {
				continue // IPv6 is out of scope for now
			}
			kind, id := routeTarget(r)
			out.Routes = append(out.Routes, Route{
				DestinationCIDR:       aws.ToString(r.DestinationCidrBlock),
				DestinationPrefixList: aws.ToString(r.DestinationPrefixListId),
				TargetKind:            kind,
				TargetID:              id,
				Blackhole:             r.State == types.RouteStateBlackhole,
			})
		}
		slices.Sort(out.Subnets)
		s.RouteTables = append(s.RouteTables, out)
	}
	sortByID(s.RouteTables, func(v RouteTable) string { return v.ID })
	return nil
}

func routeTarget(r types.Route) (TargetKind, string) {
	switch {
	case aws.ToString(r.GatewayId) == "local":
		return TargetLocal, ""
	case r.NatGatewayId != nil:
		return TargetNAT, *r.NatGatewayId
	case r.VpcPeeringConnectionId != nil:
		return TargetPeering, *r.VpcPeeringConnectionId
	case r.TransitGatewayId != nil:
		return TargetTGW, *r.TransitGatewayId
	case r.InstanceId != nil:
		return TargetInstance, *r.InstanceId
	case r.NetworkInterfaceId != nil:
		return TargetENI, *r.NetworkInterfaceId
	case strings.HasPrefix(aws.ToString(r.GatewayId), "igw-"):
		return TargetIGW, *r.GatewayId
	case strings.HasPrefix(aws.ToString(r.GatewayId), "vpce-"):
		return TargetEndpoint, *r.GatewayId
	}
	return TargetUnknown, aws.ToString(r.GatewayId)
}

func fetchNetworkACLs(ctx context.Context, c EC2API, s *Snapshot) error {
	acls, err := collect(ctx, ec2.NewDescribeNetworkAclsPaginator(c, &ec2.DescribeNetworkAclsInput{}),
		func(o *ec2.DescribeNetworkAclsOutput) []types.NetworkAcl { return o.NetworkAcls })
	if err != nil {
		return err
	}
	for _, a := range acls {
		out := NetworkACL{ID: aws.ToString(a.NetworkAclId), VPCID: aws.ToString(a.VpcId), Default: aws.ToBool(a.IsDefault)}
		for _, as := range a.Associations {
			if id := aws.ToString(as.SubnetId); id != "" {
				out.Subnets = append(out.Subnets, id)
			}
		}
		for _, e := range a.Entries {
			if e.CidrBlock == nil {
				continue // IPv6 entry
			}
			entry := ACLEntry{
				RuleNumber: aws.ToInt32(e.RuleNumber),
				Egress:     aws.ToBool(e.Egress),
				Allow:      e.RuleAction == types.RuleActionAllow,
				Protocol:   aws.ToString(e.Protocol),
				CIDR:       *e.CidrBlock,
			}
			if e.PortRange != nil {
				entry.FromPort, entry.ToPort = aws.ToInt32(e.PortRange.From), aws.ToInt32(e.PortRange.To)
			}
			if e.IcmpTypeCode != nil {
				entry.ICMPType, entry.ICMPCode = e.IcmpTypeCode.Type, e.IcmpTypeCode.Code
			}
			out.Entries = append(out.Entries, entry)
		}
		slices.Sort(out.Subnets)
		slices.SortFunc(out.Entries, func(x, y ACLEntry) int {
			if x.Egress != y.Egress {
				if x.Egress {
					return 1
				}
				return -1
			}
			return int(x.RuleNumber - y.RuleNumber)
		})
		s.NetworkACLs = append(s.NetworkACLs, out)
	}
	sortByID(s.NetworkACLs, func(v NetworkACL) string { return v.ID })
	return nil
}

func fetchSecurityGroups(ctx context.Context, c EC2API, s *Snapshot) error {
	sgs, err := collect(ctx, ec2.NewDescribeSecurityGroupsPaginator(c, &ec2.DescribeSecurityGroupsInput{}),
		func(o *ec2.DescribeSecurityGroupsOutput) []types.SecurityGroup { return o.SecurityGroups })
	if err != nil {
		return err
	}
	for _, g := range sgs {
		s.SecurityGroups = append(s.SecurityGroups, SecurityGroup{
			ID:      aws.ToString(g.GroupId),
			VPCID:   aws.ToString(g.VpcId),
			Ingress: sgRules(g.IpPermissions),
			Egress:  sgRules(g.IpPermissionsEgress),
		})
	}
	sortByID(s.SecurityGroups, func(v SecurityGroup) string { return v.ID })
	return nil
}

func sgRules(perms []types.IpPermission) []SGRule {
	var out []SGRule
	for _, p := range perms {
		r := SGRule{
			Protocol: aws.ToString(p.IpProtocol),
			FromPort: aws.ToInt32(p.FromPort),
			ToPort:   aws.ToInt32(p.ToPort),
		}
		for _, ip := range p.IpRanges {
			r.CIDRs = append(r.CIDRs, aws.ToString(ip.CidrIp))
		}
		for _, pl := range p.PrefixListIds {
			r.PrefixLists = append(r.PrefixLists, aws.ToString(pl.PrefixListId))
		}
		for _, g := range p.UserIdGroupPairs {
			r.Groups = append(r.Groups, aws.ToString(g.GroupId))
		}
		if len(r.CIDRs)+len(r.PrefixLists)+len(r.Groups) == 0 {
			continue // IPv6-only rule
		}
		out = append(out, r)
	}
	return out
}

func fetchENIs(ctx context.Context, c EC2API, s *Snapshot) error {
	enis, err := collect(ctx, ec2.NewDescribeNetworkInterfacesPaginator(c, &ec2.DescribeNetworkInterfacesInput{}),
		func(o *ec2.DescribeNetworkInterfacesOutput) []types.NetworkInterface { return o.NetworkInterfaces })
	if err != nil {
		return err
	}
	for _, n := range enis {
		out := ENI{
			ID:              aws.ToString(n.NetworkInterfaceId),
			SubnetID:        aws.ToString(n.SubnetId),
			VPCID:           aws.ToString(n.VpcId),
			MAC:             aws.ToString(n.MacAddress),
			SourceDestCheck: n.SourceDestCheck == nil || *n.SourceDestCheck,
			Type:            string(n.InterfaceType),
		}
		primary := aws.ToString(n.PrivateIpAddress)
		out.PrivateIPs = append(out.PrivateIPs, primary)
		for _, ip := range n.PrivateIpAddresses {
			if addr := aws.ToString(ip.PrivateIpAddress); addr != "" && addr != primary {
				out.PrivateIPs = append(out.PrivateIPs, addr)
			}
		}
		if n.Association != nil {
			out.PublicIP = aws.ToString(n.Association.PublicIp)
		}
		for _, g := range n.Groups {
			out.Groups = append(out.Groups, aws.ToString(g.GroupId))
		}
		slices.Sort(out.Groups)
		if n.Attachment != nil {
			out.InstanceID = aws.ToString(n.Attachment.InstanceId)
			out.DeviceIndex = aws.ToInt32(n.Attachment.DeviceIndex)
		}
		s.ENIs = append(s.ENIs, out)
	}
	sortByID(s.ENIs, func(v ENI) string { return v.ID })
	return nil
}

func fetchInstances(ctx context.Context, c EC2API, s *Snapshot) error {
	res, err := collect(ctx, ec2.NewDescribeInstancesPaginator(c, &ec2.DescribeInstancesInput{}),
		func(o *ec2.DescribeInstancesOutput) []types.Reservation { return o.Reservations })
	if err != nil {
		return err
	}
	for _, r := range res {
		for _, i := range r.Instances {
			out := Instance{
				ID:              aws.ToString(i.InstanceId),
				ImageID:         aws.ToString(i.ImageId),
				Type:            string(i.InstanceType),
				SubnetID:        aws.ToString(i.SubnetId),
				VPCID:           aws.ToString(i.VpcId),
				Metadata:        MetadataOptions{Endpoint: true, HopLimit: 1},
				SourceDestCheck: i.SourceDestCheck == nil || *i.SourceDestCheck,
			}
			if i.State != nil {
				out.State = string(i.State.Name)
			}
			for _, t := range i.Tags {
				if aws.ToString(t.Key) == "Name" {
					out.Name = aws.ToString(t.Value)
				}
			}
			for _, n := range i.NetworkInterfaces {
				out.ENIs = append(out.ENIs, aws.ToString(n.NetworkInterfaceId))
			}
			if m := i.MetadataOptions; m != nil {
				out.Metadata.Endpoint = m.HttpEndpoint != types.InstanceMetadataEndpointStateDisabled
				out.Metadata.TokensRequired = m.HttpTokens == types.HttpTokensStateRequired
				if m.HttpPutResponseHopLimit != nil {
					out.Metadata.HopLimit = *m.HttpPutResponseHopLimit
				}
			}
			s.Instances = append(s.Instances, out)
		}
	}
	sortByID(s.Instances, func(v Instance) string { return v.ID })
	return nil
}

func fetchIGWs(ctx context.Context, c EC2API, s *Snapshot) error {
	igws, err := collect(ctx, ec2.NewDescribeInternetGatewaysPaginator(c, &ec2.DescribeInternetGatewaysInput{}),
		func(o *ec2.DescribeInternetGatewaysOutput) []types.InternetGateway { return o.InternetGateways })
	if err != nil {
		return err
	}
	for _, g := range igws {
		out := IGW{ID: aws.ToString(g.InternetGatewayId)}
		for _, a := range g.Attachments {
			// Floci may report "available" for attached IGWs, as AWS does.
			if a.State == types.AttachmentStatusAttached || a.State == "available" {
				out.VPCID = aws.ToString(a.VpcId)
			}
		}
		s.IGWs = append(s.IGWs, out)
	}
	sortByID(s.IGWs, func(v IGW) string { return v.ID })
	return nil
}

func fetchNATGateways(ctx context.Context, c EC2API, s *Snapshot) error {
	nats, err := collect(ctx, ec2.NewDescribeNatGatewaysPaginator(c, &ec2.DescribeNatGatewaysInput{}),
		func(o *ec2.DescribeNatGatewaysOutput) []types.NatGateway { return o.NatGateways })
	if err != nil {
		return err
	}
	for _, n := range nats {
		if n.State == types.NatGatewayStateDeleted || n.State == types.NatGatewayStateDeleting {
			continue
		}
		out := NATGateway{
			ID:       aws.ToString(n.NatGatewayId),
			SubnetID: aws.ToString(n.SubnetId),
			VPCID:    aws.ToString(n.VpcId),
			State:    string(n.State),
			Public:   n.ConnectivityType != types.ConnectivityTypePrivate,
		}
		if len(n.NatGatewayAddresses) > 0 {
			a := n.NatGatewayAddresses[0]
			out.ENIID = aws.ToString(a.NetworkInterfaceId)
			out.Private = aws.ToString(a.PrivateIp)
			out.PublicIP = aws.ToString(a.PublicIp)
		}
		s.NATGateways = append(s.NATGateways, out)
	}
	sortByID(s.NATGateways, func(v NATGateway) string { return v.ID })
	return nil
}

func fetchElasticIPs(ctx context.Context, c EC2API, s *Snapshot) error {
	out, err := c.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{})
	if err != nil {
		return err
	}
	for _, a := range out.Addresses {
		s.ElasticIPs = append(s.ElasticIPs, ElasticIP{
			AllocationID: aws.ToString(a.AllocationId),
			PublicIP:     aws.ToString(a.PublicIp),
			ENIID:        aws.ToString(a.NetworkInterfaceId),
			PrivateIP:    aws.ToString(a.PrivateIpAddress),
		})
	}
	sortByID(s.ElasticIPs, func(v ElasticIP) string { return v.AllocationID })
	return nil
}

func fetchPeerings(ctx context.Context, c EC2API, s *Snapshot) error {
	pcxs, err := collect(ctx, ec2.NewDescribeVpcPeeringConnectionsPaginator(c, &ec2.DescribeVpcPeeringConnectionsInput{}),
		func(o *ec2.DescribeVpcPeeringConnectionsOutput) []types.VpcPeeringConnection {
			return o.VpcPeeringConnections
		})
	if err != nil {
		return err
	}
	for _, p := range pcxs {
		out := Peering{ID: aws.ToString(p.VpcPeeringConnectionId)}
		if p.Status != nil {
			out.Status = string(p.Status.Code)
		}
		if p.RequesterVpcInfo != nil {
			out.RequesterVPCID = aws.ToString(p.RequesterVpcInfo.VpcId)
			out.RequesterCIDRs = peerCIDRs(p.RequesterVpcInfo)
		}
		if p.AccepterVpcInfo != nil {
			out.AccepterVPCID = aws.ToString(p.AccepterVpcInfo.VpcId)
			out.AccepterCIDRs = peerCIDRs(p.AccepterVpcInfo)
		}
		s.Peerings = append(s.Peerings, out)
	}
	sortByID(s.Peerings, func(v Peering) string { return v.ID })
	return nil
}

func peerCIDRs(info *types.VpcPeeringConnectionVpcInfo) []string {
	var out []string
	for _, c := range info.CidrBlockSet {
		out = append(out, aws.ToString(c.CidrBlock))
	}
	if len(out) == 0 && info.CidrBlock != nil {
		out = append(out, *info.CidrBlock)
	}
	return out
}

func fetchPrefixLists(ctx context.Context, c EC2API, s *Snapshot) error {
	pls, err := collect(ctx, ec2.NewDescribeManagedPrefixListsPaginator(c, &ec2.DescribeManagedPrefixListsInput{}),
		func(o *ec2.DescribeManagedPrefixListsOutput) []types.ManagedPrefixList { return o.PrefixLists })
	if err != nil {
		return err
	}
	for _, pl := range pls {
		if pl.AddressFamily != nil && *pl.AddressFamily != "IPv4" {
			continue
		}
		entries, err := collect(ctx,
			ec2.NewGetManagedPrefixListEntriesPaginator(c, &ec2.GetManagedPrefixListEntriesInput{PrefixListId: pl.PrefixListId}),
			func(o *ec2.GetManagedPrefixListEntriesOutput) []types.PrefixListEntry { return o.Entries })
		if err != nil {
			return fmt.Errorf("%s entries: %w", aws.ToString(pl.PrefixListId), err)
		}
		out := PrefixList{ID: aws.ToString(pl.PrefixListId), Name: aws.ToString(pl.PrefixListName)}
		for _, e := range entries {
			out.CIDRs = append(out.CIDRs, aws.ToString(e.Cidr))
		}
		slices.Sort(out.CIDRs)
		s.PrefixLists = append(s.PrefixLists, out)
	}
	sortByID(s.PrefixLists, func(v PrefixList) string { return v.ID })
	return nil
}

// fetchTransitGateways reads transit gateways, their VPC attachments and
// route tables. Only static routes are read; the planner computes the
// propagated ones, because Floci does not create the default propagations.
func fetchTransitGateways(ctx context.Context, c EC2API, s *Snapshot) error {
	tgws, err := collect(ctx, ec2.NewDescribeTransitGatewaysPaginator(c, &ec2.DescribeTransitGatewaysInput{}),
		func(o *ec2.DescribeTransitGatewaysOutput) []types.TransitGateway { return o.TransitGateways })
	if err != nil {
		return err
	}
	for _, g := range tgws {
		if g.State == types.TransitGatewayStateDeleted || g.State == types.TransitGatewayStateDeleting {
			continue
		}
		out := TransitGateway{ID: aws.ToString(g.TransitGatewayId), State: string(g.State)}
		if o := g.Options; o != nil {
			out.DefaultPropagation = o.DefaultRouteTablePropagation == types.DefaultRouteTablePropagationValueEnable
			out.DefaultPropagationRT = aws.ToString(o.PropagationDefaultRouteTableId)
		}
		s.TransitGateways = append(s.TransitGateways, out)
	}
	sortByID(s.TransitGateways, func(v TransitGateway) string { return v.ID })

	vpcAtts, err := collect(ctx, ec2.NewDescribeTransitGatewayVpcAttachmentsPaginator(c, &ec2.DescribeTransitGatewayVpcAttachmentsInput{}),
		func(o *ec2.DescribeTransitGatewayVpcAttachmentsOutput) []types.TransitGatewayVpcAttachment {
			return o.TransitGatewayVpcAttachments
		})
	if err != nil {
		return err
	}
	// The association is only in DescribeTransitGatewayAttachments.
	atts, err := collect(ctx, ec2.NewDescribeTransitGatewayAttachmentsPaginator(c, &ec2.DescribeTransitGatewayAttachmentsInput{}),
		func(o *ec2.DescribeTransitGatewayAttachmentsOutput) []types.TransitGatewayAttachment {
			return o.TransitGatewayAttachments
		})
	if err != nil {
		return err
	}
	assoc := map[string]string{}
	for _, a := range atts {
		if as := a.Association; as != nil && (as.State == types.TransitGatewayAssociationStateAssociated ||
			as.State == types.TransitGatewayAssociationStateAssociating) {
			assoc[aws.ToString(a.TransitGatewayAttachmentId)] = aws.ToString(as.TransitGatewayRouteTableId)
		}
	}
	for _, a := range vpcAtts {
		if a.State == types.TransitGatewayAttachmentStateDeleted || a.State == types.TransitGatewayAttachmentStateDeleting {
			continue
		}
		id := aws.ToString(a.TransitGatewayAttachmentId)
		out := TGWAttachment{
			ID:         id,
			TGWID:      aws.ToString(a.TransitGatewayId),
			VPCID:      aws.ToString(a.VpcId),
			State:      string(a.State),
			SubnetIDs:  slices.Sorted(slices.Values(a.SubnetIds)),
			RouteTable: assoc[id],
		}
		s.TGWAttachments = append(s.TGWAttachments, out)
	}
	sortByID(s.TGWAttachments, func(v TGWAttachment) string { return v.ID })

	rts, err := collect(ctx, ec2.NewDescribeTransitGatewayRouteTablesPaginator(c, &ec2.DescribeTransitGatewayRouteTablesInput{}),
		func(o *ec2.DescribeTransitGatewayRouteTablesOutput) []types.TransitGatewayRouteTable {
			return o.TransitGatewayRouteTables
		})
	if err != nil {
		return err
	}
	for _, rt := range rts {
		if rt.State == types.TransitGatewayRouteTableStateDeleted || rt.State == types.TransitGatewayRouteTableStateDeleting {
			continue
		}
		id := aws.ToString(rt.TransitGatewayRouteTableId)
		out := TGWRouteTable{ID: id, TGWID: aws.ToString(rt.TransitGatewayId)}
		props, err := collect(ctx,
			ec2.NewGetTransitGatewayRouteTablePropagationsPaginator(c, &ec2.GetTransitGatewayRouteTablePropagationsInput{TransitGatewayRouteTableId: &id}),
			func(o *ec2.GetTransitGatewayRouteTablePropagationsOutput) []types.TransitGatewayRouteTablePropagation {
				return o.TransitGatewayRouteTablePropagations
			})
		if err != nil {
			return fmt.Errorf("%s propagations: %w", id, err)
		}
		for _, p := range props {
			if p.State == types.TransitGatewayPropagationStateEnabled || p.State == types.TransitGatewayPropagationStateEnabling {
				out.Propagations = append(out.Propagations, aws.ToString(p.TransitGatewayAttachmentId))
			}
		}
		slices.Sort(out.Propagations)
		routes, err := c.SearchTransitGatewayRoutes(ctx, &ec2.SearchTransitGatewayRoutesInput{
			TransitGatewayRouteTableId: &id,
			Filters:                    []types.Filter{{Name: aws.String("state"), Values: []string{"active", "blackhole"}}},
		})
		if err != nil {
			return fmt.Errorf("%s routes: %w", id, err)
		}
		for _, r := range routes.Routes {
			if r.Type != types.TransitGatewayRouteTypeStatic || r.DestinationCidrBlock == nil {
				continue // propagated routes are computed; prefix-list routes are not simulated
			}
			out.Routes = append(out.Routes, TGWRoute{
				DestinationCIDR: *r.DestinationCidrBlock,
				AttachmentID:    tgwRouteAttachment(r),
				Blackhole:       r.State == types.TransitGatewayRouteStateBlackhole,
			})
		}
		slices.SortFunc(out.Routes, func(a, b TGWRoute) int { return strings.Compare(a.DestinationCIDR, b.DestinationCIDR) })
		s.TGWRouteTables = append(s.TGWRouteTables, out)
	}
	sortByID(s.TGWRouteTables, func(v TGWRouteTable) string { return v.ID })
	return nil
}

func tgwRouteAttachment(r types.TransitGatewayRoute) string {
	if len(r.TransitGatewayAttachments) > 0 {
		return aws.ToString(r.TransitGatewayAttachments[0].TransitGatewayAttachmentId)
	}
	return ""
}

func sortByID[T any](s []T, id func(T) string) {
	slices.SortFunc(s, func(a, b T) int { return strings.Compare(id(a), id(b)) })
}
