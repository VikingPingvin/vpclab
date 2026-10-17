// Package snapshot reads the AWS networking state from Floci and normalises it
// into a plain, deterministic model that the renderer consumes. Keeping the
// renderer independent of SDK types makes it testable with hand-built fixtures.
package snapshot

// Snapshot is a point-in-time view of every networking resource vpcsim models.
// All slices are sorted by ID so that rendering the same state twice yields
// byte-identical output.
type Snapshot struct {
	VPCs           []VPC           `json:"vpcs"`
	Subnets        []Subnet        `json:"subnets"`
	RouteTables    []RouteTable    `json:"routeTables"`
	NetworkACLs    []NetworkACL    `json:"networkAcls"`
	SecurityGroups []SecurityGroup `json:"securityGroups"`
	ENIs           []ENI           `json:"enis"`
	Instances      []Instance      `json:"instances"`
	IGWs           []IGW           `json:"internetGateways"`
	NATGateways    []NATGateway    `json:"natGateways"`
	ElasticIPs     []ElasticIP     `json:"elasticIps"`
	Peerings       []Peering       `json:"peerings"`
	PrefixLists    []PrefixList    `json:"prefixLists"`
}

type VPC struct {
	ID    string   `json:"id"`
	CIDRs []string `json:"cidrs"` // primary first, then associated secondaries
}

type Subnet struct {
	ID                  string `json:"id"`
	VPCID               string `json:"vpcId"`
	CIDR                string `json:"cidr"`
	AZ                  string `json:"az"`
	MapPublicIPOnLaunch bool   `json:"mapPublicIpOnLaunch"`
}

type RouteTable struct {
	ID      string   `json:"id"`
	VPCID   string   `json:"vpcId"`
	Main    bool     `json:"main"`
	Subnets []string `json:"subnets"` // explicit subnet associations
	Routes  []Route  `json:"routes"`
}

// TargetKind identifies where a route sends traffic.
type TargetKind string

const (
	TargetLocal    TargetKind = "local"
	TargetIGW      TargetKind = "igw"
	TargetNAT      TargetKind = "nat"
	TargetPeering  TargetKind = "pcx"
	TargetTGW      TargetKind = "tgw"
	TargetENI      TargetKind = "eni"
	TargetInstance TargetKind = "instance"
	TargetEndpoint TargetKind = "vpce"
	TargetUnknown  TargetKind = "unknown"
)

type Route struct {
	DestinationCIDR       string     `json:"destinationCidr,omitempty"`
	DestinationPrefixList string     `json:"destinationPrefixList,omitempty"`
	TargetKind            TargetKind `json:"targetKind"`
	TargetID              string     `json:"targetId,omitempty"`
	Blackhole             bool       `json:"blackhole"`
}

type NetworkACL struct {
	ID      string     `json:"id"`
	VPCID   string     `json:"vpcId"`
	Default bool       `json:"default"`
	Subnets []string   `json:"subnets"`
	Entries []ACLEntry `json:"entries"` // sorted by Egress, then RuleNumber
}

type ACLEntry struct {
	RuleNumber int32  `json:"ruleNumber"`
	Egress     bool   `json:"egress"`
	Allow      bool   `json:"allow"`
	Protocol   string `json:"protocol"` // "-1" for all, otherwise IANA number as string
	CIDR       string `json:"cidr"`
	FromPort   int32  `json:"fromPort,omitempty"`
	ToPort     int32  `json:"toPort,omitempty"`
	ICMPType   *int32 `json:"icmpType,omitempty"`
	ICMPCode   *int32 `json:"icmpCode,omitempty"`
}

type SecurityGroup struct {
	ID      string   `json:"id"`
	VPCID   string   `json:"vpcId"`
	Ingress []SGRule `json:"ingress"`
	Egress  []SGRule `json:"egress"`
}

// SGRule is one IpPermission. Sources are OR-ed: a packet matches the rule if
// it matches the protocol/port and any of the CIDRs, prefix lists or groups.
type SGRule struct {
	Protocol    string   `json:"protocol"` // "-1", "tcp", "udp", "icmp" or IANA number
	FromPort    int32    `json:"fromPort"`
	ToPort      int32    `json:"toPort"`
	CIDRs       []string `json:"cidrs,omitempty"`
	PrefixLists []string `json:"prefixLists,omitempty"`
	Groups      []string `json:"groups,omitempty"`
}

type ENI struct {
	ID              string   `json:"id"`
	SubnetID        string   `json:"subnetId"`
	VPCID           string   `json:"vpcId"`
	MAC             string   `json:"mac,omitempty"`
	PrivateIPs      []string `json:"privateIps"` // primary first
	PublicIP        string   `json:"publicIp,omitempty"`
	Groups          []string `json:"groups"`
	SourceDestCheck bool     `json:"sourceDestCheck"`
	InstanceID      string   `json:"instanceId,omitempty"`
	DeviceIndex     int32    `json:"deviceIndex"`
	Type            string   `json:"type"` // interface, nat_gateway, ...
}

type Instance struct {
	ID       string          `json:"id"`
	ImageID  string          `json:"imageId"`
	Type     string          `json:"type"`
	State    string          `json:"state"`
	SubnetID string          `json:"subnetId"`
	VPCID    string          `json:"vpcId"`
	ENIs     []string        `json:"enis"`
	Metadata MetadataOptions `json:"metadata"`
	// SourceDestCheck mirrors the primary ENI in AWS. Floci may only update
	// one of the two, so the planner honours a "false" on either.
	SourceDestCheck bool `json:"sourceDestCheck"`
}

type MetadataOptions struct {
	Endpoint       bool  `json:"endpoint"`
	TokensRequired bool  `json:"tokensRequired"`
	HopLimit       int32 `json:"hopLimit"`
}

type IGW struct {
	ID    string `json:"id"`
	VPCID string `json:"vpcId,omitempty"` // empty when detached
}

type NATGateway struct {
	ID       string `json:"id"`
	SubnetID string `json:"subnetId"`
	VPCID    string `json:"vpcId"`
	State    string `json:"state"`
	Public   bool   `json:"public"` // ConnectivityType == public
	ENIID    string `json:"eniId"`
	Private  string `json:"privateIp"`
	PublicIP string `json:"publicIp,omitempty"`
}

type ElasticIP struct {
	AllocationID string `json:"allocationId"`
	PublicIP     string `json:"publicIp"`
	ENIID        string `json:"eniId,omitempty"`
	PrivateIP    string `json:"privateIp,omitempty"`
}

type Peering struct {
	ID             string   `json:"id"`
	Status         string   `json:"status"`
	RequesterVPCID string   `json:"requesterVpcId"`
	RequesterCIDRs []string `json:"requesterCidrs"`
	AccepterVPCID  string   `json:"accepterVpcId"`
	AccepterCIDRs  []string `json:"accepterCidrs"`
}

type PrefixList struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	CIDRs []string `json:"cidrs"`
}
