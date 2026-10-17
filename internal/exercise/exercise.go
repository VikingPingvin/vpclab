// Package exercise loads exercise definitions, creates their starting state
// in Floci, checks the learner's solution with real traffic and removes the
// resources again.
//
// An exercise lives in exercises/<name>/exercise.yaml. It declares a broken
// AWS setup (resources) and the traffic that must or must not work once the
// learner has fixed it (checks).
package exercise

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/VikingPingvin/vpclab/internal/plan"
)

type Exercise struct {
	Name      string    `yaml:"-"` // directory name
	Title     string    `yaml:"title"`
	Summary   string    `yaml:"summary"`
	Task      string    `yaml:"task"`
	Hints     []string  `yaml:"hints"`
	Resources Resources `yaml:"resources"`
	Checks    []Check   `yaml:"checks"`
}

// Resources are created in the order of the fields below. Every resource has
// a name that is unique within the exercise; other resources and checks
// refer to it by that name.
type Resources struct {
	VPCs             []VPC           `yaml:"vpcs"`
	Subnets          []Subnet        `yaml:"subnets"`
	InternetGateways []IGW           `yaml:"internetGateways"`
	RouteTables      []RouteTable    `yaml:"routeTables"`
	SecurityGroups   []SecurityGroup `yaml:"securityGroups"`
	NetworkACLs      []NetworkACL    `yaml:"networkAcls"`
	Instances        []Instance      `yaml:"instances"`
}

type VPC struct {
	Name string `yaml:"name"`
	CIDR string `yaml:"cidr"`
}

type Subnet struct {
	Name string `yaml:"name"`
	VPC  string `yaml:"vpc"`
	CIDR string `yaml:"cidr"`
}

// IGW is an internet gateway, attached to its VPC.
type IGW struct {
	Name string `yaml:"name"`
	VPC  string `yaml:"vpc"`
}

type RouteTable struct {
	Name    string   `yaml:"name"`
	VPC     string   `yaml:"vpc"`
	Routes  []Route  `yaml:"routes"`
	Subnets []string `yaml:"subnets"` // explicit associations
}

type Route struct {
	Destination string `yaml:"destination"`
	Gateway     string `yaml:"gateway"` // name of an internet gateway
}

// SecurityGroup keeps AWS's default egress rule (all traffic).
type SecurityGroup struct {
	Name    string   `yaml:"name"`
	VPC     string   `yaml:"vpc"`
	Ingress []SGRule `yaml:"ingress"`
}

// SGRule allows traffic from a CIDR or from members of a security group.
type SGRule struct {
	Protocol string `yaml:"protocol"` // tcp, udp, icmp or all
	Ports    string `yaml:"ports"`    // "80" or "1024-65535"; empty for icmp and all
	CIDR     string `yaml:"cidr"`
	Group    string `yaml:"group"`
}

// NetworkACL replaces the default ACL of its subnets.
type NetworkACL struct {
	Name    string     `yaml:"name"`
	VPC     string     `yaml:"vpc"`
	Subnets []string   `yaml:"subnets"`
	Entries []ACLEntry `yaml:"entries"`
}

type ACLEntry struct {
	Rule      int32  `yaml:"rule"`
	Direction string `yaml:"direction"` // inbound or outbound
	Action    string `yaml:"action"`    // allow or deny
	Protocol  string `yaml:"protocol"`  // tcp, udp or all
	Ports     string `yaml:"ports"`
	CIDR      string `yaml:"cidr"`
}

type Instance struct {
	Name           string   `yaml:"name"`
	Subnet         string   `yaml:"subnet"`
	SecurityGroups []string `yaml:"securityGroups"`
	ElasticIP      bool     `yaml:"elasticIp"`
}

// Check is a TCP connection that must succeed (open) or fail (closed).
//
// From is an instance name or an internet host (operator, echo). To is an
// instance name, <instance>.public for its public IPv4, or an internet host.
// Before the check, the runner starts a listener on the port of a target
// instance, so "closed" always means the network blocks the connection.
type Check struct {
	Name   string `yaml:"name"`
	From   string `yaml:"from"`
	To     string `yaml:"to"`
	Port   int    `yaml:"port"`
	Expect string `yaml:"expect"` // open or closed
}

const publicSuffix = ".public"

// Load reads exercises/<name>/exercise.yaml below dir and validates it.
func Load(dir, name string) (*Exercise, error) {
	data, err := os.ReadFile(filepath.Join(dir, name, "exercise.yaml"))
	if err != nil {
		return nil, err
	}
	ex := &Exercise{Name: name}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(ex); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	if err := ex.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}
	return ex, nil
}

// LoadAll loads every exercise below dir, sorted by name.
func LoadAll(dir string) ([]*Exercise, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []*Exercise
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		ex, err := Load(dir, e.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, ex)
	}
	return out, nil
}

// Validate checks that every reference resolves and every value parses, so
// that Start does not fail halfway through.
func (ex *Exercise) Validate() error {
	if ex.Title == "" || ex.Task == "" {
		return fmt.Errorf("title and task are required")
	}
	kinds := map[string]string{} // name -> kind
	var errs []string
	fail := func(format string, args ...any) { errs = append(errs, fmt.Sprintf(format, args...)) }
	define := func(kind, name string) {
		switch {
		case name == "":
			fail("a %s has no name", kind)
		case name == plan.OperatorName || name == plan.EchoName || strings.Contains(name, "."):
			fail("%s name %q is reserved or contains a dot", kind, name)
		case kinds[name] != "":
			fail("name %q is used twice", name)
		default:
			kinds[name] = kind
		}
	}
	ref := func(owner, kind, name string) {
		if kinds[name] != kind {
			fail("%s: %q is not a %s", owner, name, kind)
		}
	}
	cidr := func(owner, s string) {
		if _, err := netip.ParsePrefix(s); err != nil {
			fail("%s: bad CIDR %q", owner, s)
		}
	}

	r := ex.Resources
	for _, v := range r.VPCs {
		define("vpc", v.Name)
		cidr(v.Name, v.CIDR)
	}
	for _, s := range r.Subnets {
		define("subnet", s.Name)
		ref(s.Name, "vpc", s.VPC)
		cidr(s.Name, s.CIDR)
	}
	for _, g := range r.InternetGateways {
		define("internet gateway", g.Name)
		ref(g.Name, "vpc", g.VPC)
	}
	for _, rt := range r.RouteTables {
		define("route table", rt.Name)
		ref(rt.Name, "vpc", rt.VPC)
		for _, rte := range rt.Routes {
			cidr(rt.Name, rte.Destination)
			ref(rt.Name, "internet gateway", rte.Gateway)
		}
		for _, sn := range rt.Subnets {
			ref(rt.Name, "subnet", sn)
		}
	}
	for _, sg := range r.SecurityGroups {
		define("security group", sg.Name)
	}
	for _, sg := range r.SecurityGroups {
		ref(sg.Name, "vpc", sg.VPC)
		for _, rule := range sg.Ingress {
			if _, _, err := parsePorts(rule.Protocol, rule.Ports); err != nil {
				fail("%s: %v", sg.Name, err)
			}
			switch {
			case (rule.CIDR == "") == (rule.Group == ""):
				fail("%s: a rule needs exactly one of cidr and group", sg.Name)
			case rule.CIDR != "":
				cidr(sg.Name, rule.CIDR)
			default:
				ref(sg.Name, "security group", rule.Group)
			}
		}
	}
	for _, acl := range r.NetworkACLs {
		define("network ACL", acl.Name)
		ref(acl.Name, "vpc", acl.VPC)
		for _, sn := range acl.Subnets {
			ref(acl.Name, "subnet", sn)
		}
		for _, e := range acl.Entries {
			if e.Rule < 1 || e.Rule > 32766 {
				fail("%s: rule number %d is outside 1-32766", acl.Name, e.Rule)
			}
			if e.Direction != "inbound" && e.Direction != "outbound" {
				fail("%s rule %d: direction must be inbound or outbound", acl.Name, e.Rule)
			}
			if e.Action != "allow" && e.Action != "deny" {
				fail("%s rule %d: action must be allow or deny", acl.Name, e.Rule)
			}
			if _, _, err := parsePorts(e.Protocol, e.Ports); err != nil {
				fail("%s rule %d: %v", acl.Name, e.Rule, err)
			}
			cidr(acl.Name, e.CIDR)
		}
	}
	for _, in := range r.Instances {
		define("instance", in.Name)
		ref(in.Name, "subnet", in.Subnet)
		for _, sg := range in.SecurityGroups {
			ref(in.Name, "security group", sg)
		}
	}

	if len(ex.Checks) == 0 {
		fail("no checks")
	}
	for _, c := range ex.Checks {
		if c.Name == "" {
			fail("a check has no name")
		}
		if c.From != plan.OperatorName && c.From != plan.EchoName && kinds[c.From] != "instance" {
			fail("check %q: from %q is not an instance or internet host", c.Name, c.From)
		}
		to := strings.TrimSuffix(c.To, publicSuffix)
		if c.To != plan.OperatorName && c.To != plan.EchoName && kinds[to] != "instance" {
			fail("check %q: to %q is not an instance, <instance>.public or internet host", c.Name, c.To)
		}
		if c.Port < 1 || c.Port > 65535 {
			fail("check %q: bad port %d", c.Name, c.Port)
		}
		if c.Expect != "open" && c.Expect != "closed" {
			fail("check %q: expect must be open or closed", c.Name)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("invalid exercise:\n  %s", strings.Join(errs, "\n  "))
	}
	return nil
}

// protocolNumber maps a protocol name to the IANA number the EC2 API uses
// in NACL entries ("-1" for all traffic).
func protocolNumber(p string) string {
	switch p {
	case "tcp":
		return "6"
	case "udp":
		return "17"
	case "icmp":
		return "1"
	}
	return "-1"
}

// parsePorts parses "80" or "1024-65535". Protocols without ports (icmp, all)
// must leave ports empty and get -1, -1.
func parsePorts(protocol, ports string) (int32, int32, error) {
	if !slices.Contains([]string{"tcp", "udp", "icmp", "all"}, protocol) {
		return 0, 0, fmt.Errorf("protocol %q is not tcp, udp, icmp or all", protocol)
	}
	if protocol == "icmp" || protocol == "all" {
		if ports != "" {
			return 0, 0, fmt.Errorf("protocol %s takes no ports", protocol)
		}
		return -1, -1, nil
	}
	lo, hi, found := strings.Cut(ports, "-")
	if !found {
		hi = lo
	}
	from, err1 := strconv.Atoi(lo)
	to, err2 := strconv.Atoi(hi)
	if err1 != nil || err2 != nil || from < 0 || to > 65535 || from > to {
		return 0, 0, fmt.Errorf("bad port range %q", ports)
	}
	return int32(from), int32(to), nil
}
