package exercise

import (
	"strings"
	"testing"
)

func TestAllExercisesAreValid(t *testing.T) {
	all, err := LoadAll("../../exercises")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) < 3 {
		t.Errorf("found %d exercises, want at least 3", len(all))
	}
}

func valid() *Exercise {
	return &Exercise{
		Name: "x", Title: "t", Task: "do it",
		Resources: Resources{
			VPCs:           []VPC{{Name: "v", CIDR: "10.0.0.0/16"}},
			Subnets:        []Subnet{{Name: "s", VPC: "v", CIDR: "10.0.1.0/24"}},
			SecurityGroups: []SecurityGroup{{Name: "g", VPC: "v", Ingress: []SGRule{{Protocol: "tcp", Ports: "80", Group: "g"}}}},
			Instances:      []Instance{{Name: "web", Subnet: "s", SecurityGroups: []string{"g"}}},
		},
		Checks: []Check{{Name: "c", From: "operator", To: "web.public", Port: 80, Expect: "open"}},
	}
}

func TestValidate(t *testing.T) {
	if err := valid().Validate(); err != nil {
		t.Fatalf("valid exercise: %v", err)
	}
	cases := map[string]struct {
		change func(*Exercise)
		want   string
	}{
		"unknown subnet":    {func(e *Exercise) { e.Resources.Instances[0].Subnet = "nope" }, `"nope" is not a subnet`},
		"duplicate name":    {func(e *Exercise) { e.Resources.Subnets[0].Name = "v" }, `"v" is used twice`},
		"reserved name":     {func(e *Exercise) { e.Resources.Instances[0].Name = "operator" }, "reserved"},
		"bad port range":    {func(e *Exercise) { e.Resources.SecurityGroups[0].Ingress[0].Ports = "90-80" }, "bad port range"},
		"cidr and group":    {func(e *Exercise) { e.Resources.SecurityGroups[0].Ingress[0].CIDR = "0.0.0.0/0" }, "exactly one of cidr and group"},
		"check from public": {func(e *Exercise) { e.Checks[0].From = "web.public" }, "is not an instance or internet host"},
		"check to unknown":  {func(e *Exercise) { e.Checks[0].To = "db" }, `to "db"`},
		"bad expectation":   {func(e *Exercise) { e.Checks[0].Expect = "maybe" }, "open or closed"},
		"icmp with ports":   {func(e *Exercise) { e.Resources.SecurityGroups[0].Ingress[0].Protocol = "icmp" }, "takes no ports"},
		"acl rule out of range": {func(e *Exercise) {
			e.Resources.NetworkACLs = []NetworkACL{{Name: "a", VPC: "v", Entries: []ACLEntry{{Rule: 0, Direction: "inbound", Action: "allow", Protocol: "all", CIDR: "0.0.0.0/0"}}}}
		}, "outside 1-32766"},
	}
	for name, tc := range cases {
		e := valid()
		tc.change(e)
		err := e.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error = %v, want it to contain %q", name, err, tc.want)
		}
	}
}

func TestParsePorts(t *testing.T) {
	for _, tc := range []struct {
		proto, ports string
		from, to     int32
	}{
		{"tcp", "80", 80, 80},
		{"udp", "1024-65535", 1024, 65535},
		{"all", "", -1, -1},
		{"icmp", "", -1, -1},
	} {
		from, to, err := parsePorts(tc.proto, tc.ports)
		if err != nil || from != tc.from || to != tc.to {
			t.Errorf("parsePorts(%q, %q) = %d, %d, %v", tc.proto, tc.ports, from, to, err)
		}
	}
	if _, _, err := parsePorts("sctp", "1"); err == nil {
		t.Error("sctp accepted")
	}
}
