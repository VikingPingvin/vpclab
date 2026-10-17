//go:build conformance

package conformance

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/VikingPingvin/vpclab/internal/exercise"
)

// solution is the reference answer to an exercise, plus a tempting wrong
// answer that one of the exercise's checks must catch.
type solution struct {
	fix  func(e *env, st *exercise.State)
	trap func(e *env, st *exercise.State) // applied on top of fix
}

var solutions = map[string]solution{
	"fix-security-group": {
		fix: func(e *env, st *exercise.State) {
			e.allowIngress(st.IDs["web-sg"], fromCIDR(tcp(80), "0.0.0.0/0"))
		},
		trap: func(e *env, st *exercise.State) { // "just open everything"
			e.allowIngress(st.IDs["web-sg"], fromCIDR(types.IpPermission{IpProtocol: aws.String("-1")}, "0.0.0.0/0"))
		},
	},
	"nacl-ephemeral-ports": {
		fix: func(e *env, st *exercise.State) {
			acl := st.IDs["public-acl"]
			e.aclEntry(acl, aclRule{number: 110, egress: true, allow: true, cidr: "0.0.0.0/0", from: 1024, to: 65535})
			e.aclEntry(acl, aclRule{number: 110, allow: true, cidr: "0.0.0.0/0", from: 1024, to: 65535})
		},
		trap: func(e *env, st *exercise.State) { // "allow all inbound"
			if _, err := e.ec2.CreateNetworkAclEntry(e.ctx, &ec2.CreateNetworkAclEntryInput{
				NetworkAclId: aws.String(st.IDs["public-acl"]), RuleNumber: aws.Int32(120), Egress: aws.Bool(false),
				RuleAction: types.RuleActionAllow, Protocol: aws.String("-1"), CidrBlock: aws.String("0.0.0.0/0"),
			}); err != nil {
				e.t.Fatal(err)
			}
		},
	},
	"public-subnet-not-public": {
		fix: func(e *env, st *exercise.State) {
			if _, err := e.ec2.AssociateRouteTable(e.ctx, &ec2.AssociateRouteTableInput{
				RouteTableId: aws.String(st.IDs["public-rt"]), SubnetId: aws.String(st.IDs["public"]),
			}); err != nil {
				e.t.Fatal(err)
			}
		},
		trap: func(e *env, st *exercise.State) { // "route the main table to the IGW"
			if _, err := e.ec2.CreateRoute(e.ctx, &ec2.CreateRouteInput{
				RouteTableId: aws.String(e.mainRouteTable(st.IDs["shop"])), DestinationCidrBlock: aws.String("0.0.0.0/0"),
				GatewayId: aws.String(st.IDs["shop-igw"]),
			}); err != nil {
				e.t.Fatal(err)
			}
		},
	},
}

// TestExercises proves for every exercise that the starting state fails,
// the reference solution passes, and the tempting wrong answer fails.
func TestExercises(t *testing.T) {
	all, err := exercise.LoadAll("../../exercises")
	if err != nil {
		t.Fatal(err)
	}
	for _, ex := range all {
		t.Run(ex.Name, func(t *testing.T) {
			sol, ok := solutions[ex.Name]
			if !ok {
				t.Fatal("no reference solution in exercises_test.go")
			}
			e := newEnv(t)
			st, err := exercise.Start(e.ctx, e.ec2, ex)
			if err != nil {
				t.Fatal(err)
			}
			e.defer_(func() {
				for _, err := range exercise.Stop(e.ctx, e.ec2, st) {
					t.Log("stop:", err)
				}
			})
			e.apply()
			if failed := e.verify(ex, st); len(failed) == 0 {
				t.Fatal("the starting state already passes every check")
			}

			sol.fix(e, st)
			e.apply()
			if failed := e.verify(ex, st); len(failed) > 0 {
				t.Errorf("the reference solution fails: %v", failed)
			}

			sol.trap(e, st)
			e.apply()
			if failed := e.verify(ex, st); len(failed) == 0 {
				t.Error("no check catches the wrong answer")
			} else {
				t.Logf("the wrong answer fails: %v", failed)
			}
		})
	}
}

// verify runs the exercise's checks and returns the failed ones.
func (e *env) verify(ex *exercise.Exercise, st *exercise.State) []string {
	e.t.Helper()
	results, err := exercise.Verify(e.ctx, e.ec2, ex, st)
	if err != nil {
		e.t.Fatal(err)
	}
	var failed []string
	for _, r := range results {
		if !r.Pass {
			failed = append(failed, r.Check.Name+": "+r.Detail)
		}
	}
	return failed
}

func (e *env) mainRouteTable(vpc string) string {
	e.t.Helper()
	out, err := e.ec2.DescribeRouteTables(e.ctx, &ec2.DescribeRouteTablesInput{
		Filters: []types.Filter{{Name: aws.String("vpc-id"), Values: []string{vpc}}},
	})
	if err != nil {
		e.t.Fatal(err)
	}
	for _, rt := range out.RouteTables {
		for _, a := range rt.Associations {
			if aws.ToBool(a.Main) {
				return aws.ToString(rt.RouteTableId)
			}
		}
	}
	e.t.Fatalf("no main route table in %s", vpc)
	return ""
}
