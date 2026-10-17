//go:build conformance

// Package conformance checks vpcsim against expected AWS behaviour by creating
// resources in Floci, reconciling the data plane and sending real traffic.
//
// Run inside WSL with Floci up:
//
//	go test -tags conformance -v ./test/conformance/
//
// Set VPCSIM_KEEP=1 to keep resources and containers after a run for debugging.
package conformance

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/VikingPingvin/vpclab/internal/floci"
	"github.com/VikingPingvin/vpclab/internal/naming"
)

type env struct {
	t       *testing.T
	ctx     context.Context
	ec2     *ec2.Client
	cleanup []func()
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	c, err := floci.EC2(ctx)
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, ctx: ctx, ec2: c}
	t.Cleanup(func() {
		if os.Getenv("VPCSIM_KEEP") != "" {
			t.Log("VPCSIM_KEEP set: leaving resources in place")
			return
		}
		for i := len(e.cleanup) - 1; i >= 0; i-- {
			e.cleanup[i]()
		}
		e.apply() // removes containers of terminated instances
	})
	return e
}

func (e *env) defer_(f func()) { e.cleanup = append(e.cleanup, f) }

// apply runs one vpcsim reconcile in its privileged container.
func (e *env) apply() {
	e.t.Helper()
	out, err := exec.Command("bash", "../../scripts/vpcsim.sh", "apply").CombinedOutput()
	if err != nil {
		e.t.Fatalf("vpcsim apply: %v\n%s", err, out)
	}
	if len(out) > 0 {
		e.t.Logf("vpcsim apply:\n%s", out)
	}
}

func (e *env) vpc(cidr string) string {
	e.t.Helper()
	out, err := e.ec2.CreateVpc(e.ctx, &ec2.CreateVpcInput{CidrBlock: aws.String(cidr)})
	if err != nil {
		e.t.Fatal(err)
	}
	id := aws.ToString(out.Vpc.VpcId)
	e.defer_(func() { e.ec2.DeleteVpc(e.ctx, &ec2.DeleteVpcInput{VpcId: &id}) })
	return id
}

func (e *env) subnet(vpc, cidr string) string {
	e.t.Helper()
	out, err := e.ec2.CreateSubnet(e.ctx, &ec2.CreateSubnetInput{VpcId: &vpc, CidrBlock: aws.String(cidr)})
	if err != nil {
		e.t.Fatal(err)
	}
	id := aws.ToString(out.Subnet.SubnetId)
	e.defer_(func() { e.ec2.DeleteSubnet(e.ctx, &ec2.DeleteSubnetInput{SubnetId: &id}) })
	return id
}

func (e *env) sg(vpc, name string) string {
	e.t.Helper()
	out, err := e.ec2.CreateSecurityGroup(e.ctx, &ec2.CreateSecurityGroupInput{
		VpcId: &vpc, GroupName: aws.String(name + "-" + vpc), Description: aws.String(name),
	})
	if err != nil {
		e.t.Fatal(err)
	}
	id := aws.ToString(out.GroupId)
	e.defer_(func() { e.ec2.DeleteSecurityGroup(e.ctx, &ec2.DeleteSecurityGroupInput{GroupId: &id}) })
	return id
}

func tcp(port int32) types.IpPermission {
	return types.IpPermission{IpProtocol: aws.String("tcp"), FromPort: aws.Int32(port), ToPort: aws.Int32(port)}
}

func udp(port int32) types.IpPermission {
	return types.IpPermission{IpProtocol: aws.String("udp"), FromPort: aws.Int32(port), ToPort: aws.Int32(port)}
}

func fromGroup(p types.IpPermission, sg string) types.IpPermission {
	p.UserIdGroupPairs = []types.UserIdGroupPair{{GroupId: &sg}}
	return p
}

func fromCIDR(p types.IpPermission, cidr string) types.IpPermission {
	p.IpRanges = []types.IpRange{{CidrIp: &cidr}}
	return p
}

func (e *env) allowIngress(sg string, perms ...types.IpPermission) {
	e.t.Helper()
	if _, err := e.ec2.AuthorizeSecurityGroupIngress(e.ctx, &ec2.AuthorizeSecurityGroupIngressInput{
		GroupId: &sg, IpPermissions: perms,
	}); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) revokeAllEgress(sg string) {
	e.t.Helper()
	if _, err := e.ec2.RevokeSecurityGroupEgress(e.ctx, &ec2.RevokeSecurityGroupEgressInput{
		GroupId:       &sg,
		IpPermissions: []types.IpPermission{fromCIDR(types.IpPermission{IpProtocol: aws.String("-1")}, "0.0.0.0/0")},
	}); err != nil {
		e.t.Fatal(err)
	}
}

type instance struct {
	ID string
	IP string
}

func (e *env) instance(subnet string, sgs ...string) instance {
	e.t.Helper()
	out, err := e.ec2.RunInstances(e.ctx, &ec2.RunInstancesInput{
		ImageId: aws.String("ami-12345678"), InstanceType: types.InstanceTypeT3Micro,
		MinCount: aws.Int32(1), MaxCount: aws.Int32(1),
		SubnetId: &subnet, SecurityGroupIds: sgs,
	})
	if err != nil {
		e.t.Fatal(err)
	}
	in := out.Instances[0]
	id := aws.ToString(in.InstanceId)
	e.defer_(func() {
		e.ec2.TerminateInstances(e.ctx, &ec2.TerminateInstancesInput{InstanceIds: []string{id}})
	})
	return instance{ID: id, IP: aws.ToString(in.PrivateIpAddress)}
}

// sh runs a shell command inside an instance container.
func (e *env) sh(in instance, script string) (string, error) {
	var out bytes.Buffer
	cmd := exec.Command("docker", "exec", naming.InstanceContainer(in.ID), "sh", "-c", script)
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}

func (e *env) mustSh(in instance, script string) string {
	e.t.Helper()
	out, err := e.sh(in, script)
	if err != nil {
		e.t.Fatalf("%s: %q: %v\n%s", in.ID, script, err, out)
	}
	return out
}

// listenTCP starts a TCP server that answers "ok" on every connection.
func (e *env) listenTCP(in instance, port string) {
	e.t.Helper()
	e.mustSh(in, "nohup socat TCP-LISTEN:"+port+",fork,reuseaddr SYSTEM:'echo ok' >/dev/null 2>&1 &")
	time.Sleep(200 * time.Millisecond)
}

// canTCP reports whether from can open a TCP connection to ip:port and read
// the server's reply, which proves both directions work.
func (e *env) canTCP(from instance, ip, port string) bool {
	out, err := e.sh(from, "socat -T2 - TCP:"+ip+":"+port+",connect-timeout=2 </dev/null")
	return err == nil && strings.Contains(out, "ok")
}

func (e *env) expectTCP(from instance, to instance, port string, want bool, why string) {
	e.t.Helper()
	if got := e.canTCP(from, to.IP, port); got != want {
		e.t.Errorf("%s -> %s:%s: connected=%t, want %t (%s)", from.IP, to.IP, port, got, want, why)
	}
}
