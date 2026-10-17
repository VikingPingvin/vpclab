//go:build conformance

package conformance

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
)

// TestSecurityGroups covers one VPC with two subnets:
//
//	web   (subnet a, sg-web: ingress tcp/443 from sg-app, NO egress rules)
//	app   (subnet b, sg-app: default egress)
//	other (subnet a, sg-other: ingress tcp/8080 + udp/9000 from the VPC CIDR)
//
// Expected AWS behaviour (EC2 user guide, "Security group rules"):
//   - SG rules that reference a group match the private IPs of its members.
//   - SGs are stateful: replies are allowed whatever the outbound rules say.
//   - SGs apply between instances in the same subnet too.
//   - A new outbound connection needs an egress rule.
func TestSecurityGroups(t *testing.T) {
	e := newEnv(t)
	vpc := e.vpc("10.20.0.0/16")
	subA := e.subnet(vpc, "10.20.1.0/24")
	subB := e.subnet(vpc, "10.20.2.0/24")

	sgWeb, sgApp, sgOther := e.sg(vpc, "web"), e.sg(vpc, "app"), e.sg(vpc, "other")
	e.allowIngress(sgWeb, fromGroup(tcp(443), sgApp))
	e.revokeAllEgress(sgWeb)
	e.allowIngress(sgOther, fromCIDR(tcp(8080), "10.20.0.0/16"), fromCIDR(udp(9000), "10.20.0.0/16"))

	web := e.instance(subA, sgWeb)
	app := e.instance(subB, sgApp)
	other := e.instance(subA, sgOther)
	e.apply()

	e.listenTCP(web, "443")
	e.listenTCP(web, "80")
	e.listenTCP(other, "8080")

	t.Run("group reference allows members", func(t *testing.T) {
		e.expectTCP(app, web, "443", true, "sg-web allows 443 from sg-app; reply passes although sg-web has no egress rules (stateful)")
	})
	t.Run("unlisted port is dropped", func(t *testing.T) {
		e.expectTCP(app, web, "80", false, "sg-web has no rule for port 80")
	})
	t.Run("same subnet is still filtered", func(t *testing.T) {
		e.expectTCP(other, web, "443", false, "other is in web's subnet but not in sg-app")
	})
	t.Run("egress rules are enforced", func(t *testing.T) {
		e.expectTCP(app, other, "8080", true, "control: sg-other allows 8080 from the VPC")
		e.expectTCP(web, other, "8080", false, "sg-web has no egress rules")
	})
	t.Run("membership follows the instance", func(t *testing.T) {
		// Moving other into sg-app must grant it access to web:443.
		eni := e.primaryENI(other)
		if _, err := e.ec2.ModifyNetworkInterfaceAttribute(e.ctx, &ec2.ModifyNetworkInterfaceAttributeInput{
			NetworkInterfaceId: &eni, Groups: []string{sgOther, sgApp},
		}); err != nil {
			if _, err2 := e.ec2.ModifyInstanceAttribute(e.ctx, &ec2.ModifyInstanceAttributeInput{
				InstanceId: &other.ID, Groups: []string{sgOther, sgApp},
			}); err2 != nil {
				t.Skipf("Floci cannot change security groups of a running instance: %v / %v", err, err2)
			}
		}
		e.apply()
		e.expectTCP(other, web, "443", true, "other is now a member of sg-app")
	})
	t.Run("source/destination check", func(t *testing.T) {
		// app sends UDP from an address AWS did not assign to its ENI.
		e.mustSh(other, "nohup socat -u UDP-RECV:9000 OPEN:/tmp/udp.log,creat,append >/dev/null 2>&1 &")
		e.mustSh(app, "ip addr add 10.20.2.99/24 dev eth0")
		send := "echo spoofed | socat -u - UDP-SENDTO:" + other.IP + ":9000,bind=10.20.2.99"
		received := func() bool {
			time.Sleep(300 * time.Millisecond)
			out, _ := e.sh(other, "cat /tmp/udp.log 2>/dev/null")
			return out != ""
		}

		e.mustSh(app, send)
		if received() {
			t.Error("packet with a foreign source address passed the source/destination check")
		}

		if _, err := e.ec2.ModifyInstanceAttribute(e.ctx, &ec2.ModifyInstanceAttributeInput{
			InstanceId: &app.ID, SourceDestCheck: &types.AttributeBooleanValue{Value: aws.Bool(false)},
		}); err != nil {
			t.Skipf("Floci cannot disable the source/destination check: %v", err)
		}
		e.apply()
		e.mustSh(app, send)
		if !received() {
			t.Error("source/destination check is disabled, but the packet did not arrive")
		}
	})
}

func (e *env) primaryENI(in instance) string {
	e.t.Helper()
	out, err := e.ec2.DescribeInstances(e.ctx, &ec2.DescribeInstancesInput{InstanceIds: []string{in.ID}})
	if err != nil {
		e.t.Fatal(err)
	}
	return aws.ToString(out.Reservations[0].Instances[0].NetworkInterfaces[0].NetworkInterfaceId)
}
