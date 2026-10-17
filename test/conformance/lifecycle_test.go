//go:build conformance

package conformance

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ec2"

	"github.com/VikingPingvin/vpclab/internal/naming"
)

// TestStopStart covers the instance lifecycle.
//
// Expected AWS behaviour (EC2 user guide, "Stop and start your instance"):
//   - A stopped instance keeps its EBS root volume, so files survive.
//   - It keeps its private IPv4 and ENIs, and works again after a start.
//   - Processes do not survive; a start is a boot.
func TestStopStart(t *testing.T) {
	e := newEnv(t)
	vpc := e.vpc("10.70.0.0/16")
	sn := e.subnet(vpc, "10.70.1.0/24")
	sg := e.sg(vpc, "app")
	e.allowIngress(sg, fromGroup(tcp(8080), sg))
	app := e.instance(sn, sg)
	client := e.instance(sn, sg)
	e.apply()

	e.mustSh(app, "echo kept > /root/marker")
	e.listenTCP(app, "8080")
	if !e.canTCP(client, app.IP, "8080") {
		t.Fatal("client cannot reach app before the stop")
	}

	if _, err := e.ec2.StopInstances(e.ctx, &ec2.StopInstancesInput{InstanceIds: []string{app.ID}}); err != nil {
		t.Fatal(err)
	}
	e.apply()

	t.Run("stopped instance keeps a stopped container", func(t *testing.T) {
		out, err := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", naming.InstanceContainer(app.ID)).CombinedOutput()
		if err != nil || strings.TrimSpace(string(out)) != "false" {
			t.Errorf("container state: %q, %v; want it to exist and not run", strings.TrimSpace(string(out)), err)
		}
	})
	t.Run("stopped instance is unreachable", func(t *testing.T) {
		if e.canTCP(client, app.IP, "8080") {
			t.Error("client reached the stopped instance")
		}
	})

	if _, err := e.ec2.StartInstances(e.ctx, &ec2.StartInstancesInput{InstanceIds: []string{app.ID}}); err != nil {
		t.Fatal(err)
	}
	e.apply()

	t.Run("files survive a stop and start", func(t *testing.T) {
		if out, err := e.sh(app, "cat /root/marker"); err != nil || out != "kept" {
			t.Errorf("/root/marker: %q, %v", out, err)
		}
	})
	t.Run("network works after the start", func(t *testing.T) {
		e.listenTCP(app, "8080") // processes do not survive the stop
		if !e.canTCP(client, app.IP, "8080") {
			t.Error("client cannot reach app after the start")
		}
	})
}
