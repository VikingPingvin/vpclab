//go:build conformance

package conformance

import (
	"net/url"
	"os/exec"
	"strings"
	"testing"

	"github.com/VikingPingvin/vpclab/internal/floci"
	"github.com/VikingPingvin/vpclab/internal/plan"
)

// TestRealInternet covers the uplink from the simulated internet to the real
// one. It needs internet access on the host.
//
// Expected AWS behaviour (VPC user guide, "Internet gateways"):
//   - An instance with a public IPv4 in a subnet that routes to the IGW
//     reaches the internet; an instance without one does not.
//   - Private address ranges are not routed on the internet.
func TestRealInternet(t *testing.T) {
	e := newEnv(t)
	vpc := e.vpc("10.60.0.0/16")
	pub := e.subnet(vpc, "10.60.1.0/24")
	igw := e.igw(vpc)
	e.publicRouteTable(vpc, igw, pub)
	sg := e.sg(vpc, "client") // default egress: all traffic
	web := e.instance(pub, sg)
	e.eip(web)
	noPublic := e.instance(pub, sg)
	e.apply()

	if out, err := e.hostSh("internet", "ping -c1 -W3 8.8.8.8"); err != nil {
		t.Skipf("the internet namespace cannot reach 8.8.8.8; no internet on the host?\n%s", out)
	}

	t.Run("ping a public address", func(t *testing.T) {
		if out, err := e.sh(web, "ping -c1 -W3 8.8.8.8"); err != nil {
			t.Errorf("ping 8.8.8.8 failed: %v\n%s", err, out)
		}
	})
	t.Run("DNS and HTTPS", func(t *testing.T) {
		out, err := e.sh(web, "curl -sS --max-time 10 -o /dev/null -w '%{http_code}' https://example.com/")
		if err != nil || out != "200" {
			t.Errorf("https://example.com/: %q, %v", out, err)
		}
	})
	t.Run("no public IP means no real internet", func(t *testing.T) {
		if _, err := e.sh(noPublic, "ping -c1 -W3 8.8.8.8"); err == nil {
			t.Error("instance without public IP reached 8.8.8.8")
		}
	})
	t.Run("private ranges are not routed", func(t *testing.T) {
		// Floci listens on every host address, so the uplink's gateway
		// address leads to it unless the internet namespace drops it.
		gw, err := exec.Command("docker", "network", "inspect", plan.UplinkNetwork,
			"-f", "{{range .IPAM.Config}}{{.Gateway}}{{end}}").Output()
		if err != nil {
			t.Fatal(err)
		}
		ep, err := url.Parse(floci.Endpoint())
		if err != nil {
			t.Fatal(err)
		}
		url := "http://" + strings.TrimSpace(string(gw)) + ":" + ep.Port() + "/"
		if out, err := e.hostSh("internet", "wget -q -O /dev/null -T 3 "+url); err != nil {
			t.Skipf("control failed: the internet namespace cannot reach %s itself\n%s", url, out)
		}
		if _, err := e.sh(web, "curl -s -o /dev/null --max-time 3 "+url); err == nil {
			t.Errorf("instance reached %s on the host through the uplink", url)
		}
	})
}
