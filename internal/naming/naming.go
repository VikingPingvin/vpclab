// Package naming derives stable, deterministic names and addresses for the
// Linux objects vpcsim creates from AWS resource IDs.
package naming

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
)

const (
	LabelRole     = "vpcsim.role"
	LabelVPC      = "vpcsim.vpc"
	LabelInstance = "vpcsim.instance"
	LabelSpec     = "vpcsim.spec" // hash of the docker run arguments

	RoleRouter       = "router"
	RoleInstance     = "instance"
	RoleNATGateway   = "nat-gateway"
	RoleTGW          = "transit-gateway"
	RoleInternet     = "internet"
	RoleInternetHost = "internet-host"
	RoleUplink       = "uplink" // the Docker network, not a container
)

// RouterContainer is the container that owns the network namespace of a
// VPC's implicit router.
func RouterContainer(vpcID string) string { return "vpcsim-rtr-" + vpcID }

// InstanceContainer is the container that runs an EC2 instance.
func InstanceContainer(instanceID string) string { return "vpcsim-" + instanceID }

// NATGatewayContainer is the container that owns a NAT gateway's network
// namespace.
func NATGatewayContainer(natID string) string { return "vpcsim-" + natID }

// RouterIf is the router-side interface name for an ENI. Linux limits
// interface names to 15 bytes, so it is a short hash of the ENI ID.
func RouterIf(eniID string) string { return "v" + short(eniID, 11) }

// TempIf is the temporary name of the instance-side veth end before it is
// renamed to ethN inside the instance namespace.
func TempIf(eniID string) string { return "t" + short(eniID, 11) }

// InstanceIf is the interface name inside the instance for a device index.
func InstanceIf(deviceIndex int32) string { return fmt.Sprintf("eth%d", deviceIndex) }

// MAC returns a deterministic, locally administered unicast MAC for an ENI.
// Floci does not report MAC addresses, so vpcsim derives them.
func MAC(eniID string) net.HardwareAddr {
	sum := sha256.Sum256([]byte(eniID))
	mac := net.HardwareAddr(sum[:6])
	mac[0] = (mac[0] | 0x02) &^ 0x01
	return mac
}

// Hostname mirrors the default EC2 hostname, e.g. ip-10-0-1-10.
func Hostname(privateIP string) string {
	return "ip-" + strings.ReplaceAll(privateIP, ".", "-")
}

// NftID turns an AWS ID into a valid nftables identifier.
func NftID(awsID string) string { return strings.ReplaceAll(awsID, "-", "_") }

// TGWContainer is the container that owns a transit gateway's namespace.
func TGWContainer(tgwID string) string { return "vpcsim-" + tgwID }

// PeeringIf is the interface of a peering connection in both VPC routers.
func PeeringIf(pcxID string) string { return "p" + short(pcxID, 11) }

// AttachmentIf is the interface of a TGW attachment in the VPC router and in
// the TGW namespace.
func AttachmentIf(attachmentID string) string { return "a" + short(attachmentID, 11) }

// VRFIf is the VRF device of a TGW route table.
func VRFIf(routeTableID string) string { return "r" + short(routeTableID, 11) }

// InternetIf is the internet-namespace end of a VPC's internet gateway link.
func InternetIf(vpcID string) string { return "x" + short(vpcID, 11) }

// Short returns the first n hex characters of the SHA-256 of s.
func Short(s string, n int) string { return short(s, n) }

func short(s string, n int) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:n]
}
