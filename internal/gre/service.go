package gre

import (
	"UE-non3GPP/config"
	"UE-non3GPP/internal/ike/context"
	contextNas "UE-non3GPP/internal/nas/context"
	"UE-non3GPP/internal/xfrm"
	"fmt"
	"github.com/vishvananda/netlink"
	"net"
	"time"
)

func Run(
	ueIpAdr []byte,
	n3iwfIpUp net.IP,
	childSecurityAssociation *context.ChildSecurityAssociation,
	nas *contextNas.UeNas,
	QosInfo *context.PDUQoSInfo) {

	var linkGRE netlink.Link

	cfg := config.GetConfig()

	ueInnerAddr := net.IPNet{
		IP: ueIpAdr,
	}

	var err error
	// Apply XFRM rules
	if err = xfrm.ApplyXFRMRule(
		false,
		cfg.Ue.IPSecInterfaceMark,
		childSecurityAssociation); err != nil {
		return
	}

	// wait PDU Session Active
	for {

		// PDU addres received
		if nas.StateSM == 2 {
			break
		}

		time.Sleep(1 * time.Second)
	}

	newGREName := fmt.Sprintf("%s%d", cfg.Ue.LinkGRE.Name, cfg.Ue.PDUSessionId)
	if linkGRE, err = setupGreTunnel(
		newGREName,
		"ipsec0-default",
		ueInnerAddr.IP,
		n3iwfIpUp,
		nas.PduSession.PDUAdress,
		QosInfo); err != nil {
		fmt.Println(err)
		return
	}

	nas.SetGREInterface(linkGRE)

	// Add route
	upRoute := &netlink.Route{
		LinkIndex: linkGRE.Attrs().Index,
		Dst: &net.IPNet{
			IP:   net.IPv4zero,
			Mask: net.IPv4Mask(0, 0, 0, 0),
		},
	}

	nas.SetGRERoute(upRoute)

	if err := netlink.RouteAdd(upRoute); err != nil {
		fmt.Println(err)
		return
	}
}

func setupGreTunnel(greIfaceName, parentIfaceName string, ueTunnelAddr,
	n3iwfTunnelAddr, pduAddr net.IP, qoSInfo *context.PDUQoSInfo) (netlink.Link, error) {
	var (
		parent      netlink.Link
		greKeyField uint32
		err         error
	)

	if qoSInfo != nil {
		greKeyField |= (uint32(qoSInfo.QfiList[0]) & 0x3F) << 24
	}

	if parent, err = netlink.LinkByName(parentIfaceName); err != nil {
		return nil, err
	}

	// New GRE tunnel interface
	newGRETunnel := &netlink.Gretun{
		LinkAttrs: netlink.LinkAttrs{
			Name: greIfaceName,
			MTU:  1438, // remain for endpoint IP header(most 40 bytes if IPv6) and ESP header (22 bytes)
		},
		Link:   uint32(parent.Attrs().Index), // PHYS_DEV in iproute2; IFLA_GRE_LINK in linux kernel
		Local:  ueTunnelAddr,
		Remote: n3iwfTunnelAddr,
		IKey:   greKeyField,
		OKey:   greKeyField,
	}

	if err := netlink.LinkAdd(newGRETunnel); err != nil {
		return nil, err
	}

	// Get link info
	linkGRE, err := netlink.LinkByName(greIfaceName)
	if err != nil {
		return nil, fmt.Errorf("No link named %s", greIfaceName)
	}

	linkGREAddr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   pduAddr,
			Mask: net.IPv4Mask(255, 255, 255, 255),
		},
	}

	if err := netlink.AddrAdd(linkGRE, linkGREAddr); err != nil {
		return nil, err
	}

	// Set GRE interface up
	if err := netlink.LinkSetUp(linkGRE); err != nil {
		return nil, err
	}

	return linkGRE, nil
}
