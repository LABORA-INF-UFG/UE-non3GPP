package gre

import (
	"UE-non3GPP/config"
	"UE-non3GPP/internal/ike/context"
	"UE-non3GPP/internal/xfrm"
	"fmt"
	"net"
	"time"

	"github.com/vishvananda/netlink"
)

func Run(
	ueIpAdr []byte,
	n3iwfIpUp net.IP,
	childSecurityAssociation *context.ChildSecurityAssociation,
	ueIke *context.UeIke,
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
		cfg.Ue.IPSecInterface.Mark,
		childSecurityAssociation); err != nil {
		// TODO implements LOG
		return
	}

	// wait PDU Session Active
	for {

		// PDU addres received
		if ueIke.NasContext.StateSM == 2 {
			break
		}

		time.Sleep(1 * time.Second)
	}

	newGREName := fmt.Sprintf("%s%d", cfg.Ue.GREInterface.Name, cfg.Ue.PDUSessionId)
	parentIfaceName := fmt.Sprintf("%s-%s", cfg.Ue.IPSecInterface.Name, "default")

	if linkGRE, err = setupGreTunnel(
		newGREName,
		parentIfaceName,
		ueInnerAddr.IP,
		n3iwfIpUp,
		ueIke.NasContext.PduSession.PDUAdress,
		QosInfo); err != nil {
		// TODO implements LOG
		return
	}

	ueIke.NasContext.SetGREInterface(linkGRE)

	// Add route
	upRoute := &netlink.Route{
		LinkIndex: linkGRE.Attrs().Index,
		Dst: &net.IPNet{
			IP:   net.IPv4zero,
			Mask: net.IPv4Mask(0, 0, 0, 0),
		},
	}

	ueIke.NasContext.SetGRERoute(upRoute)

	if err := netlink.RouteAdd(upRoute); err != nil {
		// TODO implements LOG
		return
	}
}

// Copyright free5GC
func setupGreTunnel(greIfaceName, parentIfaceName string, ueTunnelAddr,
	n3iwfTunnelAddr, pduAddr net.IP, qoSInfo *context.PDUQoSInfo) (netlink.Link, error) {
	var (
		parent      netlink.Link
		greKeyField uint32
		err         error
	)

	cfg := config.GetConfig()

	if qoSInfo != nil {
		greKeyField |= (uint32(qoSInfo.QfiList[0]) & 0x3F) << 24
	}

	if parent, err = netlink.LinkByName(parentIfaceName); err != nil {
		// TODO implements LOG
		return nil, err
	}

	// New GRE tunnel interface
	newGRETunnel := &netlink.Gretun{
		LinkAttrs: netlink.LinkAttrs{
			Name: greIfaceName,
			MTU:  cfg.Ue.GREInterface.Mtu, // remain for endpoint IP header(most 40 bytes if IPv6) and ESP header (22 bytes)
		},
		Link:   uint32(parent.Attrs().Index), // PHYS_DEV in iproute2; IFLA_GRE_LINK in linux kernel
		Local:  ueTunnelAddr,
		Remote: n3iwfTunnelAddr,
		IKey:   greKeyField,
		OKey:   greKeyField,
		Ttl:    cfg.Ue.GREInterface.Ttl, // Define o TTL com base no parâmetro
	}

	if err := netlink.LinkAdd(newGRETunnel); err != nil {
		// TODO implements LOG
		return nil, err
	}

	// Get link info
	linkGRE, err := netlink.LinkByName(greIfaceName)
	if err != nil {
		// TODO implements LOG
		return nil, fmt.Errorf("No link named %s", greIfaceName)
	}

	linkGREAddr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   pduAddr,
			Mask: net.IPv4Mask(255, 255, 255, 255),
		},
	}

	if err := netlink.AddrAdd(linkGRE, linkGREAddr); err != nil {
		// TODO implements LOG
		return nil, err
	}

	// Set GRE interface up
	if err := netlink.LinkSetUp(linkGRE); err != nil {
		// TODO implements LOG
		return nil, err
	}

	return linkGRE, nil
}
