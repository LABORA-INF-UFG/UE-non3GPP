package ipsec

import (
	"UE-non3GPP/config"
	"UE-non3GPP/internal/ike/context"
	contextIpsec "UE-non3GPP/internal/ipsec/context"
	"UE-non3GPP/internal/ipsec/dispatch"
	contextNas "UE-non3GPP/internal/nas/context"
	"UE-non3GPP/internal/xfrm"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"net"
)

func Run(ueIpAdr []byte,
	ueIpMask []byte,
	childSecurityAssociation *context.ChildSecurityAssociation,
	N3IWFNasAddr *net.TCPAddr,
	nas *contextNas.UeNas) {

	var linkIPSec netlink.Link
	var err error

	cfg := config.GetConfig()

	// TODO understand what is it
	ueInnerAddr := net.IPNet{
		IP:   ueIpAdr,
		Mask: ueIpMask,
	}

	// setup IPsec Xfrmi
	newXfrmiName := fmt.Sprintf("%s-default", cfg.Ue.IPSecInterfaceName)
	// TODO interface IP is hardcoded
	if linkIPSec, err = xfrm.SetupIPsecXfrmi(
		newXfrmiName,
		"virbr0",
		cfg.Ue.IPSecInterfaceMark,
		&ueInnerAddr); err != nil {
		return
	}

	nas.SetXfrmInterface(linkIPSec)

	// Apply XFRM rules
	if err := xfrm.ApplyXFRMRule(
		true,
		cfg.Ue.IPSecInterfaceMark,
		childSecurityAssociation); err != nil {
		return
	}

	// UE TCP address
	localTCPAddr := &net.TCPAddr{
		IP: ueInnerAddr.IP,
	}

	tcpConnWithN3IWF, err := net.DialTCP(
		"tcp",
		localTCPAddr,
		N3IWFNasAddr)
	if err != nil {
		fmt.Println(err)
		return
	}

	// create context of UE for ipsec
	ueIpSec := contextIpsec.NewUeIpSec(
		nas,
		tcpConnWithN3IWF,
		newXfrmiName)

	nas.SetIpsecTcp(tcpConnWithN3IWF)

	// handle server tcp/NAS
	go listenAndServe(ueIpSec)
}

func listenAndServe(ue *contextIpsec.UeIpSec) {

	listener := ue.GetTcpConn()
	data := make([]byte, 65535)

	for {

		n, err := listener.Read(data)
		if err != nil {
			log.Error("Read From TCP failed: %+v", err)
			continue
		}

		forwardData := make([]byte, n)
		copy(forwardData, data[:n])

		// handle the message in IPSEC handler
		go dispatch.Dispatch(ue, forwardData)
	}
}
