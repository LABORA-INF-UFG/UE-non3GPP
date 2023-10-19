package ipsec

import (
	"UE-non3GPP/config"
	"UE-non3GPP/internal/ike/context"
	contextIpsec "UE-non3GPP/internal/ipsec/context"
	"UE-non3GPP/internal/ipsec/dispatch"
	"UE-non3GPP/internal/xfrm"
	ueMetrics "UE-non3GPP/pkg/metrics"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"net"
	"time"
)

func Run(ueIpAdr []byte,
	ueIpMask []byte,
	childSecurityAssociation *context.ChildSecurityAssociation,
	N3IWFNasAddr *net.TCPAddr,
	ueIke *context.UeIke) {

	var linkIPSec netlink.Link
	var err error

	cfg := config.GetConfig()

	// TODO understand what is it
	ueInnerAddr := net.IPNet{
		IP:   ueIpAdr,
		Mask: ueIpMask,
	}

	// get interface by name
	interfaceName, err := ueIke.Utils.GetInterfaceName(cfg.Ue.LocalPublicIPAddr)
	if err != nil {
		log.Error("[UE][IPSEC] Error in get UE interface name")
		return
	}

	// setup IPsec Xfrmi
	newXfrmiName := fmt.Sprintf("%s-default", cfg.Ue.IPSecInterface.Name)
	// TODO interface IP is hardcoded
	if linkIPSec, err = xfrm.SetupIPsecXfrmi(
		newXfrmiName,
		interfaceName,
		cfg.Ue.IPSecInterface.Mark,
		&ueInnerAddr); err != nil {
		log.Error("[UE][IPSEC] Error in setup IPSEC interface")
		return
	}

	ueIke.NasContext.SetXfrmInterface(linkIPSec)

	// Apply XFRM rules
	if err := xfrm.ApplyXFRMRule(
		true,
		cfg.Ue.IPSecInterface.Mark,
		childSecurityAssociation); err != nil {
		log.Error("[UE][IPSEC] Error in setup XFRM rules")
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
		log.Error("[UE][IPSEC][CP] Error in setup dial TCP")
		return
	}

	// create context of UE for ipsec
	ueIpSec := contextIpsec.NewUeIpSec(
		ueIke.NasContext,
		tcpConnWithN3IWF,
		newXfrmiName)

	ueIke.NasContext.SetIpsecTcp(tcpConnWithN3IWF)

	log.Info("[UE][IPSEC] IPSEC SA Tunnel established")
	ueIke.IpsecTime = time.Since(ueIke.BeginTime)
	ueMetrics.AddIpsecTime(time.Since(ueIke.BeginTime))

	// handle server tcp/NAS
	go listenAndServe(ueIpSec)
}

func listenAndServe(ue *contextIpsec.UeIpSec) {

	listener := ue.GetTcpConn()
	data := make([]byte, 65535)

	for {

		n, err := listener.Read(data)
		if err != nil {
			log.Error("[UE][IPSEC][TCP] Read From TCP failed: %+v", err)
			continue
		}

		forwardData := make([]byte, n)
		copy(forwardData, data[:n])

		// handle the message in IPSEC handler
		go dispatch.Dispatch(ue, forwardData)
	}
}
