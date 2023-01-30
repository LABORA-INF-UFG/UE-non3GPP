package service

import (
	"UE-non3GPP/config"
	"UE-non3GPP/internal/ike"
	log "github.com/sirupsen/logrus"
	"net"
)

func Run(cfg config.Config) *net.UDPConn {

	// n3wif UDP address
	n3wifAddr := cfg.N3iwfInfo.IKEBindAddress + ":" + cfg.N3iwfInfo.IKEBindPort
	n3iwfUdp, err := net.ResolveUDPAddr("udp", n3wifAddr)
	if err != nil {
		log.Fatal("Resolve N3WIF UDP address failed")
	}

	// UE UDP address
	ueAddr := cfg.Ue.LocalPublicIPAddr + ":" + cfg.Ue.LocalPublicPortUDPConnection
	ueUdp, err := net.ResolveUDPAddr("udp", ueAddr)
	if err != nil {
		log.Fatal("Resolve UE UDP address failed")
	}

	// connect to n3wif/UE udp
	connUdp, err := net.DialUDP("udp", ueUdp, n3iwfUdp)
	if err != nil {
		log.Fatal("UDP Connection N3IWF failed!")
		panic(err)
	}

	// handle messages in udp socket
	go listenAndServe(connUdp)

	return connUdp
}

func listenAndServe(listener *net.UDPConn) {

	data := make([]byte, 65535)

	for {

		n, _, err := listener.ReadFromUDP(data)
		if err != nil {
			log.Error("ReadFromUDP failed: %+v", err)
			continue
		}

		forwardData := make([]byte, n)
		copy(forwardData, data[:n])

		// handle the message in ike handler
		go ike.Dispatch(listener, forwardData)
	}
}
