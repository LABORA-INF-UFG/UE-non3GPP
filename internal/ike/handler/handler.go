package handler

import (
	"UE-non3GPP/engine/exchange/pkg/ike/message"
	"fmt"
	"net"
)

func HandleIKESAINIT(udpConn *net.UDPConn, ikeMsg *message.IKEMessage) {
	fmt.Println(udpConn)
	fmt.Println(ikeMsg)
}

func HandleIKEAUTH(udpConn *net.UDPConn, ikeMsg *message.IKEMessage) {
	fmt.Println(udpConn)
	fmt.Println(ikeMsg)
}

func HandleCREATECHILDSA(udpConn *net.UDPConn, ikeMsg *message.IKEMessage) {
	fmt.Println(udpConn)
	fmt.Println(ikeMsg)
}
