package ike

import (
	ike_message "UE-non3GPP/engine/exchange/pkg/ike/message"
	"UE-non3GPP/internal/ike/handler"
	log "github.com/sirupsen/logrus"
	"net"
)

func Dispatch(udpConn *net.UDPConn, msg []byte) {

	// decode IKE message
	ikeMessage := new(ike_message.IKEMessage)
	err := ikeMessage.Decode(msg)
	if err != nil {
		log.Error(err)
		return
	}

	switch ikeMessage.ExchangeType {
	case ike_message.IKE_SA_INIT:
		handler.HandleIKESAINIT(udpConn, ikeMessage)
	case ike_message.IKE_AUTH:
		handler.HandleIKEAUTH(udpConn, ikeMessage)
	case ike_message.CREATE_CHILD_SA:
		handler.HandleCREATECHILDSA(udpConn, ikeMessage)
	default:
		log.Error("Unimplemented IKE message type, exchange type: %d", ikeMessage.ExchangeType)
	}

}
