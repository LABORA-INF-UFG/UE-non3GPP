package dispatch

import (
	"UE-non3GPP/internal/ike/context"
	"UE-non3GPP/internal/ike/handler"
	ike_message "UE-non3GPP/internal/ike/message"
	log "github.com/sirupsen/logrus"
)

func Dispatch(ue *context.Ue, msg []byte) {

	// decode IKE message
	ikeMessage := new(ike_message.IKEMessage)
	err := ikeMessage.Decode(msg)
	if err != nil {
		log.Error(err)
		return
	}

	switch ikeMessage.ExchangeType {
	case ike_message.IKE_SA_INIT:
		handler.HandleIKESAINIT(ue, ikeMessage)
	case ike_message.IKE_AUTH:
		handler.HandleIKEAUTH(ue, ikeMessage)
	case ike_message.CREATE_CHILD_SA:
		handler.HandleCREATECHILDSA(ue, ikeMessage)
	default:
		log.Error("Unimplemented IKE message type, exchange type: %d", ikeMessage.ExchangeType)
	}

}
