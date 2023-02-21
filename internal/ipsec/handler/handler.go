package handler

import (
	"UE-non3GPP/internal/ipsec/context"
	"UE-non3GPP/internal/nas/dispatch"
)

func HandlerRegisteredInitiated(ue *context.UeIpSec, msg []byte) {

	// get registration complete/correct response
	responseNas, error := dispatch.DispatchNas(msg, ue.NasContext)
	if error != nil {
		return
	}

	// send registration complete/correct response
	tcp := ue.GetTcpConn()
	_, err := tcp.Write(responseNas)
	if err != nil {
		return
	}

	// change the state of NAS messages
	ue.NasContext.SetRegistered()

	// send the pdu establishment request for establish the pdu session
}
