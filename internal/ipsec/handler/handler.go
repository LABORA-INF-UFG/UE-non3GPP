package handler

import (
	"UE-non3GPP/internal/ipsec/context"
	"UE-non3GPP/internal/nas/dispatch"
	"fmt"
)

func HandlerRegisteredInitiated(ue *context.UeIpSec, msg []byte) {

	// get registration complete/correct response
	responseNas, error := dispatch.DispatchNas(msg, ue.NasContext)
	if error != nil {
		fmt.Println(error)
		return
	}

	// set the message as NAS envelope
	envelope := ue.EncapNasMsgToEnvelope(responseNas)

	// send registration complete/correct response
	tcp := ue.GetTcpConn()
	_, err := tcp.Write(envelope)
	if err != nil {
		return
	}

	// change the state of NAS messages
	ue.NasContext.SetRegistered()

	// send the pdu establishment request for establish the pdu session
}
