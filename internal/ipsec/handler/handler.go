package handler

import (
	"UE-non3GPP/internal/ipsec/context"
	"UE-non3GPP/internal/nas/dispatch"
	"UE-non3GPP/internal/nas/message"
	"fmt"
	"time"
)

func HandlerRegisteredInitiated(ue *context.UeIpSec, msg []byte) {

	// get registration complete/correct response
	responseNas, error := dispatch.DispatchNas(msg, ue.NasContext)
	if error != nil {
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

	// TODO investigates
	time.Sleep(500 * time.Millisecond)

	// send the pdu establishment request for establish the pdu session
	pduRequest := message.BuildPduEstablishmentRequest(ue.NasContext)

	// set the message as NAS envelope
	envelope = ue.EncapNasMsgToEnvelope(pduRequest)

	// send PDU Session Request to N3IWF
	_, err = tcp.Write(envelope)
	if err != nil {
		return
	}

	// change the state of NAS messages
	ue.NasContext.SetPduSessionPending()
}

func HandlerPDUSession(ue *context.UeIpSec, msg []byte) {

	// get UE IP PDU Session
	_, error := dispatch.DispatchNas(msg, ue.NasContext)
	if error != nil {
		fmt.Println(error)
		return
	}

	// establish GRE Tunnel
}
