package handler

import (
	"UE-non3GPP/internal/ipsec/context"
	"UE-non3GPP/internal/nas/dispatch"
	"UE-non3GPP/internal/nas/message"
	log "github.com/sirupsen/logrus"
	"time"
)

func HandlerRegisteredInitiated(ue *context.UeIpSec, msg []byte) {

	// get registration complete/correct response
	responseNas, error := dispatch.DispatchNas(msg, ue.NasContext)
	if error != nil {
		log.Error("[UE][IPSEC][NAS] Error in NAS Handler")
		return
	}

	// set the message as NAS envelope
	envelope := ue.EncapNasMsgToEnvelope(responseNas)

	// send registration complete/correct response
	tcp := ue.GetTcpConn()
	_, err := tcp.Write(envelope)
	if err != nil {
		log.Error("[UE][IPSEC][CP] Write From TCP failed")
		return
	}

	// change the state of NAS messages
	ue.NasContext.SetRegistered()

	// TODO investigates
	time.Sleep(500 * time.Millisecond)

	// send the pdu establishment request for establish the pdu session
	log.Info("[UE][IPSEC][NAS] Send PDU Establishment Request")
	pduRequest := message.BuildPduEstablishmentRequest(ue.NasContext)

	// set the message as NAS envelope
	envelope = ue.EncapNasMsgToEnvelope(pduRequest)

	// send PDU Session Request to N3IWF
	_, err = tcp.Write(envelope)
	if err != nil {
		log.Error("[UE][IPSEC][CP] Write From TCP failed")
		return
	}

	// change the state of NAS messages
	ue.NasContext.SetPduSessionPending()
}

func HandlerPDUSession(ue *context.UeIpSec, msg []byte) {

	// get UE PDU Address Session
	_, error := dispatch.DispatchNas(msg, ue.NasContext)
	if error != nil {
		log.Error("[UE][IPSEC][NAS] Error in NAS Handler")
		return
	}

	log.Info("[UE][IPSEC][NAS] Receive PDU Establishment Accept")
}
