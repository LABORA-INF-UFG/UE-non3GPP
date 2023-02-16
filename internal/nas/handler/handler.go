package handler

import (
	"UE-non3GPP/internal/nas/context"
	nasMessage "UE-non3GPP/internal/nas/message"
	"github.com/free5gc/nas"
)

func HandlerAuthenticationRequest(ue *context.UeNas, message *nas.Message) []byte {
	var authenticationResponse []byte

	// check authentication message (RAND and AUTN).
	rand := message.AuthenticationRequest.GetRANDValue()
	autn := message.AuthenticationRequest.GetAUTN()

	// getting RES*
	paramAutn, check := ue.DeriveRESstarAndSetKey(ue.NasSecurity.AuthenticationSubs,
		rand[:],
		ue.NasSecurity.Snn,
		autn[:])

	switch check {

	case "MAC failure":
		authenticationResponse = nasMessage.BuildAuthenticationFailure("MAC failure",
			"", paramAutn)
	case "SQN failure":
		authenticationResponse = nasMessage.GetAuthenticationFailure("SQN failure",
			"", paramAutn)
	case "successful":
		// getting NAS Authentication Response.
		authenticationResponse = nasMessage.BuildAuthenticationResponse(paramAutn,
			"")
	}

	// sending to IKE stack
	return authenticationResponse
}

func HandlerSecurityModeCommand(ue *context.UeNas, message *nas.Message) []byte {

	// TODO check security Mode Command Message
	// getting NAS Security Mode Complete
	securityModeComplete := nasMessage.BuildSecurityModeComplete(ue)

	// sending to IKE stack
	return securityModeComplete
}

/*
func HandlerRegistrationAccept(ue *context.UeNas, message *nas.Message) {

	// change the state of ue for registered
	ue.SetStateMM_REGISTERED()

	// saved 5g GUTI and others information.
	ue.SetAmfRegionId(message.RegistrationAccept.GetAMFRegionID())
	ue.SetAmfPointer(message.RegistrationAccept.GetAMFPointer())
	ue.SetAmfSetId(message.RegistrationAccept.GetAMFSetID())
	ue.Set5gGuti(message.RegistrationAccept.GetTMSI5G())

	// use the slice allowed by the network
	// in PDU session request
	if ue.PduSession.Snssai.Sst == 0 {

		// check the allowed NSSAI received from the 5GC
		snssai := message.RegistrationAccept.AllowedNSSAI.GetSNSSAIValue()

		// update UE slice selected for PDU Session
		ue.PduSession.Snssai.Sst = int32(snssai[1])
		ue.PduSession.Snssai.Sd = fmt.Sprintf("0%x0%x0%x", snssai[2], snssai[3], snssai[4])

		log.Warn("[UE][NAS] ALLOWED NSSAI: SST: ", ue.PduSession.Snssai.Sst, " SD: ", ue.PduSession.Snssai.Sd)
	}

	log.Info("[UE][NAS] UE 5G GUTI: ", ue.Get5gGuti())

	// getting NAS registration complete.
	registrationComplete, err := mm_5gs.RegistrationComplete(ue)
	if err != nil {
		log.Fatal("[UE][NAS] Error sending Registration Complete: ", err)
	}

	// sending to GNB
	sender.SendToGnb(ue, registrationComplete)

	// waiting receive Configuration Update Command.
	time.Sleep(20 * time.Millisecond)

	// getting ul nas transport and pduSession establishment request.
	ulNasTransport, err := mm_5gs.UlNasTransport(ue, nasMessage.ULNASTransportRequestTypeInitialRequest)
	if err != nil {
		log.Fatal("[UE][NAS] Error sending ul nas transport and pdu session establishment request: ", err)
	}

	// change the sate of ue(SM).
	ue.SetStateSM_PDU_SESSION_PENDING()

	// sending to GNB
	sender.SendToGnb(ue, ulNasTransport)
}

func HandlerDlNasTransportPduaccept(ue *context.UeNas, message *nas.Message) {

	//getting PDU Session establishment accept.
	payloadContainer := nas_control.GetNasPduFromPduAccept(message)
	if payloadContainer.GsmHeader.GetMessageType() == nas.MsgTypePDUSessionEstablishmentAccept {
		log.Info("[UE][NAS] Receiving PDU Session Establishment Accept")

		// update PDU Session information.

		// change the state of ue(SM)(PDU Session Active).
		ue.SetStateSM_PDU_SESSION_ACTIVE()

		// get UE ip
		UeIp := payloadContainer.PDUSessionEstablishmentAccept.GetPDUAddressInformation()
		ue.SetIp(UeIp)
	}
}
*/
