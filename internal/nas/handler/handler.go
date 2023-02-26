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

	// ipsec is operational send the message in envelope

	// sending to IKE stack
	return securityModeComplete
}

func HandlerRegistrationAccept(ue *context.UeNas, message *nas.Message) []byte {

	// change the state of UE for registered
	ue.SetRegistered()

	// getting NAS Registration Complete
	registrationComplete := nasMessage.BuildRegistrationComplete(ue)

	return registrationComplete
}

/*
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
