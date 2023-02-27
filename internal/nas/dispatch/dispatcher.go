package dispatch

import (
	"UE-non3GPP/internal/nas/context"
	"UE-non3GPP/internal/nas/handler"
	"fmt"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/security"
	"reflect"
)

func DispatchNas(message []byte, ue *context.UeNas) ([]byte, error) {

	var cph bool

	// check if message is null.
	if message == nil {
		// TODO return error
		// log.Fatal("[UE][NAS] NAS message is nil")
		return nil, fmt.Errorf("[UE][NAS] NAS message is nil")
	}

	// decode NAS message.
	m := new(nas.Message)
	m.SecurityHeaderType = nas.GetSecurityHeaderType(message) & 0x0f

	payload := message

	// check if NAS is security protected
	if m.SecurityHeaderType != nas.SecurityHeaderTypePlainNas {

		// log.Info("[UE][NAS] Message with security header")

		// information to check integrity and ciphered.

		// sequence number
		sequenceNumber := payload[6]

		// mac verification
		macReceived := payload[2:6]

		// remove security Header except for sequence Number
		payload := payload[6:]

		// check security header type.
		cph = false
		switch m.SecurityHeaderType {

		case nas.SecurityHeaderTypeIntegrityProtected:
			// log.Info("[UE][NAS] Message with integrity")

		case nas.SecurityHeaderTypeIntegrityProtectedAndCiphered:
			// log.Info("[UE][NAS] Message with integrity and ciphered")
			cph = true

		case nas.SecurityHeaderTypeIntegrityProtectedWithNew5gNasSecurityContext:
			// log.Info("[UE][NAS] Message with integrity and with NEW 5G NAS SECURITY CONTEXT")
			ue.NasSecurity.DLCount.Set(0, 0)

		case nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext:
			//log.Info("[UE][NAS] Message with integrity, ciphered and with NEW 5G NAS SECURITY CONTEXT")
			cph = true
			ue.NasSecurity.DLCount.Set(0, 0)

		}

		// check security header(Downlink data).
		if ue.NasSecurity.DLCount.SQN() > sequenceNumber {
			ue.NasSecurity.DLCount.SetOverflow(ue.NasSecurity.DLCount.Overflow() + 1)
		}
		ue.NasSecurity.DLCount.SetSQN(sequenceNumber)

		mac32, err := security.NASMacCalculate(ue.NasSecurity.IntegrityAlg,
			ue.NasSecurity.KnasInt, ue.NasSecurity.DLCount.Get(),
			security.BearerNon3GPP, security.DirectionDownlink,
			payload)
		if err != nil {
			return nil, fmt.Errorf("NAS MAC calculate error")
		}

		// check integrity
		if !reflect.DeepEqual(mac32, macReceived) {
			return nil, fmt.Errorf("[UE][NAS] NAS MAC verification failed(received:", macReceived, "expected:", mac32)
		} else {
			//log.Info("[UE][NAS] successful NAS MAC verification")
		}

		// check ciphering.
		if cph {
			if err = security.NASEncrypt(ue.NasSecurity.CipheringAlg,
				ue.NasSecurity.KnasEnc, ue.NasSecurity.DLCount.Get(),
				security.BearerNon3GPP, security.DirectionDownlink,
				payload[1:]); err != nil {
				return nil, fmt.Errorf("error in encrypt algorithm")
			} else {
				// log.Info("[UE][NAS] successful NAS CIPHERING")
			}
		}

		// remove security header.
		payload = message[7:]

		// decode NAS message.
		err = m.PlainNasDecode(&payload)
		if err != nil {
			// TODO return error
			return nil, fmt.Errorf("[UE][NAS] Decode NAS error")
		}

	} else {
		// log.Info("[UE][NAS] Message without security header")

		// decode NAS message.
		err := m.PlainNasDecode(&payload)
		if err != nil {
			// TODO return error
			return nil, fmt.Errorf("[UE][NAS] Decode NAS error")
		}
	}

	switch m.GmmHeader.GetMessageType() {

	case nas.MsgTypeAuthenticationRequest:
		// handler authentication request.
		// log.Info("[UE][NAS] Receive Authentication Request")
		return handler.HandlerAuthenticationRequest(ue, m), nil

	case nas.MsgTypeAuthenticationReject:
		// handler authentication reject.
		// log.Info("[UE][NAS] Receive Authentication Reject")
		// handler.HandlerAuthenticationReject(ue, m)

	case nas.MsgTypeIdentityRequest:
		// log.Info("[UE][NAS] Receive Identify Request")
		// handler identity request.

	case nas.MsgTypeSecurityModeCommand:
		// handler security mode command.
		// log.Info("[UE][NAS] Receive Security Mode Command")
		return handler.HandlerSecurityModeCommand(ue, m), nil

	case nas.MsgTypeRegistrationAccept:
		// handler registration accept.
		// log.Info("[UE][NAS] Receive Registration Accept")
		return handler.HandlerRegistrationAccept(ue, m), nil

	case nas.MsgTypeConfigurationUpdateCommand:
		// log.Info("[UE][NAS] Receive Configuration Update Command")
		// handler Configuration Update Command.

	case nas.MsgTypeDLNASTransport:
		// handler DL NAS Transport.
		// log.Info("[UE][NAS] Receive DL NAS Transport")
		return handler.HandlerDlNasTransportPduaccept(ue, m), nil

	case nas.MsgTypeRegistrationReject:
		// handler registration reject
		// log.Info("[UE][NAS] Receive Registration Reject")
	}

	return nil, fmt.Errorf("[UE][NAS] Decode NAS error")
}
