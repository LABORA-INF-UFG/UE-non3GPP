package handler

import (
	"UE-non3GPP/internal/ike/context"
	"UE-non3GPP/internal/ike/message"
	"fmt"
)

func HandleIKESAINIT(ue *context.Ue, ikeMsg *message.IKEMessage) {

	// handle IKE SA INIT Response
	var securityAssociation *message.SecurityAssociation
	var keyExchange *message.KeyExchange
	var nonce *message.Nonce
	var notifications []*message.Notification
	var sharedKeyData []byte
	var concatenatedNonce []byte
	var encryptionAlgorithmTransform, pseudorandomFunctionTransform *message.Transform
	var integrityAlgorithmTransform, diffieHellmanGroupTransform *message.Transform

	if ikeMsg.Flags != message.ResponseBitCheck {
		// TODO handle errors in ike header
		return
	}

	// recover UE information based in parameters of ike message
	for _, ikePayload := range ikeMsg.Payloads {
		switch ikePayload.Type() {
		case message.TypeSA:
			securityAssociation = ikePayload.(*message.SecurityAssociation)
		case message.TypeKE:
			keyExchange = ikePayload.(*message.KeyExchange)
		case message.TypeNiNr:
			nonce = ikePayload.(*message.Nonce)
		case message.TypeN:
			notifications = append(notifications, ikePayload.(*message.Notification))
		default:
			// TODO handle in ike payloads
		}
	}

	// retrieve client context

	if securityAssociation != nil {

		for _, proposal := range securityAssociation.Proposals {
			// We need ENCR, PRF, INTEG, DH
			encryptionAlgorithmTransform = nil
			pseudorandomFunctionTransform = nil
			integrityAlgorithmTransform = nil
			diffieHellmanGroupTransform = nil

			if len(proposal.EncryptionAlgorithm) > 0 {
				for _, transform := range proposal.EncryptionAlgorithm {
					if transform.TransformID == ue.GetEncryptionAlgoritm() {
						encryptionAlgorithmTransform = transform
						break
					}
				}
				if encryptionAlgorithmTransform == nil {
					continue
				}
			} else {
				continue // mandatory
			}

			if len(proposal.PseudorandomFunction) > 0 {
				for _, transform := range proposal.PseudorandomFunction {
					if transform.TransformID == ue.GetPseudorandomFunction() {
						pseudorandomFunctionTransform = transform
						break
					}
				}
				if pseudorandomFunctionTransform == nil {
					continue
				}
			} else {
				continue // mandatory
			}

			if len(proposal.IntegrityAlgorithm) > 0 {
				for _, transform := range proposal.IntegrityAlgorithm {
					if transform.TransformID == ue.GetIntegrityAlgorithm() {
						integrityAlgorithmTransform = transform
						break
					}
				}
				if integrityAlgorithmTransform == nil {
					continue
				}
			} else {
				continue // mandatory
			}

			if len(proposal.DiffieHellmanGroup) > 0 {
				for _, transform := range proposal.DiffieHellmanGroup {
					if transform.TransformID == ue.GetDiffieHellmanGroup() {
						diffieHellmanGroupTransform = transform
						break
					}
				}
				if diffieHellmanGroupTransform == nil {
					continue
				}
			} else {
				continue // mandatory
			}

		}
	}

	// handle keyExchange
	if keyExchange != nil {
		_, sharedKeyData = context.CalculateDiffieHellmanMaterials(context.GenerateRandomNumber(),
			keyExchange.KeyExchangeData, ue.GetDiffieHellmanGroup())
	}

	if nonce != nil {
		localNonce := context.GenerateRandomNumber().Bytes()
		concatenatedNonce = append(nonce.NonceData, localNonce...)
	}

	ikeSecurityAssociation := &context.IKESecurityAssociation{
		LocalSPI:               ikeMsg.InitiatorSPI,
		RemoteSPI:              ikeMsg.ResponderSPI,
		InitiatorMessageID:     ikeMsg.MessageID + 1,
		ResponderMessageID:     ikeMsg.MessageID + 1,
		EncryptionAlgorithm:    encryptionAlgorithmTransform,
		IntegrityAlgorithm:     integrityAlgorithmTransform,
		PseudorandomFunction:   pseudorandomFunctionTransform,
		DiffieHellmanGroup:     diffieHellmanGroupTransform,
		ConcatenatedNonce:      concatenatedNonce,
		DiffieHellmanSharedKey: sharedKeyData,
	}

	if err := context.GenerateKeyForIKESA(ikeSecurityAssociation); err != nil {
		// TODO handle errors
		return
	}

	// send IKE_AUTH
	responseIKEMessage := new(message.IKEMessage)
	responseIKEMessage.BuildIKEHeader(
		ikeSecurityAssociation.LocalSPI, ikeSecurityAssociation.RemoteSPI,
		message.IKE_AUTH, message.InitiatorBitCheck, ikeSecurityAssociation.InitiatorMessageID)

	var ikePayload message.IKEPayloadContainer

	// Identification
	ikePayload.BuildIdentificationInitiator(message.ID_FQDN, []byte("UE"))

	// Security Association
	securityAssociation = ikePayload.BuildSecurityAssociation()

	var attributeType uint16 = message.AttributeTypeKeyLength
	var keyLength uint16 = 256

	// Proposal 1
	inboundSPI := ue.GenerateSPI()

	proposal := securityAssociation.Proposals.BuildProposal(1, message.TypeESP, inboundSPI)
	// ENCR
	proposal.EncryptionAlgorithm.BuildTransform(message.TypeEncryptionAlgorithm, ue.GetEncryptionAlgoritm(), &attributeType, &keyLength, nil)
	// INTEG
	proposal.IntegrityAlgorithm.BuildTransform(message.TypeIntegrityAlgorithm, ue.GetIntegrityAlgorithm(), nil, nil, nil)
	// ESN
	proposal.ExtendedSequenceNumbers.BuildTransform(message.TypeExtendedSequenceNumbers, message.ESN_NO, nil, nil, nil)

	// Traffic Selector
	tsi := ikePayload.BuildTrafficSelectorInitiator()
	tsi.TrafficSelectors.BuildIndividualTrafficSelector(message.TS_IPV4_ADDR_RANGE, 0, 0, 65535, []byte{0, 0, 0, 0}, []byte{255, 255, 255, 255})
	tsr := ikePayload.BuildTrafficSelectorResponder()
	tsr.TrafficSelectors.BuildIndividualTrafficSelector(message.TS_IPV4_ADDR_RANGE, 0, 0, 65535, []byte{0, 0, 0, 0}, []byte{255, 255, 255, 255})

	if err := context.EncryptProcedure(ikeSecurityAssociation, ikePayload, responseIKEMessage); err != nil {
		// TODO handle errors
		return
	}

	// Send to N3IWF
	ikeMessageData, err := responseIKEMessage.Encode()
	if err != nil {
		// TODO handle errors
		return
	}
	udp := ue.GetUdpConn()
	_, err = udp.Write(ikeMessageData)
	if err != nil {
		// TODO handle errors
		return
	}

}

func HandleIKEAUTH(ue *context.Ue, ikeMsg *message.IKEMessage) {
	fmt.Println(ue)
	fmt.Println(ikeMsg)
}

func HandleCREATECHILDSA(ue *context.Ue, ikeMsg *message.IKEMessage) {
	fmt.Println(ue)
	fmt.Println(ikeMsg)
}
