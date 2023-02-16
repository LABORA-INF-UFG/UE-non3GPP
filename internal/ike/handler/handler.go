package handler

import (
	"UE-non3GPP/internal/ike/context"
	"UE-non3GPP/internal/ike/message"
	"UE-non3GPP/internal/nas/dispatch"
	messageNas "UE-non3GPP/internal/nas/message"
	"encoding/binary"
	"fmt"
	"math/big"
)

func HandleIKESAINIT(ue *context.UeIke, ikeMsg *message.IKEMessage) {

	// handle IKE SA INIT Response
	var securityAssociation *message.SecurityAssociation
	var notifications []*message.Notification
	var sharedKeyData []byte
	var remoteNonce []byte
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
			remotePublicKeyExchangeValue := ikePayload.(*message.KeyExchange).KeyExchangeData
			var i int = 0
			for {
				if remotePublicKeyExchangeValue[i] != 0 {
					break
				}
			}
			remotePublicKeyExchangeValue = remotePublicKeyExchangeValue[i:]
			remotePublicKeyExchangeValueBig := new(big.Int).
				SetBytes(remotePublicKeyExchangeValue)
			sharedKeyData = new(big.Int).Exp(remotePublicKeyExchangeValueBig,
				ue.GetSecret(), ue.GetFactor()).Bytes()
		case message.TypeNiNr:
			remoteNonce = ikePayload.(*message.Nonce).NonceData
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

	ikeSecurityAssociation := &context.IKESecurityAssociation{
		LocalSPI:               ikeMsg.InitiatorSPI,
		RemoteSPI:              ikeMsg.ResponderSPI,
		InitiatorMessageID:     ikeMsg.MessageID,
		ResponderMessageID:     ikeMsg.MessageID,
		EncryptionAlgorithm:    encryptionAlgorithmTransform,
		IntegrityAlgorithm:     integrityAlgorithmTransform,
		PseudorandomFunction:   pseudorandomFunctionTransform,
		DiffieHellmanGroup:     diffieHellmanGroupTransform,
		ConcatenatedNonce:      append(ue.GetLocalNonce(), remoteNonce...),
		DiffieHellmanSharedKey: sharedKeyData,
	}

	if err := context.GenerateKeyForIKESA(ikeSecurityAssociation); err != nil {
		// TODO handle errors
		return
	}

	// create ike security assocation
	ue.CreateN3IWFIKESecurityAssociation(ikeSecurityAssociation)

	// send IKE_AUTH
	responseIKEMessage := new(message.IKEMessage)

	ue.N3IWFIKESecurityAssociation.InitiatorMessageID++

	responseIKEMessage.BuildIKEHeader(
		ue.N3IWFIKESecurityAssociation.LocalSPI, ue.N3IWFIKESecurityAssociation.RemoteSPI,
		message.IKE_AUTH, message.InitiatorBitCheck,
		ue.N3IWFIKESecurityAssociation.InitiatorMessageID)

	var ikePayload message.IKEPayloadContainer

	// Identification
	ikePayload.BuildIdentificationInitiator(message.ID_FQDN, []byte("UE"))

	// Security Association
	securityAssociation = ikePayload.BuildSecurityAssociation()

	var attributeType uint16 = message.AttributeTypeKeyLength
	var keyLength uint16 = 256

	// Proposal 1
	inboundSPI := ue.GenerateSPI()

	proposal := securityAssociation.Proposals.BuildProposal(1,
		message.TypeESP, inboundSPI)
	// ENCR
	proposal.EncryptionAlgorithm.BuildTransform(message.TypeEncryptionAlgorithm,
		ue.GetEncryptionAlgoritm(), &attributeType, &keyLength, nil)
	// INTEG
	proposal.IntegrityAlgorithm.BuildTransform(message.TypeIntegrityAlgorithm,
		ue.GetIntegrityAlgorithm(), nil, nil,
		nil)
	// ESN
	proposal.ExtendedSequenceNumbers.BuildTransform(message.TypeExtendedSequenceNumbers,
		message.ESN_NO, nil, nil, nil)

	// Traffic Selector
	tsi := ikePayload.BuildTrafficSelectorInitiator()
	tsi.TrafficSelectors.BuildIndividualTrafficSelector(message.TS_IPV4_ADDR_RANGE,
		0, 0, 65535,
		[]byte{0, 0, 0, 0}, []byte{255, 255, 255, 255})
	tsr := ikePayload.BuildTrafficSelectorResponder()
	tsr.TrafficSelectors.BuildIndividualTrafficSelector(message.TS_IPV4_ADDR_RANGE,
		0, 0, 65535, []byte{0, 0, 0, 0},
		[]byte{255, 255, 255, 255})

	if err := context.EncryptProcedure(ue.N3IWFIKESecurityAssociation, ikePayload,
		responseIKEMessage); err != nil {
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

const (
	PreSignalling = iota
	EAPSignalling
	PostSignalling
)

func HandleIKEAUTH(ue *context.UeIke, ikeMsg *message.IKEMessage) {

	var encryptedPayload *message.Encrypted

	if ikeMsg.Flags != message.ResponseBitCheck {
		// TODO handle errors in IKE header
		return
	}

	localSPI := ikeMsg.ResponderSPI
	if localSPI != ue.N3IWFIKESecurityAssociation.RemoteSPI {
		// TODO handle errors in IKE header
		return
	}

	for _, ikePayload := range ikeMsg.Payloads {
		switch ikePayload.Type() {
		case message.TypeSK:
			encryptedPayload = ikePayload.(*message.Encrypted)
		default:
			return
		}
	}

	decryptedIKEPayload, err := context.DecryptProcedure(ue.N3IWFIKESecurityAssociation,
		ikeMsg, encryptedPayload)
	if err != nil {
		// TODO handle errors in IKE header
		return
	}

	var eap *message.EAP

	for _, ikePayload := range decryptedIKEPayload {
		switch ikePayload.Type() {
		case message.TypeIDi:
			_ = ikePayload.(*message.IdentificationInitiator)
		case message.TypeCERTreq:
			_ = ikePayload.(*message.CertificateRequest)
		case message.TypeCERT:
			_ = ikePayload.(*message.Certificate)
		case message.TypeSA:
			_ = ikePayload.(*message.SecurityAssociation)
		case message.TypeTSi:
			_ = ikePayload.(*message.TrafficSelectorInitiator)
		case message.TypeTSr:
			_ = ikePayload.(*message.TrafficSelectorResponder)
		case message.TypeEAP:
			eap = ikePayload.(*message.EAP)
		case message.TypeAUTH:
			_ = ikePayload.(*message.Authentication)
		case message.TypeCP:
			_ = ikePayload.(*message.Configuration)
		default:
			// TODO handle errors in IKE header
		}
	}

	var ikePayload message.IKEPayloadContainer
	var responseIKEMessage *message.IKEMessage

	responseIKEMessage = new(message.IKEMessage)

	switch ue.N3IWFIKESecurityAssociation.State {
	case PreSignalling:
		// IKE_AUTH - EAP exchange
		ue.N3IWFIKESecurityAssociation.InitiatorMessageID++

		responseIKEMessage.BuildIKEHeader(
			ue.N3IWFIKESecurityAssociation.LocalSPI,
			ue.N3IWFIKESecurityAssociation.RemoteSPI,
			message.IKE_AUTH, message.InitiatorBitCheck,
			ue.N3IWFIKESecurityAssociation.InitiatorMessageID)

		// EAP-5G vendor type data
		//TODO duplicate code
		eapVendorTypeData := make([]byte, 2)
		eapVendorTypeData[0] = message.EAP5GType5GNAS

		// AN Parameters
		// TODO Hardcode snssai, mcc, mnc and guami information
		anParameters := message.BuildEAP5GANParameters()
		anParametersLength := make([]byte, 2)
		binary.BigEndian.PutUint16(anParametersLength, uint16(len(anParameters)))
		eapVendorTypeData = append(eapVendorTypeData, anParametersLength...)
		eapVendorTypeData = append(eapVendorTypeData, anParameters...)

		// Send Registration Request
		// create context for NAS signal
		registrationRequest := messageNas.BuildRegistrationRequest(ue.NasContext)
		nasLength := make([]byte, 2)
		binary.BigEndian.PutUint16(nasLength, uint16(len(registrationRequest)))
		eapVendorTypeData = append(eapVendorTypeData, nasLength...)
		eapVendorTypeData = append(eapVendorTypeData, registrationRequest...)

		// EAP
		eap := ikePayload.BuildEAP(message.EAPCodeResponse, eap.Identifier)
		eap.EAPTypeData.BuildEAPExpanded(message.VendorID3GPP, message.VendorTypeEAP5G,
			eapVendorTypeData)
		if err := context.EncryptProcedure(ue.N3IWFIKESecurityAssociation, ikePayload,
			responseIKEMessage); err != nil {
			// TODO handle errors
			return
		}

		// change the IKE state to EAP signalling
		ue.N3IWFIKESecurityAssociation.State++

	case EAPSignalling:

		// receive EAP/NAS messages
		// get NAS data
		eapExpanded, ok := eap.EAPTypeData[0].(*message.EAPExpanded)
		if !ok {
			// TODO handle errors in IKE header
			return
		}
		nasData := eapExpanded.VendorData[4:]

		// handle NAS message
		responseNas, error := dispatch.DispatchNas(nasData, ue.NasContext)
		if error != nil {
			// TODO handle errors in IKE header
			return
		}

		ue.N3IWFIKESecurityAssociation.InitiatorMessageID++

		responseIKEMessage.BuildIKEHeader(
			ue.N3IWFIKESecurityAssociation.LocalSPI,
			ue.N3IWFIKESecurityAssociation.RemoteSPI,
			message.IKE_AUTH, message.InitiatorBitCheck,
			ue.N3IWFIKESecurityAssociation.InitiatorMessageID,
		)

		// EAP-5G vendor type data
		eapVendorTypeData := make([]byte, 4)
		eapVendorTypeData[0] = message.EAP5GType5GNAS

		// NAS messages
		nasLength := make([]byte, 2)
		binary.BigEndian.PutUint16(nasLength, uint16(len(responseNas)))
		eapVendorTypeData = append(eapVendorTypeData, nasLength...)
		eapVendorTypeData = append(eapVendorTypeData, responseNas...)

		// EAP
		eap := ikePayload.BuildEAP(message.EAPCodeResponse, eap.Identifier)
		eap.EAPTypeData.BuildEAPExpanded(message.VendorID3GPP, message.VendorTypeEAP5G,
			eapVendorTypeData)
		if err := context.EncryptProcedure(ue.N3IWFIKESecurityAssociation,
			ikePayload, responseIKEMessage); err != nil {
			// TODO handle errors
			return
		}

	case PostSignalling:
		// TODO implement this information
	default:
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

func HandleCREATECHILDSA(ue *context.UeIke, ikeMsg *message.IKEMessage) {
	fmt.Println(ue)
	fmt.Println(ikeMsg)
}
