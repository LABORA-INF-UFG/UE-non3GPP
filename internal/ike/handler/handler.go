package handler

import (
	"UE-non3GPP/engine/exchange/pkg/context"
	"UE-non3GPP/engine/exchange/pkg/ike/message"
	"fmt"
	"net"
)

func HandleIKESAINIT(udpConn *net.UDPConn, ikeMsg *message.IKEMessage) {

	// handle IKE SA INIT Response
	var securityAssociation *message.SecurityAssociation
	var keyExchange *message.KeyExchange
	var nonce *message.Nonce
	var notifications []*message.Notification
	var sharedKeyData []byte

	if ikeMsg.Flags != message.ResponseBitCheck {
		// TODO handle errors in ike header
		return
	}

	// recover UE information basead in parameters of ike message
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

	if securityAssociation != nil {
	}

	// handle keyExchange
	if keyExchange != nil {

		var localPublicValue []byte
		_, sharedKeyData = CalculateDiffieHellmanMaterials(GenerateRandomNumber(),
			keyExchange.KeyExchangeData, chosenDiffieHellmanGroup)
	}

	if nonce != nil {
	}

	ikeSecurityAssociation := &context.IKESecurityAssociation{
		LocalSPI:               ikeInitiatorSPI,
		RemoteSPI:              ikeMsg.ResponderSPI,
		InitiatorMessageID:     0,
		ResponderMessageID:     0,
		EncryptionAlgorithm:    proposal.EncryptionAlgorithm[0],
		IntegrityAlgorithm:     proposal.IntegrityAlgorithm[0],
		PseudorandomFunction:   proposal.PseudorandomFunction[0],
		DiffieHellmanGroup:     proposal.DiffieHellmanGroup[0],
		ConcatenatedNonce:      append(localNonce, remoteNonce...),
		DiffieHellmanSharedKey: sharedKeyData,
	}

	if err := GenerateKeyForIKESA(ikeSecurityAssociation); err != nil {
		// TODO handle errors
		return
	}

}

func HandleIKEAUTH(udpConn *net.UDPConn, ikeMsg *message.IKEMessage) {
	fmt.Println(udpConn)
	fmt.Println(ikeMsg)
}

func HandleCREATECHILDSA(udpConn *net.UDPConn, ikeMsg *message.IKEMessage) {
	fmt.Println(udpConn)
	fmt.Println(ikeMsg)
}
