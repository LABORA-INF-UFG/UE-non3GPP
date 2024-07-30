package message

import (
	"UE-non3GPP/internal/nas/context"
	utils "UE-non3GPP/pkg/utils"
	"fmt"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/nas/security"
	log "github.com/sirupsen/logrus"
	"net"
)

func GetPduAddresFromPduEstablishmentAccept(message *nas.Message) net.IP {

	container := getNasPduAcceptFromDlNasTransport(message)
	if container.GsmHeader.GetMessageType() == nas.MsgTypePDUSessionEstablishmentAccept {
		// get UE ip
		UeIp := container.PDUSessionEstablishmentAccept.GetPDUAddressInformation()
		return net.IPv4(UeIp[0], UeIp[1], UeIp[2], UeIp[3])
	}

	return nil
}
func BuildSecurityModeComplete(ue *context.UeNas) []byte {
	var registrationRequest []byte

	registrationRequest = BuildRegistrationRequest(ue)
	securityModeComplete := GetSecurityModeComplete(registrationRequest)
	securityModeCompleteWithSecurityHeader, _ := EncodeNasPduWithSecurity(ue,
		securityModeComplete,
		nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext,
		true, true)

	return securityModeCompleteWithSecurityHeader
}

func BuildRegistrationComplete(ue *context.UeNas) []byte {
	var registrationComplete []byte

	registrationComplete = GetRegistrationComplete(nil)
	registrationCompleteWithSecurityHeader, _ := EncodeNasPduWithSecurity(ue,
		registrationComplete,
		nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext,
		true, true)

	return registrationCompleteWithSecurityHeader
}

func BuildAuthenticationFailure(cause, eapMsg string, paramAutn []byte) []byte {
	return GetAuthenticationFailure(cause, eapMsg, paramAutn)
}

func BuildAuthenticationResponse(paramAutn []uint8, eapMsg string) []byte {
	return GetAuthenticationResponse(eapMsg, paramAutn)
}

func BuildRegistrationRequest(ue *context.UeNas) []byte {

	// get mcc and mcc
	resu := utils.GetMccAndMncInOctets(ue.NasSecurity.Mcc, ue.NasSecurity.Mnc)
	log.Info("Mcc and Mnc In Octets: % x", resu)

	// get msin
	suciV1, suciV2, suciV3, suciV4, suciV5 := utils.EncodeUeSuci(ue.NasSecurity.Msin)

	//fmt.Printf("codedAMFServedGUAMI: %d\n", codedAMFServedGUAMI)
	//fmt.Printf("codedAMFServedGUAMI: %v\n", codedAMFServedGUAMI)
	//fmt.Printf("codedAMFServedGUAMI: %x\n", codedAMFServedGUAMI)

	log.Info("suciV1: %d\n", suciV1)
	log.Info("suciV2: %d\n", suciV2)
	log.Info("suciV3: %d\n", suciV3)
	log.Info("suciV4: %d\n", suciV4)
	log.Info("suciV5: %d\n", suciV5)

	var suci nasType.MobileIdentity5GS

	if len(ue.NasSecurity.Msin) == 8 {
		suci = nasType.MobileIdentity5GS{
			Len:    12,
			Buffer: []uint8{0x01, resu[0], resu[1], resu[2], 0xf0, 0xff, 0x00, 0x00, suciV4, suciV3, suciV2, suciV1},
		}
	} else if len(ue.NasSecurity.Msin) == 10 {
		suci = nasType.MobileIdentity5GS{
			Len:    13,
			Buffer: []uint8{0x01, resu[0], resu[1], resu[2], 0xf0, 0xff, 0x00, 0x00, suciV5, suciV4, suciV3, suciV2, suciV1},
		}
	}

	// get capability 5GMM
	capability5GMM := &nasType.Capability5GMM{
		Iei:   nasMessage.RegistrationRequestCapability5GMMType,
		Len:   1,
		Octet: [13]uint8{0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}

	return GetRegistrationRequest(
		nasMessage.RegistrationType5GSInitialRegistration,
		suci,
		nil,
		getUESecurityCapability(ue.NasSecurity.CipheringAlg, ue.NasSecurity.IntegrityAlg),
		capability5GMM,
		nil,
		nil,
	)
}

func BuildPduEstablishmentRequest(ue *context.UeNas) []byte {
	var ulNasPduRequestMessage []byte

	ulNasPduRequestMessage = GetUlNasTransport(ue.PduSession.Id,
		nasMessage.ULNASTransportRequestTypeInitialRequest,
		ue.PduSession.Dnn,
		&ue.PduSession.Snssai)
	ulNasPduRequestMessageWithSecurityHeader, _ := EncodeNasPduWithSecurity(ue,
		ulNasPduRequestMessage,
		nas.SecurityHeaderTypeIntegrityProtectedAndCiphered,
		true, false)

	return ulNasPduRequestMessageWithSecurityHeader

}

func getUESecurityCapability(cipheringAlg, integrityAlg uint8) (UESecurityCapability *nasType.UESecurityCapability) {
	UESecurityCapability = &nasType.UESecurityCapability{
		Iei:    nasMessage.RegistrationRequestUESecurityCapabilityType,
		Len:    2,
		Buffer: []uint8{0x00, 0x00},
	}
	switch cipheringAlg {
	case security.AlgCiphering128NEA0:
		UESecurityCapability.SetEA0_5G(1)
	case security.AlgCiphering128NEA1:
		UESecurityCapability.SetEA1_128_5G(1)
	case security.AlgCiphering128NEA2:
		UESecurityCapability.SetEA2_128_5G(1)
	case security.AlgCiphering128NEA3:
		UESecurityCapability.SetEA3_128_5G(1)
	}

	switch integrityAlg {
	case security.AlgIntegrity128NIA0:
		UESecurityCapability.SetIA0_5G(1)
	case security.AlgIntegrity128NIA1:
		UESecurityCapability.SetIA1_128_5G(1)
	case security.AlgIntegrity128NIA2:
		UESecurityCapability.SetIA2_128_5G(1)
	case security.AlgIntegrity128NIA3:
		UESecurityCapability.SetIA3_128_5G(1)
	}

	return
}

func EncodeNasPduWithSecurity(ue *context.UeNas, pdu []byte,
	securityHeaderType uint8, securityContextAvailable,
	newSecurityContext bool) ([]byte, error) {

	m := nas.NewMessage()
	err := m.PlainNasDecode(&pdu)
	if err != nil {
		return nil, err
	}
	m.SecurityHeader = nas.SecurityHeader{
		ProtocolDiscriminator: nasMessage.Epd5GSMobilityManagementMessage,
		SecurityHeaderType:    securityHeaderType,
	}

	return NASEncode(ue, m, securityContextAvailable, newSecurityContext)
}

func NASEncode(ue *context.UeNas, msg *nas.Message,
	securityContextAvailable bool, newSecurityContext bool) (payload []byte, err error) {
	var sequenceNumber uint8
	if ue == nil {
		err = fmt.Errorf("amfUe is nil")
		return
	}
	if msg == nil {
		err = fmt.Errorf("Nas message is empty")
		return
	}

	if !securityContextAvailable {
		return msg.PlainNasEncode()
	} else {
		if newSecurityContext {
			ue.NasSecurity.ULCount.Set(0, 0)
			ue.NasSecurity.DLCount.Set(0, 0)
		}

		sequenceNumber = ue.NasSecurity.ULCount.SQN()
		payload, err = msg.PlainNasEncode()
		if err != nil {
			return
		}

		// TODO: Support for ue has nas connection in both accessType
		// make ciphering of NAS message.
		if err = security.NASEncrypt(ue.NasSecurity.CipheringAlg,
			ue.NasSecurity.KnasEnc, ue.NasSecurity.ULCount.Get(),
			security.BearerNon3GPP, security.DirectionUplink,
			payload); err != nil {
			return
		}

		// add sequence number
		payload = append([]byte{sequenceNumber}, payload[:]...)
		mac32 := make([]byte, 4)

		mac32, err = security.NASMacCalculate(ue.NasSecurity.IntegrityAlg,
			ue.NasSecurity.KnasInt, ue.NasSecurity.ULCount.Get(),
			security.BearerNon3GPP, security.DirectionUplink,
			payload)
		if err != nil {
			return
		}

		// Add mac value
		payload = append(mac32, payload[:]...)
		// Add EPD and Security Type
		msgSecurityHeader := []byte{msg.SecurityHeader.ProtocolDiscriminator,
			msg.SecurityHeader.SecurityHeaderType}
		payload = append(msgSecurityHeader,
			payload[:]...)

		// Increase UL Count
		ue.NasSecurity.ULCount.AddOne()
	}
	return
}
