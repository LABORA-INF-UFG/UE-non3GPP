package message

import (
	"UE-non3GPP/internal/nas/context"
	"encoding/hex"
	"fmt"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/nas/security"
)

func BuildAuthenticationFailure(cause, eapMsg string, paramAutn []byte) []byte {
	return GetAuthenticationFailure(cause, eapMsg, paramAutn)
}

func BuildAuthenticationResponse(paramAutn []uint8, eapMsg string) []byte {
	return GetAuthenticationResponse(eapMsg, paramAutn)
}

func BuildRegistrationRequest(ue *context.UeNas) []byte {

	// get mcc and mcc
	resu := getMccAndMncInOctets(ue.NasSecurity.Mcc, ue.NasSecurity.Mnc)

	// get msin
	suciV1, suciV2, suciV3, suciV4, suciV5 := encodeUeSuci(ue.NasSecurity.Msin)

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

func getMccAndMncInOctets(mcc, mnc string) []byte {

	// reverse mcc and mnc
	mcc = reverse(mcc)
	mnc = reverse(mnc)

	// include mcc and mnc in octets
	oct5 := mcc[1:3]
	var oct6 string
	var oct7 string
	if len(mnc) == 2 {
		oct6 = "f" + string(mcc[0])
		oct7 = mnc
	} else {
		oct6 = string(mnc[0]) + string(mcc[0])
		oct7 = mnc[1:3]
	}

	// changed for bytes.
	resu, err := hex.DecodeString(oct5 + oct6 + oct7)
	if err != nil {
		fmt.Println(err)
	}

	return resu
}

func reverse(s string) string {
	// reverse string.
	var aux string
	for _, valor := range s {
		aux = string(valor) + aux
	}
	return aux

}

func encodeUeSuci(msin string) (uint8, uint8, uint8, uint8, uint8) {

	// reverse imsi string.
	aux := reverse(msin)

	// calculate decimal value.
	suci, error := hex.DecodeString(aux)
	if error != nil {
		return 0, 0, 0, 0, 0
	}

	// return decimal value
	if len(msin) == 8 {
		return uint8(suci[0]), uint8(suci[1]), uint8(suci[2]), uint8(suci[3]), 0
	} else {
		return uint8(suci[0]), uint8(suci[1]), uint8(suci[2]), uint8(suci[3]), uint8(suci[4])
	}
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
