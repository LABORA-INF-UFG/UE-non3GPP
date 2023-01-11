package security

import (
	ran_ue "UE-non3GPP/engine/ran"
	"fmt"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/security"
	"github.com/free5gc/openapi/models"
)

func NASEncode(ue *ran_ue.RanUeContext, msg *nas.Message, securityContextAvailable bool, newSecurityContext bool) (
	payload []byte, err error) {
	var sequenceNumber uint8
	if ue == nil {
		err = fmt.Errorf("amfUe is nil")
		return
	}
	if msg == nil {
		err = fmt.Errorf("Nas Message is empty")
		return
	}

	if !securityContextAvailable {
		return msg.PlainNasEncode()
	} else {
		if newSecurityContext {
			ue.ULCount.Set(0, 0)
			ue.DLCount.Set(0, 0)
		}

		sequenceNumber = ue.ULCount.SQN()
		payload, err = msg.PlainNasEncode()
		if err != nil {
			return
		}

		if err = security.NASEncrypt(ue.CipheringAlg, ue.KnasEnc, ue.ULCount.Get(), ue.GetBearerType(),
			security.DirectionUplink, payload); err != nil {
			return
		}
		// add sequece number
		payload = append([]byte{sequenceNumber}, payload[:]...)
		mac32 := make([]byte, 4)
		_ = mac32

		//fmt.Println("ue.IntegrityAlg", ue.IntegrityAlg)
		//fmt.Println("ue.KnasInt", ue.KnasInt)
		//fmt.Println("ue.ULCount.Get()", ue.ULCount.Get())
		//fmt.Println("acessType", ue.GetBearerByType(models.AccessType_NON_3_GPP_ACCESS))
		//fmt.Println("security.DirectionUplink", security.DirectionUplink)
		//fmt.Println("payload", payload)

		//fmt.Println("sequenceNumber", sequenceNumber)
		//fmt.Println("security.Bearer3GPP", security.Bearer3GPP)

		mac32, err = security.NASMacCalculate(ue.IntegrityAlg, ue.KnasInt, ue.ULCount.Get(), ue.GetBearerByType(models.AccessType_NON_3_GPP_ACCESS),
			security.DirectionUplink, payload)
		if err != nil {
			return
		}

		// Add mac value
		payload = append(mac32, payload[:]...)

		//fmt.Println("tem isso aqui --> ", mac32[:])
		// Add EPD and Security Type
		msgSecurityHeader := []byte{msg.SecurityHeader.ProtocolDiscriminator, msg.SecurityHeader.SecurityHeaderType}
		payload = append(msgSecurityHeader, payload[:]...)

		// Increase UL Count
		ue.ULCount.AddOne()
	}
	return payload, err
}
