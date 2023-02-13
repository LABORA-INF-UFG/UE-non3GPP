package context

import (
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/nas/security"
	"github.com/free5gc/openapi/models"
)

type UeNas struct {
	id          uint8
	StateMM     int
	StateSM     int
	PduSession  PDUSession
	NasSecurity NASecurity
}

type PDUSession struct {
	Id     int32
	Snssai models.Snssai
	Dnn    string
}

type NASecurity struct {
	RanUeNgapId        int64
	AmfUeNgapId        int64
	Supi               string
	ULCount            security.Count
	DLCount            security.Count
	CipheringAlg       uint8
	IntegrityAlg       uint8
	Snn                string
	KnasEnc            [16]uint8
	KnasInt            [16]uint8
	Kamf               []uint8
	AuthenticationSubs models.AuthenticationSubscription
	Suci               nasType.MobileIdentity5GS
	Guti               [4]byte
	AnType             models.AccessType
}

func NewUeNas(supi string, ranUeNgapId int64,
	k, opc, op, amf, sqn string,
	sst int32, sd, dnn string) *UeNas {

	ue := &UeNas{}
	ue.id = 1
	ue.StateMM = 0
	ue.StateSM = 0
	ue.NasSecurity = newNasSecurity(supi, ranUeNgapId, security.AlgCiphering128NEA0,
		security.AlgIntegrity128NIA2, models.AccessType_NON_3_GPP_ACCESS, k,
		opc, op, amf, sqn)
	ue.PduSession = newPDUSession(1, sst, sd, dnn)
	ue.PduSession.Dnn = dnn

	return ue
}

func newPDUSession(id, sst int32, sd, dnn string) PDUSession {

	pdu := PDUSession{}
	pdu.Id = id
	pdu.Snssai.Sst = sst
	pdu.Snssai.Sd = sd
	pdu.Dnn = dnn

	return pdu
}

func newNasSecurity(supi string, ranUeNgapId int64, cipheringAlg, integrityAlg uint8,
	anType models.AccessType, k, opc, op, amf, sqn string) NASecurity {

	nas := NASecurity{}
	nas.Supi = supi
	nas.RanUeNgapId = ranUeNgapId
	nas.CipheringAlg = cipheringAlg
	nas.IntegrityAlg = integrityAlg
	nas.AnType = anType
	nas.AuthenticationSubs = setAuthSubscription(k, opc, op, amf, sqn)

	return nas
}

func setAuthSubscription(k, opc, op, amf, sqn string) models.AuthenticationSubscription {
	auth := models.AuthenticationSubscription{}
	auth.PermanentKey = &models.PermanentKey{
		PermanentKeyValue: k,
	}
	auth.Opc = &models.Opc{
		OpcValue: opc,
	}
	auth.Milenage = &models.Milenage{
		Op: &models.Op{
			OpValue: op,
		},
	}
	auth.AuthenticationManagementField = amf
	auth.SequenceNumber = sqn
	auth.AuthenticationMethod = models.AuthMethod__5_G_AKA
	return auth
}
