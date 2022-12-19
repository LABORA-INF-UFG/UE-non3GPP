package util

import (
	"github.com/free5gc/nas/security"
	"github.com/free5gc/openapi/models"
)

type RanUeContext struct {
	Supi               string
	RanUeNgapId        int64
	AmfUeNgapId        int64
	ULCount            security.Count
	DLCount            security.Count
	CipheringAlg       uint8
	IntegrityAlg       uint8
	KnasEnc            [16]uint8
	KnasInt            [16]uint8
	Kamf               []uint8
	AnType             models.AccessType
	AuthenticationSubs models.AuthenticationSubscription
}

func NewRanUeContext(supi string, ranUeNgapId int64, cipheringAlg, integrityAlg uint8,
	AnType models.AccessType) *RanUeContext {
	ue := RanUeContext{}
	ue.RanUeNgapId = ranUeNgapId
	ue.Supi = supi
	ue.CipheringAlg = cipheringAlg
	ue.IntegrityAlg = integrityAlg
	ue.AnType = AnType
	return &ue
}
