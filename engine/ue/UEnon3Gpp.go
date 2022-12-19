package ue

import (
	"fmt"
	"github.com/LABORA-INF-UFG/UE-non3GPP/config"
	context "github.com/LABORA-INF-UFG/UE-non3GPP/engine/mockups/n3iwf/context"
	"github.com/LABORA-INF-UFG/UE-non3GPP/engine/mockups/test"
	"github.com/LABORA-INF-UFG/UE-non3GPP/engine/util"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/nas/security"
	"github.com/free5gc/openapi/models"
	log "github.com/sirupsen/logrus"
)

func UENon3GPPConnection() {

	cfg, err := config.GetConfig()
	if err != nil {
		//return nil
		log.Fatal("Error in get configuration")
	}

	ue := util.NewRanUeContext(cfg.Ue.Supi, cfg.Ue.RanUeNgapId, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2,
		models.AccessType_NON_3_GPP_ACCESS)

	ue.AmfUeNgapId = cfg.Ue.AmfUeNgapId
	ue.AuthenticationSubs = getAuthSubscription()
	mobileIdentity5GS := nasType.MobileIdentity5GS{
		Len:    12, // suci
		Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
	}

	// Used to save IPsec/IKE related data
	n3ue := new(context.N3IWFUe)
	n3ue.PduSessionList = make(map[int64]*context.PDUSession)

	fmt.Println(mobileIdentity5GS)
}

func getAuthSubscription() (authSubs models.AuthenticationSubscription) {
	cfg, err := config.GetConfig()
	if err != nil {
		log.Fatal("Error in get configuration")
	}
	authSubs.PermanentKey = &models.PermanentKey{
		PermanentKeyValue: test.MilenageTestSet19.K,
	}
	authSubs.Opc = &models.Opc{
		OpcValue: test.MilenageTestSet19.OPC,
	}
	authSubs.Milenage = &models.Milenage{
		Op: &models.Op{
			OpValue: test.MilenageTestSet19.OP,
		},
	}
	authSubs.AuthenticationManagementField = cfg.Ue.AuthenticationManagementField
	authSubs.SequenceNumber = test.MilenageTestSet19.SQN
	authSubs.AuthenticationMethod = models.AuthMethod__5_G_AKA
	return
}
