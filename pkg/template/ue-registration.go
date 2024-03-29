package template

import (
	"UE-non3GPP/config"
	controlPlane "UE-non3GPP/internal/ike"
	"UE-non3GPP/internal/ike/context"
	contextNas "UE-non3GPP/internal/nas/context"

	"UE-non3GPP/pkg/utils"

	log "github.com/sirupsen/logrus"
	"os"
	"os/signal"
)

func UENon3GPPConnection() {

	cfg := config.GetConfig()

	// create args for creation of instance Nas
	argsNas := contextNas.ArgumentsNas{
		Mcc:         cfg.Ue.Hplmn.Mcc,
		Mnc:         cfg.Ue.Hplmn.Mnc,
		Msin:        cfg.Ue.Msin,
		RanUeNgapId: cfg.Ue.RanUeNgapId,
		K:           cfg.Ue.AuthSubscription.PermanentKeyValue,
		Opc:         cfg.Ue.AuthSubscription.OpcValue,
		Op:          cfg.Ue.AuthSubscription.OpValue,
		Amf:         cfg.Ue.AuthenticationManagementField,
		Sqn:         cfg.Ue.AuthSubscription.SequenceNumber,
		Sst:         cfg.Ue.Snssai.Sst,
		Sd:          cfg.Ue.Snssai.Sd,
		Dnn:         cfg.Ue.DNNString,
	}

	ueNas := contextNas.NewUeNas(argsNas)
	log.Info("[UE][NAS] NAS Context Created")

	utils := utils.NewUtils()
	ueIke := context.NewUeIke(ueNas, utils)
	log.Info("[UE][IKE] IKE Context Created")

	// init ue control plane
	controlPlane.Run(cfg, ueIke)

	sigUE := make(chan os.Signal, 1)
	signal.Notify(sigUE, os.Interrupt)

	// Block until a signal is received.
	<-sigUE
	err := ueIke.Terminate()
	if !err {
		log.Error("[UE][IKE] IKE Context Termination failed")
		log.Error("[UE][IKE] ", err)
		return
	}

	err = ueNas.Terminate()
	if !err {
		log.Error("[UE][NAS] NAS Context Termination failed")
		log.Error("[UE][NAS] ", err)
		return
	}
	log.Info("[UE] UE terminated")
}

type UeHandler struct {
	nasInfo *contextNas.UeNas
	ikeInfo *context.UeIke
}
