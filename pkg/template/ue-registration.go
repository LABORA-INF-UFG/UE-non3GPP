package template

import (
	"UE-non3GPP/config"
	controlPlane "UE-non3GPP/internal/ike"
	"UE-non3GPP/internal/ike/context"
	contextNas "UE-non3GPP/internal/nas/context"
	"UE-non3GPP/pkg/utils"
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
	utils := utils.NewUtils()
	ueIke := context.NewUeIke(ueNas, utils)

	// init ue control plane
	controlPlane.Run(cfg, ueIke)

	// control the signals
	sigUE := make(chan os.Signal, 1)
	signal.Notify(sigUE, os.Interrupt)

	// Block until a signal is received.
	<-sigUE
	err := ueIke.Terminate()
	if !err {
		// TODO implement logs
		return
	}

	err = ueNas.Terminate()
	if !err {
		// TODO implement logs
		return
	}
}
