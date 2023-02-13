package template

import (
	"UE-non3GPP/config"
	controlPlane "UE-non3GPP/internal/ike"
	"UE-non3GPP/internal/ike/context"
	contextNas "UE-non3GPP/internal/nas/context"
	"time"
)

func UENon3GPPConnection() {

	cfg := config.GetConfig()

	// create args for creation of instance Nas
	argsNas := contextNas.ArgumentsNas{
		Supi:        cfg.Ue.Supi,
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

	ueIke := context.NewUeIke(ueNas)

	// init ue control plane
	controlPlane.Run(cfg, ueIke)

	time.Sleep(20 * time.Second)
}
