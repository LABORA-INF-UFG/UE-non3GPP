package template

import (
	"UE-non3GPP/config"
	controlPlane "UE-non3GPP/internal/ike"
)

func UENon3GPPConnection() {

	cfg := config.GetConfig()

	// init ue control plane
	controlPlane.Run(cfg)
}
