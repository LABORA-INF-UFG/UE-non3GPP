package ue

import (
	"UE-non3GPP/config"
	"fmt"
	log "github.com/sirupsen/logrus"
	//"net"
)

func UENon3GPPConnection() {
	fmt.Println("...foi", nil)
	cfg, err := config.GetConfig()
	if err != nil {
		//return nil
		log.Fatal("Could not resolve config file")
	}

	fmt.Println("...foi", cfg)

}
