package util

import (
	"UE-non3GPP/config"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/execabs"
)

func ConfigMTUGreTun(cfg config.Config) {
	//remove a interface de rede GRE (se existir)
	dropGreTunInterface := "ifconfig " + cfg.Ue.LinkGRE.Name + " mtu 1200"
	cmd := execabs.Command("bash", "-c", dropGreTunInterface)
	err := cmd.Run()
	if err != nil {
		log.Info(cfg.Ue.LinkGRE.Name + " not found!")
	} else {
		log.Info(cfg.Ue.LinkGRE.Name + " mtu set 1300!")
	}
}

func InitialSetup(cfg config.Config) {
	//remove a interface de rede GRE (se existir)
	dropGreTunInterface := "ip link del " + cfg.Ue.LinkGRE.Name
	cmd := execabs.Command("bash", "-c", dropGreTunInterface)
	err := cmd.Run()
	if err != nil {
		log.Info(cfg.Ue.LinkGRE.Name + " not found!")
	} else {
		log.Info(cfg.Ue.LinkGRE.Name + " was droped!")
	}

	//remove ipsec0 (se existir)
	dropIpsec0Interface := "sudo ip link del " + cfg.Ue.IPSecInterfaceName
	cmd = execabs.Command("bash", "-c", dropIpsec0Interface)
	err = cmd.Run()
	if err != nil {
		log.Info(cfg.Ue.IPSecInterfaceName + " not found!")
	} else {
		log.Info(cfg.Ue.IPSecInterfaceName + " was droped!")
	}

	//cria ipsec0
	createIpsec0Interface := "sudo ip link add " + cfg.Ue.IPSecInterfaceName + " type vti local " + cfg.Ue.LocalPublicIPAddr + " remote " + cfg.N3iwfInfo.IKEBindAddress + " key " + cfg.Ue.IPSecInterfaceMark
	cmd = execabs.Command("bash", "-c", createIpsec0Interface)
	err = cmd.Run()
	if err != nil {
		log.Warning(createIpsec0Interface)
		log.Error("could not create interface " + cfg.Ue.IPSecInterfaceName)
		panic(err)
	} else {
		log.Info(cfg.Ue.IPSecInterfaceName + " interface was created")
	}

	//up ipsec0
	upIpsec0Interface := "sudo ip link set " + cfg.Ue.IPSecInterfaceName + " up "
	cmd = execabs.Command("bash", "-c", upIpsec0Interface)
	err = cmd.Run()
	if err != nil {
		log.Info("up " + cfg.Ue.IPSecInterfaceName + " fail!")
		panic(err)
	}
}
