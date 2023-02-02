package util

import (
	"UE-non3GPP/config"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/execabs"
)

func ConfigMTUGreTun(cfg config.Config) {
	//remove a interface de rede GRE (se existir)
	dropGreTunInterface := "ifconfig " + cfg.Ue.LinkGRE.Name + " mtu 1300"
	cmd := execabs.Command("bash", "-c", dropGreTunInterface)
	err := cmd.Run()
	if err != nil {
		log.Info(cfg.Ue.LinkGRE.Name + " not found!")
	} else {
		log.Info(cfg.Ue.LinkGRE.Name + " mtu set 1300!")
	}
}

func CleanEnvironment(cfg config.Config) {

	/* clear XFRM interfaces */
	_ = netlink.XfrmPolicyFlush()
	_ = netlink.XfrmStateFlush(netlink.XFRM_PROTO_IPSEC_ANY)

	//remove a interface de rede GRE (se existir)
	downGreTunInterface := "ip link set " + cfg.Ue.LinkGRE.Name + " down"
	cmd := execabs.Command("bash", "-c", downGreTunInterface)
	err := cmd.Run()
	if err == nil {
		log.Info(cfg.Ue.LinkGRE.Name + " was set down!")
	}

	//remove a interface de rede GRE (se existir)
	dropGreTunInterface := "ip link del " + cfg.Ue.LinkGRE.Name
	cmd = execabs.Command("bash", "-c", dropGreTunInterface)
	err = cmd.Run()
	if err == nil {
		log.Info(cfg.Ue.LinkGRE.Name + " was droped!")
	}

	downIpsec0Interface := "sudo ip link set " + cfg.Ue.IPSecInterfaceName + " down"
	cmd = execabs.Command("bash", "-c", downIpsec0Interface)
	err = cmd.Run()
	if err == nil {
		log.Info(cfg.Ue.IPSecInterfaceName + " was set down!")
	}

	//remove ipsec0 (se existir)
	dropIpsec0Interface := "sudo ip link del " + cfg.Ue.IPSecInterfaceName
	cmd = execabs.Command("bash", "-c", dropIpsec0Interface)
	err = cmd.Run()
	if err == nil {
		log.Info(cfg.Ue.IPSecInterfaceName + " was droped!")
	}

	//cria ipsec0
	ipSecInterfaceMark := StrConverter(cfg.Ue.IPSecInterfaceMark)
	createIpsec0Interface := "sudo ip link add " + cfg.Ue.IPSecInterfaceName + " type vti local " + cfg.Ue.LocalPublicIPAddr + " remote " + cfg.N3iwfInfo.IKEBindAddress + " key " + ipSecInterfaceMark
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
		log.Error("up " + cfg.Ue.IPSecInterfaceName + " fail!")
		panic(err)
	}
}
