package util

import (
	"UE-non3GPP/config"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
)

func GetLinkGRE(cfg config.Config) netlink.Link {
	links, err := netlink.LinkList()
	if err != nil {
		log.Fatal(err)
		panic(err)
	}
	var linkGRE netlink.Link
	for _, link := range links {
		if link.Attrs() != nil {
			if link.Attrs().Name == cfg.Ue.GRETunName {
				linkGRE = link
				break
			}
		}
	}
	return linkGRE
}
