package ue

import (
	"UE-non3GPP/config"
	"UE-non3GPP/free5gc/n3iwf/pkg/context"
	"UE-non3GPP/test/consumerTestdata/UDM/TestGenAuthData"
	"fmt"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/nas/security"
	"github.com/free5gc/openapi/models"
	log "github.com/sirupsen/logrus"
	"net"
	//"net"
)

func UENon3GPPConnection() {
	cfg, err := config.GetConfig()
	if err != nil {
		//return nil
		log.Fatal("Could not resolve config file")
	}

	ue := NewRanUeContext(cfg.Ue.Supi, 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2,
		models.AccessType_NON_3_GPP_ACCESS)
	ue.AmfUeNgapId = cfg.Ue.AmfUeNgapId
	ue.AuthenticationSubs = getAuthSubscription(cfg)
	mobileIdentity5GS := nasType.MobileIdentity5GS{
		Len:    12, // suci
		Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
	}

	n3ue := new(context.N3IWFUe)
	n3ue.PduSessionList = make(map[int64]*context.PDUSession)
	n3ue.N3IWFChildSecurityAssociation = make(map[uint32]*context.ChildSecurityAssociation)
	n3ue.TemporaryExchangeMsgIDChildSAMapping = make(map[uint32]*context.ChildSecurityAssociation)

	address := cfg.N3iwfInfo.IKEBindAddress + ":" + cfg.N3iwfInfo.IKEBindPort

	n3iwfUDPAddr, err := net.ResolveUDPAddr(cfg.N3iwfInfo.IPSecIfaceProtocol, address)
	if err != nil {
		log.Fatal(err)
		return
	}

	udpConnection := setupUDPSocket(cfg)

	fmt.Println(mobileIdentity5GS, n3ue, udpConnection, n3iwfUDPAddr)
}

func setupUDPSocket(cfg config.Config) *net.UDPConn {
	bindAddr := cfg.Ue.IpUDPConnection + ":" + cfg.Ue.PortUDPConnection
	udpAddr, err := net.ResolveUDPAddr("udp", bindAddr)
	if err != nil {
		log.Fatal("Resolve UDP address failed")
	}
	udpListener, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("Listen UDP socket failed: %+v", err)
	}
	return udpListener
}

func getAuthSubscription(cfg config.Config) (authSubs models.AuthenticationSubscription) {
	authSubs.PermanentKey = &models.PermanentKey{
		PermanentKeyValue: TestGenAuthData.MilenageTestSet19.K,
	}
	authSubs.Opc = &models.Opc{
		OpcValue: TestGenAuthData.MilenageTestSet19.OPC,
	}
	authSubs.Milenage = &models.Milenage{
		Op: &models.Op{
			OpValue: TestGenAuthData.MilenageTestSet19.OP,
		},
	}
	authSubs.AuthenticationManagementField = cfg.Ue.AuthenticationManagementField //"8000"

	authSubs.SequenceNumber = TestGenAuthData.MilenageTestSet19.SQN
	authSubs.AuthenticationMethod = models.AuthMethod__5_G_AKA
	return
}
