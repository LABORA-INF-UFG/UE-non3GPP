package util

import (
	"UE-non3GPP/config"
	ran_ue "UE-non3GPP/engine/ran"
	"UE-non3GPP/free5gc/n3iwf/pkg/context"
	"UE-non3GPP/free5gc/n3iwf/pkg/ike/message"
	"fmt"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/nas/security"
	"github.com/free5gc/openapi/models"
	"net"
)

func CreateRanUEContext(cfg config.Config) *ran_ue.RanUeContext {
	ue := ran_ue.NewRanUeContext(cfg.Ue.Supi,
		cfg.Ue.RanUeNgapId,
		security.AlgCiphering128NEA0,
		security.AlgIntegrity128NIA2,
		models.AccessType_NON_3_GPP_ACCESS)

	ue.AmfUeNgapId = cfg.Ue.AmfUeNgapId
	ue.AuthenticationSubs = CreateAuthSubscription(cfg)
	return ue
}

func CreateAuthSubscription(cfg config.Config) (authSubs models.AuthenticationSubscription) {
	authSubs.PermanentKey = &models.PermanentKey{
		PermanentKeyValue: cfg.Ue.AuthSubscription.PermanentKeyValue,
	}
	authSubs.Opc = &models.Opc{
		OpcValue: cfg.Ue.AuthSubscription.OpcValue,
	}
	authSubs.Milenage = &models.Milenage{
		Op: &models.Op{
			OpValue: cfg.Ue.AuthSubscription.OpValue,
		},
	}
	authSubs.AuthenticationManagementField = cfg.Ue.AuthenticationManagementField //"8000"
	authSubs.SequenceNumber = cfg.Ue.AuthSubscription.SequenceNumber
	authSubs.AuthenticationMethod = models.AuthMethod__5_G_AKA
	return
}

func CreateMobileIdentity() nasType.MobileIdentity5GS {
	return nasType.MobileIdentity5GS{
		Len:    12, // suci
		Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
	}
}

func CreateN3IWFUe() *context.N3IWFUe {
	n3ue := new(context.N3IWFUe)
	n3ue.PduSessionList = make(map[int64]*context.PDUSession)
	n3ue.N3IWFChildSecurityAssociation = make(map[uint32]*context.ChildSecurityAssociation)
	n3ue.TemporaryExchangeMsgIDChildSAMapping = make(map[uint32]*context.ChildSecurityAssociation)
	return n3ue
}

func CreateN3IWFIKEConnection(cfg config.Config) *net.UDPAddr {
	address := cfg.N3iwfInfo.IKEBindAddress + ":" + cfg.N3iwfInfo.IKEBindPort
	UDPAddr, err := net.ResolveUDPAddr(cfg.N3iwfInfo.IPSecIfaceProtocol, address)
	if err != nil {
		fmt.Println("UDP Connection N3IWF failed!")
		panic(err)
	}
	return UDPAddr
}

func CreateUEUDPListener(cfg config.Config) *net.UDPConn {
	bindAddr := cfg.Ue.LocalPublicIPAddr + ":" + cfg.Ue.LocalPublicPortUDPConnection
	udpAddr, err := net.ResolveUDPAddr("udp", bindAddr)
	if err != nil {
		fmt.Println("Resolve UDP address failed")
		panic(err)
	}
	udpListener, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Listen UDP socket failed: %+v", err)
		panic(err)
	}
	return udpListener
}

func CreateIKEMessageSAInit() (*message.IKEMessage, *message.Proposal) {
	ikeInitiatorSPI := CreateIKEInitiatorSPI()
	ikeMessage := new(message.IKEMessage)
	ikeMessage.BuildIKEHeader(ikeInitiatorSPI, 0, message.IKE_SA_INIT, message.InitiatorBitCheck, 0)

	securityAssociation := ikeMessage.Payloads.BuildSecurityAssociation()
	proposal := securityAssociation.Proposals.BuildProposal(1, message.TypeIKE, nil)

	return ikeMessage, proposal
}

func CreateIKEInitiatorSPI() uint64 {
	return uint64(123123)
}
