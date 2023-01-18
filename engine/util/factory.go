package util

import (
	"UE-non3GPP/config"
	"UE-non3GPP/engine/exchange/pkg/context"
	"UE-non3GPP/engine/exchange/pkg/ike/handler"
	"UE-non3GPP/engine/exchange/pkg/ike/message"
	ran_ue "UE-non3GPP/engine/ran"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/nas/security"
	"github.com/free5gc/openapi/models"
	log "github.com/sirupsen/logrus"
	"math/big"
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
		log.Fatal("UDP Connection N3IWF failed!")
		panic(err)
	}
	return UDPAddr
}

func CreateUEUDPListener(cfg config.Config) *net.UDPConn {
	bindAddr := cfg.Ue.LocalPublicIPAddr + ":" + cfg.Ue.LocalPublicPortUDPConnection
	udpAddr, err := net.ResolveUDPAddr("udp", bindAddr)
	if err != nil {
		log.Fatal("Resolve UDP address failed")
		panic(err)
	}
	udpListener, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatal("Listen UDP socket failed: %+v", err)
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

	// ENCR
	var attributeType uint16 = message.AttributeTypeKeyLength
	var keyLength uint16 = 256
	proposal.EncryptionAlgorithm.BuildTransform(message.TypeEncryptionAlgorithm, message.ENCR_AES_CBC, &attributeType, &keyLength, nil)
	// INTEG
	proposal.IntegrityAlgorithm.BuildTransform(message.TypeIntegrityAlgorithm, message.AUTH_HMAC_SHA1_96, nil, nil, nil)
	// PRF
	proposal.PseudorandomFunction.BuildTransform(message.TypePseudorandomFunction, message.PRF_HMAC_SHA1, nil, nil, nil)
	// DH
	proposal.DiffieHellmanGroup.BuildTransform(message.TypeDiffieHellmanGroup, message.DH_2048_BIT_MODP, nil, nil, nil)

	return ikeMessage, proposal
}

func CreateIKEInitiatorSPI() uint64 {
	return uint64(123123)
}

func BuildInitIKEMessageData(ikeMessage *message.IKEMessage) (*big.Int, *big.Int, []byte, []byte) {
	secret := handler.GenerateRandomNumber()
	factor, ok := new(big.Int).SetString(handler.Group14PrimeString, 16)
	// Key exchange data
	if !ok {
		log.Fatal("Generate key exchange data failed")
		panic("Generate key exchange data failed")
	}
	_generator := new(big.Int).SetUint64(handler.Group14Generator)
	localPublicKeyExchangeValue := new(big.Int).Exp(_generator, secret, factor).Bytes()
	prependZero := make([]byte, len(factor.Bytes())-len(localPublicKeyExchangeValue))
	localPublicKeyExchangeValue = append(prependZero, localPublicKeyExchangeValue...)

	ikeMessage.Payloads.BUildKeyExchange(message.DH_2048_BIT_MODP, localPublicKeyExchangeValue)

	localNonce := handler.GenerateRandomNumber().Bytes()
	ikeMessage.Payloads.BuildNonce(localNonce)

	ikeMessageData, err := ikeMessage.Encode()
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	return secret, factor, localNonce, ikeMessageData
}