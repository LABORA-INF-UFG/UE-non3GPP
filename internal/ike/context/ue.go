package context

import (
	"UE-non3GPP/internal/ike/message"
	"UE-non3GPP/internal/nas/context"
	"encoding/binary"
	"github.com/vishvananda/netlink"
	"math/big"
	"net"
)

type UeIke struct {
	udpConn                       *net.UDPConn
	stateIke                      uint8
	ikeSecurity                   IkeSecurity
	N3IWFChildSecurityAssociation map[uint32]*ChildSecurityAssociation // inbound SPI as key
	secret                        *big.Int
	factor                        *big.Int
	localNonce                    []byte
	N3IWFIKESecurityAssociation   *IKESecurityAssociation
	NasContext                    *context.UeNas
}

type IkeSecurity struct {
	EncryptionAlgorithm  uint16
	PseudorandomFunction uint16
	IntegrityAlgorithm   uint16
	DiffieHellmanGroup   uint16
}

type ChildSecurityAssociation struct {
	// SPI
	InboundSPI  uint32 // N3IWF Specify
	OutboundSPI uint32 // Non-3GPP UE Specify

	// Associated XFRM interface
	XfrmIface netlink.Link

	// IP address
	PeerPublicIPAddr  net.IP
	LocalPublicIPAddr net.IP

	// Traffic selector
	SelectedIPProtocol    uint8
	TrafficSelectorLocal  net.IPNet
	TrafficSelectorRemote net.IPNet

	// Security
	EncryptionAlgorithm               uint16
	InitiatorToResponderEncryptionKey []byte
	ResponderToInitiatorEncryptionKey []byte
	IntegrityAlgorithm                uint16
	InitiatorToResponderIntegrityKey  []byte
	ResponderToInitiatorIntegrityKey  []byte
	ESN                               bool

	// Encapsulate
	EnableEncapsulate bool
	N3IWFPort         int
	NATPort           int

	// PDU Session IDs associated with this child SA
	PDUSessionIds []int64
}

func NewUeIke(ueNas *context.UeNas) *UeIke {
	ue := &UeIke{}
	ue.NewDiffieHellmanGroup(true)
	ue.NewEncryptionAlgoritm(true)
	ue.NewPseudorandomFunction(true)
	ue.NewIntegrityAlgorithm(true)
	ue.N3IWFChildSecurityAssociation = make(map[uint32]*ChildSecurityAssociation)
	ue.NasContext = ueNas
	return ue
}

func (ue *UeIke) CreateN3IWFIKESecurityAssociation(ikeSecurity *IKESecurityAssociation) {
	ue.N3IWFIKESecurityAssociation = ikeSecurity
	ue.N3IWFIKESecurityAssociation.State = 0 // pre-signaling

}

func (ue *UeIke) NewEncryptionAlgoritm(encryptionAlgorithm1 bool) {
	// encryption algorithm
	if encryptionAlgorithm1 {
		ue.ikeSecurity.EncryptionAlgorithm = message.ENCR_AES_CBC
	}
}

func (ue *UeIke) NewPseudorandomFunction(PseudorandomFunction1 bool) {
	// pseudo random function
	if PseudorandomFunction1 {
		ue.ikeSecurity.PseudorandomFunction = message.PRF_HMAC_SHA1
	}
}

func (ue *UeIke) NewDiffieHellmanGroup(DiffieHellmanGroup1 bool) {
	// diffieHellman algorithm
	if DiffieHellmanGroup1 {
		ue.ikeSecurity.DiffieHellmanGroup = message.DH_2048_BIT_MODP
	}

}

func (ue *UeIke) NewIntegrityAlgorithm(IntegrityFunction1 bool) {
	// pseudo random function
	if IntegrityFunction1 {
		ue.ikeSecurity.IntegrityAlgorithm = message.AUTH_HMAC_SHA1_96
	}
}

func (ue *UeIke) GetIntegrityAlgorithm() uint16 {
	return ue.ikeSecurity.IntegrityAlgorithm
}

func (ue *UeIke) GetDiffieHellmanGroup() uint16 {
	return ue.ikeSecurity.DiffieHellmanGroup
}

func (ue *UeIke) GetPseudorandomFunction() uint16 {
	return ue.ikeSecurity.PseudorandomFunction
}

func (ue *UeIke) GetEncryptionAlgoritm() uint16 {
	return ue.ikeSecurity.EncryptionAlgorithm
}

func (ue *UeIke) GetUdpConn() *net.UDPConn {
	return ue.udpConn
}

func (ue *UeIke) SetUdpConn(conn *net.UDPConn) {
	ue.udpConn = conn
}

func (ue *UeIke) GenerateSPI() []byte {
	var spi uint32
	spiByte := make([]byte, 4)
	for {
		randomUint64 := GenerateRandomNumber().Uint64()
		if _, ok := ue.N3IWFChildSecurityAssociation[uint32(randomUint64)]; !ok {
			spi = uint32(randomUint64)
			binary.BigEndian.PutUint32(spiByte, spi)
			break
		}
	}
	return spiByte
}

func (ue *UeIke) SetSecret(secret *big.Int) {
	ue.secret = secret
}

func (ue *UeIke) GetSecret() *big.Int {
	return ue.secret
}

func (ue *UeIke) SetFactor(factor *big.Int) {
	ue.factor = factor
}

func (ue *UeIke) GetFactor() *big.Int {
	return ue.factor
}

func (ue *UeIke) SetLocalNonce(localNonce []byte) {
	ue.localNonce = localNonce
}

func (ue *UeIke) GetLocalNonce() []byte {
	return ue.localNonce
}
