package context

import (
	"UE-non3GPP/internal/ike/message"
	"encoding/binary"
	"github.com/vishvananda/netlink"
	"net"
)

type Ue struct {
	udpConn                       *net.UDPConn
	stateIke                      uint8
	ikeSecurity                   IkeSecurity
	N3IWFChildSecurityAssociation map[uint32]*ChildSecurityAssociation // inbound SPI as key
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

func NewUe() *Ue {
	ue := &Ue{}
	ue.N3IWFChildSecurityAssociation = make(map[uint32]*ChildSecurityAssociation)
	return ue
}

func (ue *Ue) NewEncryptionAlgoritm(encryptionAlgorithm1 bool) {
	// encryption algorithm
	if encryptionAlgorithm1 {
		ue.ikeSecurity.EncryptionAlgorithm = message.ENCR_AES_CBC
	}
}

func (ue *Ue) NewPseudorandomFunction(PseudorandomFunction1 bool) {
	// pseudo random function
	if PseudorandomFunction1 {
		ue.ikeSecurity.PseudorandomFunction = message.PRF_HMAC_SHA1
	}
}

func (ue *Ue) NewDiffieHellmanGroup(DiffieHellmanGroup1 bool) {
	// diffieHellman algorithm
	if DiffieHellmanGroup1 {
		ue.ikeSecurity.DiffieHellmanGroup = message.DH_2048_BIT_MODP
	}

}

func (ue *Ue) NewIntegrityAlgorithm(PseudorandomFunction1 bool) {
	// pseudo random function
	if PseudorandomFunction1 {
		ue.ikeSecurity.PseudorandomFunction = message.PRF_HMAC_SHA1
	}
}

func (ue *Ue) GetIntegrityAlgorithm() uint16 {
	return ue.ikeSecurity.IntegrityAlgorithm
}

func (ue *Ue) GetDiffieHellmanGroup() uint16 {
	return ue.ikeSecurity.DiffieHellmanGroup
}

func (ue *Ue) GetPseudorandomFunction() uint16 {
	return ue.ikeSecurity.PseudorandomFunction
}

func (ue *Ue) GetEncryptionAlgoritm() uint16 {
	return ue.ikeSecurity.EncryptionAlgorithm
}

func (ue *Ue) GetUdpConn() *net.UDPConn {
	return ue.udpConn
}

func (ue *Ue) SetUdpConn(conn *net.UDPConn) {
	ue.udpConn = conn
}

func (ue *Ue) GenerateSPI() []byte {
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
