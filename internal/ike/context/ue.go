package context

import (
	"UE-non3GPP/internal/ike/message"
	"UE-non3GPP/internal/nas/context"
	"UE-non3GPP/pkg/utils"
	"encoding/binary"
	"fmt"
	"github.com/vishvananda/netlink"
	"math/big"
	"net"
	"time"
)

type UeIke struct {
	n3iwfIp                              string
	ueIp                                 string
	udpConn                              *net.UDPConn
	ikeSecurity                          IkeSecurity
	N3IWFChildSecurityAssociation        map[uint32]*ChildSecurityAssociation // inbound SPI as key
	secret                               *big.Int
	factor                               *big.Int
	localNonce                           []byte
	N3IWFIKESecurityAssociation          *IKESecurityAssociation
	NasContext                           *context.UeNas
	TemporaryExchangeMsgIDChildSAMapping map[uint32]*ChildSecurityAssociation // Message ID as a key
	QosInfo                              *PDUQoSInfo
	N3iwfNasAddr                         net.TCPAddr
	N3iwfUpAddr                          net.IP
	ONAddrIp                             []byte
	ONMask                               []byte
	Utils                                *utils.Utils
	BeginTime                            time.Time
	IpsecTime                            time.Duration
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

type PDUQoSInfo struct {
	pduSessionID    uint8
	QfiList         []uint8
	isDefault       bool
	isDSCPSpecified bool
	DSCP            uint8
}

func NewUeIke(ueNas *context.UeNas, utils *utils.Utils) *UeIke {

	ue := &UeIke{}
	ue.NewDiffieHellmanGroup(true)
	ue.NewEncryptionAlgoritm(true)
	ue.NewPseudorandomFunction(true)
	ue.NewIntegrityAlgorithm(true)
	ue.N3IWFChildSecurityAssociation = make(map[uint32]*ChildSecurityAssociation)
	ue.TemporaryExchangeMsgIDChildSAMapping = make(map[uint32]*ChildSecurityAssociation)
	ue.NasContext = ueNas
	ue.Utils = utils
	ue.BeginTime = time.Now()

	return ue
}

func (ue *UeIke) Terminate() error {

	// close IKE socket udp
	//udpConn := ue.GetUdpConn()
	//udpConn.Close()

	// clean xfrm policy and states
	err := netlink.XfrmPolicyFlush()
	if err != nil {
		return fmt.Errorf("Error in delete XFRM Policy")
	}

	err = netlink.XfrmStateFlush(netlink.XFRM_PROTO_IPSEC_ANY)
	if err != nil {
		return fmt.Errorf("Error in delete XFRM State")
	}

	return nil
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

func (ue *UeIke) SetN3IWFIp(ip string) {
	ue.n3iwfIp = ip
}

func (ue *UeIke) GetN3IWFIp() string {
	return ue.n3iwfIp
}

func (ue *UeIke) GetUEIp() string {
	return ue.ueIp
}

func (ue *UeIke) SetUEIp(ip string) {
	ue.ueIp = ip
}

func (ue *UeIke) CreateHalfChildSA(msgID, inboundSPI uint32, pduSessionID int64) {
	childSA := new(ChildSecurityAssociation)
	childSA.InboundSPI = inboundSPI
	childSA.PDUSessionIds = append(childSA.PDUSessionIds, pduSessionID)
	// Map Exchange Message ID and Child SA data until get paired response
	ue.TemporaryExchangeMsgIDChildSAMapping[msgID] = childSA
}

func (ue *UeIke) CompleteChildSA(msgID uint32, outboundSPI uint32,
	chosenSecurityAssociation *message.SecurityAssociation) (*ChildSecurityAssociation, error) {
	childSA, ok := ue.TemporaryExchangeMsgIDChildSAMapping[msgID]

	if !ok {
		return nil, fmt.Errorf("There's not a half child SA created by the exchange with message ID %d.", msgID)
	}

	// Remove mapping of exchange msg ID and child SA
	delete(ue.TemporaryExchangeMsgIDChildSAMapping, msgID)

	if chosenSecurityAssociation == nil {
		return nil, fmt.Errorf("chosenSecurityAssociation is nil")
	}

	if len(chosenSecurityAssociation.Proposals) == 0 {
		return nil, fmt.Errorf("No proposal")
	}

	childSA.OutboundSPI = outboundSPI

	if len(chosenSecurityAssociation.Proposals[0].EncryptionAlgorithm) != 0 {
		childSA.EncryptionAlgorithm = chosenSecurityAssociation.Proposals[0].EncryptionAlgorithm[0].TransformID
	}
	if len(chosenSecurityAssociation.Proposals[0].IntegrityAlgorithm) != 0 {
		childSA.IntegrityAlgorithm = chosenSecurityAssociation.Proposals[0].IntegrityAlgorithm[0].TransformID
	}
	if len(chosenSecurityAssociation.Proposals[0].ExtendedSequenceNumbers) != 0 {
		if chosenSecurityAssociation.Proposals[0].ExtendedSequenceNumbers[0].TransformID == 0 {
			childSA.ESN = false
		} else {
			childSA.ESN = true
		}
	}

	// Record to UE context with inbound SPI as key
	ue.N3IWFChildSecurityAssociation[childSA.InboundSPI] = childSA
	// Record to N3IWF context with inbound SPI as key
	// n3iwfContext.ChildSA.Store(childSA.InboundSPI, childSA)

	return childSA, nil
}
