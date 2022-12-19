package context

import (
	ike_message "github.com/LABORA-INF-UFG/UE-non3GPP/engine/mockups/n3iwf/ike/message"
	"github.com/free5gc/ngap/ngapType"
	"github.com/vishvananda/netlink"
	"github.com/wmnsk/go-gtp/gtpv1"

	"net"
)

type N3IWFUe struct {
	/* UE identity */
	RanUeNgapId      int64
	AmfUeNgapId      int64
	IPAddrv4         string
	IPAddrv6         string
	PortNumber       int32
	MaskedIMEISV     *ngapType.MaskedIMEISV // TS 38.413 9.3.1.54
	Guti             string
	IPSecInnerIP     net.IP
	IPSecInnerIPAddr *net.IPAddr // Used to send UP packets to UE

	/* Relative Context */
	AMF *N3IWFAMF

	/* PDU Session */
	PduSessionList map[int64]*PDUSession // pduSessionId as key

	/* PDU Session Setup Temporary Data */
	TemporaryPDUSessionSetupData *PDUSessionSetupTemporaryData

	/* Temporary cached NAS message */
	// Used when NAS registration accept arrived before
	// UE setup NAS TCP connection with N3IWF, and
	// Forward pduSessionEstablishmentAccept to UE after
	// UE send CREATE_CHILD_SA response
	TemporaryCachedNASMessage []byte

	/* Security */
	Kn3iwf               []uint8                          // 32 bytes (256 bits), value is from NGAP IE "Security Key"
	SecurityCapabilities *ngapType.UESecurityCapabilities // TS 38.413 9.3.1.86

	/* IKE Security Association */
	N3IWFIKESecurityAssociation   *IKESecurityAssociation
	N3IWFChildSecurityAssociation map[uint32]*ChildSecurityAssociation // inbound SPI as key
	SignallingIPsecSAEstablished  bool

	/* Temporary Mapping of two SPIs */
	// Exchange Message ID(including a SPI) and ChildSA(including a SPI)
	// Mapping of Message ID of exchange in IKE and Child SA when creating new child SA
	TemporaryExchangeMsgIDChildSAMapping map[uint32]*ChildSecurityAssociation // Message ID as a key

	/* NAS IKE Connection */
	IKEConnection *UDPSocketInfo
	/* NAS TCP Connection */
	TCPConnection net.Conn

	/* Others */
	Guami                            *ngapType.GUAMI
	IndexToRfsp                      int64
	Ambr                             *ngapType.UEAggregateMaximumBitRate
	AllowedNssai                     *ngapType.AllowedNSSAI
	RadioCapability                  *ngapType.UERadioCapability                // TODO: This is for RRC, can be deleted
	CoreNetworkAssistanceInformation *ngapType.CoreNetworkAssistanceInformation // TS 38.413 9.3.1.15
	IMSVoiceSupported                int32
	RRCEstablishmentCause            int16
	PduSessionReleaseList            ngapType.PDUSessionResourceReleasedListRelRes
}

type UDPSocketInfo struct {
	Conn      *net.UDPConn
	N3IWFAddr *net.UDPAddr
	UEAddr    *net.UDPAddr
}

type IKESecurityAssociation struct {
	// SPI
	RemoteSPI uint64
	LocalSPI  uint64

	// Message ID
	InitiatorMessageID uint32
	ResponderMessageID uint32

	// Transforms for IKE SA
	EncryptionAlgorithm    *ike_message.Transform
	PseudorandomFunction   *ike_message.Transform
	IntegrityAlgorithm     *ike_message.Transform
	DiffieHellmanGroup     *ike_message.Transform
	ExpandedSequenceNumber *ike_message.Transform

	// Used for key generating
	ConcatenatedNonce      []byte
	DiffieHellmanSharedKey []byte

	// Keys
	SK_d  []byte // used for child SA key deriving
	SK_ai []byte // used by initiator for integrity checking
	SK_ar []byte // used by responder for integrity checking
	SK_ei []byte // used by initiator for encrypting
	SK_er []byte // used by responder for encrypting
	SK_pi []byte // used by initiator for IKE authentication
	SK_pr []byte // used by responder for IKE authentication

	// State for IKE_AUTH
	State uint8

	// Temporary data stored for the use in later exchange
	InitiatorID              *ike_message.IdentificationInitiator
	InitiatorCertificate     *ike_message.Certificate
	IKEAuthResponseSA        *ike_message.SecurityAssociation
	TrafficSelectorInitiator *ike_message.TrafficSelectorInitiator
	TrafficSelectorResponder *ike_message.TrafficSelectorResponder
	LastEAPIdentifier        uint8

	// Authentication data
	ResponderSignedOctets []byte
	InitiatorSignedOctets []byte

	// NAT detection
	// If UEIsBehindNAT == true, N3IWF should enable NAT traversal and
	// TODO: should support dynamic updating network address (MOBIKE)
	UEIsBehindNAT bool
	// If N3IWFIsBehindNAT == true, N3IWF should send UDP keepalive periodically
	N3IWFIsBehindNAT bool

	// UE context
	ThisUE *N3IWFUe

	DPDReqRetransTimer *Timer // The time from sending the DPD request to receiving the response
	CurrentRetryTimes  int32  // Accumulate the number of times the DPD response wasn't received
	IKESAClosedCh      chan struct{}
}

type ChildSecurityAssociation struct {
	// SPI
	InboundSPI  uint32 // N3IWF Specify
	OutboundSPI uint32 // Non-3GPP UE Specify

	// Associated XFRM interface
	XfrmIface netlink.Link

	XfrmStateList  []netlink.XfrmState
	XfrmPolicyList []netlink.XfrmPolicy

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

	// UE context
	ThisUE *N3IWFUe
}

type PDUSessionSetupTemporaryData struct {
	// Slice of unactivated PDU session
	UnactivatedPDUSession []int64 // PDUSessionID as content
	// NGAPProcedureCode is used to identify which type of
	// response shall be used
	NGAPProcedureCode ngapType.ProcedureCode
	// PDU session setup list response
	SetupListCxtRes  *ngapType.PDUSessionResourceSetupListCxtRes
	FailedListCxtRes *ngapType.PDUSessionResourceFailedToSetupListCxtRes
	SetupListSURes   *ngapType.PDUSessionResourceSetupListSURes
	FailedListSURes  *ngapType.PDUSessionResourceFailedToSetupListSURes
}

type PDUSession struct {
	Id                               int64 // PDU Session ID
	Type                             *ngapType.PDUSessionType
	Ambr                             *ngapType.PDUSessionAggregateMaximumBitRate
	Snssai                           ngapType.SNSSAI
	NetworkInstance                  *ngapType.NetworkInstance
	SecurityCipher                   bool
	SecurityIntegrity                bool
	MaximumIntegrityDataRateUplink   *ngapType.MaximumIntegrityProtectedDataRate
	MaximumIntegrityDataRateDownlink *ngapType.MaximumIntegrityProtectedDataRate
	GTPConnection                    *GTPConnectionInfo
	QFIList                          []uint8
	QosFlows                         map[int64]*QosFlow // QosFlowIdentifier as key
}

type QosFlow struct {
	Identifier int64
	Parameters ngapType.QosFlowLevelQosParameters
}

type GTPConnectionInfo struct {
	UPFIPAddr           string
	UPFUDPAddr          net.Addr
	IncomingTEID        uint32
	OutgoingTEID        uint32
	UserPlaneConnection *gtpv1.UPlaneConn
}
