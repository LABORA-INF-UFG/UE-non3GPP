package message

type IdentificationInitiator struct {
	IDType uint8
	IDData []byte
}

type Transform struct {
	TransformType                uint8
	TransformID                  uint16
	AttributePresent             bool
	AttributeFormat              uint8
	AttributeType                uint16
	AttributeValue               uint16
	VariableLengthAttributeValue []byte
}

type Certificate struct {
	CertificateEncoding uint8
	CertificateData     []byte
}

type SecurityAssociation struct {
	Proposals ProposalContainer
}

type ProposalContainer []*Proposal

type Proposal struct {
	ProposalNumber          uint8
	ProtocolID              uint8
	SPI                     []byte
	EncryptionAlgorithm     TransformContainer
	PseudorandomFunction    TransformContainer
	IntegrityAlgorithm      TransformContainer
	DiffieHellmanGroup      TransformContainer
	ExtendedSequenceNumbers TransformContainer
}

type TransformContainer []*Transform

type TrafficSelectorInitiator struct {
	TrafficSelectors IndividualTrafficSelectorContainer
}

type IndividualTrafficSelectorContainer []*IndividualTrafficSelector

type IndividualTrafficSelector struct {
	TSType       uint8
	IPProtocolID uint8
	StartPort    uint16
	EndPort      uint16
	StartAddress []byte
	EndAddress   []byte
}

type TrafficSelectorResponder struct {
	TrafficSelectors IndividualTrafficSelectorContainer
}
