package context

import (
	"UE-non3GPP/engine/exchange/pkg/ike/message"
	"net"
)

type Ue struct {
	udpConn     *net.UDPConn
	stateIke    uint8
	ikeSecurity IkeSecurity
}

type IkeSecurity struct {
	EncryptionAlgorithm  uint16
	PseudorandomFunction uint16
	IntegrityAlgorithm   uint16
	DiffieHellmanGroup   uint16
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
