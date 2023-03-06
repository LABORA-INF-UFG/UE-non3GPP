package context

import (
	"UE-non3GPP/internal/nas/context"
	"encoding/binary"
	"fmt"
	"net"
)

type UeIpSec struct {
	InterfaceName string
	tcpConn       *net.TCPConn
	NasContext    *context.UeNas
}

func NewUeIpSec(ueNas *context.UeNas,
	conn *net.TCPConn,
	intName string) *UeIpSec {

	ue := &UeIpSec{}
	ue.tcpConn = conn
	ue.NasContext = ueNas
	ue.InterfaceName = intName

	return ue
}

func (ue *UeIpSec) GetTcpConn() *net.TCPConn {
	return ue.tcpConn
}

func (ue *UeIpSec) SetTcpConn(conn *net.TCPConn) {
	ue.tcpConn = conn
}

func (ue *UeIpSec) EncapNasMsgToEnvelope(nasPDU []byte) []byte {
	// According to TS 24.502 8.2.4,
	// in order to transport a NAS message over the non-3GPP access between the UE and the N3IWF,
	// the NAS message shall be framed in a NAS message envelope as defined in subclause 9.4.
	// According to TS 24.502 9.4,
	// a NAS message envelope = Length | NAS Message
	nasEnv := make([]byte, 2)
	binary.BigEndian.PutUint16(nasEnv, uint16(len(nasPDU)))
	nasEnv = append(nasEnv, nasPDU...)
	return nasEnv
}

func (ue *UeIpSec) DecapNasPduFromEnvelope(envelop []byte) ([]byte, int, error) {
	// According to TS 24.502 8.2.4 and TS 24.502 9.4,
	// a NAS message envelope = Length | NAS Message

	if uint16(len(envelop)) < 2 {
		return envelop, 0, fmt.Errorf("NAS message envelope is less than 2 bytes")
	}
	// Get NAS Message Length
	nasLen := binary.BigEndian.Uint16(envelop[:2])
	if uint16(len(envelop)) < 2+nasLen {
		return envelop, 0, fmt.Errorf("NAS message envelope is less than the sum of 2 and naslen")
	}
	nasMsg := make([]byte, nasLen)
	copy(nasMsg, envelop[2:2+nasLen])

	return nasMsg, int(nasLen), nil
}
