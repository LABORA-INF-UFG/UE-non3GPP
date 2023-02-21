package context

import (
	"UE-non3GPP/internal/nas/context"
	"net"
)

type UeIpSec struct {
	tcpConn    *net.TCPConn
	NasContext *context.UeNas
}

func NewUeIpSec(ueNas *context.UeNas,
	conn *net.TCPConn) *UeIpSec {
	ue := &UeIpSec{}
	ue.tcpConn = conn
	ue.NasContext = ueNas
	return ue
}

func (ue *UeIpSec) GetTcpConn() *net.TCPConn {
	return ue.tcpConn
}

func (ue *UeIpSec) SetTcpConn(conn *net.TCPConn) {
	ue.tcpConn = conn
}
