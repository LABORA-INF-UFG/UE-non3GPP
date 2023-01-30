package context

import "net"

type Ue struct {
	udpConn  *net.UDPConn
	stateIke uint8
}

func (ue *Ue) GetUdpConn() *net.UDPConn {
	return ue.udpConn
}

func (ue *Ue) SetUdpConn(conn *net.UDPConn) {
	ue.udpConn = conn
}
