package api

type UeStatus struct {
	RegisterTime string `json:"registerTime"`
	PduTime      string `json:"pduSessionTime"`
	AuthTime     string `json:"authenticationNasTime"`
	SecurityTime string `json:"securityProcedureNasTime"`
	IpsecTime    string `json:"ipsecTime"`
}

type NetworkStatus struct {
	NetworkInterfaceName string        `json:"networkInterfaceName"`
	Values               []StatusValue `json:"statusValue"`
}

type StatusValue struct {
	BytesRecv   uint64 `json:"bytesRecv"`
	BytesSent   uint64 `json:"bytesSent"`
	PacketsSent uint64 `json:"packetsSent"`
	PacketsRecv uint64 `json:"packetsRecv"`
}

type NetworkThroughput struct {
	NetworkInterfaceName string       `json:"networkInterfaceName"`
	Throughputs          []Throughput `json:"throughputs"`
}

type Throughput struct {
	In  uint64 `json:"in"`
	Out uint64 `json:"out"`
}
