package api

type UeStatus struct {
	RegisterTime string `json:"registerTime"`
	PduTime      string `json:"pduSessionTime"`
	AuthTime     string `json:"authenticationNasTime"`
	SecurityTime string `json:"securityProcedureNasTime"`
	IpsecTime    string `json:"ipsecTime"`
}

type StatusValue struct {
	BytesRecv   uint64 `json:"bytesRecv"`
	BytesSent   uint64 `json:"bytesSent"`
	PacketsSent uint64 `json:"packetsSent"`
	PacketsRecv uint64 `json:"packetsRecv"`
}

type Throughput struct {
	ThroughputIn  uint64 `json:"throughputIn"`
	ThroughputOut uint64 `json:"throughputOut"`
}
