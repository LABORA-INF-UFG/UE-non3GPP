package api

import "time"

type UeStatus struct {
	RegisterTime string `json:"registerTime"`
	PduTime      string `json:"pduSessionTime"`
	AuthTime     string `json:"authenticationNasTime"`
	SecurityTime string `json:"securityProcedureNasTime"`
	IpsecTime    string `json:"ipsecTime"`
}

type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type WifiMetrics struct {
	TimeStamp   time.Time `json:"timestamp"`
	ESSID       string    `json:"essid"`
	Mode        string    `json:"mode"`
	Frequency   string    `json:"frequency"`
	AccessPoint string    `json:"access_point"`
	BitRate     string    `json:"bit_rate"`
	TxPower     string    `json:"tx_power"`
	LinkQuality string    `json:"link_quality"`
	SignalLevel string    `json:"signal_level"`
	NoiseLevel  string    `json:"noise_level"`
}

type StatusValue struct {
	BytesRecv   uint64 `json:"bytesRecv"`
	BytesSent   uint64 `json:"bytesSent"`
	PacketsSent uint64 `json:"packetsSent"`
	PacketsRecv uint64 `json:"packetsRecv"`
}

type Throughput struct {
	ThroughputIn  float64 `json:"throughputIn"`
	ThroughputOut float64 `json:"throughputOut"`
}
