package api

type UeStatus struct {
	RegisterTime int64 `json:"registerTime"`
	PduTime      int64 `json:"pduSessionTime"`
	AuthTime     int64 `json:"authenticationNasTime"`
	SecurityTime int64 `json:"securityProcedureNasTime"`
	IpsecTime    int64 `json:"ipsecTime"`
}

type NetworkStatus struct {
	NetworkInterfaceName string        `json:"networkInterfaceName"`
	Leak                 []NetworkLeak `json:"inputLeak"`
}

type NetworkLeak struct {
	InputThroughput  uint64 `json:"inputThroughput"`
	OutputThroughput uint64 `json:"outputThroughput"`
}
