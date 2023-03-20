package api

type UeStatus struct {
	UeIsRegister string `json:"ueIsRegister"`
	PduIsActive  string `json:"pduIsActive"`
	RegisterTime int64  `json:"registerTime"`
	PduTime      int64  `json:"pduSessionTime"`
	AuthTime     int64  `json:"authenticationNasTime"`
	SecurityTime int64  `json:"securityProcedureNasTime"`
	IpsecTime    int64  `json:"ipsecTime"`
}
