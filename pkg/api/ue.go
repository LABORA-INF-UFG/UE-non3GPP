package api

type UeStatus struct {
	UeIsRegister string `json:"ueIsRegister"`
	PduIsActive  string `json:"pduIsActive"`
	RegisterTime int64  `json:"registerTime"`
	PduTime      int64  `json:"pduTime"`
}
