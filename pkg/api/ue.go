package api

type UeStatus struct {
	UeIsRegister string `json:"ueIsRegister"`
	PduIsActive  string `json:"pduIsActive"`
	RegisterTime string `json:"registerTime"`
	PduTime      string `json:"pduTime"`
}
