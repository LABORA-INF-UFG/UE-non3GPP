package controller

import (
	contextIke "UE-non3GPP/internal/ike/context"
	"UE-non3GPP/internal/nas/context"
	"UE-non3GPP/pkg/api"
	"github.com/gin-gonic/gin"
	"net/http"
)

type UeHandler struct {
	nasInfo *context.UeNas
	ikeInfo *contextIke.UeIke
}

func NewUEHandler(router *gin.Engine, nas *context.UeNas, ike *contextIke.UeIke) *UeHandler {
	routesUE := router.Group("ue")

	handler := &UeHandler{
		nasInfo: nas,
		ikeInfo: ike,
	}

	routesUE.GET("/info", handler.getInfoUE)

	return handler
}

func (ue *UeHandler) getInfoUE(ctx *gin.Context) {
	ueDto := &api.UeStatus{}

	// PDU Session information
	if ue.nasInfo.StateSM == 2 {
		ueDto.PduIsActive = "Yes"
	} else {
		ueDto.PduIsActive = "No"
	}

	// Registration information
	if ue.nasInfo.StateMM == 1 {
		ueDto.UeIsRegister = "Yes"
	} else {
		ueDto.UeIsRegister = "No"
	}

	// time of Registration and PDU Session
	ueDto.RegisterTime = ue.nasInfo.RegisterTime.Milliseconds()
	ueDto.PduTime = ue.nasInfo.PduTime.Milliseconds()

	ctx.JSON(http.StatusOK, ueDto)
}
