package controller

import "github.com/gin-gonic/gin"

type UeHandler struct {
}

func NewUEHandler(router *gin.Engine) *UeHandler {
	routesUE := router.Group("ue")

	handler := &UeHandler{}

	routesUE.GET("/info", handler.getInfoUE)

	return handler
}

func (ue *UeHandler) getInfoUE(ctx *gin.Context) {
}
