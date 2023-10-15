package controller

import (
	contextIke "UE-non3GPP/internal/ike/context"
	"UE-non3GPP/internal/nas/context"
	"UE-non3GPP/webconsole/api"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/shirou/gopsutil/net"
	log "github.com/sirupsen/logrus"
	"net/http"
	"time"
)

type UeHandler struct {
	nasInfo *context.UeNas
	ikeInfo *contextIke.UeIke
}

func NewNetworkMonitorHandler(router *gin.Engine) {
	routesNetwork := router.Group("network")
	routesNetwork.GET("/monitor", getNetworkStatus)
}

func getNetTeste(ctx *gin.Context) {
	//interfaceName := "eth0" // Substitua "eth0" pelo nome da sua interface de rede

	// Obtenha as estatísticas da interface de rede
	netStats, err := net.IOCounters(true)
	if err != nil {
		fmt.Println("Erro ao obter estatísticas de rede:", err)
		return
	}

	// Procure as estatísticas da interface específica
	for _, stats := range netStats {
		//if stats.Name == interfaceName {
		fmt.Printf("Interface: %s\n", stats.Name)
		fmt.Printf("Bytes Recebidos: %d\n", stats.BytesRecv)
		fmt.Printf("Bytes Enviados: %d\n", stats.BytesSent)
		fmt.Printf("Pacotes Recebidos: %d\n", stats.PacketsRecv)
		fmt.Printf("Pacotes Enviados: %d\n", stats.PacketsSent)
		//}
	}
}

func getNetworkStatus(ctx *gin.Context) {
	netStatusDto := &api.NetworkStatus{}
	interfaceName := "gretun1"

	netStatusDto.NetworkInterfaceName = interfaceName

	var lsLeak []api.NetworkLeak
	for i := 0; i < 10; i++ {
		leakDto := api.NetworkLeak{}

		/* captura latencia */
		prevNetStat, err := net.IOCounters(true)
		if err != nil {
			fmt.Println("Erro ao obter estatísticas de rede:", err)
			return
		}
		time.Sleep(1 * time.Second)

		currentNetStat, err := net.IOCounters(true)
		if err != nil {
			fmt.Println("Erro ao obter estatísticas de rede:", err)
			return
		}

		// Encontra a interface de rede desejada
		var prevStat, currentStat *net.IOCountersStat

		for _, stat := range prevNetStat {

			if stat.Name == interfaceName {
				prevStat = &stat
				break
			}
		}

		for _, stat := range currentNetStat {

			if stat.Name == interfaceName {
				currentStat = &stat
				break
			}
		}

		// Calcula a vazão de entrada e saída em bytes por segundo
		if prevStat != nil && currentStat != nil {
			leakDto.InputThroughput = currentStat.BytesRecv - prevStat.BytesRecv
			leakDto.OutputThroughput = currentStat.BytesSent - prevStat.BytesSent
		} else {
			//fmt.Println("Interface de rede não encontrada.")
		}

		lsLeak = append(lsLeak, leakDto)
	}
	netStatusDto.Leak = lsLeak

	ctx.JSON(http.StatusOK, netStatusDto)
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
	ueDto.SecurityTime = ue.nasInfo.SecurityTime.Milliseconds()
	ueDto.AuthTime = ue.nasInfo.AuthTime.Milliseconds()
	ueDto.IpsecTime = ue.ikeInfo.IpsecTime.Milliseconds()

	log.Info("Metrics Server Request ok!")

	ctx.JSON(http.StatusOK, ueDto)
}
