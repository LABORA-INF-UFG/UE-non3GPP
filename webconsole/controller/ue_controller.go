package controller

import (
	"UE-non3GPP/pkg/metrics"
	"UE-non3GPP/webconsole/api"
	"github.com/gin-gonic/gin"
	"github.com/shirou/gopsutil/net"
	log "github.com/sirupsen/logrus"
	"net/http"
	"strconv"
	"time"
)

func NewNetworkStatustHandler(router *gin.Engine) {
	routesNetwork := router.Group("ue")
	routesNetwork.GET("/interface/:interface/network/status/:interval", GetNetworkStatus)
}

func GetNetworkStatus(ctx *gin.Context) {
	net_name := ctx.Param("interface")

	interval := ctx.Param("interval")

	num, err := strconv.Atoi(interval)
	if err != nil {
		log.Fatal("[UE][Metrics][Throughput] It is mandatory to inform :interval - /interface/:interface/throughput/monitor/:interval ")
		return
	}

	netStatusDto := &api.NetworkStatus{}
	netStatusDto.NetworkInterfaceName = net_name

	var statusValues []api.StatusValue

	for i := 0; i < num; i++ {

		time.Sleep(1 * time.Second)
		netStats, err := net.IOCounters(true)

		if err != nil {
			log.Fatal("[UE][Metrics][Status] Error getting network  prev statistics from interface "+net_name, err)
			return
		}
		for _, stats := range netStats {
			if stats.Name == net_name {
				netStatusDto := api.StatusValue{}

				netStatusDto.BytesRecv = stats.BytesRecv
				netStatusDto.BytesSent = stats.BytesSent
				netStatusDto.PacketsRecv = stats.PacketsRecv
				netStatusDto.PacketsSent = stats.PacketsSent

				statusValues = append(statusValues, netStatusDto)

			}
		}
	}
	if statusValues == nil {
		log.Fatal("[UE][Metrics][Status] NetWork Interface not found! "+net_name, err)
		return
	}
	netStatusDto.Values = statusValues
	ctx.JSON(http.StatusOK, netStatusDto)
}

func NewNetworkThroughputHandler(router *gin.Engine) {
	routesNetwork := router.Group("ue")
	routesNetwork.GET("/interface/:interface/throughput/monitor/:interval", GetNetworkThroughput)
}

func GetNetworkThroughput(ctx *gin.Context) {
	net_name := ctx.Param("interface")
	interval := ctx.Param("interval")

	num, err := strconv.Atoi(interval)
	if err != nil {
		log.Fatal("[UE][Metrics][Throughput] It is mandatory to inform :interval - /interface/:interface/throughput/monitor/:interval ")
		return
	}

	netStatusDto := &api.NetworkThroughput{}
	netStatusDto.NetworkInterfaceName = net_name

	var lsLeak []api.Throughput
	for i := 0; i < num; i++ {
		leakDto := api.Throughput{}

		prevNetStat, err := net.IOCounters(true)
		if err != nil {
			log.Fatal("[UE][Metrics][Throughput] Error getting network  prev statistics from interface "+net_name, err)
			return
		}
		time.Sleep(1 * time.Second)
		currentNetStat, err := net.IOCounters(true)
		if err != nil {
			log.Fatal("[UE][Metrics][Throughput] Error getting network current statistics from interface "+net_name, err)
			return
		}
		var prevStat, currentStat *net.IOCountersStat
		for _, stat := range prevNetStat {
			if stat.Name == net_name {
				prevStat = &stat
				break
			}
		}

		for _, stat := range currentNetStat {
			if stat.Name == net_name {
				currentStat = &stat
				break
			}
		}

		if prevStat != nil && currentStat != nil {
			leakDto.In = currentStat.BytesRecv - prevStat.BytesRecv
			leakDto.Out = currentStat.BytesSent - prevStat.BytesSent
		}
		lsLeak = append(lsLeak, leakDto)
	}
	netStatusDto.Throughputs = lsLeak
	ctx.JSON(http.StatusOK, netStatusDto)
}

func NewUEConnectionInfo(router *gin.Engine) {
	routesUE := router.Group("ue")
	routesUE.GET("/info", GetInfoUE)
}

func GetInfoUE(ctx *gin.Context) {
	ueDto := &api.UeStatus{}

	// time of Registration and PDU Session
	RegTime, _ := metrics.GetMetricsValue("RegisterTime")
	ueDto.RegisterTime = RegTime

	PduTime, _ := metrics.GetMetricsValue("PduTime")
	ueDto.PduTime = PduTime

	SecurityTime, _ := metrics.GetMetricsValue("SecurityTime")
	ueDto.SecurityTime = SecurityTime

	AuthTime, _ := metrics.GetMetricsValue("AuthTime")
	ueDto.AuthTime = AuthTime

	IpsecTime, _ := metrics.GetMetricsValue("IpsecTime")
	ueDto.IpsecTime = IpsecTime

	ctx.JSON(http.StatusOK, ueDto)
}
