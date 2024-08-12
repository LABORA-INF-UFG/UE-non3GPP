package controller

import (
	"UE-non3GPP/pkg/metrics"
	"UE-non3GPP/webconsole/backend/api"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/shirou/gopsutil/net"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"time"
)

func NewWiFiMetricstHandler(router *gin.Engine) {
	routesNetwork := router.Group("ue")
	routesNetwork.GET("/interface/:interface/wifi/metrics/:interval", GetWiFiMetrics)
}

func GetWiFiMetrics(ctx *gin.Context) {
	net_name := ctx.Param("interface")
	interval := ctx.Param("interval")

	num, err := strconv.Atoi(interval)
	if err != nil {
		log.Errorf("[UE][WiFi][Metrics]  %v", err)
		errorResponse := api.ErrorResponse{
			Code:    http.StatusBadRequest,
			Message: fmt.Sprintf("Intervall invalid: %v", err),
		}
		ctx.JSON(http.StatusBadRequest, errorResponse)
		return
	}

	var wifiMetrics []api.WifiMetrics
	for i := 0; i < num; i++ {

		cmd := exec.Command("iwconfig", net_name)
		output, err := cmd.Output()
		if err != nil {
			log.Errorf("[UE][WiFi][Metrics]  %v", err)
			errorResponse := api.ErrorResponse{
				Code:    http.StatusBadRequest,
				Message: fmt.Sprintf("Failed to execute command: %v", err),
			}
			ctx.JSON(http.StatusBadRequest, errorResponse)
			return
		}
		outStr := string(output)

		metrics := api.WifiMetrics{
			TimeStamp:   time.Now(),
			ESSID:       extractValue(outStr, `ESSID:"([^"]+)"`),
			Mode:        extractValue(outStr, `Mode:([^\s]+)`),
			Frequency:   extractValue(outStr, `Frequency:([^\s]+)`),
			AccessPoint: extractValue(outStr, `Access Point: ([^\s]+)`),
			BitRate:     extractValue(outStr, `Bit Rate=([^\s]+)`),
			TxPower:     extractValue(outStr, `Tx-Power=([^\s]+)`),
			LinkQuality: extractValue(outStr, `Link Quality=([^\s]+/[^\s]+)`),
			SignalLevel: extractValue(outStr, `Signal level=([^\s]+)`),
			NoiseLevel:  extractValue(outStr, `Noise level=([^\s]+)`),
		}
		wifiMetrics = append(wifiMetrics, metrics)
		time.Sleep(1 * time.Second)
	}

	if wifiMetrics == nil {
		log.Errorf("[UE][WiFi][Metrics] WiFi NetWork Interface not found")
		errorResponse := api.ErrorResponse{
			Code:    http.StatusBadRequest,
			Message: fmt.Sprintf("WiFi NetWork Interface not found"),
		}
		ctx.JSON(http.StatusBadRequest, errorResponse)
		return
	}
	ctx.JSON(http.StatusOK, wifiMetrics)
}

func extractValue(output, regex string) string {
	re := regexp.MustCompile(regex)
	matches := re.FindStringSubmatch(output)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

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

	ctx.JSON(http.StatusOK, statusValues)
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

	var lsThroughput []api.Throughput
	for i := 0; i < num; i++ {
		leakDto := api.Throughput{}

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
			inputThroughput := currentStat.BytesRecv - prevStat.BytesRecv
			outputThroughput := currentStat.BytesSent - prevStat.BytesSent

			//leakDto.ThroughputIn = inputThroughput
			//leakDto.ThroughputOut = outputThroughput

			//fmt.Println("IN: " + strconv.FormatUint(leakDto.ThroughputIn, 10))
			//fmt.Println("Out: " + strconv.FormatUint(leakDto.ThroughputOut, 10))

			// Convertendo bytes para megabytes
			inputThroughputMB := float64(inputThroughput) / 1048576.0
			outputThroughputMB := float64(outputThroughput) / 1048576.0

			// Armazenando os valores convertidos em MB
			leakDto.ThroughputIn = inputThroughputMB
			leakDto.ThroughputOut = outputThroughputMB

			//fmt.Printf("IN: %.2f MB\n", inputThroughputMB)
			//fmt.Printf("Out: %.2f MB\n", outputThroughputMB)
		}

		lsThroughput = append(lsThroughput, leakDto)
	}
	ctx.JSON(http.StatusOK, lsThroughput)
}

func NewUEConnectionInfo(router *gin.Engine) {
	routesUE := router.Group("ue")
	routesUE.GET("/info", GetInfoUE)
}

func GetInfoUE(ctx *gin.Context) {
	ueDto := &api.UeStatus{}

	RegTime, _ := metrics.GetMetricsValue("RegisterTime")
	ueDto.RegisterTime = RegTime

	PduTime, _ := metrics.GetMetricsValue("PDUTime")
	ueDto.PduTime = PduTime

	SecurityTime, _ := metrics.GetMetricsValue("SecurityTime")
	ueDto.SecurityTime = SecurityTime

	AuthTime, _ := metrics.GetMetricsValue("AuthTime")
	ueDto.AuthTime = AuthTime

	IpsecTime, _ := metrics.GetMetricsValue("IpsecTime")
	ueDto.IpsecTime = IpsecTime

	ctx.JSON(http.StatusOK, ueDto)
}
