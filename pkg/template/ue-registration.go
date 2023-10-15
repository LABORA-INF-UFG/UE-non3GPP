package template

import (
	"UE-non3GPP/config"
	controlPlane "UE-non3GPP/internal/ike"
	"UE-non3GPP/internal/ike/context"
	contextNas "UE-non3GPP/internal/nas/context"

	"UE-non3GPP/pkg/utils"

	log "github.com/sirupsen/logrus"
	"os"
	"os/signal"
)

func UENon3GPPConnection() {

	cfg := config.GetConfig()

	// create args for creation of instance Nas
	argsNas := contextNas.ArgumentsNas{
		Mcc:         cfg.Ue.Hplmn.Mcc,
		Mnc:         cfg.Ue.Hplmn.Mnc,
		Msin:        cfg.Ue.Msin,
		RanUeNgapId: cfg.Ue.RanUeNgapId,
		K:           cfg.Ue.AuthSubscription.PermanentKeyValue,
		Opc:         cfg.Ue.AuthSubscription.OpcValue,
		Op:          cfg.Ue.AuthSubscription.OpValue,
		Amf:         cfg.Ue.AuthenticationManagementField,
		Sqn:         cfg.Ue.AuthSubscription.SequenceNumber,
		Sst:         cfg.Ue.Snssai.Sst,
		Sd:          cfg.Ue.Snssai.Sd,
		Dnn:         cfg.Ue.DNNString,
	}

	//	routerUe := GetRouter()

	ueNas := contextNas.NewUeNas(argsNas)
	log.Info("[UE][NAS] NAS Context Created")

	utils := utils.NewUtils()
	ueIke := context.NewUeIke(ueNas, utils)
	log.Info("[UE][IKE] IKE Context Created")

	//_ = controllers.NewUEHandler(routerUe, ueNas, ueIke)
	//	controllers.NewNetworkMonitorHandler(routerUe)
	//	log.Info("[UE][METRICS][HTTP] Metrics Context Created")

	// init ue control plane
	controlPlane.Run(cfg, ueIke)

	// init http server for metrics
	//go SetServer(cfg.MetricInfo.Httport, cfg.MetricInfo.HttpAddress, routerUe)

	//	address := fmt.Sprintf("%s:%s", cfg.MetricInfo.HttpAddress, cfg.MetricInfo.Httport)
	//	log.Info("[UE][METRICS][HTTP] Metric Server is running - " + address)

	// control the signals
	sigUE := make(chan os.Signal, 1)
	signal.Notify(sigUE, os.Interrupt)

	// Block until a signal is received.
	<-sigUE
	err := ueIke.Terminate()
	if !err {
		log.Error("[UE][IKE] IKE Context Termination failed")
		log.Error("[UE][IKE] ", err)
		return
	}

	err = ueNas.Terminate()
	if !err {
		log.Error("[UE][NAS] NAS Context Termination failed")
		log.Error("[UE][NAS] ", err)
		return
	}
	log.Info("[UE] UE terminated")
}

type UeHandler struct {
	nasInfo *contextNas.UeNas
	ikeInfo *context.UeIke
}

//func RegLogUeInitInfoHandler(ueNas *contextNas.UeNas, ueIke *context.UeIke) {
//	handler := &UeHandler{
//		nasInfo: ueNas,
//		ikeInfo: ueIke,
//	}
//}

//func RegLogUeInitInfo(ueNas *contextNas.UeNas, ueIke *context.UeIke) {
//
//	ueDto := &api.UeStatus{}
//
//	// PDU Session information
//	if ueNas.StateSM == 2 {
//		ueDto.PduIsActive = "Yes"
//	} else {
//		ueDto.PduIsActive = "No"
//	}
//
//	// Registration information
//	if ueNas.StateMM == 1 {
//		ueDto.UeIsRegister = "Yes"
//	} else {
//		ueDto.UeIsRegister = "No"
//	}
//
//	// time of Registration and PDU Session
//	ueDto.RegisterTime = ueNas.RegisterTime.Milliseconds()
//	ueDto.PduTime = ueNas.PduTime.Milliseconds()
//	ueDto.SecurityTime = ueNas.SecurityTime.Milliseconds()
//	ueDto.AuthTime = ueNas.AuthTime.Milliseconds()
//	ueDto.IpsecTime = ueIke.IpsecTime.Milliseconds()
//
//	fmt.Println("ueDto.RegisterTime: " + strconv.FormatInt(ueDto.RegisterTime, 10))
//	fmt.Println("ueDto.PduTime: " + strconv.FormatInt(ueDto.PduTime, 10))
//	fmt.Println("ueDto.IpsecTime: " + strconv.FormatInt(ueDto.IpsecTime, 10))
//	fmt.Println("ueDto.AuthTime: " + strconv.FormatInt(ueDto.AuthTime, 10))
//	fmt.Println("ueDto.SecurityTime: " + strconv.FormatInt(ueDto.SecurityTime, 10))
//
//}

/*func GetRouter() *gin.Engine {

	// set the infraestructure
	router := gin.Default()

	router.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"PUT", "GET", "DELETE", "POST"},
		AllowHeaders:     []string{"Origin", "Content-Length", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour},
	))

	return router
}
*/

/*
func SetServer(port, ip string, router *gin.Engine) {
	// set the server
	address := fmt.Sprintf("%s:%s", ip, port)
	log.Info("[UE][METRICS][HTTP] Init HTTP Server " + address)
	err := http.ListenAndServe(address, router)
	if err != nil {
		log.Fatal("[UE][METRICS][HTTP] Error in set HTTP server")
		return
	}

}

*/
