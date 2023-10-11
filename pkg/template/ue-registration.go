package template

import (
	"UE-non3GPP/config"
	controlPlane "UE-non3GPP/internal/ike"
	"UE-non3GPP/internal/ike/context"
	contextNas "UE-non3GPP/internal/nas/context"
	ueController "UE-non3GPP/pkg/controller"
	"UE-non3GPP/pkg/utils"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
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

	routerUe := GetRouter()

	ueNas := contextNas.NewUeNas(argsNas)
	log.Info("[UE][NAS] NAS Context Created")

	utils := utils.NewUtils()
	ueIke := context.NewUeIke(ueNas, utils)
	log.Info("[UE][IKE] IKE Context Created")

	_ = ueController.NewUEHandler(routerUe, ueNas, ueIke)
	log.Info("[UE][HTTP] Metrics Context Created")

	// init ue control plane
	controlPlane.Run(cfg, ueIke)

	// init http server for metrics
	go SetServer(cfg.MetricInfo.Httport, cfg.MetricInfo.HttpAddress, routerUe)
	log.Info("[UE][HTTP] Metric Server is running")

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

func GetRouter() *gin.Engine {

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

func SetServer(port, ip string, router *gin.Engine) {
	// set the server
	address := fmt.Sprintf("%s:%s", ip, port)

	err := http.ListenAndServe(address, router)
	if err != nil {
		log.Fatal("[UE][HTTP] Error in set HTTP server")
		return
	}
}
