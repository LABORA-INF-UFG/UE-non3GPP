package main

import (
	"UE-non3GPP/webconsole/config"
	controllers "UE-non3GPP/webconsole/controller"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"net/http"
	"os"
	"time"
)

const version = "1.0.0"

func init() {
	cfg := config.GetConfig()

	// Output to stdout instead of the default stderr
	log.SetOutput(os.Stdout)

	if cfg.Logs.Level == 0 {
		log.SetLevel(log.InfoLevel)
	} else {
		log.SetLevel(log.Level(cfg.Logs.Level))
	}
	spew.Config.Indent = "\t"
	log.Info("UE-non3GPP API-Server version: " + version)
}

func main() {
	app := &cli.App{
		Name:     "Non-3GPP API-Server",
		Usage:    "Non-3GPP API-Server",
		Commands: []*cli.Command{
			// Adicione seus comandos personalizados aqui, se necessário.
		},
		Action: func(c *cli.Context) error {
			name := "Non 3GPP UE API-Server - Metrics "
			cfg := config.Data
			log.Info("---------------------------------------")
			log.Info("[UE-non3GPP-API-Server] Starting connect function: ", name)
			log.Info("[UE-non3GPP-API-Server] HttpAddress: ", cfg.MetricInfo.HttpAddress)
			log.Info("[UE-non3GPP-API-Server] Httport: ", cfg.MetricInfo.Httport)

			routerUe := GetRouter()
			//aqui vamos precisar recuperar do arquivo de log
			//_ = controllers.NewUEHandler(routerUe, ueNas, ueIke)
			controllers.NewNetworkMonitorHandler(routerUe)

			log.Info("[UE][METRICS][HTTP] Metrics Context Created")
			// init http server for metrics
			SetServer(cfg.MetricInfo.Httport, cfg.MetricInfo.HttpAddress, routerUe)

			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
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
	log.Info("[UE][METRICS][HTTP] Init HTTP Server " + address)
	err := http.ListenAndServe(address, router)
	if err != nil {
		log.Fatal("[UE][METRICS][HTTP] Error in set HTTP server")
		return
	}
}