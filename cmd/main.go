package main

import (
	"UE-non3GPP/config"
	"UE-non3GPP/pkg/metrics"
	"UE-non3GPP/pkg/template"
	"os"

	"github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
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
	log.Info("UE-non3GPP version " + version)
}

func main() {

	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name:    "ue",
				Aliases: []string{"non3GPPAccess"},
				Usage:   "Non-3GPP UE-Connection",
				Action: func(c *cli.Context) error {
					name := "Non 3GPP UE attached with configuration"
					cfg := config.Data
					log.Info("---------------------------------------")
					log.Info("[UE] Starting connect function: ", name)
					log.Info("[UE] Info MSIN: ", cfg.Ue.Msin)

					metrics.RemoveMetricsFile()
					template.UENon3GPPConnection()

					return nil
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}

}
