package main

import (
	"github.com/LABORA-INF-UFG/UE-non3GPP/config"
	"github.com/LABORA-INF-UFG/UE-non3GPP/engine/ue"
	"github.com/davecgh/go-spew/spew"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
	"os"
)

const version = "1.0.0"

func init() {
	cfg, err := config.GetConfig()
	if err != nil {
		log.Fatal("Config file not found!")
	}

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
				Aliases: []string{"ue"},
				Usage:   "Testing Non 3GPP UE connection",
				Action: func(c *cli.Context) error {
					name := "Testing an Non 3GPP UE attached with configuration"
					cfg := config.Data
					log.Info("---------------------------------------")
					log.Info("[UE-non3GPP] Starting connect function: ", name)
					log.Info("[UE-non3GPP][UE] Supi: ", cfg.Ue.Supi)

					ue.UENon3GPPConnection()

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
