package config

import (
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"path"
	"path/filepath"
	"runtime"
)

var Data = getConfig()

type Config struct {
	Ue struct {
		Supi                          string `yaml: "supi"`
		RanUeNgapId                   int64  `yaml: "ranuengapid"`
		AmfUeNgapId                   int64  `yaml: "amfuengapid"`
		AuthenticationManagementField string `yaml: "authenticationmanagementfield"`
	} `yaml:"ue"`

	Logs struct {
		Level int `yaml: "level"`
	} `yaml:"logs"`
}

func RootDir() string {
	_, b, _, _ := runtime.Caller(0)
	d := path.Join(path.Dir(b))
	return filepath.Dir(d)
}

func getConfig() Config {
	var cfg = Config{}
	Ddir := RootDir()
	configPath, err := filepath.Abs(Ddir + "/config/config.yml")
	log.Debug(configPath)
	if err != nil {
		log.Fatal("Could not find config in: ", configPath)
	}
	file, err := ioutil.ReadFile(configPath)
	err = yaml.Unmarshal([]byte(file), &cfg)
	if err != nil {
		log.Fatal("Could not read file in: ", configPath)
	}

	return cfg
}

func GetConfig() (Config, error) {
	var cfg = Config{}
	Ddir := RootDir()
	configPath, err := filepath.Abs(Ddir + "/config/config.yml")
	log.Debug(configPath)
	if err != nil {
		return Config{}, nil
	}
	file, err := ioutil.ReadFile(configPath)
	err = yaml.Unmarshal([]byte(file), &cfg)
	if err != nil {
		return Config{}, nil
	}

	return cfg, nil
}
