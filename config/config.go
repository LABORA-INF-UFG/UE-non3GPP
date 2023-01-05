package config

import (
	"io/ioutil"
	"path"
	"path/filepath"
	"runtime"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"
)

var Data = getConfig()

type Config struct {
	Ue struct {
		AuthSubscription struct {
			PermanentKeyValue string `yaml: "permanentkeyvalue"`
			OpcValue          string `yaml: "opcvalue"`
			OpValue           string `yaml: "opvalue"`
			SequenceNumber    string `yaml: "sequencenumber"`
		} `yaml: "authsubscription"`
		Supi                          string `yaml: "supi"`
		RanUeNgapId                   int64  `yaml: "ranuengapid"`
		AmfUeNgapId                   int64  `yaml: "amfuengapid"`
		AuthenticationManagementField string `yaml: "authenticationmanagementfield"`
		IpUDPConnection               string `yaml: "ipudpconnection"`
		PortUDPConnection             string `yaml: "portudpconnection"`
	} `yaml:"ue"`

	N3iwfInfo struct {
		IKEBindAddress     string `yaml: "ikebindaddress"`
		IKEBindPort        string `yaml: "ikebindport"`
		IPSecIfaceProtocol string `yaml: "ipsecifaceprotocol"`
	} `yaml:"n3iwfinfo"`

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
	configPath, err := filepath.Abs(Ddir + "/config/config.yaml")
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
	configPath, err := filepath.Abs(Ddir + "/config/config.yaml")
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
