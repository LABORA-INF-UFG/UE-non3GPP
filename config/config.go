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
		Msin  string `yaml: "msin"`
		Hplmn struct {
			Mcc string `yaml: "mcc"`
			Mnc string `yaml: "mnc"`
		} `yaml: "hplmn"`
		RanUeNgapId                   int64  `yaml: "ranuengapid"`
		AmfUeNgapId                   int64  `yaml: "amfuengapid"`
		AuthenticationManagementField string `yaml: "authenticationmanagementfield"`
		LocalPublicIPAddr             string `yaml: "localpublicipaddr"`
		LocalPublicPortUDPConnection  string `yaml: "localpublicportudpconnection"`
		GREInterface                  struct {
			Name string `yaml: "name"`
			Mtu  int    `yaml: "mtu"`
			Ttl  uint8    `yaml: "ttl"`
		} `yaml: "greinterface"`

		IPSecInterface struct {
			Name string `yaml: "name"`
			Mark uint32 `yaml: "mark"`
			Mtu  int    `yaml: "mtu"`
			
		} `yaml: "ipsecinterface"`

		Snssai struct {
			Sst int32  `yaml: "sst"`
			Sd  string `yaml: "sd"`
		} `yaml: "snssai"`
		PDUSessionId uint8  `yaml: "pdusessionid"`
		DNNString    string `yaml: "dnnstring"`
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

func GetConfig() Config {
	var cfg = Config{}
	Ddir := RootDir()
	configPath, err := filepath.Abs(Ddir + "/config/config.yaml")
	log.Debug(configPath)
	if err != nil {
		panic(err)
	}
	file, err := ioutil.ReadFile(configPath)
	err = yaml.Unmarshal([]byte(file), &cfg)
	if err != nil {
		panic(err)
	}
	return cfg
}
