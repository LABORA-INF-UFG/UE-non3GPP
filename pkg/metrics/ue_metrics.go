package metrics

import (
	"bufio"
	"errors"
	log "github.com/sirupsen/logrus"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var ueMetrics string = "ue-metrics.txt"

func GetMetricsFilePath() string {
	Ddir := RootDir()
	return Ddir + "/metrics/" + ueMetrics
}

func InitMetricsFile() {
	filename := GetMetricsFilePath()
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		CreateMetricsFile()
	} else {
		log.Info("[UE] [Metrics]  could not find metrics file in: ", filename)
	}
}

func RemoveMetricsFile() {
	filename := GetMetricsFilePath()
	log.Info("[UE] [Metrics] Remove Ue Metrics File: ", filename)
	if _, err := os.Stat(filename); !os.IsNotExist(err) {

		err := os.Remove(filename)
		if err != nil {
			log.Fatal("[UE] [Metrics] could not find metrics file in: ", filename)
			return
		}
	}
}

func CreateMetricsFile() {
	filename := GetMetricsFilePath()
	initialContent := "Este é o conteúdo inicial do arquivo."
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		log.Fatal("[UE] [Metrics] could not open metrics file ", err)
		return
	}
	defer file.Close()
	_, err = file.WriteString(initialContent)
	if err != nil {
		log.Fatal("[UE] [Metrics] could not Wrinte into metrics file ", err)
		return
	}
	log.Info("[UE][Metrics] Metrics File was create: ", filename)
}

func RootDir() string {
	_, b, _, _ := runtime.Caller(0)
	d := path.Join(path.Dir(b))
	return filepath.Dir(d)
}

func AddRegisterTime(duration time.Duration) {
	newText := "RegisterTime:" + strconv.FormatInt(duration.Milliseconds(), 10)
	AddNewLine(newText)
}

func AddPDUTime(duration time.Duration) {
	newText := "PDUTime:" + strconv.FormatInt(duration.Milliseconds(), 10)
	AddNewLine(newText)
}

func AddIpsecTime(duration time.Duration) {
	newText := "IpsecTime:" + strconv.FormatInt(duration.Milliseconds(), 10)
	AddNewLine(newText)
}

func AddSecurityTime(duration time.Duration) {
	newText := "SecurityTime:" + strconv.FormatInt(duration.Milliseconds(), 10)
	AddNewLine(newText)
}

func AddAuthTime(duration time.Duration) {
	newText := "AuthTime:" + strconv.FormatInt(duration.Milliseconds(), 10)
	AddNewLine(newText)
}

func GetMetricsValue(key string) (string, error) {
	filename := GetMetricsFilePath()

	file, err := os.Open(filename)
	if err != nil {
		log.Fatal("[UE] [Metrics] could not open metrics file ", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		linha := scanner.Text()
		partes := strings.SplitN(linha, ":", 2)
		if len(partes) != 2 {
			log.Fatal("[UE] [Metrics] invalid format line metrics file ", err)
			continue
		}

		propriedade, valor := strings.TrimSpace(partes[0]), strings.TrimSpace(partes[1])
		if propriedade == key {
			return valor, nil
		}
	}
	return "", errors.New("[UE] [Metrics] property not found into metrics file")
}

func AddNewLine(newLine string) {
	filename := GetMetricsFilePath()
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
	if err != nil {
		log.Fatal("[UE] [Metrics] could not open metrics file ", err)
		return
	}
	defer file.Close()
	_, err = file.WriteString(newLine + "\n")
	if err != nil {
		log.Fatal("[UE] [Metrics] could not write new line into metrics file ", err)
		return
	}
}
