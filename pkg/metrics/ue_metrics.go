package metrics

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
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
		log.Info("Could not find metrics file in: ", filename)
	}
}

func RemoveMetricsFile() {
	filename := GetMetricsFilePath()
	log.Info("[UE-non3GPP] [Metrics] Remove Ue Metrics File: ", filename)
	if _, err := os.Stat(filename); !os.IsNotExist(err) {

		err := os.Remove(filename)
		if err != nil {
			log.Fatal("Could not find metrics file in: ", filename)
			return
		}
	}
}

func CreateMetricsFile() {

	filename := GetMetricsFilePath()
	initialContent := "Este é o conteúdo inicial do arquivo."
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE, 0666)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()
	_, err = file.WriteString(initialContent)
	if err != nil {
		fmt.Println(err)
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

func AddNewLine(newLine string) {
	filename := GetMetricsFilePath()
	// Abrir o arquivo em modo de escrita (append)
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0666)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer file.Close()
	_, err = file.WriteString(newLine + "\n")
	if err != nil {
		fmt.Println(err)
		return
	}
}
