package main

import (
	"fmt"
	"github.com/shirou/gopsutil/net"
	"time"
)

func main() {
	// Substitua "eth0" pelo nome da sua interface de rede
	interfaceName := "gretun1"

	// Monitora a vazão de rede a cada segundo
	for {
		prevNetStat, err := net.IOCounters(true)
		if err != nil {
			fmt.Println("Erro ao obter estatísticas de rede:", err)
			return
		}

		time.Sleep(1 * time.Second)

		currentNetStat, err := net.IOCounters(true)
		if err != nil {
			fmt.Println("Erro ao obter estatísticas de rede:", err)
			return
		}

		// Encontra a interface de rede desejada
		var prevStat, currentStat *net.IOCountersStat
		for _, stat := range prevNetStat {
			if stat.Name == interfaceName {
				prevStat = &stat
				break
			}
		}
		for _, stat := range currentNetStat {
			if stat.Name == interfaceName {
				currentStat = &stat
				break
			}
		}

		// Calcula a vazão de entrada e saída em bytes por segundo
		if prevStat != nil && currentStat != nil {
			inputThroughput := currentStat.BytesRecv - prevStat.BytesRecv
			outputThroughput := currentStat.BytesSent - prevStat.BytesSent

			fmt.Printf("Vazão de Entrada: %d bytes/segundo\n", inputThroughput)
			fmt.Printf("Vazão de Saída: %d bytes/segundo\n", outputThroughput)
		} else {
			fmt.Println("Interface de rede não encontrada.")
		}
	}
}
