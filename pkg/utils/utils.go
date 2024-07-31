package utils

import (
	"encoding/hex"
	"errors"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net"
	"strconv"
	"strings"
	"unicode"
)

type Utils struct {
}

func NewUtils() *Utils {
	util := &Utils{}
	return util
}

func (utils *Utils) GetInterfaceName(IPAddress string) (interfaceName string, err error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "nil", err
	}

	res, err := net.ResolveIPAddr("ip4", IPAddress)
	if err != nil {
		return "", fmt.Errorf("Error resolving address '%s': %v", IPAddress, err)
	}
	IPAddress = res.String()

	for _, inter := range interfaces {
		addrs, err := inter.Addrs()
		if err != nil {
			return "nil", err
		}
		for _, addr := range addrs {
			if IPAddress == addr.String()[0:strings.Index(addr.String(), "/")] {
				return inter.Name, nil
			}
		}
	}
	return "", fmt.Errorf("Cannot find interface name")
}

func GetMccAndMncInOctets(mcc, mnc string) []byte {

	// reverse mcc and mnc
	mcc = ReverseStr(mcc)
	mnc = ReverseStr(mnc)

	// include mcc and mnc in octets
	oct5 := mcc[1:3]
	var oct6 string
	var oct7 string
	if len(mnc) == 2 {
		oct6 = "f" + string(mcc[0])
		oct7 = mnc
	} else {
		oct6 = string(mnc[0]) + string(mcc[0])
		oct7 = mnc[1:3]
	}

	// changed for bytes.
	resu, err := hex.DecodeString(oct5 + oct6 + oct7)
	if err != nil {
		log.Fatal(err)
	}

	return resu
}

func ReverseStr(s string) string {
	// reverse string.
	var aux string
	for _, valor := range s {
		aux = string(valor) + aux
	}
	return aux
}

func ParseUint8ToHexadecimal(num uint8) string {
	hexStr := fmt.Sprintf("%x", num)
	return hexStr
}

func ParseStringToHexadecimal(num string) string {
	hexStr := fmt.Sprintf("%x", num)
	return hexStr
}

func ValidateLenStringField(label string, value string, size uint8) error {
	if len(value) == 0 {
		return errors.New(label + " cannot be empty")
	}
	if len(value) != int(size) {
		return errors.New(label + " must have " + strconv.Itoa(int(size)) + " characters")
	}
	return nil
}

func ConvertToHexByte(str string) byte {
	// Convertendo a string hexadecimal para um valor inteiro
	if (IsNumeric(str)) {
		value, err := strconv.ParseUint(str, 10, 8)
		if err != nil {
			log.Fatal(err)
		}
		return byte(value)
	} else {
		value, err := strconv.ParseUint(str, 16, 8)
		if err != nil {
			log.Fatal(err)
		}
		return byte(value)
	}
}

func IsNumeric(s string) bool {
	for _, char := range s {
		if !unicode.IsDigit(char) {
			return false
		}
	}
	return true
}

func EncodeUeSuci(msin string) (uint8, uint8, uint8, uint8, uint8) {

	// reverse imsi string.
	aux := ReverseStr(msin)

	// calculate decimal value.
	suci, error := hex.DecodeString(aux)
	if error != nil {
		return 0, 0, 0, 0, 0
	}

	// return decimal value
	if len(msin) == 8 {
		return uint8(suci[0]), uint8(suci[1]), uint8(suci[2]), uint8(suci[3]), 0
	} else {
		return uint8(suci[0]), uint8(suci[1]), uint8(suci[2]), uint8(suci[3]), uint8(suci[4])
	}
}
