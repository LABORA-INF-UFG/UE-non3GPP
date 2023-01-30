package util

import "strconv"

func StrReverse(s string) string {
	// reverse string.
	var aux string
	for _, valor := range s {
		aux = string(valor) + aux
	}
	return aux
}

func StrConverter(value uint32) string {
	return strconv.FormatUint(uint64(value), 10)
}
