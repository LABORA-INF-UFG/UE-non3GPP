package dispatch

import (
	"UE-non3GPP/internal/ipsec/context"
	"UE-non3GPP/internal/ipsec/handler"
	"fmt"
)

const (
	registeredInitiated = iota
	registered
)

const (
	pduSessionInactive = iota
	pduSessionPending
	pduSessionActive
)

func Dispatch(ue *context.UeIpSec, msg []byte) {
	fmt.Println("Here 2")
	switch ue.NasContext.StateMM {
	case registeredInitiated:
		handler.HandlerRegisteredInitiated(ue, msg)
	case registered:
		switch ue.NasContext.StateSM {
		case pduSessionInactive:
		case pduSessionPending:
		case pduSessionActive:

		}
	}

}
