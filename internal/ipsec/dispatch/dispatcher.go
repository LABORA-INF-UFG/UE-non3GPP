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

	// get NAS msg to envelope
	nasMsg, _, err := ue.DecapNasPduFromEnvelope(msg)
	if err != nil {
		fmt.Println("Here2")
		return
	}

	switch ue.NasContext.StateMM {
	case registeredInitiated:
		handler.HandlerRegisteredInitiated(ue, nasMsg)
	case registered:
		switch ue.NasContext.StateSM {
		case pduSessionInactive:
		case pduSessionPending:
		case pduSessionActive:

		}
	}

}
