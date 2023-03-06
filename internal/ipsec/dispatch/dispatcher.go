package dispatch

import (
	"UE-non3GPP/internal/ipsec/context"
	"UE-non3GPP/internal/ipsec/handler"
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
		return
	}

	switch ue.NasContext.StateMM {
	case registeredInitiated:
		handler.HandlerRegisteredInitiated(ue, nasMsg)
	case registered:
		switch ue.NasContext.StateSM {
		case pduSessionInactive:
		case pduSessionPending:
			handler.HandlerPDUSession(ue, nasMsg)
		case pduSessionActive:

		}
	}

}
