package nas

import (
	ran_ue "UE-non3GPP/engine/ran"
	security "UE-non3GPP/engine/security"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
)

func EncodeNasPduWithSecurity(ue *ran_ue.RanUeContext, pdu []byte, securityHeaderType uint8,
	securityContextAvailable, newSecurityContext bool) ([]byte, error) {
	m := nas.NewMessage()
	err := m.PlainNasDecode(&pdu)
	if err != nil {
		return nil, err
	}
	m.SecurityHeader = nas.SecurityHeader{
		ProtocolDiscriminator: nasMessage.Epd5GSMobilityManagementMessage,
		SecurityHeaderType:    securityHeaderType,
	}
	return security.NASEncode(ue, m, securityContextAvailable, newSecurityContext)
}
