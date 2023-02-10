package trigger

import (
	"UE-non3GPP/internal/ike/context"
	"UE-non3GPP/internal/ike/message"
	log "github.com/sirupsen/logrus"
	"math/big"
)

func InitRegistration(ue *context.Ue) {

	// IKE_SA_INIT
	ikeInitiatorSPI := uint64(123123)
	ikeMessage := new(message.IKEMessage)

	ikeMessage.BuildIKEHeader(ikeInitiatorSPI, 0, message.IKE_SA_INIT, message.InitiatorBitCheck, 0)

	// Security Association
	securityAssociation := ikeMessage.Payloads.BuildSecurityAssociation()
	// Proposal 1
	proposal := securityAssociation.Proposals.BuildProposal(1, message.TypeIKE, nil)
	// ENCR
	var attributeType uint16 = message.AttributeTypeKeyLength
	var keyLength uint16 = 256
	proposal.EncryptionAlgorithm.BuildTransform(message.TypeEncryptionAlgorithm, message.ENCR_AES_CBC, &attributeType, &keyLength, nil)
	// INTEG
	proposal.IntegrityAlgorithm.BuildTransform(message.TypeIntegrityAlgorithm, message.AUTH_HMAC_SHA1_96, nil, nil, nil)
	// PRF
	proposal.PseudorandomFunction.BuildTransform(message.TypePseudorandomFunction, message.PRF_HMAC_SHA1, nil, nil, nil)
	// DH
	proposal.DiffieHellmanGroup.BuildTransform(message.TypeDiffieHellmanGroup, message.DH_2048_BIT_MODP, nil, nil, nil)

	// Key exchange data
	generator := new(big.Int).SetUint64(context.Group14Generator)
	factor, ok := new(big.Int).SetString(context.Group14PrimeString, 16)
	if !ok {
		log.Info("Generate key exchange data failed")
	}

	secret := context.GenerateRandomNumber()

	localPublicKeyExchangeValue := new(big.Int).Exp(generator, secret, factor).Bytes()
	prependZero := make([]byte, len(factor.Bytes())-len(localPublicKeyExchangeValue))
	localPublicKeyExchangeValue = append(prependZero, localPublicKeyExchangeValue...)
	ikeMessage.Payloads.BUildKeyExchange(message.DH_2048_BIT_MODP, localPublicKeyExchangeValue)

	// stored secret and factor
	ue.SetFactor(factor)
	ue.SetSecret(secret)

	// Nonce
	localNonce := context.GenerateRandomNumber().Bytes()
	ue.SetLocalNonce(localNonce)
	ikeMessage.Payloads.BuildNonce(localNonce)

	// Send to N3IWF
	ikeMessageData, err := ikeMessage.Encode()
	if err != nil {
		log.Info("Encode IKE Message fail: %+v", err)
	}
	if _, err := ue.GetUdpConn().Write(ikeMessageData); err != nil {
		log.Info("Write IKE maessage fail: %+v", err)
	}
}
