package util

import (
	"UE-non3GPP/free5gc/n3iwf/pkg/context"
	"UE-non3GPP/free5gc/n3iwf/pkg/ike/handler"
	"UE-non3GPP/free5gc/n3iwf/pkg/ike/message"
	"errors"
)

func EncryptProcedure(ikeSecurityAssociation *context.IKESecurityAssociation, ikePayload message.IKEPayloadContainer, responseIKEMessage *message.IKEMessage) error {
	// Load needed information
	transformIntegrityAlgorithm := ikeSecurityAssociation.IntegrityAlgorithm
	transformEncryptionAlgorithm := ikeSecurityAssociation.EncryptionAlgorithm
	checksumLength := 12 // HMAC_SHA1_96

	// Encrypting
	notificationPayloadData, err := ikePayload.Encode()
	if err != nil {
		return errors.New("Encoding IKE payload failed.")
	}

	encryptedData, err := handler.EncryptMessage(ikeSecurityAssociation.SK_ei, notificationPayloadData, transformEncryptionAlgorithm.TransformID)
	if err != nil {
		return errors.New("Error encrypting message")
	}

	encryptedData = append(encryptedData, make([]byte, checksumLength)...)
	sk := responseIKEMessage.Payloads.BuildEncrypted(ikePayload[0].Type(), encryptedData)

	// Calculate checksum
	responseIKEMessageData, err := responseIKEMessage.Encode()
	if err != nil {
		return errors.New("Encoding IKE message error")
	}
	checksumOfMessage, err := handler.CalculateChecksum(ikeSecurityAssociation.SK_ai, responseIKEMessageData[:len(responseIKEMessageData)-checksumLength], transformIntegrityAlgorithm.TransformID)
	if err != nil {
		return errors.New("Error calculating checksum")
	}
	checksumField := sk.EncryptedData[len(sk.EncryptedData)-checksumLength:]
	copy(checksumField, checksumOfMessage)

	return nil
}

func DecryptProcedure(ikeSecurityAssociation *context.IKESecurityAssociation, ikeMessage *message.IKEMessage, encryptedPayload *message.Encrypted) (message.IKEPayloadContainer, error) {
	// Load needed information
	transformIntegrityAlgorithm := ikeSecurityAssociation.IntegrityAlgorithm
	transformEncryptionAlgorithm := ikeSecurityAssociation.EncryptionAlgorithm
	checksumLength := 12 // HMAC_SHA1_96

	// Checksum
	checksum := encryptedPayload.EncryptedData[len(encryptedPayload.EncryptedData)-checksumLength:]

	ikeMessageData, err := ikeMessage.Encode()
	if err != nil {
		return nil, errors.New("Encoding IKE message failed")
	}

	ok, err := handler.VerifyIKEChecksum(ikeSecurityAssociation.SK_ar, ikeMessageData[:len(ikeMessageData)-checksumLength], checksum, transformIntegrityAlgorithm.TransformID)
	if err != nil {
		return nil, errors.New("Error verify checksum")
	}
	if !ok {
		return nil, errors.New("Checksum failed, drop.")
	}

	// Decrypt
	encryptedData := encryptedPayload.EncryptedData[:len(encryptedPayload.EncryptedData)-checksumLength]
	plainText, err := handler.DecryptMessage(ikeSecurityAssociation.SK_er, encryptedData, transformEncryptionAlgorithm.TransformID)
	if err != nil {
		return nil, errors.New("Error decrypting message")
	}

	var decryptedIKEPayload message.IKEPayloadContainer
	err = decryptedIKEPayload.Decode(encryptedPayload.NextPayload, plainText)
	if err != nil {
		return nil, errors.New("Decoding decrypted payload failed")
	}

	return decryptedIKEPayload, nil

}
