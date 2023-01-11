package ue

import (
	"UE-non3GPP/config"
	util "UE-non3GPP/engine/util"

	"UE-non3GPP/free5gc/n3iwf/pkg/context"
	"UE-non3GPP/free5gc/n3iwf/pkg/ike/handler"
	"UE-non3GPP/free5gc/n3iwf/pkg/ike/message"
	"UE-non3GPP/test"
	"UE-non3GPP/test/nasTestpacket"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/nas/security"
	"github.com/free5gc/openapi/models"
	"github.com/go-ping/ping"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"golang.org/x/sys/unix"
	"hash"
	"math/big"
	"net"
	"time"
	//"net"
)

func UENon3GPPConnection() {
	cfg, err := config.GetConfig()
	if err != nil {
		log.Fatal("Could not resolve config file")
		return
	}

	/* initial config */
	util.InitialSetup(cfg)

	ue := test.NewRanUeContext(cfg.Ue.Supi, 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2,
		models.AccessType_NON_3_GPP_ACCESS)
	ue.AmfUeNgapId = cfg.Ue.AmfUeNgapId
	ue.AuthenticationSubs = getAuthSubscription(cfg)
	mobileIdentity5GS := nasType.MobileIdentity5GS{
		Len:    12, // suci
		Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
	}

	n3ue := new(context.N3IWFUe)
	n3ue.PduSessionList = make(map[int64]*context.PDUSession)
	n3ue.N3IWFChildSecurityAssociation = make(map[uint32]*context.ChildSecurityAssociation)
	n3ue.TemporaryExchangeMsgIDChildSAMapping = make(map[uint32]*context.ChildSecurityAssociation)

	address := cfg.N3iwfInfo.IKEBindAddress + ":" + cfg.N3iwfInfo.IKEBindPort

	n3iwfUDPAddr, err := net.ResolveUDPAddr(cfg.N3iwfInfo.IPSecIfaceProtocol, address)
	if err != nil {
		log.Fatal(err)
		return
	}

	udpConnection := setupUDPSocket(cfg)

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
	generator := new(big.Int).SetUint64(handler.Group14Generator)
	factor, ok := new(big.Int).SetString(handler.Group14PrimeString, 16)
	if !ok {
		log.Fatal("Generate key exchange datd failed")
		return
	}
	secert := handler.GenerateRandomNumber()
	localPublicKeyExchangeValue := new(big.Int).Exp(generator, secert, factor).Bytes()
	prependZero := make([]byte, len(factor.Bytes())-len(localPublicKeyExchangeValue))
	localPublicKeyExchangeValue = append(prependZero, localPublicKeyExchangeValue...)
	ikeMessage.Payloads.BUildKeyExchange(message.DH_2048_BIT_MODP, localPublicKeyExchangeValue)

	// Nonce
	localNonce := handler.GenerateRandomNumber().Bytes()
	ikeMessage.Payloads.BuildNonce(localNonce)

	// Send to N3IWF
	ikeMessageData, err := ikeMessage.Encode()
	if err != nil {
		log.Fatal(err)
		return
	}
	if _, err := udpConnection.WriteToUDP(ikeMessageData, n3iwfUDPAddr); err != nil {
		log.Fatal(err)
		return
	}

	// Receive N3IWF reply
	buffer := make([]byte, 65535)
	n, _, err := udpConnection.ReadFromUDP(buffer)
	if err != nil {
		log.Fatal(err)
	}
	ikeMessage.Payloads.Reset()
	err = ikeMessage.Decode(buffer[:n])
	if err != nil {
		log.Fatal(err)
		return
	}

	var sharedKeyExchangeData []byte
	var remoteNonce []byte

	for _, ikePayload := range ikeMessage.Payloads {
		switch ikePayload.Type() {
		case message.TypeSA:
			log.Info("Get SA payload")
		case message.TypeKE:
			remotePublicKeyExchangeValue := ikePayload.(*message.KeyExchange).KeyExchangeData
			var i int = 0
			for {
				if remotePublicKeyExchangeValue[i] != 0 {
					break
				}
			}
			remotePublicKeyExchangeValue = remotePublicKeyExchangeValue[i:]
			remotePublicKeyExchangeValueBig := new(big.Int).SetBytes(remotePublicKeyExchangeValue)
			sharedKeyExchangeData = new(big.Int).Exp(remotePublicKeyExchangeValueBig, secert, factor).Bytes()
		case message.TypeNiNr:
			remoteNonce = ikePayload.(*message.Nonce).NonceData
		}
	}

	ikeSecurityAssociation := &context.IKESecurityAssociation{
		LocalSPI:               ikeInitiatorSPI,
		RemoteSPI:              ikeMessage.ResponderSPI,
		InitiatorMessageID:     0,
		ResponderMessageID:     0,
		EncryptionAlgorithm:    proposal.EncryptionAlgorithm[0],
		IntegrityAlgorithm:     proposal.IntegrityAlgorithm[0],
		PseudorandomFunction:   proposal.PseudorandomFunction[0],
		DiffieHellmanGroup:     proposal.DiffieHellmanGroup[0],
		ConcatenatedNonce:      append(localNonce, remoteNonce...),
		DiffieHellmanSharedKey: sharedKeyExchangeData,
	}

	if err := generateKeyForIKESA(ikeSecurityAssociation); err != nil {
		log.Fatalf("Generate key for IKE SA failed: %+v", err)
		return
	}

	n3ue.N3IWFIKESecurityAssociation = ikeSecurityAssociation

	// IKE_AUTH
	ikeMessage.Payloads.Reset()
	n3ue.N3IWFIKESecurityAssociation.InitiatorMessageID++
	ikeMessage.BuildIKEHeader(
		n3ue.N3IWFIKESecurityAssociation.LocalSPI, n3ue.N3IWFIKESecurityAssociation.RemoteSPI,
		message.IKE_AUTH, message.InitiatorBitCheck, n3ue.N3IWFIKESecurityAssociation.InitiatorMessageID)

	var ikePayload message.IKEPayloadContainer

	// Identification
	ikePayload.BuildIdentificationInitiator(message.ID_FQDN, []byte("UE"))

	// Security Association
	securityAssociation = ikePayload.BuildSecurityAssociation()
	// Proposal 1
	inboundSPI := generateSPI(n3ue)
	proposal = securityAssociation.Proposals.BuildProposal(1, message.TypeESP, inboundSPI)
	// ENCR
	proposal.EncryptionAlgorithm.BuildTransform(message.TypeEncryptionAlgorithm, message.ENCR_AES_CBC, &attributeType, &keyLength, nil)
	// INTEG
	proposal.IntegrityAlgorithm.BuildTransform(message.TypeIntegrityAlgorithm, message.AUTH_HMAC_SHA1_96, nil, nil, nil)
	// ESN
	proposal.ExtendedSequenceNumbers.BuildTransform(message.TypeExtendedSequenceNumbers, message.ESN_NO, nil, nil, nil)

	// Traffic Selector
	tsi := ikePayload.BuildTrafficSelectorInitiator()
	tsi.TrafficSelectors.BuildIndividualTrafficSelector(message.TS_IPV4_ADDR_RANGE, 0, 0, 65535, []byte{0, 0, 0, 0}, []byte{255, 255, 255, 255})
	tsr := ikePayload.BuildTrafficSelectorResponder()
	tsr.TrafficSelectors.BuildIndividualTrafficSelector(message.TS_IPV4_ADDR_RANGE, 0, 0, 65535, []byte{0, 0, 0, 0}, []byte{255, 255, 255, 255})

	if err := util.EncryptProcedure(ikeSecurityAssociation, ikePayload, ikeMessage); err != nil {
		log.Fatalf("Encrypting IKE message failed: %+v", err)
		return
	}

	// Send to N3IWF
	ikeMessageData, err = ikeMessage.Encode()
	if err != nil {
		log.Fatal(err)
		return
	}
	if _, err := udpConnection.WriteToUDP(ikeMessageData, n3iwfUDPAddr); err != nil {
		log.Fatal(err)
		return
	}

	n3ue.CreateHalfChildSA(n3ue.N3IWFIKESecurityAssociation.InitiatorMessageID, binary.BigEndian.Uint32(inboundSPI))

	// Receive N3IWF reply
	n, _, err = udpConnection.ReadFromUDP(buffer)
	if err != nil {
		log.Fatal(err)
		return
	}
	ikeMessage.Payloads.Reset()
	err = ikeMessage.Decode(buffer[:n])
	if err != nil {
		log.Fatal(err)
		return
	}

	encryptedPayload, ok := ikeMessage.Payloads[0].(*message.Encrypted)
	if !ok {
		log.Fatal("Received payload is not an encrypted payload")
		return
	}

	decryptedIKEPayload, err := util.DecryptProcedure(ikeSecurityAssociation, ikeMessage, encryptedPayload)
	if err != nil {
		log.Fatalf("Decrypt IKE message failed: %+v", err)
		return
	}

	var eapIdentifier uint8

	for _, ikePayload := range decryptedIKEPayload {
		switch ikePayload.Type() {
		case message.TypeIDr:
			log.Info("Get IDr")
		case message.TypeAUTH:
			log.Info("Get AUTH")
		case message.TypeCERT:
			log.Info("Get CERT")
		case message.TypeEAP:
			eapIdentifier = ikePayload.(*message.EAP).Identifier
			log.Info("Get EAP")
		}
	}

	// IKE_AUTH - EAP exchange
	ikeMessage.Payloads.Reset()
	n3ue.N3IWFIKESecurityAssociation.InitiatorMessageID++
	ikeMessage.BuildIKEHeader(n3ue.N3IWFIKESecurityAssociation.LocalSPI, n3ue.N3IWFIKESecurityAssociation.RemoteSPI,
		message.IKE_AUTH, message.InitiatorBitCheck, n3ue.N3IWFIKESecurityAssociation.InitiatorMessageID)

	ikePayload.Reset()

	// EAP-5G vendor type data
	eapVendorTypeData := make([]byte, 2)
	eapVendorTypeData[0] = message.EAP5GType5GNAS

	// AN Parameters
	anParameters := buildEAP5GANParameters()
	anParametersLength := make([]byte, 2)
	binary.BigEndian.PutUint16(anParametersLength, uint16(len(anParameters)))
	eapVendorTypeData = append(eapVendorTypeData, anParametersLength...)
	eapVendorTypeData = append(eapVendorTypeData, anParameters...)

	// NAS
	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)

	nasLength := make([]byte, 2)
	binary.BigEndian.PutUint16(nasLength, uint16(len(registrationRequest)))
	eapVendorTypeData = append(eapVendorTypeData, nasLength...)
	eapVendorTypeData = append(eapVendorTypeData, registrationRequest...)

	eap := ikePayload.BuildEAP(message.EAPCodeResponse, eapIdentifier)
	eap.EAPTypeData.BuildEAPExpanded(message.VendorID3GPP, message.VendorTypeEAP5G, eapVendorTypeData)

	if err := util.EncryptProcedure(ikeSecurityAssociation, ikePayload, ikeMessage); err != nil {
		log.Fatal(err)
		return
	}

	// Send to N3IWF
	ikeMessageData, err = ikeMessage.Encode()
	if err != nil {
		log.Fatal(err)
		return
	}
	if _, err := udpConnection.WriteToUDP(ikeMessageData, n3iwfUDPAddr); err != nil {
		log.Fatal(err)
		return
	}

	// Receive N3IWF reply - Neste ponte é necessário o UE estar cadastrado no CORE com mesmo SUPI do arquivo de configuração, caso contrário teremos um erro de autenticação no AUSF
	n, _, err = udpConnection.ReadFromUDP(buffer)
	if err != nil {
		log.Fatal(err)
		return
	}
	ikeMessage.Payloads.Reset()
	err = ikeMessage.Decode(buffer[:n])
	if err != nil {
		log.Fatal(err)
		return
	}
	encryptedPayload, ok = ikeMessage.Payloads[0].(*message.Encrypted)
	if !ok {
		log.Fatal("Received payload is not an encrypted payload")
		return
	}
	decryptedIKEPayload, err = util.DecryptProcedure(ikeSecurityAssociation, ikeMessage, encryptedPayload)
	if err != nil {
		log.Fatalf("Decrypt IKE message failed: %+v", err)
		return
	}

	var eapReq *message.EAP
	var eapExpanded *message.EAPExpanded

	eapReq, ok = decryptedIKEPayload[0].(*message.EAP)
	if !ok {
		log.Fatal("Received packet is not an EAP payload")
		return
	}

	var decodedNAS *nas.Message

	eapExpanded, ok = eapReq.EAPTypeData[0].(*message.EAPExpanded)
	if !ok {
		log.Fatal("The EAP data is not an EAP expended.")
		return
	}

	// Decode NAS - Authentication Request
	nasData := eapExpanded.VendorData[4:]
	decodedNAS = new(nas.Message)
	if err := decodedNAS.PlainNasDecode(&nasData); err != nil {
		log.Fatal(err)
		return
	}

	// Calculate for RES*
	if decodedNAS == nil {
		log.Fatal("Erro inesperado! - Assert")
	}
	rand := decodedNAS.AuthenticationRequest.GetRANDValue()

	resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu := nasTestpacket.GetAuthenticationResponse(resStat, "")

	// IKE_AUTH - EAP exchange
	ikeMessage.Payloads.Reset()
	n3ue.N3IWFIKESecurityAssociation.InitiatorMessageID++
	ikeMessage.BuildIKEHeader(n3ue.N3IWFIKESecurityAssociation.LocalSPI, n3ue.N3IWFIKESecurityAssociation.RemoteSPI,
		message.IKE_AUTH, message.InitiatorBitCheck, n3ue.N3IWFIKESecurityAssociation.InitiatorMessageID)

	ikePayload.Reset()

	// EAP-5G vendor type data
	eapVendorTypeData = make([]byte, 4)
	eapVendorTypeData[0] = message.EAP5GType5GNAS

	// NAS - Authentication Response
	nasLength = make([]byte, 2)
	binary.BigEndian.PutUint16(nasLength, uint16(len(pdu)))
	eapVendorTypeData = append(eapVendorTypeData, nasLength...)
	eapVendorTypeData = append(eapVendorTypeData, pdu...)

	eap = ikePayload.BuildEAP(message.EAPCodeResponse, eapReq.Identifier)
	eap.EAPTypeData.BuildEAPExpanded(message.VendorID3GPP, message.VendorTypeEAP5G, eapVendorTypeData)

	err = util.EncryptProcedure(ikeSecurityAssociation, ikePayload, ikeMessage)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	// Send to N3IWF
	ikeMessageData, err = ikeMessage.Encode()
	if err != nil {
		log.Fatal(err)
		panic(err)
	}
	_, err = udpConnection.WriteToUDP(ikeMessageData, n3iwfUDPAddr)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	// Receive N3IWF reply
	n, _, err = udpConnection.ReadFromUDP(buffer)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}
	ikeMessage.Payloads.Reset()
	err = ikeMessage.Decode(buffer[:n])
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	encryptedPayload, ok = ikeMessage.Payloads[0].(*message.Encrypted)
	if !ok {
		log.Fatal("Received pakcet is not and encrypted payload")
		panic("Received pakcet is not and encrypted payload")
	}

	decryptedIKEPayload, err = util.DecryptProcedure(ikeSecurityAssociation, ikeMessage, encryptedPayload)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}
	eapReq, ok = decryptedIKEPayload[0].(*message.EAP)
	if !ok {
		log.Fatal("Received packet is not an EAP payload")
		panic("Received packet is not an EAP payload")
	}
	eapExpanded, ok = eapReq.EAPTypeData[0].(*message.EAPExpanded)
	if !ok {
		log.Fatal("Received packet is not an EAP expended payload")
		panic("Received packet is not an EAP expended payload")
	}

	nasData = eapExpanded.VendorData[4:]

	// Send NAS Security Mode Complete Msg
	registrationRequestWith5GMM := nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
	pdu = nasTestpacket.GetSecurityModeComplete(registrationRequestWith5GMM)

	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
	if err != nil {
		//assert.Nil(t, err
		panic(err)
	}

	// IKE_AUTH - EAP exchange
	ikeMessage.Payloads.Reset()
	n3ue.N3IWFIKESecurityAssociation.InitiatorMessageID++
	ikeMessage.BuildIKEHeader(n3ue.N3IWFIKESecurityAssociation.LocalSPI, n3ue.N3IWFIKESecurityAssociation.RemoteSPI,
		message.IKE_AUTH, message.InitiatorBitCheck, n3ue.N3IWFIKESecurityAssociation.InitiatorMessageID)

	ikePayload.Reset()

	// EAP-5G vendor type data
	eapVendorTypeData = make([]byte, 4)
	eapVendorTypeData[0] = message.EAP5GType5GNAS

	// NAS - Authentication Response
	nasLength = make([]byte, 2)
	binary.BigEndian.PutUint16(nasLength, uint16(len(pdu)))
	eapVendorTypeData = append(eapVendorTypeData, nasLength...)
	eapVendorTypeData = append(eapVendorTypeData, pdu...)

	eap = ikePayload.BuildEAP(message.EAPCodeResponse, eapReq.Identifier)
	eap.EAPTypeData.BuildEAPExpanded(message.VendorID3GPP, message.VendorTypeEAP5G, eapVendorTypeData)

	err = util.EncryptProcedure(ikeSecurityAssociation, ikePayload, ikeMessage)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	// Send to N3IWF
	ikeMessageData, err = ikeMessage.Encode()

	if err != nil {
		log.Fatal(err)
		panic(err)
	}
	_, err = udpConnection.WriteToUDP(ikeMessageData, n3iwfUDPAddr)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	// Receive N3IWF reply
	n, _, err = udpConnection.ReadFromUDP(buffer)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	ikeMessage.Payloads.Reset()
	err = ikeMessage.Decode(buffer[:n])
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	encryptedPayload, ok = ikeMessage.Payloads[0].(*message.Encrypted)
	if !ok {
		log.Fatal("Received pakcet is not and encrypted payload")
		panic("Received pakcet is not and encrypted payload")
	}
	decryptedIKEPayload, err = util.DecryptProcedure(ikeSecurityAssociation, ikeMessage, encryptedPayload)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	eapReq, ok = decryptedIKEPayload[0].(*message.EAP)
	if !ok {
		log.Fatal("Received packet is not an EAP payload")
		panic("Received packet is not an EAP payload")
	}

	if eapReq.Code != message.EAPCodeSuccess {
		log.Warnf("Check UE sequenceNumber value in config.yaml with the respective value in MONGO db.subscriptionData.authenticationData.authenticationSubscription.")
		log.Fatal("Not Success! Eap Req Code: ", eapReq.Code)
		panic("Not Success")
	}

	// IKE_AUTH - Authentication
	ikeMessage.Payloads.Reset()
	n3ue.N3IWFIKESecurityAssociation.InitiatorMessageID++
	ikeMessage.BuildIKEHeader(n3ue.N3IWFIKESecurityAssociation.LocalSPI, n3ue.N3IWFIKESecurityAssociation.RemoteSPI,
		message.IKE_AUTH, message.InitiatorBitCheck, n3ue.N3IWFIKESecurityAssociation.InitiatorMessageID)

	ikePayload.Reset()

	// Authentication
	ikePayload.BuildAuthentication(message.SharedKeyMesageIntegrityCode, []byte{1, 2, 3})

	// Configuration Request
	configurationRequest := ikePayload.BuildConfiguration(message.CFG_REQUEST)
	configurationRequest.ConfigurationAttribute.BuildConfigurationAttribute(message.INTERNAL_IP4_ADDRESS, nil)

	err = util.EncryptProcedure(ikeSecurityAssociation, ikePayload, ikeMessage)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	// Send to N3IWF
	ikeMessageData, err = ikeMessage.Encode()
	if err != nil {
		log.Fatal(err)
		panic(err)
	}
	_, err = udpConnection.WriteToUDP(ikeMessageData, n3iwfUDPAddr)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	// Receive N3IWF reply
	n, _, err = udpConnection.ReadFromUDP(buffer)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}
	ikeMessage.Payloads.Reset()
	err = ikeMessage.Decode(buffer[:n])
	if err != nil {
		log.Fatal(err)
		panic(err)
	}
	encryptedPayload, ok = ikeMessage.Payloads[0].(*message.Encrypted)
	if !ok {
		log.Fatal("Received pakcet is not and encrypted payload")
		panic("Received pakcet is not and encrypted payload")
	}
	decryptedIKEPayload, err = util.DecryptProcedure(ikeSecurityAssociation, ikeMessage, encryptedPayload)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	// AUTH, SAr2, TSi, Tsr, N(NAS_IP_ADDRESS), N(NAS_TCP_PORT)
	var responseSecurityAssociation *message.SecurityAssociation
	var responseTrafficSelectorInitiator *message.TrafficSelectorInitiator
	var responseTrafficSelectorResponder *message.TrafficSelectorResponder
	var responseConfiguration *message.Configuration
	n3iwfNASAddr := new(net.TCPAddr)
	ueAddr := new(net.IPNet)

	for _, ikePayload := range decryptedIKEPayload {
		switch ikePayload.Type() {
		case message.TypeAUTH:
			log.Info("Get Authentication from N3IWF")
		case message.TypeSA:
			responseSecurityAssociation = ikePayload.(*message.SecurityAssociation)
			n3ue.N3IWFIKESecurityAssociation.IKEAuthResponseSA = responseSecurityAssociation
		case message.TypeTSi:
			responseTrafficSelectorInitiator = ikePayload.(*message.TrafficSelectorInitiator)
		case message.TypeTSr:
			responseTrafficSelectorResponder = ikePayload.(*message.TrafficSelectorResponder)
		case message.TypeN:
			notification := ikePayload.(*message.Notification)
			if notification.NotifyMessageType == message.Vendor3GPPNotifyTypeNAS_IP4_ADDRESS {
				n3iwfNASAddr.IP = net.IPv4(notification.NotificationData[0], notification.NotificationData[1], notification.NotificationData[2], notification.NotificationData[3])
			}
			if notification.NotifyMessageType == message.Vendor3GPPNotifyTypeNAS_TCP_PORT {
				n3iwfNASAddr.Port = int(binary.BigEndian.Uint16(notification.NotificationData))
			}
		case message.TypeCP:
			responseConfiguration = ikePayload.(*message.Configuration)
			if responseConfiguration.ConfigurationType == message.CFG_REPLY {
				for _, configAttr := range responseConfiguration.ConfigurationAttribute {
					if configAttr.Type == message.INTERNAL_IP4_ADDRESS {
						ueAddr.IP = configAttr.Value
					}
					if configAttr.Type == message.INTERNAL_IP4_NETMASK {
						ueAddr.Mask = configAttr.Value
					}
				}
			}
		}
	}

	OutboundSPI := binary.BigEndian.Uint32(n3ue.N3IWFIKESecurityAssociation.IKEAuthResponseSA.Proposals[0].SPI)
	childSecurityAssociationContext, err := n3ue.CompleteChildSA(
		0x01, OutboundSPI, n3ue.N3IWFIKESecurityAssociation.IKEAuthResponseSA)
	if err != nil {
		log.Fatalf("Create child security association context failed: %+v", err)
		panic(err)
	}
	err = parseIPAddressInformationToChildSecurityAssociation(cfg, childSecurityAssociationContext,
		responseTrafficSelectorInitiator.TrafficSelectors[0],
		responseTrafficSelectorResponder.TrafficSelectors[0])

	if err != nil {
		log.Fatalf("Parse IP address to child security association failed: %+v", err)
		panic(err)
	}
	// Select TCP traffic
	childSecurityAssociationContext.SelectedIPProtocol = unix.IPPROTO_TCP

	if err := generateKeyForChildSA(ikeSecurityAssociation, childSecurityAssociationContext); err != nil {
		log.Fatalf("Generate key for child SA failed: %+v", err)
		panic(err)
	}

	// Aplly XFRM rules
	if err = applyXFRMRule(true, childSecurityAssociationContext); err != nil {
		log.Fatalf("Applying XFRM rules failed: %+v", err)
		panic(err)
	}

	// Get link ipsec0
	links, err := netlink.LinkList()
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	var linkIPSec netlink.Link
	for _, link := range links {
		if link.Attrs() != nil {
			if link.Attrs().Name == "ipsec0" {
				linkIPSec = link
				break
			}
		}
	}
	if linkIPSec == nil {
		log.Fatal("k named ipsec0")
		panic("No link named ipsec0")
	}

	linkIPSecAddr := &netlink.Addr{
		IPNet: ueAddr,
	}

	if err := netlink.AddrAdd(linkIPSec, linkIPSecAddr); err != nil {
		log.Fatalf("Set ipsec0 addr failed: %v", err)
		panic(err)
	}

	defer func() {
		_ = netlink.AddrDel(linkIPSec, linkIPSecAddr)
		_ = netlink.XfrmPolicyFlush()
		_ = netlink.XfrmStateFlush(netlink.XFRM_PROTO_IPSEC_ANY)
	}()

	localTCPAddr := &net.TCPAddr{
		IP: ueAddr.IP,
	}

	tcpConnWithN3IWF, err := net.DialTCP("tcp", localTCPAddr, n3iwfNASAddr)
	if err != nil {
		log.Warning("The error may be related to the ipsec0 interface that provides communication between UE and N3IWF. Try to recreate the interfaces")
		log.Fatal(err)
		panic(err)
	}

	nasMsg := make([]byte, 65535)

	_, err = tcpConnWithN3IWF.Read(nasMsg)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	// send NAS Registration Complete Msg
	pdu = nasTestpacket.GetRegistrationComplete(nil)
	pdu, err = EncodeNasPduInEnvelopeWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}
	_, err = tcpConnWithN3IWF.Write(pdu)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	time.Sleep(500 * time.Millisecond)

	// UE request PDU session setup
	sNssai := models.Snssai{
		Sst: cfg.Ue.Snssai.Sst,
		Sd:  cfg.Ue.Snssai.Sd,
	}
	pdu = nasTestpacket.GetUlNasTransport_PduSessionEstablishmentRequest(10, nasMessage.ULNASTransportRequestTypeInitialRequest, "internet", &sNssai)
	pdu, err = EncodeNasPduInEnvelopeWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}
	_, err = tcpConnWithN3IWF.Write(pdu)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}
	// Receive N3IWF reply
	n, _, err = udpConnection.ReadFromUDP(buffer)
	if err != nil {
		log.Warning("This error could be related to the data plane configuration involving AMF, SMF and UPF. Check the logs of these microservices for any anomalies. Re-creating the GTP5 tunnel may also be an option!")
		log.Fatal(err)
		panic(err)
	}
	ikeMessage.Payloads.Reset()
	err = ikeMessage.Decode(buffer[:n])
	if err != nil {
		log.Fatal(err)
		panic(err)
	}
	log.Info("IKE message exchange type: ", ikeMessage.ExchangeType)
	log.Info("IKE message ID: ", ikeMessage.MessageID)
	encryptedPayload, ok = ikeMessage.Payloads[0].(*message.Encrypted)
	if !ok {
		log.Fatal("Received pakcet is not and encrypted payload")
		panic("Received pakcet is not and encrypted payload")
	}
	decryptedIKEPayload, err = util.DecryptProcedure(ikeSecurityAssociation, ikeMessage, encryptedPayload)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	var QoSInfo *PDUQoSInfo

	var upIPAddr net.IP
	for _, ikePayload := range decryptedIKEPayload {
		switch ikePayload.Type() {
		case message.TypeSA:
			responseSecurityAssociation = ikePayload.(*message.SecurityAssociation)
			OutboundSPI = binary.BigEndian.Uint32(responseSecurityAssociation.Proposals[0].SPI)
		case message.TypeTSi:
			responseTrafficSelectorInitiator = ikePayload.(*message.TrafficSelectorInitiator)
		case message.TypeTSr:
			responseTrafficSelectorResponder = ikePayload.(*message.TrafficSelectorResponder)
		case message.TypeN:
			notification := ikePayload.(*message.Notification)
			if notification.NotifyMessageType == message.Vendor3GPPNotifyType5G_QOS_INFO {
				log.Info("Received Qos Flow settings")
				if info, err := parse5GQoSInfoNotify(notification); err == nil {
					QoSInfo = info
					log.Info("NotificationData: ", notification.NotificationData)
					if QoSInfo.isDSCPSpecified {
						log.Info("DSCP is specified but test not support")
					}
				} else {
					log.Info(err)
				}
			}
			if notification.NotifyMessageType == message.Vendor3GPPNotifyTypeUP_IP4_ADDRESS {
				log.Info("UP IP Address: ", notification.NotificationData)
				upIPAddr = notification.NotificationData[:4]
			}
		case message.TypeNiNr:
			responseNonce := ikePayload.(*message.Nonce)
			ikeSecurityAssociation.ConcatenatedNonce = responseNonce.NonceData
		}
	}

	// IKE CREATE_CHILD_SA response
	ikeMessage.Payloads.Reset()
	ikeMessage.BuildIKEHeader(ikeMessage.InitiatorSPI, ikeMessage.ResponderSPI, message.CREATE_CHILD_SA,
		message.ResponseBitCheck|message.InitiatorBitCheck, n3ue.N3IWFIKESecurityAssociation.ResponderMessageID)

	ikePayload.Reset()

	// SA
	inboundSPI = generateSPI(n3ue)
	responseSecurityAssociation.Proposals[0].SPI = inboundSPI
	ikePayload = append(ikePayload, responseSecurityAssociation)

	// TSi
	ikePayload = append(ikePayload, responseTrafficSelectorInitiator)

	// TSr
	ikePayload = append(ikePayload, responseTrafficSelectorResponder)

	// Nonce
	localNonce = handler.GenerateRandomNumber().Bytes()
	ikeSecurityAssociation.ConcatenatedNonce = append(ikeSecurityAssociation.ConcatenatedNonce, localNonce...)
	ikePayload.BuildNonce(localNonce)

	if err := util.EncryptProcedure(ikeSecurityAssociation, ikePayload, ikeMessage); err != nil {
		log.Fatal(err)
		panic(err)
	}

	// Send to N3IWF
	ikeMessageData, err = ikeMessage.Encode()
	if err != nil {
		log.Fatal(err)
		panic(err)
	}
	_, err = udpConnection.WriteToUDP(ikeMessageData, n3iwfUDPAddr)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	n3ue.CreateHalfChildSA(n3ue.N3IWFIKESecurityAssociation.ResponderMessageID, binary.BigEndian.Uint32(inboundSPI))
	childSecurityAssociationContextUserPlane, err := n3ue.CompleteChildSA(
		n3ue.N3IWFIKESecurityAssociation.ResponderMessageID, OutboundSPI, responseSecurityAssociation)

	if err != nil {
		log.Fatalf("Create child security association context failed: %+v", err)
		panic(err)
	}
	err = parseIPAddressInformationToChildSecurityAssociation(cfg, childSecurityAssociationContextUserPlane, responseTrafficSelectorResponder.TrafficSelectors[0], responseTrafficSelectorInitiator.TrafficSelectors[0])
	if err != nil {
		log.Fatalf("Parse IP address to child security association failed: %+v", err)
		panic(err)
	}
	// Select GRE traffic
	childSecurityAssociationContextUserPlane.SelectedIPProtocol = unix.IPPROTO_GRE

	if err := generateKeyForChildSA(ikeSecurityAssociation, childSecurityAssociationContextUserPlane); err != nil {
		log.Fatalf("Generate key for child SA failed: %+v", err)
		panic(err)
	}

	//fmt.Println("---------------------------------")
	//fmt.Println("State Function:")
	//fmt.Println("   encr:")
	//fmt.Println(childSecurityAssociationContextUserPlane.EncryptionAlgorithm)
	//fmt.Println("   auth:")
	//fmt.Println(childSecurityAssociationContextUserPlane.IntegrityAlgorithm)
	//fmt.Println("---------------------------------")

	// Aplly XFRM rules
	if err = applyXFRMRule(false, childSecurityAssociationContextUserPlane); err != nil {
		log.Fatalf("Applying XFRM rules failed: %+v", err)
		panic(err)
	}

	var greKeyField uint32

	if QoSInfo != nil {
		greKeyField |= (uint32(QoSInfo.qfiList[0]) & 0x3F) << 24
	}

	// New GRE tunnel interface
	newGRETunnel := &netlink.Gretun{
		LinkAttrs: netlink.LinkAttrs{
			Name: cfg.Ue.LinkGRE.Name,
		},
		Local:  ueAddr.IP,
		Remote: upIPAddr,
		IKey:   greKeyField,
		OKey:   greKeyField,
	}

	if err := netlink.LinkAdd(newGRETunnel); err != nil {
		log.Fatal(err)
		panic(err)
	}

	// Get link info GRETun1
	var linkGRE = util.GetLinkGRE(cfg)
	if linkGRE == nil {
		log.Fatal("No link named " + cfg.Ue.LinkGRE.Name)
		panic("No link named " + cfg.Ue.LinkGRE.Name)
	}

	util.ConfigMTUGreTun(cfg)

	// Link address 10.60.0.1/24
	linkGREAddr := &netlink.Addr{
		IPNet: &net.IPNet{
			IP: net.IPv4(cfg.Ue.LinkGRE.IPAddress[0],
				cfg.Ue.LinkGRE.IPAddress[1],
				cfg.Ue.LinkGRE.IPAddress[2],
				cfg.Ue.LinkGRE.IPAddress[3]),
			Mask: net.IPv4Mask(cfg.Ue.LinkGRE.Mask[0],
				cfg.Ue.LinkGRE.Mask[1],
				cfg.Ue.LinkGRE.Mask[2],
				cfg.Ue.LinkGRE.Mask[3]),
		},
	}
	if err := netlink.AddrAdd(linkGRE, linkGREAddr); err != nil {
		log.Fatal(err)
		panic(err)
	}
	// Set GRE interface up
	if err := netlink.LinkSetUp(linkGRE); err != nil {
		log.Fatal(err)
		panic(err)
	}
	// Add route
	upRoute := &netlink.Route{
		LinkIndex: linkGRE.Attrs().Index,
		Dst: &net.IPNet{
			//IP: net.IPv4zero,
			/*ip da rede do ip publico da UPF - */
			/*comando: route --> pegar o último endereço da pilha */
			IP: net.IPv4(cfg.UPFInfo.NetworkAddress[0],
				cfg.UPFInfo.NetworkAddress[1],
				cfg.UPFInfo.NetworkAddress[2],
				cfg.UPFInfo.NetworkAddress[3]),
			/* máscara de rede da UPF - verificar na Digital Occean */
			Mask: net.IPv4Mask(cfg.UPFInfo.NetworkMask[0],
				cfg.UPFInfo.NetworkMask[1],
				cfg.UPFInfo.NetworkMask[2],
				cfg.UPFInfo.NetworkMask[3]),
		},
	}

	if err := netlink.RouteAdd(upRoute); err != nil {
		log.Fatal(err)
		panic(err)
	}

	defer func() {
		_ = netlink.LinkSetDown(linkGRE)
		_ = netlink.LinkDel(linkGRE)
	}()

	// Ping remote
	pinger, err := ping.NewPinger("60.60.0.101")
	//pinger, err := ping.NewPinger("8.8.8.8")
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	// Run with root
	pinger.SetPrivileged(true)

	pinger.OnRecv = func(pkt *ping.Packet) {
		fmt.Println("")
		fmt.Println("............................")
		fmt.Println("------PING 60.60.0.101----------")
		fmt.Println("Bytes recebidos:")
		fmt.Println(pkt.Nbytes)
		fmt.Println("Host Origem:")
		fmt.Println(pkt.IPAddr)
		fmt.Println("ICMP Seq:")
		fmt.Println(pkt.Seq)
		fmt.Println("RTT:")
		fmt.Println(pkt.Rtt)
	}

	pinger.OnFinish = func(stats *ping.Statistics) {
		fmt.Println("")
		fmt.Println("............................")
		fmt.Println("------Estatísticas----------")
		fmt.Println("Pacotes transmitidos:")
		fmt.Println(stats.PacketsSent)
		fmt.Println("Pacotes recebidos:")
		fmt.Println(stats.PacketsRecv)
		fmt.Println("Pacotes perdidos:")
		fmt.Println(stats.PacketLoss)
		fmt.Println("round-trip min:")
		fmt.Println(stats.MinRtt)
		fmt.Println("round-trip avg:")
		fmt.Println(stats.AvgRtt)
		fmt.Println("round-trip max:")
		fmt.Println(stats.MaxRtt)
		fmt.Println("round-trip stddev:")
		fmt.Println(stats.StdDevRtt)
	}

	pinger.Count = 5
	pinger.Timeout = 10 * time.Second
	pinger.Source = "60.60.0.1"

	time.Sleep(3 * time.Second)

	pinger.Run()

	time.Sleep(1 * time.Second)

	//fmt.Println(".................................")
	//fmt.Println("......finish!!!!")
	//fmt.Println(".................................")
	//time.Sleep(15 * time.Second)

	stats := pinger.Statistics()
	if stats.PacketsSent != stats.PacketsRecv {
		log.Fatal("Ping Failed")
		panic("Ping Failed")
	}

}

func parse5GQoSInfoNotify(n *message.Notification) (info *PDUQoSInfo, err error) {
	info = new(PDUQoSInfo)
	var offset int = 0
	data := n.NotificationData
	dataLen := int(data[0])
	info.pduSessionID = data[1]
	qfiListLen := int(data[2])
	offset += (3 + qfiListLen)

	if offset > dataLen {
		return nil, errors.New("parse5GQoSInfoNotify err: Length and content of 5G-QoS-Info-Notify mismatch")
	}

	info.qfiList = make([]byte, qfiListLen)
	copy(info.qfiList, data[3:3+qfiListLen])

	info.isDefault = (data[offset] & message.NotifyType5G_QOS_INFOBitDCSICheck) > 0
	info.isDSCPSpecified = (data[offset] & message.NotifyType5G_QOS_INFOBitDSCPICheck) > 0

	return
}

func EncodeNasPduInEnvelopeWithSecurity(ue *test.RanUeContext, pdu []byte, securityHeaderType uint8,
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
	return NASEnvelopeEncode(ue, m, securityContextAvailable, newSecurityContext)
}

func NASEnvelopeEncode(ue *test.RanUeContext, msg *nas.Message, securityContextAvailable bool, newSecurityContext bool) (
	payload []byte, err error) {
	var sequenceNumber uint8
	if ue == nil {
		err = fmt.Errorf("amfUe is nil")
		return
	}
	if msg == nil {
		err = fmt.Errorf("Nas Message is empty")
		return
	}

	if !securityContextAvailable {
		tmpNasPdu, err := msg.PlainNasEncode()
		return encapNasMsgToEnvelope(tmpNasPdu), err
	} else {
		if newSecurityContext {
			ue.ULCount.Set(0, 0)
			ue.DLCount.Set(0, 0)
		}

		sequenceNumber = ue.ULCount.SQN()

		payload, err = msg.PlainNasEncode()

		if err != nil {
			return
		}

		if err = security.NASEncrypt(ue.CipheringAlg, ue.KnasEnc, ue.ULCount.Get(), ue.GetBearerType(),
			security.DirectionUplink, payload); err != nil {
			return
		}
		// add sequece number
		payload = append([]byte{sequenceNumber}, payload[:]...)
		mac32 := make([]byte, 4)
		_ = mac32
		// fmt.Println("sequenceNumber", sequenceNumber)
		// fmt.Println("ue.IntegrityAlg", ue.IntegrityAlg)
		// fmt.Println("ue.KnasInt", ue.KnasInt)
		// fmt.Println("ue.ULCount.Get()", ue.ULCount.Get())
		// fmt.Println("security.Bearer3GPP", security.Bearer3GPP)
		// fmt.Println("security.DirectionUplink", security.DirectionUplink)
		// fmt.Println("payload", payload)

		mac32, err = security.NASMacCalculate(ue.IntegrityAlg, ue.KnasInt, ue.ULCount.Get(), ue.GetBearerType(),
			security.DirectionUplink, payload)
		if err != nil {
			return
		}

		// Add mac value
		payload = append(mac32, payload[:]...)
		// Add EPD and Security Type
		msgSecurityHeader := []byte{msg.SecurityHeader.ProtocolDiscriminator, msg.SecurityHeader.SecurityHeaderType}
		payload = append(msgSecurityHeader, payload[:]...)

		// Increase UL Count
		ue.ULCount.AddOne()
	}

	payload = encapNasMsgToEnvelope(payload)
	return payload, err
}

func encapNasMsgToEnvelope(nasPDU []byte) []byte {
	// According to TS 24.502 8.2.4,
	// in order to transport a NAS message over the non-3GPP access between the UE and the N3IWF,
	// the NAS message shall be framed in a NAS message envelope as defined in subclause 9.4.
	// According to TS 24.502 9.4,
	// a NAS message envelope = Length | NAS Message
	nasEnv := make([]byte, 2)
	binary.BigEndian.PutUint16(nasEnv, uint16(len(nasPDU)))
	nasEnv = append(nasEnv, nasPDU...)
	return nasEnv
}

func applyXFRMRule(ue_is_initiator bool, childSecurityAssociation *context.ChildSecurityAssociation) error {
	// Build XFRM information data structure for incoming traffic.

	// Mark
	mark := &netlink.XfrmMark{
		Value: 5,
	}

	// Direction: N3IWF -> UE
	// State
	var xfrmEncryptionAlgorithm, xfrmIntegrityAlgorithm *netlink.XfrmStateAlgo
	if ue_is_initiator {
		xfrmEncryptionAlgorithm = &netlink.XfrmStateAlgo{
			Name: handler.XFRMEncryptionAlgorithmType(childSecurityAssociation.EncryptionAlgorithm).String(),
			Key:  childSecurityAssociation.ResponderToInitiatorEncryptionKey,
		}
		if childSecurityAssociation.IntegrityAlgorithm != 0 {
			xfrmIntegrityAlgorithm = &netlink.XfrmStateAlgo{
				Name: handler.XFRMIntegrityAlgorithmType(childSecurityAssociation.IntegrityAlgorithm).String(),
				Key:  childSecurityAssociation.ResponderToInitiatorIntegrityKey,
			}
		}
	} else {
		xfrmEncryptionAlgorithm = &netlink.XfrmStateAlgo{
			Name: handler.XFRMEncryptionAlgorithmType(childSecurityAssociation.EncryptionAlgorithm).String(),
			Key:  childSecurityAssociation.InitiatorToResponderEncryptionKey,
		}
		if childSecurityAssociation.IntegrityAlgorithm != 0 {
			xfrmIntegrityAlgorithm = &netlink.XfrmStateAlgo{
				Name: handler.XFRMIntegrityAlgorithmType(childSecurityAssociation.IntegrityAlgorithm).String(),
				Key:  childSecurityAssociation.InitiatorToResponderIntegrityKey,
			}
		}
	}

	xfrmState := new(netlink.XfrmState)

	xfrmState.Src = childSecurityAssociation.PeerPublicIPAddr
	xfrmState.Dst = childSecurityAssociation.LocalPublicIPAddr
	xfrmState.Proto = netlink.XFRM_PROTO_ESP
	xfrmState.Mode = netlink.XFRM_MODE_TUNNEL
	xfrmState.Spi = int(childSecurityAssociation.InboundSPI)
	xfrmState.Mark = mark
	xfrmState.Auth = xfrmIntegrityAlgorithm
	xfrmState.Crypt = xfrmEncryptionAlgorithm
	xfrmState.ESN = childSecurityAssociation.ESN

	// Commit xfrm state to netlink
	var err error
	if err = netlink.XfrmStateAdd(xfrmState); err != nil {
		return fmt.Errorf("Set XFRM state rule failed: %+v", err)
	}

	// Policy
	xfrmPolicyTemplate := netlink.XfrmPolicyTmpl{
		Src:   xfrmState.Src,
		Dst:   xfrmState.Dst,
		Proto: xfrmState.Proto,
		Mode:  xfrmState.Mode,
		Spi:   xfrmState.Spi,
	}

	xfrmPolicy := new(netlink.XfrmPolicy)

	if childSecurityAssociation.SelectedIPProtocol == 0 {
		return errors.New("Protocol == 0")
	}

	xfrmPolicy.Src = &childSecurityAssociation.TrafficSelectorRemote
	xfrmPolicy.Dst = &childSecurityAssociation.TrafficSelectorLocal
	xfrmPolicy.Proto = netlink.Proto(childSecurityAssociation.SelectedIPProtocol)
	xfrmPolicy.Dir = netlink.XFRM_DIR_IN
	xfrmPolicy.Mark = mark
	xfrmPolicy.Tmpls = []netlink.XfrmPolicyTmpl{
		xfrmPolicyTemplate,
	}

	// Commit xfrm policy to netlink
	if err = netlink.XfrmPolicyAdd(xfrmPolicy); err != nil {
		return fmt.Errorf("Set XFRM policy rule failed: %+v", err)
	}

	// Direction: UE -> N3IWF
	// State
	if ue_is_initiator {
		xfrmEncryptionAlgorithm.Key = childSecurityAssociation.InitiatorToResponderEncryptionKey
		if childSecurityAssociation.IntegrityAlgorithm != 0 {
			xfrmIntegrityAlgorithm.Key = childSecurityAssociation.InitiatorToResponderIntegrityKey
		}
	} else {
		xfrmEncryptionAlgorithm.Key = childSecurityAssociation.ResponderToInitiatorEncryptionKey
		if childSecurityAssociation.IntegrityAlgorithm != 0 {
			xfrmIntegrityAlgorithm.Key = childSecurityAssociation.ResponderToInitiatorIntegrityKey
		}
	}

	xfrmState.Src, xfrmState.Dst = xfrmState.Dst, xfrmState.Src
	xfrmState.Spi = int(childSecurityAssociation.OutboundSPI)

	// Commit xfrm state to netlink
	if err = netlink.XfrmStateAdd(xfrmState); err != nil {
		return fmt.Errorf("Set XFRM state rule failed: %+v", err)
	}

	// Policy
	xfrmPolicyTemplate.Src, xfrmPolicyTemplate.Dst = xfrmPolicyTemplate.Dst, xfrmPolicyTemplate.Src
	xfrmPolicyTemplate.Spi = int(childSecurityAssociation.OutboundSPI)

	xfrmPolicy.Src, xfrmPolicy.Dst = xfrmPolicy.Dst, xfrmPolicy.Src
	xfrmPolicy.Dir = netlink.XFRM_DIR_OUT
	xfrmPolicy.Tmpls = []netlink.XfrmPolicyTmpl{
		xfrmPolicyTemplate,
	}

	// Commit xfrm policy to netlink
	if err = netlink.XfrmPolicyAdd(xfrmPolicy); err != nil {
		return fmt.Errorf("Set XFRM policy rule failed: %+v", err)
	}

	return nil
}

func generateKeyForChildSA(ikeSecurityAssociation *context.IKESecurityAssociation, childSecurityAssociation *context.ChildSecurityAssociation) error {
	// Transforms
	transformPseudorandomFunction := ikeSecurityAssociation.PseudorandomFunction
	var transformIntegrityAlgorithmForIPSec *message.Transform
	if len(ikeSecurityAssociation.IKEAuthResponseSA.Proposals[0].IntegrityAlgorithm) != 0 {
		transformIntegrityAlgorithmForIPSec = ikeSecurityAssociation.IKEAuthResponseSA.Proposals[0].IntegrityAlgorithm[0]
	}

	// Get key length for encryption and integrity key for IPSec
	var lengthEncryptionKeyIPSec, lengthIntegrityKeyIPSec, totalKeyLength int
	var ok bool

	lengthEncryptionKeyIPSec = 32
	if transformIntegrityAlgorithmForIPSec != nil {
		lengthIntegrityKeyIPSec = 20
	}
	totalKeyLength = lengthEncryptionKeyIPSec + lengthIntegrityKeyIPSec
	totalKeyLength = totalKeyLength * 2

	// Generate key for child security association as specified in RFC 7296 section 2.17
	seed := ikeSecurityAssociation.ConcatenatedNonce
	var pseudorandomFunction hash.Hash

	var keyStream, generatedKeyBlock []byte
	var index byte
	for index = 1; len(keyStream) < totalKeyLength; index++ {
		if pseudorandomFunction, ok = handler.NewPseudorandomFunction(ikeSecurityAssociation.SK_d, transformPseudorandomFunction.TransformID); !ok {
			return errors.New("New pseudorandom function failed")
		}
		if _, err := pseudorandomFunction.Write(append(append(generatedKeyBlock, seed...), index)); err != nil {
			return errors.New("Pseudorandom function write failed")
		}
		generatedKeyBlock = pseudorandomFunction.Sum(nil)
		keyStream = append(keyStream, generatedKeyBlock...)
	}

	childSecurityAssociation.InitiatorToResponderEncryptionKey = append(childSecurityAssociation.InitiatorToResponderEncryptionKey, keyStream[:lengthEncryptionKeyIPSec]...)
	keyStream = keyStream[lengthEncryptionKeyIPSec:]
	childSecurityAssociation.InitiatorToResponderIntegrityKey = append(childSecurityAssociation.InitiatorToResponderIntegrityKey, keyStream[:lengthIntegrityKeyIPSec]...)
	keyStream = keyStream[lengthIntegrityKeyIPSec:]
	childSecurityAssociation.ResponderToInitiatorEncryptionKey = append(childSecurityAssociation.ResponderToInitiatorEncryptionKey, keyStream[:lengthEncryptionKeyIPSec]...)
	keyStream = keyStream[lengthEncryptionKeyIPSec:]
	childSecurityAssociation.ResponderToInitiatorIntegrityKey = append(childSecurityAssociation.ResponderToInitiatorIntegrityKey, keyStream[:lengthIntegrityKeyIPSec]...)

	return nil

}

func parseIPAddressInformationToChildSecurityAssociation(cfg config.Config,
	childSecurityAssociation *context.ChildSecurityAssociation,
	trafficSelectorLocal *message.IndividualTrafficSelector,
	trafficSelectorRemote *message.IndividualTrafficSelector) error {

	if childSecurityAssociation == nil {
		return errors.New("childSecurityAssociation is nil")
	}

	childSecurityAssociation.PeerPublicIPAddr = net.ParseIP(cfg.N3iwfInfo.IKEBindAddress).To4()

	//childSecurityAssociation.LocalPublicIPAddr = net.ParseIP("192.168.127.2")
	childSecurityAssociation.LocalPublicIPAddr = net.ParseIP(cfg.Ue.LocalPublicIPAddr)

	childSecurityAssociation.TrafficSelectorLocal = net.IPNet{
		IP:   trafficSelectorLocal.StartAddress,
		Mask: []byte{255, 255, 255, 255},
	}

	childSecurityAssociation.TrafficSelectorRemote = net.IPNet{
		IP:   trafficSelectorRemote.StartAddress,
		Mask: []byte{255, 255, 255, 255},
	}

	return nil
}

func buildEAP5GANParameters() []byte {
	var anParameters []byte

	// [TS 24.502] 9.3.2.2.2.3
	// AN-parameter value field in GUAMI, PLMN ID and NSSAI is coded as value part
	// Therefore, IEI of AN-parameter is not needed to be included.

	// anParameter = AN-parameter Type | AN-parameter Length | Value part of IE

	// Build GUAMI
	anParameter := make([]byte, 2)
	guami := make([]byte, 6)
	guami[0] = 0x02
	guami[1] = 0xf8
	guami[2] = 0x39
	guami[3] = 0xca
	guami[4] = 0xfe
	guami[5] = 0x0
	anParameter[0] = message.ANParametersTypeGUAMI
	anParameter[1] = byte(len(guami))
	anParameter = append(anParameter, guami...)

	anParameters = append(anParameters, anParameter...)

	// Build Establishment Cause
	anParameter = make([]byte, 2)
	establishmentCause := make([]byte, 1)
	establishmentCause[0] = message.EstablishmentCauseMO_Signalling
	anParameter[0] = message.ANParametersTypeEstablishmentCause
	anParameter[1] = byte(len(establishmentCause))
	anParameter = append(anParameter, establishmentCause...)

	anParameters = append(anParameters, anParameter...)

	// Build PLMN ID
	anParameter = make([]byte, 2)
	plmnID := make([]byte, 3)
	plmnID[0] = 0x02
	plmnID[1] = 0xf8
	plmnID[2] = 0x39
	anParameter[0] = message.ANParametersTypeSelectedPLMNID
	anParameter[1] = byte(len(plmnID))
	anParameter = append(anParameter, plmnID...)

	anParameters = append(anParameters, anParameter...)

	// Build NSSAI
	anParameter = make([]byte, 2)
	var nssai []byte
	// s-nssai = s-nssai length(1 byte) | SST(1 byte) | SD(3 bytes)
	snssai := make([]byte, 5)
	snssai[0] = 4
	snssai[1] = 1
	snssai[2] = 0x01
	snssai[3] = 0x02
	snssai[4] = 0x03
	nssai = append(nssai, snssai...)
	snssai = make([]byte, 5)
	snssai[0] = 4
	snssai[1] = 1
	snssai[2] = 0x11
	snssai[3] = 0x22
	snssai[4] = 0x33
	nssai = append(nssai, snssai...)
	anParameter[0] = message.ANParametersTypeRequestedNSSAI
	anParameter[1] = byte(len(nssai))
	anParameter = append(anParameter, nssai...)

	anParameters = append(anParameters, anParameter...)

	return anParameters
}

func generateSPI(n3ue *context.N3IWFUe) []byte {
	var spi uint32
	spiByte := make([]byte, 4)
	for {
		randomUint64 := handler.GenerateRandomNumber().Uint64()
		if _, ok := n3ue.N3IWFChildSecurityAssociation[uint32(randomUint64)]; !ok {
			spi = uint32(randomUint64)
			binary.BigEndian.PutUint32(spiByte, spi)
			break
		}
	}
	return spiByte
}

func generateKeyForIKESA(ikeSecurityAssociation *context.IKESecurityAssociation) error {
	// Transforms
	transformPseudorandomFunction := ikeSecurityAssociation.PseudorandomFunction

	// Get key length of SK_d, SK_ai, SK_ar, SK_ei, SK_er, SK_pi, SK_pr
	var length_SK_d, length_SK_ai, length_SK_ar, length_SK_ei, length_SK_er, length_SK_pi, length_SK_pr, totalKeyLength int
	var ok bool

	length_SK_d = 20
	length_SK_ai = 20
	length_SK_ar = length_SK_ai
	length_SK_ei = 32
	length_SK_er = length_SK_ei
	length_SK_pi, length_SK_pr = length_SK_d, length_SK_d
	totalKeyLength = length_SK_d + length_SK_ai + length_SK_ar + length_SK_ei + length_SK_er + length_SK_pi + length_SK_pr

	// Generate IKE SA key as defined in RFC7296 Section 1.3 and Section 1.4
	var pseudorandomFunction hash.Hash

	if pseudorandomFunction, ok = handler.NewPseudorandomFunction(ikeSecurityAssociation.ConcatenatedNonce, transformPseudorandomFunction.TransformID); !ok {
		return errors.New("New pseudorandom function failed")
	}

	if _, err := pseudorandomFunction.Write(ikeSecurityAssociation.DiffieHellmanSharedKey); err != nil {
		return errors.New("Pseudorandom function write failed")
	}

	SKEYSEED := pseudorandomFunction.Sum(nil)

	seed := concatenateNonceAndSPI(ikeSecurityAssociation.ConcatenatedNonce, ikeSecurityAssociation.LocalSPI, ikeSecurityAssociation.RemoteSPI)

	var keyStream, generatedKeyBlock []byte
	var index byte
	for index = 1; len(keyStream) < totalKeyLength; index++ {
		if pseudorandomFunction, ok = handler.NewPseudorandomFunction(SKEYSEED, transformPseudorandomFunction.TransformID); !ok {
			return errors.New("New pseudorandom function failed")
		}
		if _, err := pseudorandomFunction.Write(append(append(generatedKeyBlock, seed...), index)); err != nil {
			return errors.New("Pseudorandom function write failed")
		}
		generatedKeyBlock = pseudorandomFunction.Sum(nil)
		keyStream = append(keyStream, generatedKeyBlock...)
	}

	// Assign keys into context
	ikeSecurityAssociation.SK_d = keyStream[:length_SK_d]
	keyStream = keyStream[length_SK_d:]
	ikeSecurityAssociation.SK_ai = keyStream[:length_SK_ai]
	keyStream = keyStream[length_SK_ai:]
	ikeSecurityAssociation.SK_ar = keyStream[:length_SK_ar]
	keyStream = keyStream[length_SK_ar:]
	ikeSecurityAssociation.SK_ei = keyStream[:length_SK_ei]
	keyStream = keyStream[length_SK_ei:]
	ikeSecurityAssociation.SK_er = keyStream[:length_SK_er]
	keyStream = keyStream[length_SK_er:]
	ikeSecurityAssociation.SK_pi = keyStream[:length_SK_pi]
	keyStream = keyStream[length_SK_pi:]
	ikeSecurityAssociation.SK_pr = keyStream[:length_SK_pr]
	keyStream = keyStream[length_SK_pr:]

	return nil
}

func concatenateNonceAndSPI(nonce []byte, SPI_initiator uint64, SPI_responder uint64) []byte {
	spi := make([]byte, 8)

	binary.BigEndian.PutUint64(spi, SPI_initiator)
	newSlice := append(nonce, spi...)
	binary.BigEndian.PutUint64(spi, SPI_responder)
	newSlice = append(newSlice, spi...)

	return newSlice
}

func setupUDPSocket(cfg config.Config) *net.UDPConn {
	bindAddr := cfg.Ue.LocalPublicIPAddr + ":" + cfg.Ue.LocalPublicPortUDPConnection
	udpAddr, err := net.ResolveUDPAddr("udp", bindAddr)
	if err != nil {
		log.Fatal("Resolve UDP address failed")
	}
	udpListener, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Fatalf("Listen UDP socket failed: %+v", err)
	}
	return udpListener
}

func getAuthSubscription(cfg config.Config) (authSubs models.AuthenticationSubscription) {
	authSubs.PermanentKey = &models.PermanentKey{
		PermanentKeyValue: cfg.Ue.AuthSubscription.PermanentKeyValue,
	}
	authSubs.Opc = &models.Opc{
		OpcValue: cfg.Ue.AuthSubscription.OpcValue,
	}
	authSubs.Milenage = &models.Milenage{
		Op: &models.Op{
			OpValue: cfg.Ue.AuthSubscription.OpValue,
		},
	}
	authSubs.AuthenticationManagementField = cfg.Ue.AuthenticationManagementField //"8000"
	authSubs.SequenceNumber = cfg.Ue.AuthSubscription.SequenceNumber
	authSubs.AuthenticationMethod = models.AuthMethod__5_G_AKA
	return
}

type PDUQoSInfo struct {
	pduSessionID    uint8
	qfiList         []uint8
	isDefault       bool
	isDSCPSpecified bool
	DSCP            uint8
}
