package ue

import (
	"UE-non3GPP/config"
	nas_registration "UE-non3GPP/engine/nas"
	ran_ue "UE-non3GPP/engine/ran"
	util "UE-non3GPP/engine/util"
	"golang.org/x/sys/execabs"

	"UE-non3GPP/engine/exchange/pkg/context"
	"UE-non3GPP/engine/exchange/pkg/ike/handler"
	"UE-non3GPP/engine/exchange/pkg/ike/message"

	"encoding/binary"
	"errors"
	"fmt"
	"github.com/free5gc/nas"
	"github.com/free5gc/nas/nasMessage"
	"github.com/free5gc/nas/security"
	"github.com/free5gc/openapi/models"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"

	"golang.org/x/sys/unix"
	"hash"

	"net"
	"time"
	//"net"
)

/* Global Variable */
var cfg config.Config
var n3ue *context.N3IWFUe
var ue *ran_ue.RanUeContext
var n3iwfUDPAddr *net.UDPAddr
var udpConnection *net.UDPConn
var tcpConnWithN3IWF *net.TCPConn

func InitCommunicationElements() {
	ue = util.CreateRanUEContext(cfg)
	/* new N3IWF Ue*/
	n3ue = util.CreateN3IWFUe()
	/* create N3IWF IKE connection */
	n3iwfUDPAddr = util.CreateN3IWFIKEConnection(cfg)
	/* create Local UE UDP Listener */
	udpConnection = util.CreateUEUDPListener(cfg)

}

func IkeSaInit() (*message.IKEMessage, *message.Proposal, *context.IKESecurityAssociation, message.IKEPayloadContainer) {
	ikeMessage, proposal := util.CreateIKEMessageSAInit()
	/* N3IWF Security Association request */
	ikeSecurityAssociation := util.CreateN3IWFSecurityAssociation(proposal, udpConnection, n3iwfUDPAddr, ikeMessage)
	n3ue.N3IWFIKESecurityAssociation = ikeSecurityAssociation

	var ikePayload message.IKEPayloadContainer
	ikePayload.BuildIdentificationInitiator(message.ID_FQDN, []byte("UE"))

	return ikeMessage, proposal, ikeSecurityAssociation, ikePayload
}

func IkeAuthRequest(ikeMessage *message.IKEMessage, _proposal *message.Proposal, ikeSecurityAssociation *context.IKESecurityAssociation, ikePayload message.IKEPayloadContainer) uint8 {

	ikeMessage.Payloads.Reset()
	n3ue.N3IWFIKESecurityAssociation.InitiatorMessageID++
	ikeMessage.BuildIKEHeader(
		n3ue.N3IWFIKESecurityAssociation.LocalSPI, n3ue.N3IWFIKESecurityAssociation.RemoteSPI,
		message.IKE_AUTH, message.InitiatorBitCheck, n3ue.N3IWFIKESecurityAssociation.InitiatorMessageID)

	var _attributeType uint16 = message.AttributeTypeKeyLength
	var _keyLength uint16 = 256

	// Security Association
	securityAssociation := ikePayload.BuildSecurityAssociation()
	// Proposal 1
	inboundSPI := generateSPI(n3ue)
	_proposal = securityAssociation.Proposals.BuildProposal(1, message.TypeESP, inboundSPI)
	// ENCR
	_proposal.EncryptionAlgorithm.BuildTransform(message.TypeEncryptionAlgorithm, message.ENCR_AES_CBC, &_attributeType, &_keyLength, nil)
	// INTEG
	_proposal.IntegrityAlgorithm.BuildTransform(message.TypeIntegrityAlgorithm, message.AUTH_HMAC_SHA1_96, nil, nil, nil)
	// ESN
	_proposal.ExtendedSequenceNumbers.BuildTransform(message.TypeExtendedSequenceNumbers, message.ESN_NO, nil, nil, nil)

	// Traffic Selector
	tsi := ikePayload.BuildTrafficSelectorInitiator()
	tsi.TrafficSelectors.BuildIndividualTrafficSelector(message.TS_IPV4_ADDR_RANGE, 0, 0, 65535, []byte{0, 0, 0, 0}, []byte{255, 255, 255, 255})
	tsr := ikePayload.BuildTrafficSelectorResponder()
	tsr.TrafficSelectors.BuildIndividualTrafficSelector(message.TS_IPV4_ADDR_RANGE, 0, 0, 65535, []byte{0, 0, 0, 0}, []byte{255, 255, 255, 255})

	if err := util.EncryptProcedure(ikeSecurityAssociation, ikePayload, ikeMessage); err != nil {
		log.Fatalf("Encrypting IKE message failed: %+v", err)
		panic(err)
	}

	// Send to N3IWF
	ikeMessageData, err := ikeMessage.Encode()
	if err != nil {
		log.Fatal(err)
		panic(err)
	}
	if _, err := udpConnection.WriteToUDP(ikeMessageData, n3iwfUDPAddr); err != nil {
		log.Fatal(err)
		panic(err)
	}

	n3ue.CreateHalfChildSA(n3ue.N3IWFIKESecurityAssociation.InitiatorMessageID, binary.BigEndian.Uint32(inboundSPI))

	// Receive N3IWF reply
	buffer := make([]byte, 65535)
	n, _, err := udpConnection.ReadFromUDP(buffer)
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

	encryptedPayload, ok := ikeMessage.Payloads[0].(*message.Encrypted)
	if !ok {
		log.Fatal("Received payload is not an encrypted payload")
		panic(err)
	}

	decryptedIKEPayload, err := util.DecryptProcedure(ikeSecurityAssociation, ikeMessage, encryptedPayload)
	if err != nil {
		log.Fatalf("Decrypt IKE message failed: %+v", err)
		panic(err)
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
	return eapIdentifier
}

func IkeAuthEapExchange(ikeMessage *message.IKEMessage, ikePayload message.IKEPayloadContainer, eapIdentifier uint8, ikeSecurityAssociation *context.IKESecurityAssociation) {

	/* 1º Registration Request */
	ikeMessage.Payloads.Reset()
	n3ue.N3IWFIKESecurityAssociation.InitiatorMessageID++
	ikeMessage.BuildIKEHeader(n3ue.N3IWFIKESecurityAssociation.LocalSPI,
		n3ue.N3IWFIKESecurityAssociation.RemoteSPI,
		message.IKE_AUTH,
		message.InitiatorBitCheck,
		n3ue.N3IWFIKESecurityAssociation.InitiatorMessageID)

	ikePayload.Reset()

	// EAP-5G vendor type data
	eapVendorTypeData := make([]byte, 2)
	eapVendorTypeData[0] = message.EAP5GType5GNAS

	// AN Parameters
	anParameters := util.CreateEAP5GANParameters()
	anParametersLength := make([]byte, 2)
	binary.BigEndian.PutUint16(anParametersLength, uint16(len(anParameters)))
	eapVendorTypeData = append(eapVendorTypeData, anParametersLength...)
	eapVendorTypeData = append(eapVendorTypeData, anParameters...)

	// NAS
	ueSecurityCapability := ue.GetUESecurityCapability()
	mobileIdentity := util.CreateMobileIdentity(cfg)

	registrationRequest := nas_registration.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		mobileIdentity,
		nil,
		ueSecurityCapability,
		nil,
		nil,
		nil)

	nasLength := make([]byte, 2)
	binary.BigEndian.PutUint16(nasLength, uint16(len(registrationRequest)))
	eapVendorTypeData = append(eapVendorTypeData, nasLength...)
	eapVendorTypeData = append(eapVendorTypeData, registrationRequest...)

	eap := ikePayload.BuildEAP(message.EAPCodeResponse, eapIdentifier)
	eap.EAPTypeData.BuildEAPExpanded(message.VendorID3GPP, message.VendorTypeEAP5G, eapVendorTypeData)

	if err := util.EncryptProcedure(ikeSecurityAssociation, ikePayload, ikeMessage); err != nil {
		log.Fatal(err)
		panic(err)
	}

	// Send to N3IWF
	ikeMessageData, err := ikeMessage.Encode()
	if err != nil {
		log.Fatal(err)
		panic(err)
	}
	if _, err := udpConnection.WriteToUDP(ikeMessageData, n3iwfUDPAddr); err != nil {
		log.Fatal(err)
		panic(err)
	}

	// Receive N3IWF reply - Neste ponte é necessário o UE estar cadastrado no CORE com mesmo SUPI do arquivo de configuração, caso contrário teremos um erro de autenticação no AUSF
	buffer := make([]byte, 65535)
	n, _, err := udpConnection.ReadFromUDP(buffer)
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
	encryptedPayload, ok := ikeMessage.Payloads[0].(*message.Encrypted)
	if !ok {
		log.Fatal("Received payload is not an encrypted payload")
		panic(err)
	}
	decryptedIKEPayload, err := util.DecryptProcedure(ikeSecurityAssociation, ikeMessage, encryptedPayload)
	if err != nil {
		log.Fatalf("Decrypt IKE message failed: %+v", err)
		panic(err)
	}

	var eapReq *message.EAP
	var eapExpanded *message.EAPExpanded

	eapReq, ok = decryptedIKEPayload[0].(*message.EAP)
	if !ok {
		log.Fatal("Received packet is not an EAP payload")
		panic(err)
	}

	var decodedNAS *nas.Message

	eapExpanded, ok = eapReq.EAPTypeData[0].(*message.EAPExpanded)
	if !ok {
		log.Fatal("The EAP data is not an EAP expended.")
		panic(err)
	}

	// Decode NAS - Authentication Request
	nasData := eapExpanded.VendorData[4:]
	decodedNAS = new(nas.Message)
	if err := decodedNAS.PlainNasDecode(&nasData); err != nil {
		log.Fatal(err)
		panic(err)
	}

	// Calculate for RES*
	if decodedNAS == nil {
		log.Fatal("Erro inesperado! - Assert")
	}
	rand := decodedNAS.AuthenticationRequest.GetRANDValue()

	resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu := nas_registration.GetAuthenticationResponse(resStat, "")

	/* 2º Registration Request */
	ikeMessage.Payloads.Reset()
	n3ue.N3IWFIKESecurityAssociation.InitiatorMessageID++
	ikeMessage.BuildIKEHeader(n3ue.N3IWFIKESecurityAssociation.LocalSPI,
		n3ue.N3IWFIKESecurityAssociation.RemoteSPI,
		message.IKE_AUTH,
		message.InitiatorBitCheck,
		n3ue.N3IWFIKESecurityAssociation.InitiatorMessageID)

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
	buffer = make([]byte, 65535)
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
	_, ok = eapReq.EAPTypeData[0].(*message.EAPExpanded)
	if !ok {
		log.Fatal("Received packet is not an EAP expended payload")
		panic("Received packet is not an EAP expended payload")
	}

	nasData = eapExpanded.VendorData[4:]

	// Send NAS Security Mode Complete Msg
	registrationRequestWith5GMM := nas_registration.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		mobileIdentity,
		nil,
		ueSecurityCapability,
		ue.Get5GMMCapability(),
		nil,
		nil)

	pdu = nas_registration.GetSecurityModeComplete(registrationRequestWith5GMM)

	pdu, err = nas_registration.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
	if err != nil {
		panic(err)
	}

	/*3 - requisição */
	ikeMessage.Payloads.Reset()
	n3ue.N3IWFIKESecurityAssociation.InitiatorMessageID++
	ikeMessage.BuildIKEHeader(n3ue.N3IWFIKESecurityAssociation.LocalSPI,
		n3ue.N3IWFIKESecurityAssociation.RemoteSPI,
		message.IKE_AUTH,
		message.InitiatorBitCheck,
		n3ue.N3IWFIKESecurityAssociation.InitiatorMessageID)

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
	eap.EAPTypeData.BuildEAPExpanded(message.VendorID3GPP,
		message.VendorTypeEAP5G,
		eapVendorTypeData)

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
	buffer = make([]byte, 65535)
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
}

func IkeAuth(ikeMessage *message.IKEMessage, ikePayload message.IKEPayloadContainer, ikeSecurityAssociation *context.IKESecurityAssociation) (*net.IPNet, *net.TCPAddr) {
	ikeMessage.Payloads.Reset()
	n3ue.N3IWFIKESecurityAssociation.InitiatorMessageID++
	ikeMessage.BuildIKEHeader(n3ue.N3IWFIKESecurityAssociation.LocalSPI,
		n3ue.N3IWFIKESecurityAssociation.RemoteSPI,
		message.IKE_AUTH,
		message.InitiatorBitCheck,
		n3ue.N3IWFIKESecurityAssociation.InitiatorMessageID)

	ikePayload.Reset()

	// Authentication
	ikePayload.BuildAuthentication(message.SharedKeyMesageIntegrityCode, []byte{1, 2, 3})

	// Configuration Request
	configurationRequest := ikePayload.BuildConfiguration(message.CFG_REQUEST)
	configurationRequest.ConfigurationAttribute.BuildConfigurationAttribute(message.INTERNAL_IP4_ADDRESS, nil)

	err := util.EncryptProcedure(ikeSecurityAssociation,
		ikePayload,
		ikeMessage)

	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	// Send to N3IWF
	ikeMessageData, err := ikeMessage.Encode()
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
	buffer := make([]byte, 65535)
	n, _, err := udpConnection.ReadFromUDP(buffer)
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
	encryptedPayload, ok := ikeMessage.Payloads[0].(*message.Encrypted)
	if !ok {
		log.Fatal("Received pakcet is not and encrypted payload")
		panic("Received pakcet is not and encrypted payload")
	}
	decryptedIKEPayload, err := util.DecryptProcedure(ikeSecurityAssociation, ikeMessage, encryptedPayload)
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
	return ueAddr, n3iwfNASAddr
}

func NASRegistration(ueAddr *net.IPNet, n3iwfNASAddr *net.TCPAddr) {
	links, err := netlink.LinkList()
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	var linkIPSec netlink.Link
	for _, link := range links {
		if link.Attrs() != nil {
			if link.Attrs().Name == cfg.Ue.IPSecInterfaceName {
				linkIPSec = link
				break
			}
		}
	}
	if linkIPSec == nil {
		log.Fatal("No link named " + cfg.Ue.IPSecInterfaceName)
		panic("No link named " + cfg.Ue.IPSecInterfaceName)
	}

	linkIPSecAddr := &netlink.Addr{
		IPNet: ueAddr,
	}

	if err := netlink.AddrAdd(linkIPSec, linkIPSecAddr); err != nil {
		log.Fatalf("Set ipsec0 addr failed: %v", err)
		panic(err)
	}

	localTCPAddr := &net.TCPAddr{
		IP: ueAddr.IP,
	}

	tcpConnWithN3IWF, err = net.DialTCP("tcp", localTCPAddr, n3iwfNASAddr)
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

	pdu := nas_registration.GetRegistrationComplete(nil)
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
}

func UePDUSessionSetup(ikeMessage *message.IKEMessage, ikePayload message.IKEPayloadContainer, ikeSecurityAssociation *context.IKESecurityAssociation) (*PDUQoSInfo, net.IP) {
	sNssai := models.Snssai{
		Sst: cfg.Ue.Snssai.Sst,
		Sd:  cfg.Ue.Snssai.Sd,
	}
	pdu := nas_registration.GetUlNasTransport_PduSessionEstablishmentRequest(cfg.Ue.PDUSessionId, nasMessage.ULNASTransportRequestTypeInitialRequest, cfg.Ue.DNNString, &sNssai)
	pdu, err := EncodeNasPduInEnvelopeWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
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
	buffer := make([]byte, 65535)
	n, _, err := udpConnection.ReadFromUDP(buffer)
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
	encryptedPayload, ok := ikeMessage.Payloads[0].(*message.Encrypted)
	if !ok {
		log.Fatal("Received pakcet is not and encrypted payload")
		panic("Received pakcet is not and encrypted payload")
	}
	decryptedIKEPayload, err := util.DecryptProcedure(ikeSecurityAssociation, ikeMessage, encryptedPayload)
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	var responseSecurityAssociation *message.SecurityAssociation
	var responseTrafficSelectorInitiator *message.TrafficSelectorInitiator
	var responseTrafficSelectorResponder *message.TrafficSelectorResponder

	var QoSInfo *PDUQoSInfo
	var upIPAddr net.IP
	OutboundSPI := binary.BigEndian.Uint32(n3ue.N3IWFIKESecurityAssociation.IKEAuthResponseSA.Proposals[0].SPI)

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

	ikeMessage.Payloads.Reset()
	ikeMessage.BuildIKEHeader(ikeMessage.InitiatorSPI,
		ikeMessage.ResponderSPI,
		message.CREATE_CHILD_SA,
		message.ResponseBitCheck|message.InitiatorBitCheck,
		n3ue.N3IWFIKESecurityAssociation.ResponderMessageID)

	ikePayload.Reset()

	// SA
	inboundSPI := generateSPI(n3ue)
	responseSecurityAssociation.Proposals[0].SPI = inboundSPI
	ikePayload = append(ikePayload, responseSecurityAssociation)

	// TSi
	ikePayload = append(ikePayload, responseTrafficSelectorInitiator)

	// TSr
	ikePayload = append(ikePayload, responseTrafficSelectorResponder)

	// Nonce
	localNonce := handler.GenerateRandomNumber().Bytes()
	ikeSecurityAssociation.ConcatenatedNonce = append(ikeSecurityAssociation.ConcatenatedNonce, localNonce...)
	ikePayload.BuildNonce(localNonce)

	if err := util.EncryptProcedure(ikeSecurityAssociation, ikePayload, ikeMessage); err != nil {
		log.Fatal(err)
		panic(err)
	}

	// Send to N3IWF
	ikeMessageData, err := ikeMessage.Encode()
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

	// Aplly XFRM rules
	if err = applyXFRMRule(false, childSecurityAssociationContextUserPlane); err != nil {
		log.Fatalf("Applying XFRM rules failed: %+v", err)
		panic(err)
	}
	return QoSInfo, upIPAddr
}

func GRETunSetup(QoSInfo *PDUQoSInfo, upIPAddr net.IP, ueAddr *net.IPNet) {
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

	// Link address 60.60.0.1/20
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

	upRoute := &netlink.Route{
		LinkIndex: linkGRE.Attrs().Index,
		Dst: &net.IPNet{
			IP:   net.IPv4zero,
			Mask: net.IPv4Mask(0, 0, 0, 0),
		},
		Table: 1,
	}

	if err := netlink.RouteAdd(upRoute); err != nil {
		log.Warning("UPF Route exist!")
	}
}

func UENon3GPPConnection() {
	/* initial config */
	cfg = config.GetConfig()
	util.CleanEnvironment(cfg)

	/* create communitcaion elements */
	InitCommunicationElements()

	/* Fig 7: https://www.wipro.com/network-edge-providers/untrusted-non-3gpp-access-network-interworking-with-5g-core */
	/* ----------------------- */
	/* ---- 1º IKE SA INIT --- */
	/* ----------------------- */
	ikeMessage, proposal, ikeSecurityAssociation, ikePayload := IkeSaInit()

	/* -------------------------- */
	/* -- 2º IKE AUTH Request --- */
	/* -------------------------- */
	eapIdentifier := IkeAuthRequest(ikeMessage, proposal, ikeSecurityAssociation, ikePayload)

	/* -------------------------- */
	/* -- 3º IKE_AUTH - EAP exchange | 3 Requisições -- refatorar --- */
	/* -------------------------- */
	IkeAuthEapExchange(ikeMessage, ikePayload, eapIdentifier, ikeSecurityAssociation)

	/* ----------------------------------- */
	/* -- 4º IKE_AUTH - Authentication --- */
	/* ----------------------------------- */
	ueAddr, n3iwfNASAddr := IkeAuth(ikeMessage, ikePayload, ikeSecurityAssociation)

	/* ------------------------------------ */
	/* -- 5º Stablish TCP communication + NAS Registration --- */
	/* ------------------------------------ */
	NASRegistration(ueAddr, n3iwfNASAddr)

	/* -------------------------------------- */
	/* -- 6º UE request PDU session setup --- */
	/* ------------------------------------ */
	QoSInfo, upIPAddr := UePDUSessionSetup(ikeMessage, ikePayload, ikeSecurityAssociation)

	/* ------------------------------------ */
	/* -- 7º Data Communication Setup  --- */
	/* ------------------------------------ */
	GRETunSetup(QoSInfo, upIPAddr, ueAddr)

	for {
		downGreTunInterface := "ping -I " + cfg.Ue.LinkGRE.Name + " 8.8.8.8"
		cmd := execabs.Command("bash", "-c", downGreTunInterface)
		err := cmd.Run()
		if err != nil {
			log.Info(" não pingou!")
		} else {
			log.Info(" pingou!")
		}
		time.Sleep(1 * time.Second)
	}

	//pinger, err := ping.NewPinger("60.60.0.101")
	////pinger, err := ping.NewPinger("8.8.8.8")
	//if err != nil {
	//	log.Fatal(err)
	//	panic(err)
	//}
	//pinger.SetPrivileged(true)
	//
	//n_loop := 1
	//for n_loop < 2 {
	//	fmt.Println("..ping ", n_loop)
	//	pinger.OnRecv = func(pkt *ping.Packet) {
	//		fmt.Println("")
	//		fmt.Println("............................")
	//		fmt.Println("------PING 60.60.0.101----------")
	//		fmt.Println("Bytes recebidos:")
	//		fmt.Println(pkt.Nbytes)
	//		fmt.Println("Host Origem:")
	//		fmt.Println(pkt.IPAddr)
	//		fmt.Println("ICMP Seq:")
	//		fmt.Println(pkt.Seq)
	//		fmt.Println("RTT:")
	//		fmt.Println(pkt.Rtt)
	//	}
	//
	//	pinger.OnFinish = func(stats *ping.Statistics) {
	//		fmt.Println("------Estatísticas----------")
	//		fmt.Print("Pacotes transmitidos: ")
	//		fmt.Println(stats.PacketsSent)
	//		fmt.Print("Pacotes recebidos: ")
	//		fmt.Println(stats.PacketsRecv)
	//		fmt.Print("Pacotes perdidos: ")
	//		fmt.Println(stats.PacketLoss)
	//		fmt.Print("round-trip min: ")
	//		fmt.Println(stats.MinRtt)
	//		fmt.Print("round-trip avg: ")
	//		fmt.Println(stats.AvgRtt)
	//		fmt.Print("round-trip max: ")
	//		fmt.Println(stats.MaxRtt)
	//		fmt.Print("round-trip stddev: ")
	//		fmt.Println(stats.StdDevRtt)
	//	}
	//
	//	pinger.Count = 5
	//	pinger.Timeout = 5 * time.Second
	//	pinger.Source = "60.60.0.1"
	//	time.Sleep(2 * time.Second)
	//	pinger.Run()
	//	time.Sleep(1 * time.Second)
	//	stats := pinger.Statistics()
	//
	//	if stats.PacketsSent != stats.PacketsRecv {
	//		log.Warning("Ping Failed!")
	//	}
	//	fmt.Println("              ")
	//	n_loop = n_loop + 1
	//}

	//defer func() {
	//	fmt.Println("del LINK GRE")
	//	_ = netlink.LinkSetDown(linkGRE)
	//	_ = netlink.LinkDel(linkGRE)
	//}()
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

func EncodeNasPduInEnvelopeWithSecurity(ue *ran_ue.RanUeContext, pdu []byte, securityHeaderType uint8,
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

func NASEnvelopeEncode(ue *ran_ue.RanUeContext, msg *nas.Message, securityContextAvailable bool, newSecurityContext bool) (
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

type PDUQoSInfo struct {
	pduSessionID    uint8
	qfiList         []uint8
	isDefault       bool
	isDSCPSpecified bool
	DSCP            uint8
}
