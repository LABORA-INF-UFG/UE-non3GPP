package util

import (
	"UE-non3GPP/config"
	"UE-non3GPP/engine/exchange/pkg/context"
	"UE-non3GPP/engine/exchange/pkg/ike/message"
	log "github.com/sirupsen/logrus"
	"github.com/vishvananda/netlink"
	"math/big"
	"net"
)

func GetLinkGRE(cfg config.Config) netlink.Link {
	links, err := netlink.LinkList()
	if err != nil {
		log.Fatal(err)
		panic(err)
	}
	var linkGRE netlink.Link
	for _, link := range links {
		if link.Attrs() != nil {
			if link.Attrs().Name == cfg.Ue.LinkGRE.Name {
				linkGRE = link
				break
			}
		}
	}
	return linkGRE
}

func CreateN3IWFSecurityAssociation(_proposal *message.Proposal, _localNonce []byte, udpConnection *net.UDPConn, ikeMessageData []byte, n3iwfUDPAddr *net.UDPAddr, ikeMessage *message.IKEMessage, secret *big.Int, factor *big.Int) *context.IKESecurityAssociation {
	/*Send to N3IWF */
	if _, err := udpConnection.WriteToUDP(ikeMessageData, n3iwfUDPAddr); err != nil {
		log.Fatal(err)
		panic(err)
	}

	// Receive N3IWF reply
	_buffer := make([]byte, 65535)
	n, _, err := udpConnection.ReadFromUDP(_buffer)
	if err != nil {
		log.Fatal(err)
	}
	ikeMessage.Payloads.Reset()
	err = ikeMessage.Decode(_buffer[:n])
	if err != nil {
		log.Fatal(err)
		panic(err)
	}

	var _sharedKeyExchangeData []byte
	var _remoteNonce []byte

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
			_sharedKeyExchangeData = new(big.Int).Exp(remotePublicKeyExchangeValueBig, secret, factor).Bytes()
		case message.TypeNiNr:
			_remoteNonce = ikePayload.(*message.Nonce).NonceData
		}
	}
	_ikeSecurityAssociation := &context.IKESecurityAssociation{
		LocalSPI:               CreateIKEInitiatorSPI(),
		RemoteSPI:              ikeMessage.ResponderSPI,
		InitiatorMessageID:     0,
		ResponderMessageID:     0,
		EncryptionAlgorithm:    _proposal.EncryptionAlgorithm[0],
		IntegrityAlgorithm:     _proposal.IntegrityAlgorithm[0],
		PseudorandomFunction:   _proposal.PseudorandomFunction[0],
		DiffieHellmanGroup:     _proposal.DiffieHellmanGroup[0],
		ConcatenatedNonce:      append(_localNonce, _remoteNonce...),
		DiffieHellmanSharedKey: _sharedKeyExchangeData,
	}

	if err := GgenerateKeyForIKESA(_ikeSecurityAssociation); err != nil {
		log.Fatalf("Generate key for IKE SA failed: %+v", err)
		panic(err)
	}
	return _ikeSecurityAssociation
}
