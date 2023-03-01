package context

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/free5gc/nas/nasType"
	"github.com/free5gc/nas/security"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/milenage"
	"github.com/free5gc/util/ueauth"
	"github.com/vishvananda/netlink"
	"net"
	"reflect"
	"regexp"
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

type UeNas struct {
	id            uint8
	StateMM       int
	StateSM       int
	PduSession    PDUSession
	NasSecurity   NASecurity
	XfrmInterface netlink.Link
	tcpIpsec      *net.TCPConn
}

type PDUSession struct {
	Id           uint8
	Snssai       models.Snssai
	Dnn          string
	PDUAdress    net.IP
	GreInterface netlink.Link
	route        *netlink.Route
}

type NASecurity struct {
	RanUeNgapId        int64
	AmfUeNgapId        int64
	Msin               string
	Mcc                string
	Mnc                string
	Supi               string
	ULCount            security.Count
	DLCount            security.Count
	CipheringAlg       uint8
	IntegrityAlg       uint8
	Snn                string
	KnasEnc            [16]uint8
	KnasInt            [16]uint8
	Kamf               []uint8
	AuthenticationSubs models.AuthenticationSubscription
	Suci               nasType.MobileIdentity5GS
	Guti               [4]byte
	AnType             models.AccessType
}

type ArgumentsNas struct {
	Mcc         string
	Mnc         string
	Msin        string
	RanUeNgapId int64
	K           string
	Opc         string
	Op          string
	Amf         string
	Sqn         string
	Sst         int32
	Sd          string
	Dnn         string
}

func NewUeNas(argsNas ArgumentsNas) *UeNas {

	ue := &UeNas{}
	ue.id = 1
	ue.StateMM = registeredInitiated
	ue.StateSM = pduSessionInactive
	ue.NasSecurity = newNasSecurity(argsNas.Msin,
		argsNas.Mcc, argsNas.Mnc, argsNas.RanUeNgapId,
		security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2,
		models.AccessType_NON_3_GPP_ACCESS, argsNas.K,
		argsNas.Opc, argsNas.Op, argsNas.Amf, argsNas.Sqn)
	ue.PduSession = newPDUSession(1,
		argsNas.Sst, argsNas.Sd,
		argsNas.Dnn)

	return ue
}

func newPDUSession(id uint8, sst int32, sd, dnn string) PDUSession {

	pdu := PDUSession{}
	pdu.Id = id
	pdu.Snssai.Sst = sst
	pdu.Snssai.Sd = sd
	pdu.Dnn = dnn

	return pdu
}

func newNasSecurity(msin, mcc, mnc string, ranUeNgapId int64, cipheringAlg, integrityAlg uint8,
	anType models.AccessType, k, opc, op, amf, sqn string) NASecurity {

	nas := NASecurity{}
	nas.Msin = msin
	nas.Mcc = mcc
	nas.Mnc = mnc
	nas.RanUeNgapId = ranUeNgapId
	nas.CipheringAlg = cipheringAlg
	nas.IntegrityAlg = integrityAlg
	nas.AnType = anType
	nas.AuthenticationSubs = setAuthSubscription(k, opc, op, amf, sqn)
	nas.Snn = deriveSNN(mcc, mnc)
	nas.Supi = fmt.Sprintf("imsi-%s%s%s", mcc, mnc, msin)

	return nas
}

func (ue *UeNas) Terminate() bool {

	err := netlink.LinkDel(ue.XfrmInterface)
	if err != nil {
		return false
	}

	ue.tcpIpsec.Close()

	err = netlink.LinkDel(ue.PduSession.GreInterface)
	if err != nil {
		return false
	}

	err = netlink.RouteDel(ue.PduSession.route)
	if err != nil {
		return false
	}

	return true
}

func (ue *UeNas) SetRegistered() {
	ue.StateMM = registered
}

func (ue *UeNas) SetGRERoute(route *netlink.Route) {
	ue.PduSession.route = route
}

func (ue *UeNas) SetGREInterface(greInterface netlink.Link) {
	ue.PduSession.GreInterface = greInterface
}

func (ue *UeNas) SetXfrmInterface(xfrmInterface netlink.Link) {
	ue.XfrmInterface = xfrmInterface
}

func (ue *UeNas) GetXfrmInterface() netlink.Link {
	return ue.XfrmInterface
}

func (ue *UeNas) SetIpsecTcp(tcpsocket *net.TCPConn) {
	ue.tcpIpsec = tcpsocket
}

func (ue *UeNas) GetIpsecTcp() *net.TCPConn {
	return ue.tcpIpsec
}

func (ue *UeNas) SetPduSessionPending() {
	ue.StateSM = pduSessionPending
}

func (ue *UeNas) SetPduSessionActive() {
	ue.StateSM = pduSessionActive
}

func (ue *UeNas) DeriveRESstarAndSetKey(authSubs models.AuthenticationSubscription,
	RAND []byte,
	snNmae string,
	AUTN []byte) ([]byte, string) {

	// parameters for authentication challenge.
	mac_a, mac_s := make([]byte, 8), make([]byte, 8)
	CK, IK := make([]byte, 16), make([]byte, 16)
	RES := make([]byte, 8)
	AK, AKstar := make([]byte, 6), make([]byte, 6)

	// Get OPC, K, SQN, AMF from USIM.
	OPC, _ := hex.DecodeString(authSubs.Opc.OpcValue)
	K, _ := hex.DecodeString(authSubs.PermanentKey.PermanentKeyValue)
	sqnUe, _ := hex.DecodeString(authSubs.SequenceNumber)
	AMF, _ := hex.DecodeString(authSubs.AuthenticationManagementField)

	// Generate RES, CK, IK, AK, AKstar
	milenage.F2345(OPC, K, RAND, RES, CK, IK, AK, AKstar)

	// Get SQN, MAC_A, AMF from AUTN
	sqnHn, _, mac_aHn := ue.deriveAUTN(AUTN, AK)

	// Generate MAC_A, MAC_S
	milenage.F1(OPC, K, RAND, sqnHn, AMF, mac_a, mac_s)

	// MAC verification.
	if !reflect.DeepEqual(mac_a, mac_aHn) {
		return nil, "MAC failure"
	}

	// Verification of sequence number freshness.
	if bytes.Compare(sqnUe, sqnHn) > 0 {

		// get AK*
		milenage.F2345(OPC, K, RAND, RES, CK, IK, AK, AKstar)

		// From the standard, AMF(0x0000) should be used in the synch failure.
		amfSynch, _ := hex.DecodeString("0000")

		// get mac_s using sqn ue.
		milenage.F1(OPC, K, RAND, sqnUe, amfSynch, mac_a, mac_s)

		sqnUeXorAK := make([]byte, 6)
		for i := 0; i < len(sqnUe); i++ {
			sqnUeXorAK[i] = sqnUe[i] ^ AKstar[i]
		}

		failureParam := append(sqnUeXorAK, mac_s...)

		return failureParam, "SQN failure"
	}

	// updated sqn value.
	authSubs.SequenceNumber = fmt.Sprintf("%x", sqnHn)

	// derive RES*
	key := append(CK, IK...)
	FC := ueauth.FC_FOR_RES_STAR_XRES_STAR_DERIVATION
	P0 := []byte(snNmae)
	P1 := RAND
	P2 := RES

	ue.DerivateKamf(key, snNmae, sqnHn, AK)
	ue.DerivateAlgKey()
	kdfVal_for_resStar, _ := ueauth.GetKDFValue(key, FC, P0, ueauth.KDFLen(P0), P1, ueauth.KDFLen(P1), P2, ueauth.KDFLen(P2))
	return kdfVal_for_resStar[len(kdfVal_for_resStar)/2:], "successful"
}

func (ue *UeNas) DerivateKamf(key []byte, snName string, SQN, AK []byte) {

	FC := ueauth.FC_FOR_KAUSF_DERIVATION
	P0 := []byte(snName)
	SQNxorAK := make([]byte, 6)
	for i := 0; i < len(SQN); i++ {
		SQNxorAK[i] = SQN[i] ^ AK[i]
	}
	P1 := SQNxorAK
	Kausf, _ := ueauth.GetKDFValue(key, FC, P0, ueauth.KDFLen(P0), P1, ueauth.KDFLen(P1))
	P0 = []byte(snName)
	Kseaf, _ := ueauth.GetKDFValue(Kausf, ueauth.FC_FOR_KSEAF_DERIVATION, P0, ueauth.KDFLen(P0))

	supiRegexp, _ := regexp.Compile("(?:imsi|supi)-([0-9]{5,15})")
	groups := supiRegexp.FindStringSubmatch(ue.NasSecurity.Supi)

	P0 = []byte(groups[1])
	L0 := ueauth.KDFLen(P0)
	P1 = []byte{0x00, 0x00}
	L1 := ueauth.KDFLen(P1)

	ue.NasSecurity.Kamf, _ = ueauth.GetKDFValue(Kseaf, ueauth.FC_FOR_KAMF_DERIVATION, P0, L0, P1, L1)
}

// Algorithm key Derivation function defined in TS 33.501 Annex A.9
func (ue *UeNas) DerivateAlgKey() {
	// Security Key
	P0 := []byte{security.NNASEncAlg}
	L0 := ueauth.KDFLen(P0)
	P1 := []byte{ue.NasSecurity.CipheringAlg}
	L1 := ueauth.KDFLen(P1)

	kenc, _ := ueauth.GetKDFValue(ue.NasSecurity.Kamf, ueauth.FC_FOR_ALGORITHM_KEY_DERIVATION, P0, L0, P1, L1)
	copy(ue.NasSecurity.KnasEnc[:], kenc[16:32])

	// Integrity Key
	P0 = []byte{security.NNASIntAlg}
	L0 = ueauth.KDFLen(P0)
	P1 = []byte{ue.NasSecurity.IntegrityAlg}
	L1 = ueauth.KDFLen(P1)

	kint, _ := ueauth.GetKDFValue(ue.NasSecurity.Kamf, ueauth.FC_FOR_ALGORITHM_KEY_DERIVATION, P0, L0, P1, L1)
	copy(ue.NasSecurity.KnasInt[:], kint[16:32])
}

func setAuthSubscription(k, opc, op, amf, sqn string) models.AuthenticationSubscription {
	auth := models.AuthenticationSubscription{}
	auth.PermanentKey = &models.PermanentKey{
		PermanentKeyValue: k,
	}
	auth.Opc = &models.Opc{
		OpcValue: opc,
	}
	auth.Milenage = &models.Milenage{
		Op: &models.Op{
			OpValue: op,
		},
	}
	auth.AuthenticationManagementField = amf
	auth.SequenceNumber = sqn
	auth.AuthenticationMethod = models.AuthMethod__5_G_AKA
	return auth
}

func (ue *UeNas) deriveAUTN(autn []byte, ak []uint8) ([]byte, []byte, []byte) {

	sqn := make([]byte, 6)

	// get SQNxorAK
	SQNxorAK := autn[0:6]
	amf := autn[6:8]
	mac_a := autn[8:]

	// get SQN
	for i := 0; i < len(SQNxorAK); i++ {
		sqn[i] = SQNxorAK[i] ^ ak[i]
	}

	// return SQN, amf, mac_a
	return sqn, amf, mac_a
}

func deriveSNN(mcc, mnc string) string {
	// 5G:mnc093.mcc208.3gppnetwork.org
	var resu string
	if len(mnc) == 2 {
		resu = "5G:mnc0" + mnc + ".mcc" + mcc + ".3gppnetwork.org"
	} else {
		resu = "5G:mnc" + mnc + ".mcc" + mcc + ".3gppnetwork.org"
	}

	return resu
}
func (ue *UeNas) DeriveKn3iwf() []byte {
	P0 := make([]byte, 4)
	binary.BigEndian.PutUint32(P0, ue.NasSecurity.ULCount.Get()-1)
	L0 := ueauth.KDFLen(P0)
	P1 := []byte{security.AccessTypeNon3GPP}
	L1 := ueauth.KDFLen(P1)

	Kn3iwf, err := ueauth.GetKDFValue(
		ue.NasSecurity.Kamf,
		ueauth.FC_FOR_KGNB_KN3IWF_DERIVATION,
		P0,
		L0,
		P1,
		L1)
	if err != nil {
		// TODO handler error
		return nil
	}
	return Kn3iwf
}
