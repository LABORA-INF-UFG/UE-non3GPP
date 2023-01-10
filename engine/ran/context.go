package ran

//func NewRanUeContext(supi string, ranUeNgapId int64, cipheringAlg, integrityAlg uint8,
//	AnType models.AccessType) *RanUeContext {
//	ue := RanUeContext{}
//	ue.RanUeNgapId = ranUeNgapId
//	ue.Supi = supi
//	ue.CipheringAlg = cipheringAlg
//	ue.IntegrityAlg = integrityAlg
//	ue.AnType = AnType
//	return &ue
//}
//
//type RanUeContext struct {
//	Supi               string
//	RanUeNgapId        int64
//	AmfUeNgapId        int64
//	ULCount            security.Count
//	DLCount            security.Count
//	CipheringAlg       uint8
//	IntegrityAlg       uint8
//	KnasEnc            [16]uint8
//	KnasInt            [16]uint8
//	Kamf               []uint8
//	AnType             models.AccessType
//	AuthenticationSubs models.AuthenticationSubscription
//}
//
//func (ue *RanUeContext) DeriveRESstarAndSetKey(
//	authSubs models.AuthenticationSubscription, rand []byte, snName string) []byte {
//
//	sqn, err := hex.DecodeString(authSubs.SequenceNumber)
//	if err != nil {
//		log.Fatal("DecodeString error:", err)
//		panic(err)
//	}
//
//	amf, err := hex.DecodeString(authSubs.AuthenticationManagementField)
//	if err != nil {
//		log.Fatalf("DecodeString error: ", err)
//		panic(err)
//	}
//
//	// Run milenage
//	macA, macS := make([]byte, 8), make([]byte, 8)
//	ck, ik := make([]byte, 16), make([]byte, 16)
//	res := make([]byte, 8)
//	ak, akStar := make([]byte, 6), make([]byte, 6)
//
//	opc := make([]byte, 16)
//	_ = opc
//	k, err := hex.DecodeString(authSubs.PermanentKey.PermanentKeyValue)
//	if err != nil {
//		log.Fatalf("DecodeString error: %+v", err)
//		panic(err)
//	}
//
//	if authSubs.Opc.OpcValue == "" {
//		opStr := authSubs.Milenage.Op.OpValue
//		var op []byte
//		op, err = hex.DecodeString(opStr)
//		if err != nil {
//			log.Fatalf("DecodeString error: %+v", err)
//			panic(err)
//		}
//
//		opc, err = milenage.GenerateOPC(k, op)
//		if err != nil {
//			log.Fatalf("milenage GenerateOPC error: %+v", err)
//			panic(err)
//		}
//	} else {
//		opc, err = hex.DecodeString(authSubs.Opc.OpcValue)
//		if err != nil {
//			log.Fatalf("DecodeString error: %+v", err)
//			panic(err)
//		}
//	}
//
//	// Generate MAC_A, MAC_S
//	err = milenage.F1(opc, k, rand, sqn, amf, macA, macS)
//	if err != nil {
//		log.Fatalf("regexp Compile error: %+v", err)
//		panic(err)
//	}
//
//	// Generate RES, CK, IK, AK, AKstar
//	err = milenage.F2345(opc, k, rand, res, ck, ik, ak, akStar)
//	if err != nil {
//		log.Fatalf("regexp Compile error: %+v", err)
//		panic(err)
//	}
//
//	// derive RES*
//	key := append(ck, ik...)
//	FC := ueauth.FC_FOR_RES_STAR_XRES_STAR_DERIVATION
//	P0 := []byte(snName)
//	P1 := rand
//	P2 := res
//
//	ue.DerivateKamf(key, snName, sqn, ak)
//	ue.DerivateAlgKey()
//	kdfVal_for_resStar, err :=
//		ueauth.GetKDFValue(key, FC, P0, ueauth.KDFLen(P0), P1, ueauth.KDFLen(P1), P2, ueauth.KDFLen(P2))
//	if err != nil {
//		log.Fatalf("GetKDFValue error: %+v", err)
//		panic(err)
//	}
//	return kdfVal_for_resStar[len(kdfVal_for_resStar)/2:]
//}
//
//func (ue *RanUeContext) DerivateKamf(key []byte, snName string, SQN, AK []byte) {
//	FC := ueauth.FC_FOR_KAUSF_DERIVATION
//	P0 := []byte(snName)
//	SQNxorAK := make([]byte, 6)
//	for i := 0; i < len(SQN); i++ {
//		SQNxorAK[i] = SQN[i] ^ AK[i]
//	}
//	P1 := SQNxorAK
//
//	Kausf, err := ueauth.GetKDFValue(key, FC, P0, ueauth.KDFLen(P0), P1, ueauth.KDFLen(P1))
//	if err != nil {
//		log.Fatalf("GetKDFValue error: %+v", err)
//		panic(err)
//	}
//
//	P0 = []byte(snName)
//	Kseaf, err := ueauth.GetKDFValue(Kausf, ueauth.FC_FOR_KSEAF_DERIVATION, P0, ueauth.KDFLen(P0))
//	if err != nil {
//		log.Fatalf("GetKDFValue error: %+v", err)
//		panic(err)
//	}
//
//	supiRegexp, err := regexp.Compile("(?:imsi|supi)-([0-9]{5,15})")
//	if err != nil {
//		log.Fatalf("regexp Compile error: %+v", err)
//		panic(err)
//	}
//	groups := supiRegexp.FindStringSubmatch(ue.Supi)
//
//	P0 = []byte(groups[1])
//	L0 := ueauth.KDFLen(P0)
//	P1 = []byte{0x00, 0x00}
//	L1 := ueauth.KDFLen(P1)
//
//	ue.Kamf, err = ueauth.GetKDFValue(Kseaf, ueauth.FC_FOR_KAMF_DERIVATION, P0, L0, P1, L1)
//	if err != nil {
//		log.Fatalf("GetKDFValue error: %+v", err)
//		panic(err)
//	}
//}
//
//// Algorithm key Derivation function defined in TS 33.501 Annex A.9
//func (ue *RanUeContext) DerivateAlgKey() {
//	// Security Key
//	P0 := []byte{security.NNASEncAlg}
//	L0 := ueauth.KDFLen(P0)
//	P1 := []byte{ue.CipheringAlg}
//	L1 := ueauth.KDFLen(P1)
//
//	kenc, err := ueauth.GetKDFValue(ue.Kamf, ueauth.FC_FOR_ALGORITHM_KEY_DERIVATION, P0, L0, P1, L1)
//	if err != nil {
//		log.Fatalf("GetKDFValue error: %+v", err)
//		panic(err)
//	}
//	copy(ue.KnasEnc[:], kenc[16:32])
//
//	// Integrity Key
//	P0 = []byte{security.NNASIntAlg}
//	L0 = ueauth.KDFLen(P0)
//	P1 = []byte{ue.IntegrityAlg}
//	L1 = ueauth.KDFLen(P1)
//
//	kint, err := ueauth.GetKDFValue(ue.Kamf, ueauth.FC_FOR_ALGORITHM_KEY_DERIVATION, P0, L0, P1, L1)
//	if err != nil {
//		log.Fatalf("GetKDFValue error: %+v", err)
//		panic(err)
//	}
//	copy(ue.KnasInt[:], kint[16:32])
//}
//
//func (ue *RanUeContext) GetUESecurityCapability() (UESecurityCapability *nasType.UESecurityCapability) {
//	UESecurityCapability = &nasType.UESecurityCapability{
//		Iei:    nasMessage.RegistrationRequestUESecurityCapabilityType,
//		Len:    2,
//		Buffer: []uint8{0x00, 0x00},
//	}
//	switch ue.CipheringAlg {
//	case security.AlgCiphering128NEA0:
//		UESecurityCapability.SetEA0_5G(1)
//	case security.AlgCiphering128NEA1:
//		UESecurityCapability.SetEA1_128_5G(1)
//	case security.AlgCiphering128NEA2:
//		UESecurityCapability.SetEA2_128_5G(1)
//	case security.AlgCiphering128NEA3:
//		UESecurityCapability.SetEA3_128_5G(1)
//	}
//
//	switch ue.IntegrityAlg {
//	case security.AlgIntegrity128NIA0:
//		UESecurityCapability.SetIA0_5G(1)
//	case security.AlgIntegrity128NIA1:
//		UESecurityCapability.SetIA1_128_5G(1)
//	case security.AlgIntegrity128NIA2:
//		UESecurityCapability.SetIA2_128_5G(1)
//	case security.AlgIntegrity128NIA3:
//		UESecurityCapability.SetIA3_128_5G(1)
//	}
//
//	return
//}
//
//func (ue *RanUeContext) Get5GMMCapability() (capability5GMM *nasType.Capability5GMM) {
//	return &nasType.Capability5GMM{
//		Iei:   nasMessage.RegistrationRequestCapability5GMMType,
//		Len:   1,
//		Octet: [13]uint8{0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
//	}
//}
//
//func (ue *RanUeContext) GetBearerType() uint8 {
//	if ue.AnType == models.AccessType__3_GPP_ACCESS {
//		return security.Bearer3GPP
//	} else if ue.AnType == models.AccessType_NON_3_GPP_ACCESS {
//		return security.BearerNon3GPP
//	} else {
//		return security.OnlyOneBearer
//	}
//}
//
//func (ue *RanUeContext) GetBearerByType(accessType models.AccessType) uint8 {
//	if accessType == models.AccessType__3_GPP_ACCESS {
//		return security.Bearer3GPP
//	} else if accessType == models.AccessType_NON_3_GPP_ACCESS {
//		return security.BearerNon3GPP
//	} else {
//		return security.OnlyOneBearer
//	}
//}
