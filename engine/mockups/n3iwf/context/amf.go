package context

import (
	"git.cs.nctu.edu.tw/calee/sctp"
	"github.com/free5gc/ngap/ngapType"
)

type N3IWFAMF struct {
	SCTPAddr              string
	SCTPConn              *sctp.SCTPConn
	AMFName               *ngapType.AMFName
	ServedGUAMIList       *ngapType.ServedGUAMIList
	RelativeAMFCapacity   *ngapType.RelativeAMFCapacity
	PLMNSupportList       *ngapType.PLMNSupportList
	AMFTNLAssociationList map[string]*AMFTNLAssociationItem // v4+v6 as key
	// Overload related
	AMFOverloadContent *AMFOverloadContent
	// Relative Context
	N3iwfUeList map[int64]*N3IWFUe // ranUeNgapId as key
}

type AMFTNLAssociationItem struct {
	Ipv4                   string
	Ipv6                   string
	TNLAssociationUsage    *ngapType.TNLAssociationUsage
	TNLAddressWeightFactor *int64
}

type AMFOverloadContent struct {
	Action     *ngapType.OverloadAction
	TrafficInd *int64
	NSSAIList  []SliceOverloadItem
}

type SliceOverloadItem struct {
	SNssaiList []ngapType.SNSSAI
	Action     *ngapType.OverloadAction
	TrafficInd *int64
}
