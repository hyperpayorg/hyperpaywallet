package hdwallet

var coins = make(map[uint32]func(*Key) Wallet)

// Wallet interface
type Wallet interface {
	GetType() uint32
	GetName() string
	GetSymbol() string
	GetKey() *Key
	GetAddress() (string, error)
	GetWalletAccount() *WalletAccount
	GetWalletAccountFromWif() (*WalletAccount, error)
	CreateRawTransaction(signIn *SignInput) (*SignResult, error)
	SignRawTransaction(signIn *SignInput) (*SignResult, error)
	GenerateTxHash(signIn *SignInput) (*TxHashResult, error)
	SignTxHash(signIn *SignTxHashInput) (*TxHashResult, error)
}
type WAVESParams struct {
	AmountAsset string
	FeeAsset    string
	Attachment  string
}

//         /* from */ from,
//         /* to */ to,
//         /* fee */ 488931,
//         /* amount */ 847,
//         /* first round */ 51,
//         /* last round */ 61,
//         /* note */ note,
//         /* type */ "pay",
//         /* genesis id*/ genesisId,
//         /* genesis hash*/ genesisHash
//     );
type ALGOParams struct {
	FirstRound  int64
	LastRound   int64
	GenesisHash string
}
type AEPPParams struct {
	TTL   int64
	Nonce int64
}

type WalletAccount struct {
	Res        int    // 0 失败 1 成功
	Address    string // 成功必定包含地址
	PublicKey  string // 公钥
	PrivateKey string // 私钥
	Seed       string //根Seed

	Coin    string //币种
	ErrMsg  string // 失败原因(便于排查问题,不是必定返回)
	ErrCode int    //错误码
	Params  string //预留字段
}

type TransferResult struct {
	Res     int    // 0 失败 1 成功
	ErrMsg  string //  失败原因(便于排查问题,不是必定返回)
	ErrCode int    //错误码
	TxID    string // 成功: 返回TxID
	Symbol  string // 币种
	Params  []byte //预留字段
}

type OutPutItem struct {
	TxHash   string
	Vout     uint32
	Value    int64
	Pkscript string
}

type BTMOutPutItem struct {
	SourceID       string
	SourcePosition uint64
	AssetID        string
	Amount         uint64
	ControlProgram string
}

type SignTxHashInput struct {
	Coin      string // 主链币
	Symbol    string // symbol
	Signature string //签名数据
	TxHash    string //交易Hash
	TxRawHex  string // 原始交易RawHex
	Params    []byte //预留字段
}
type SignInput struct {
	PrivateKey   string //私钥
	Coin         string // 主链币
	Symbol       string // symbol
	Amount       int64  //转账数量
	Change       int64  //找零数量
	Fee          int64  //交易费用
	GasLimit     int64  // gas数量
	GasPrice     int64  // gas价格
	Type         string //交易类型 //xtz TYPE = branch
	SrcAddr      string //转账地址
	DestAddr     string //接受地址
	ContractAddr string //合约地址
	Sequence     int64  // 序列号
	Memo         string //交易备注
	Inputs       []byte //Vin构造
	Params       []byte //预留字段
}

type SignResult struct {
	Res     int    // 0 失败 1 成功
	Coin    string // 主链币
	Symbol  string // symbol币种
	RawTX   string //签名后的数据
	TxHash  string // 交易Hash
	ErrMsg  string // 失败原因(便于排查问题,不是必定返回)
	ErrCode int    //错误码
	Params  []byte //预留字段
}
type TxHashResult struct {
	ResCode  int    // 0 失败 1 成功
	Coin     string // 主链币
	Symbol   string // symbol币种
	RawTX    string //签名后的数据
	TxHash   string //交易Hash
	TxRawHex string //交易TxRawHex
	ErrMsg   string // 失败原因(便于排查问题,不是必定返回)
	ErrCode  int    //错误码(暂时保留)

	Params []byte //预留字段
}
type FeeResult struct {
	ResCode int    // 0 失败 1 成功
	ErrMsg  string // 失败原因(便于排查问题,不是必定返回)
	ErrCode int    //错误码
	Fee     int64  // 成功: 返回TxID
	Coin    string // 币种
	Symbol  string // symbol

	Params []byte //预留字段
}
