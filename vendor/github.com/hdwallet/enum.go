package hdwallet

// mnemonic language
const (
	English            = "english"
	ChineseSimplified  = "chinese_simplified"
	ChineseTraditional = "chinese_traditional"
)

// zero is deafult of uint32
const (
	Zero      uint32 = 0
	ZeroQuote uint32 = 0x80000000
	BTCToken  uint32 = 0x10000000
	ETHToken  uint32 = 0x20000000
)

// wallet type from bip44
const (
	// https://github.com/satoshilabs/slips/blob/master/slip-0044.md#registered-coin-types
	BTC  = ZeroQuote + 0
	LTC  = ZeroQuote + 2
	DOGE = ZeroQuote + 3
	DASH = ZeroQuote + 5
	DCR  = ZeroQuote + 42
	NEM  = ZeroQuote + 43

	ETH   = ZeroQuote + 60
	ETC   = ZeroQuote + 61
	QTUM  = ZeroQuote + 88
	ATOM  = ZeroQuote + 118
	XMR   = ZeroQuote + 128
	ZCash = ZeroQuote + 133
	XRP   = ZeroQuote + 144
	BCH   = ZeroQuote + 145
	BTM   = ZeroQuote + 153
	HC    = ZeroQuote + 171
	RVN   = ZeroQuote + 175
	XLM   = ZeroQuote + 184

	EOS  = ZeroQuote + 194
	TRX  = ZeroQuote + 195
	ALGO = ZeroQuote + 283
	CKB  = ZeroQuote + 309

	AE    = ZeroQuote + 457
	BNB   = ZeroQuote + 714
	VET   = ZeroQuote + 818
	NEO   = ZeroQuote + 888
	ONT   = ZeroQuote + 1024
	XTZ   = ZeroQuote + 1729
	Libra = ZeroQuote + 9999
	WAVES = ZeroQuote + 5741564
	// btc token
	USDT = BTCToken + 1

	// eth token
	IOST = ETHToken + 1
	USDC = ETHToken + 2
)

var coinTypes = map[uint32]uint32{
	USDT: BTC,
	IOST: ETH,
	USDC: ETH,
}
