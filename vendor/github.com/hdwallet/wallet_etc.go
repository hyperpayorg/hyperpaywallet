package hdwallet

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// 参考
// https://github.com/krboktv/blockchain-swiss-knife/blob/master/ethereumClassic/ethereumClassic.go

type ETCParams struct {
	Nonce int64
}

func init() {
	coins[ETC] = newETC
}

type etc struct {
	name   string
	symbol string
	key    *Key
}

func newETC(key *Key) Wallet {
	return &etc{
		name:   "Ethereum Classic",
		symbol: "ETC",
		key:    key,
	}
}

func (c *etc) GetType() uint32 {
	return c.key.opt.CoinType
}

func (c *etc) GetName() string {
	return c.name
}

func (c *etc) GetSymbol() string {
	return c.symbol
}

func (c *etc) GetKey() *Key {
	return c.key
}

func (c *etc) GetAddress() (string, error) {
	return crypto.PubkeyToAddress(*c.key.PublicECDSA).Hex(), nil
}
func (c *etc) GenerateTxHash(signIn *SignInput) (*TxHashResult, error) {
	return &TxHashResult{}, nil
}
func (c *etc) SignTxHash(signIn *SignTxHashInput) (*TxHashResult, error) {
	return &TxHashResult{}, nil
}

func (c *etc) CreateRawTransaction(signIn *SignInput) (*SignResult, error) {
	return &SignResult{
		Res: 0,
	}, nil
}

func (c *etc) SignRawTransaction(signIn *SignInput) (*SignResult, error) {

	var params ETCParams
	err := json.Unmarshal(signIn.Params, &params)
	if err != nil {
		fmt.Println("Parse Error: ", err)
		return nil, err
	}
	// fmt.Println("Nonce:", params.Nonce)

	privateKey, err := crypto.HexToECDSA(signIn.PrivateKey)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	toAddress := common.HexToAddress(signIn.DestAddr)
	amount := big.NewInt(signIn.Amount)     // in wei (1 eth)
	gasLimit := uint64(signIn.GasLimit)     // in units
	gasPrice := big.NewInt(signIn.GasPrice) // in wei (1 eth)

	var data []byte
	tx := types.NewTransaction(uint64(params.Nonce), toAddress, amount, gasLimit, gasPrice, data)

	// ETC 主网 ChainID = 61，见这里： https://chainid.network/   https://chainid.network/chains/
	chainID := big.NewInt(61)
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	ts := types.Transactions{signedTx}
	rawTxBytes := ts.GetRlp(0)
	rawTxHex := hex.EncodeToString(rawTxBytes)

	// fmt.Println("TxID 构造结果：", rawTxHex)
	// c.SendRawTx(rawTxHex) // Push
	return &SignResult{Res: 1, RawTX: rawTxHex}, nil
}

// func (c *etc) SendRawTx(rawTx string) {

// 	fmt.Println("开始上传交易ID")
// 	client, err := ethclient.Dial("https://ethereumclassic.network")
// 	if err != nil {
// 		fmt.Println("Client Error: ", err)
// 		return
// 	}

// 	rawTxBytes, err := hex.DecodeString(rawTx)
// 	tx := new(types.Transaction)
// 	rlp.DecodeBytes(rawTxBytes, &tx)
// 	err = client.SendTransaction(context.Background(), tx)

// 	if err != nil {
// 		fmt.Println("Send Error: ", err)
// 		return
// 	}
// 	fmt.Println("TX 发送结果: ", tx.Hash().Hex())
// }

func (c *etc) GetWalletAccount() *WalletAccount {
	if c.GetKey().Extended == nil {
		return &WalletAccount{
			Res: 0,
		}
	}
	address, err := c.GetAddress()
	if err != nil {
		return &WalletAccount{
			Res: 0,
		}
	}
	pri := crypto.FromECDSA(c.key.PrivateECDSA)
	pub := crypto.FromECDSAPub(c.key.PublicECDSA)

	return &WalletAccount{
		Res:        1,
		Address:    address,
		PrivateKey: hex.EncodeToString(pri),
		PublicKey:  hex.EncodeToString(pub),
		Seed:       c.GetKey().Seed,
	}
}
func (c *etc) GetWalletAccountFromWif() (*WalletAccount, error) {
	hexPri := c.GetKey().Wif
	if len(hexPri) > 0 {
		pri, err := crypto.HexToECDSA(hexPri)
		if err != nil {
			return nil, err
		}

		pub := crypto.FromECDSAPub(&pri.PublicKey)
		address := crypto.PubkeyToAddress(pri.PublicKey).Hex()
		return &WalletAccount{
			Res:        1,
			Address:    address,
			PrivateKey: hexPri,
			PublicKey:  hex.EncodeToString(pub),
		}, nil
	}
	return &WalletAccount{
		Res:        0,
		PrivateKey: hexPri,
	}, nil
}
