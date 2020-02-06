package hdwallet

import (
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
)

func init() {
	coins[ETH] = newETH
}

type eth struct {
	name   string
	symbol string
	key    *Key

	// eth token
	contract string
}

func newETH(key *Key) Wallet {
	return &eth{
		name:   "Ethereum",
		symbol: "ETH",
		key:    key,
	}
}

func (c *eth) GetType() uint32 {
	return c.key.opt.CoinType
}

func (c *eth) GetName() string {
	return c.name
}

func (c *eth) GetSymbol() string {
	return c.symbol
}

func (c *eth) GetKey() *Key {
	return c.key
}

func (c *eth) GetAddress() (string, error) {
	return crypto.PubkeyToAddress(*c.key.PublicECDSA).Hex(), nil
}
func (c *eth) GenerateTxHash(signIn *SignInput) (*TxHashResult, error) {
	return &TxHashResult{}, nil
}
func (c *eth) SignTxHash(signIn *SignTxHashInput) (*TxHashResult, error) {
	return &TxHashResult{}, nil
}

func (c *eth) CreateRawTransaction(signIn *SignInput) (*SignResult, error) {
	return &SignResult{
		Res: 0,
	}, nil
}

func (c *eth) GetNonce(privateKey string) (uint64, error) {

	hashPrivKey, err := crypto.HexToECDSA(privateKey)
	if err != nil {
		return 0, err
	}

	publicKey := hashPrivKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return 0, errors.New("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	}

	client, err := ethclient.Dial("https://mainnet.infura.io")
	if err != nil {
		fmt.Println("fetch Client failed：", err)
		return 0, err
	}
	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
	if err == nil {
		return nonce, nil
	}
	return 0, err
}

func (c *eth) SignRawTransaction(signIn *SignInput) (*SignResult, error) {
	privkey := signIn.PrivateKey
	toAddr := signIn.DestAddr

	nonce, err := c.GetNonce(privkey)
	if err != nil {
		return nil, err
	}

	fmt.Println("Get Nonce: ", nonce)

	amount := big.NewInt(signIn.Amount)
	gasLimit := uint64(signIn.GasLimit)
	gasPrice := big.NewInt(signIn.GasPrice)

	// gasPrice, err := client.SuggestGasPrice(context.Background())
	// if err != nil {
	// 	log.Fatal("获取Gas出错：", err)
	// }
	// fmt.Println("GasPrice: ", gasPrice)
	key, err := crypto.HexToECDSA(privkey)
	if err != nil {
		return nil, err
	}
	to := common.HexToAddress(toAddr)
	tx := types.NewTransaction(nonce, to, amount, gasLimit, gasPrice, nil)

	// 其中签名有两种算法
	// types.NewEIP155Signer(big.NewInt(chainId))
	// types.HomesteadSigner{}
	// 第二种不需要提供 chainId 但是据说不稳定，types.NewEIP155Signer(big.NewInt(4) 4 是 rinkeby 测试网络，1是主网
	// signature, _ := types.SignTx(tx, types.HomesteadSigner{}, key)
	signature, err := types.SignTx(tx, types.NewEIP155Signer(big.NewInt(1)), key)
	if err != nil {
		return nil, err
	}

	ts := types.Transactions{signature}
	rawTx := fmt.Sprintf("%x", ts.GetRlp(0))
	// client := ethConnect("https://mainnet.infura.io")
	// err := client.SendTransaction(context.Background(), signature)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	fmt.Println("TxID 构造结果：", rawTx)
	return &SignResult{Res: 1, RawTX: rawTx}, nil
}

func (c *eth) GetWalletAccount() *WalletAccount {
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
	// fmt.Println("pk : ", hex.EncodeToString(pub))
	// fmt.Println("pri hex : ", hex.EncodeToString(pri))

	return &WalletAccount{
		Res:        1,
		Address:    address,
		PrivateKey: hex.EncodeToString(pri),
		PublicKey:  hex.EncodeToString(pub),
		Seed:       c.GetKey().Seed,
	}
}
func (c *eth) GetWalletAccountFromWif() (*WalletAccount, error) {
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
