package hpywallet

import (
	"encoding/hex"
	"strings"

	"github.com/hdwallet"
	"github.com/hdwallet/go-bip39"
	"github.com/keystore"
)

var (
	// ## 已经支持的 BTC ETH ONT BCH LTC QTUM  HC
	coinMap = map[string]uint32{
		"eth":  hdwallet.ETH,
		"etc":  hdwallet.ETC,
		"btc":  hdwallet.BTC,
		"usdt": hdwallet.USDT,
		"ltc":  hdwallet.LTC,
		"bch":  hdwallet.BCH,
		"qtum": hdwallet.QTUM,
		"dash": hdwallet.DASH,
		"doge": hdwallet.DOGE,
	}
	feeMap = map[string]uint32{
		"hc": hdwallet.HC,
	}
)

func GenerateSeed(mnemonic string, password string) string {
	masterSeed := bip39.NewSeed(mnemonic, password)

	return hex.EncodeToString(masterSeed)
}

func GenerateSeedWallet(seed string, coin string) *WalletAccount {
	if coinType, ok := coinMap[strings.ToLower(coin)]; ok {
		seedByte, err := hex.DecodeString(seed)
		if err != nil {
			return &WalletAccount{
				ResCode: 0,
				Coin:    coin,
				ErrMsg:  err.Error(),
			}
		}
		master, err := hdwallet.NewKey(
			hdwallet.Seed(seedByte), hdwallet.CoinType(coinType),
		)
		if err != nil {
			return &WalletAccount{
				ResCode: 0,
				Coin:    coin,
				ErrMsg:  err.Error(),
			}
		}
		wallet, err := master.GetWallet(hdwallet.Seed(seedByte), hdwallet.CoinType(coinType))
		if err != nil {
			return &WalletAccount{
				ResCode: 0,
				ErrMsg:  err.Error(),
				Coin:    coin,
			}
		}
		acc := wallet.GetWalletAccount()
		return &WalletAccount{
			ResCode:    acc.Res,
			PrivateKey: acc.PrivateKey,
			Address:    acc.Address,
			PublicKey:  acc.PublicKey,
			Seed:       acc.Seed,
			ErrMsg:     acc.ErrMsg,
			Coin:       coin,
		}
	}
	return &WalletAccount{
		ResCode: 0,
		Coin:    coin,
		ErrMsg:  "Coin type is not supported!",
	}
}

func GenerateMnemonicWallet(mnemonic, password, coin string) *WalletAccount {

	if coinType, ok := coinMap[strings.ToLower(coin)]; ok {
		master, err := hdwallet.NewKey(
			hdwallet.Mnemonic(mnemonic), hdwallet.Password(password), hdwallet.CoinType(coinType),
		)
		seedByte, err := hex.DecodeString(master.Seed)
		if err != nil {
			return &WalletAccount{
				ResCode: 0,
				Coin:    coin,
				ErrMsg:  err.Error(),
			}
		}

		wallet, err := master.GetWallet(hdwallet.Seed(seedByte), hdwallet.CoinType(coinType))
		if err != nil {
			return &WalletAccount{
				ResCode: 0,
				ErrMsg:  err.Error(),
				Coin:    coin,
			}
		}
		acc := wallet.GetWalletAccount()
		return &WalletAccount{
			ResCode:    acc.Res,
			PrivateKey: acc.PrivateKey,
			Address:    acc.Address,
			PublicKey:  acc.PublicKey,
			ErrMsg:     acc.ErrMsg,
			Seed:       acc.Seed,
			Coin:       coin,
		}
	}
	return &WalletAccount{
		ResCode: 0,
		Coin:    coin,
		ErrMsg:  "Coin type is not supported!",
	}
}

func GenerateWallet(mnemonic string, coin string) *WalletAccount {

	if coinType, ok := coinMap[strings.ToLower(coin)]; ok {
		master, err := hdwallet.NewKey(
			hdwallet.Mnemonic(mnemonic), hdwallet.CoinType(coinType),
		)
		seedByte, err := hex.DecodeString(master.Seed)
		if err != nil {
			return &WalletAccount{
				ResCode: 0,
				Coin:    coin,
				ErrMsg:  err.Error(),
			}
		}
		wallet, err := master.GetWallet(hdwallet.Seed(seedByte), hdwallet.CoinType(coinType))
		if err != nil {
			return &WalletAccount{
				ResCode: 0,
				ErrMsg:  err.Error(),
				Coin:    coin,
			}
		}
		acc := wallet.GetWalletAccount()
		return &WalletAccount{
			ResCode:    acc.Res,
			PrivateKey: acc.PrivateKey,
			Address:    acc.Address,
			PublicKey:  acc.PublicKey,
			ErrMsg:     acc.ErrMsg,
			Seed:       acc.Seed,
			Coin:       coin,
		}
	}
	return &WalletAccount{
		ResCode: 0,
		Coin:    coin,
		ErrMsg:  "Coin type is not supported!",
	}
}

func ImportPrivateWIF(wif string, coin string) *WalletAccount {
	if coinType, ok := coinMap[strings.ToLower(coin)]; ok {
		acc, err := hdwallet.NewWalletFromWif(wif, coinType)
		if err != nil {
			return &WalletAccount{
				ResCode: 0,
				Coin:    coin,
				ErrMsg:  err.Error(),
			}
		}
		return &WalletAccount{
			ResCode:    acc.Res,
			PrivateKey: acc.PrivateKey,
			Address:    acc.Address,
			PublicKey:  acc.PublicKey,
			ErrMsg:     acc.ErrMsg,
			Coin:       coin,
		}
	}
	return &WalletAccount{
		ResCode: 0,
		Coin:    coin,
		ErrMsg:  "Coin type is not supported!",
	}
}

/*TODOList*/
func CheckCoinAddress(address string, coin string) bool {

	if coinType, ok := coinMap[strings.ToLower(coin)]; ok {
		switch coinType {
		case hdwallet.BTC:
			break
		default:
			break
		}
	}
	return true
}

func CreateRawTransaction(signIn *SignInput) *SignResult {
	if coinType, ok := coinMap[strings.ToLower(signIn.Coin)]; ok {
		switch coinType {
		case hdwallet.BTC:
			break
		default:
			break
		}
		signInput := &hdwallet.SignInput{
			Coin:       signIn.Coin,
			Symbol:     signIn.Symbol,
			PrivateKey: signIn.PrivateKey,

			Change:       signIn.Change,
			Fee:          signIn.Fee,
			SrcAddr:      signIn.SrcAddr,
			DestAddr:     signIn.DestAddr,
			ContractAddr: signIn.ContractAddr,
			Memo:         signIn.Memo,
			GasLimit:     signIn.GasLimit,
			GasPrice:     signIn.GasPrice,
			Sequence:     signIn.Sequence, // 序列号
			Amount:       signIn.Amount,
			Inputs:       signIn.Inputs,
			Params:       signIn.Params,
		}
		acc, err := hdwallet.CreateRawTransaction(signInput, coinType)
		if err != nil {
			return &SignResult{
				ResCode: 0,
				Coin:    signIn.Coin,
				Symbol:  signIn.Symbol,
				ErrMsg:  err.Error(),
			}
		}
		return &SignResult{
			ResCode: acc.Res,
			Coin:    signIn.Coin,
			Symbol:  signIn.Symbol,
			RawTX:   acc.RawTX,
			TxHash:  acc.TxHash,
			ErrMsg:  acc.ErrMsg,
			Params:  acc.Params,
		}
	}
	return &SignResult{
		ResCode: 0,
		Coin:    signIn.Coin,
		Symbol:  signIn.Symbol,
		ErrMsg:  "Coin type is not supported!",
	}
}
func SignRawTransaction(signIn *SignInput) *SignResult {

	if coinType, ok := coinMap[strings.ToLower(signIn.Coin)]; ok {
		switch coinType {
		case hdwallet.BTC:
			break
		default:
			break
		}
		signInput := &hdwallet.SignInput{
			Coin:         signIn.Coin,
			Symbol:       signIn.Symbol,
			PrivateKey:   signIn.PrivateKey,
			Type:         signIn.Type,
			Change:       signIn.Change,
			Fee:          signIn.Fee,
			SrcAddr:      signIn.SrcAddr,
			DestAddr:     signIn.DestAddr,
			ContractAddr: signIn.ContractAddr,
			Memo:         signIn.Memo,
			GasLimit:     signIn.GasLimit,
			GasPrice:     signIn.GasPrice,
			Amount:       signIn.Amount,
			Sequence:     signIn.Sequence, // 序列号
			Inputs:       signIn.Inputs,
			Params:       signIn.Params,
		}
		acc, err := hdwallet.SignRawTransaction(signInput, coinType)
		if err != nil {
			return &SignResult{
				ResCode: 0,
				Coin:    signIn.Coin,
				Symbol:  signIn.Symbol,
				ErrMsg:  err.Error(),
			}
		}
		return &SignResult{
			ResCode: acc.Res,
			Coin:    signIn.Coin,
			Symbol:  signIn.Symbol,
			RawTX:   acc.RawTX,
			TxHash:  acc.TxHash,
			ErrMsg:  acc.ErrMsg,
			Params:  acc.Params,
		}
	}
	return &SignResult{
		ResCode: 0,
		Coin:    signIn.Coin,
		Symbol:  signIn.Symbol,
		ErrMsg:  "Coin type is not supported!",
	}
}

// EnKeystore 用于将私钥和 `密码 + udid` 加密得到 keystore json 数据。
func EnKeystore(privateKey, password, udid string) *KeystoreResult {

	result, err := keystore.EncryptKey(privateKey, password, udid)
	if err != nil {
		return &KeystoreResult{ResCode: 0, ErrMsg: err.Error()}
	}
	return &KeystoreResult{ResCode: 1, Result: result}
}

// DeKeystore 用于将 keystore json 数据通过 `密码 + udid` 解密得到私钥。
func DeKeystore(json, password, udid string) *KeystoreResult {
	result, err := keystore.DecryptKey(json, password, udid)
	if err != nil {
		return &KeystoreResult{ResCode: 0, ErrMsg: err.Error()}
	}
	return &KeystoreResult{ResCode: 1, Result: result}
}
