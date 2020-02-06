package hpywallet_test

import (
	"HPWalletCommon/hpywallet"
	"encoding/json"
	"fmt"
	"testing"
)

var (
	testmnemonic = "hint fatigue scale tired venture regular vicious echo satoshi gun cash spy"
	mnemonic     = "zero guard grass mandate invest anger actress moral gasp easy way student"
)

func TestGenerateSeed(t *testing.T) {
	seed := hpywallet.GenerateSeed(mnemonic, "")
	fmt.Println("Seed1 = ", seed)
	seed1 := hpywallet.GenerateSeed(mnemonic, "123")

	fmt.Println("Seed2 = ", seed1)
	wallet1 := hpywallet.GenerateSeedWallet(seed, "btc")
	wallet2 := hpywallet.GenerateSeedWallet(seed1, "btc")
	fmt.Println("Wallet1 = ", wallet1)
	fmt.Println("Wallet2 = ", wallet2)

	wallet3 := hpywallet.GenerateMnemonicWallet(mnemonic, "123456", "btc")
	wallet4 := hpywallet.GenerateMnemonicWallet(mnemonic, "12345", "btc")

	fmt.Println("Wallet3 = ", wallet3)
	fmt.Println("Wallet4 = ", wallet4)

}

func TestKeystore(t *testing.T) {
	privateKey := "KxkUeg9G2ghaZHewELhjuDUtKtnbtP95pH3g8Siswvu5uNxxFPRc"
	pwd := "11111"
	udid := "AOIJF-QWEQR-VDFBET-YTAWWE"

	// Encode
	enResult := hpywallet.EnKeystore(privateKey, pwd, udid)
	if enResult.ResCode != 1 {
		fmt.Println("Error: ", enResult.ErrMsg)
		return
	}
	fmt.Println("Keystore : \n", enResult.Result)

	fmt.Println("************************************************")
	// Decode
	deResult := hpywallet.DeKeystore(enResult.Result, pwd, udid)
	if deResult.ResCode != 1 {
		fmt.Println("Error: ", deResult.ErrMsg)
		return
	}
	fmt.Println("PrivateKey : ", deResult.Result)

}

func TestCreateDoge(t *testing.T) {
	dogeWallet := hpywallet.GenerateWallet(mnemonic, "doge")
	toWallet := hpywallet.GenerateWallet(testmnemonic, "doge")
	importWallet := hpywallet.ImportPrivateWIF(dogeWallet.PrivateKey, "doge")

	fmt.Println("dogeWallet: ", dogeWallet)
	fmt.Println("toWallet: ", toWallet)
	fmt.Println("importWallet: ", importWallet)

	// need utxo
	signInput := &hpywallet.SignInput{
		Coin:       "doge",
		Symbol:     "doge",
		PrivateKey: dogeWallet.PrivateKey,
		SrcAddr:    dogeWallet.Address,
		DestAddr:   toWallet.Address,
		Fee:        10000,
		Amount:     2000000000,
	}

	tranferResult := hpywallet.SignRawTransaction(signInput)
	if tranferResult.ResCode == 0 {
		fmt.Println("Fail! Transfer doge Msg: ", tranferResult.ErrMsg)
	} else {
		fmt.Println("Success! Transfer doge RawTX: ", tranferResult.RawTX)
	}

	// https://dogechain.info/address/DNzF31pAuNjofu27ukV3NjWCcy6uB9haFR
	// https://dogechain.info/api/v1/unspent/DNzF31pAuNjofu27ukV3NjWCcy6uB9haFR?nsukey=ANpE25lxuDndL1c%2BTKD4rJcpG58RT9EkO6FB%2FNh1xAJNDX8coA8WdflJ%2BQgp%2FkUwYxiA1aTajX0b67nYpihZI7%2BaMoR4s7oS5VW8pbOQ4ky3MMDyy%2BJ9yFyGTeFLZcdsG6yzmoXTk4V6hYZEBY9zJLe3xgle76BdIzLyIfZ%2FKLB097prwUVV6QEk3sv%2BWH3iYylvxma%2BwPFMN2YGZZSR2Q%3D%3D
}

func TestCreateDASH(t *testing.T) {
	wallet := hpywallet.GenerateWallet(mnemonic, "dash") //
	toWallet := hpywallet.GenerateWallet(testmnemonic, "dash")
	// importWallet := hpywallet.ImportPrivateWIF(wallet.PrivateKey, "dash")

	fmt.Println("DASH Wallet: ", wallet)
	fmt.Println("toWallet: ", toWallet)

	fmt.Println("From PrivateKey：", wallet.PrivateKey)

	fmt.Println("To Address：", toWallet.Address)

	item1 := hpywallet.OutPutItem{
		TxHash:   "f620269227d91079cc1c499047b5cfd9c4a0ec6c3ddf220e20dd5761a9c26b7c",
		Value:    1000000,
		Vout:     0,
		Pkscript: "76a91426739443ce47332bb1d21cd8eae9039da3f9602e88ac",
	}

	outputs := []hpywallet.OutPutItem{item1}
	// fmt.Println("ltc outputs: ", outputs)

	jsonInputs, err := json.Marshal(outputs)
	if err != nil {
		fmt.Println("outputs err: ", err.Error())
	}

	signInput := &hpywallet.SignInput{
		Coin:       "dash",
		Symbol:     "dash",
		PrivateKey: wallet.PrivateKey,
		SrcAddr:    wallet.Address,
		DestAddr:   toWallet.Address,
		Change:     11000,
		Amount:     10000,
		Inputs:     jsonInputs,
	}
	// fmt.Println("Transfer dash signInput: ", signInput)
	tranferResult := hpywallet.SignRawTransaction(signInput)
	if tranferResult.ResCode == 0 {
		fmt.Println("错误 Transfer dash Msg: ", tranferResult.ErrMsg)
	} else {
		fmt.Println("成功 Transfer dash RawTX: ", tranferResult.RawTX)
	}

	//  https://chainz.cryptoid.info/dash/address.dws?XhqADVUCcqN93C92JToCerMnqWTAZdTgoM.htm
	//  https://explorer.dash.org/chain/Dash
	//  https://www.thepolyglotdeveloper.com/2018/03/create-bitcoin-hardware-wallet-golang-raspberry-pi-zero/

}

func Test_TransferBCH(t *testing.T) {
	wallet := hpywallet.GenerateWallet(mnemonic, "bch") //

	hpwallet := hpywallet.ImportPrivateWIF(wallet.PrivateKey, "bch")
	fmt.Println("bch Address: ", hpwallet.Address)
	fmt.Println("bch Wif: ", hpwallet.PrivateKey)
	item1 := hpywallet.OutPutItem{
		TxHash:   "b211224d3a773dd7566ba2c221125547df3bbb011c7626021ab5e9f6de7fc112",
		Value:    1890000,
		Vout:     1,
		Pkscript: "76a9143a97cd827522fd88d97ee1b44eaa0ed37cb0585b88ac",
	}

	item2 := hpywallet.OutPutItem{
		TxHash:   "b211224d3a773dd7566ba2c221125547df3bbb011c7626021ab5e9f6de7fc112",
		Value:    10000,
		Vout:     0,
		Pkscript: "76a9143a97cd827522fd88d97ee1b44eaa0ed37cb0585b88ac",
	}

	item3 := hpywallet.OutPutItem{
		TxHash:   "c02179b60aefeed32fe003ddc699f2e9aeaf2c8d8d495fa0cbc0d5f04b8fea49",
		Value:    10000,
		Vout:     0,
		Pkscript: "76a9143a97cd827522fd88d97ee1b44eaa0ed37cb0585b88ac",
	}

	outputs := []hpywallet.OutPutItem{item1, item2, item3}
	// fmt.Println("ltc outputs: ", outputs)

	jsonInputs, err := json.Marshal(outputs)
	if err != nil {
		//log.Fatal("Cannot encode to JSON ", err)
		fmt.Println("outputs err: ", err.Error())

	}
	// fmt.Println("ltc outputs: ", jsonInputs)

	signInput := &hpywallet.SignInput{
		Coin:       "bch",
		Symbol:     "bch",
		PrivateKey: wallet.PrivateKey,
		SrcAddr:    "16Lp3ZvcusRGtqy7DgF5gz6PGutvuEtwRt",
		DestAddr:   "16Lp3ZvcusRGtqy7DgF5gz6PGutvuEtwRt",
		Amount:     900000,
		Change:     1000000,
		Inputs:     jsonInputs,
	}
	tranferResult := hpywallet.SignRawTransaction(signInput)
	if tranferResult.ResCode == 0 {
		fmt.Println("Transfer bch Msg: ", tranferResult.ErrMsg)
	} else {
		fmt.Println("Transfer bch RawTX: ", tranferResult.RawTX)
	}

}

func Test_TransferQTUMQRC20(t *testing.T) {
	qtumWallet := hpywallet.GenerateWallet(mnemonic, "qtum")
	item1 := hpywallet.OutPutItem{
		TxHash:   "c774983ae03dd2fd3d29022899ba9d26ae7792ae0b939e1909b6389b261fc109",
		Value:    43000000,
		Vout:     1,
		Pkscript: "76a914507d2234de017230c7cd4e9971c13496bde771c488ac",
	}

	outputs := []hpywallet.OutPutItem{item1}
	// fmt.Println("ltc outputs: ", outputs)

	jsonInputs, err := json.Marshal(outputs)
	if err != nil {
		//log.Fatal("Cannot encode to JSON ", err)
		fmt.Println("outputs err: ", err.Error())

	}
	// fmt.Println("ltc outputs: ", jsonInputs)

	signInput := &hpywallet.SignInput{
		Coin:         "qtum",
		Symbol:       "hpy",
		PrivateKey:   qtumWallet.PrivateKey,
		SrcAddr:      qtumWallet.Address,
		DestAddr:     "QTa3opXhHQSD1kwJmHiFS2TY3DV1RPPP4n",
		Fee:          10000000,
		Amount:       1000000,
		Change:       33000000,
		ContractAddr: "f2703e93f87b846a7aacec1247beaec1c583daa4",
		Inputs:       jsonInputs,
	}
	tranferResult := hpywallet.SignRawTransaction(signInput)
	if tranferResult.ResCode == 0 {
		fmt.Println("Transfer qtum Msg: ", tranferResult.ErrMsg)
	} else {
		fmt.Println("Transfer qtum RawTX: ", tranferResult.RawTX)
	}

}
func Test_TransferBTC(t *testing.T) {
	btcWallet := hpywallet.GenerateWallet(mnemonic, "btc")
	fmt.Println("btc Address: ", btcWallet.Address)
	fmt.Println("btc Wif: ", btcWallet.PrivateKey)
	// fmt.Println("ltc PublicKey: ", hcWallet.PublicKey)
	item1 := hpywallet.OutPutItem{
		TxHash:   "921784b1e11fcbfe267a04b9e54a45e597710d0f9413e658813737c06f44a987",
		Value:    1200000,
		Vout:     1,
		Pkscript: "76a914bc68c7efc2f672c3ea028e10ec321a9c68d5da7788ac",
	}
	item2 := hpywallet.OutPutItem{
		TxHash:   "62409f73492acc32aa7760423e56127f78f62745f07a68c4107ea69394dce485",
		Value:    400000,
		Vout:     1,
		Pkscript: "76a914bc68c7efc2f672c3ea028e10ec321a9c68d5da7788ac",
	}
	item3 := hpywallet.OutPutItem{
		TxHash:   "b886364bf351ac4ae47e4eea8ab4e1039c4fd92fed04899bb360d0570a0f92a2",
		Value:    100000,
		Vout:     0,
		Pkscript: "76a914bc68c7efc2f672c3ea028e10ec321a9c68d5da7788ac",
	}
	item4 := hpywallet.OutPutItem{
		TxHash:   "ca2695a680d6e7bea7dc5155f9cbe13f3b230a648dd48135ff5b090ae9c89194",
		Value:    100000,
		Vout:     1,
		Pkscript: "76a914bc68c7efc2f672c3ea028e10ec321a9c68d5da7788ac",
	}
	item5 := hpywallet.OutPutItem{
		TxHash:   "761faedb198081b97478ae3bc6f85deefc43ab5d1e116fe2a83ff33bd9dbea14",
		Value:    15500000,
		Vout:     1,
		Pkscript: "76a914bc68c7efc2f672c3ea028e10ec321a9c68d5da7788ac",
	}
	outputs := []hpywallet.OutPutItem{item1, item2, item3, item4, item5}
	// fmt.Println("ltc outputs: ", outputs)

	jsonInputs, err := json.Marshal(outputs)
	if err != nil {
		//log.Fatal("Cannot encode to JSON ", err)
		fmt.Println("outputs err: ", err.Error())

	}
	// fmt.Println("ltc outputs: ", jsonInputs)

	signInput := &hpywallet.SignInput{
		Coin:       "btc",
		Symbol:     "btc",
		PrivateKey: btcWallet.PrivateKey,
		SrcAddr:    btcWallet.Address,
		DestAddr:   btcWallet.Address,
		Fee:        200000,
		Amount:     100000,
		Change:     900000,
		Inputs:     jsonInputs,
	}
	tranferResult := hpywallet.SignRawTransaction(signInput)
	if tranferResult.ResCode == 0 {
		fmt.Println("Transfer btc Msg: ", tranferResult.ErrMsg)
	} else {
		fmt.Println("Transfer btc RawTX: ", tranferResult.RawTX)
	}

}

func Test_TransferUSDT(t *testing.T) {
	wallet := hpywallet.GenerateWallet(mnemonic, "usdt")
	usdtWallet := hpywallet.ImportPrivateWIF(wallet.PrivateKey, "usdt")
	fmt.Println("usdt : ", wallet)
	fmt.Println("usdtWallet : ", usdtWallet)
	item1 := hpywallet.OutPutItem{
		TxHash:   "0f90f5e98cfbcbeb23e84e9275540d853aa062630ae8b2a30ac5f1308a30fe14",
		Value:    40172,
		Vout:     1,
		Pkscript: "76a914ccfbd451e79ed9dc55356179548f18fa95c500f288ac",
	}
	// item2 := hpywallet.OutPutItem{
	// 	TxHash:   "42d8fa535fd889abe51efe633882cf4399e1f39ea346fd98967b9af9da8f9754",
	// 	Value:    546,
	// 	Vout:     2,
	// 	Pkscript: "76a9149d5fb37c2ac97ec80bcacba917cb4fccfca9f1ea88ac",
	// }
	outputs := []hpywallet.OutPutItem{item1}
	// fmt.Println("ltc outputs: ", outputs)

	jsonInputs, err := json.Marshal(outputs)
	if err != nil {
		//log.Fatal("Cannot encode to JSON ", err)
		fmt.Println("outputs err: ", err.Error())

	}
	// fmt.Println("ltc outputs: ", jsonInputs)

	signInput := &hpywallet.SignInput{
		Coin:       "usdt",
		Symbol:     "usdt",
		PrivateKey: wallet.PrivateKey,
		SrcAddr:    wallet.Address,
		DestAddr:   "1FQ6Sv1yDi6AnC8n8BQnLLNAaQ1esGT5oN",
		Fee:        2000,
		Amount:     10000,
		Change:     40172 - 1000 - 2000,
		Inputs:     jsonInputs,
	}
	tranferResult := hpywallet.SignRawTransaction(signInput)
	if tranferResult.ResCode == 0 {
		fmt.Println("Transfer USDT Msg: ", tranferResult.ErrMsg)
	} else {
		fmt.Println("Transfer USDT RawTX: ", tranferResult.RawTX)
	}

}

func Test_TransferLTC(t *testing.T) {
	ltcWallet := hpywallet.GenerateWallet(mnemonic, "ltc")
	// fmt.Println("ltc Address: ", ltcWallet.Address)
	// fmt.Println("ltc Wif: ", ltcWallet.PrivateKey)
	// fmt.Println("ltc PublicKey: ", ltcWallet.PublicKey)
	item1 := hpywallet.OutPutItem{
		TxHash:   "921784b1e11fcbfe267a04b9e54a45e597710d0f9413e658813737c06f44a987",
		Value:    1200000,
		Vout:     1,
		Pkscript: "76a914bc68c7efc2f672c3ea028e10ec321a9c68d5da7788ac",
	}
	item2 := hpywallet.OutPutItem{
		TxHash:   "62409f73492acc32aa7760423e56127f78f62745f07a68c4107ea69394dce485",
		Value:    400000,
		Vout:     1,
		Pkscript: "76a914bc68c7efc2f672c3ea028e10ec321a9c68d5da7788ac",
	}
	item3 := hpywallet.OutPutItem{
		TxHash:   "b886364bf351ac4ae47e4eea8ab4e1039c4fd92fed04899bb360d0570a0f92a2",
		Value:    100000,
		Vout:     0,
		Pkscript: "76a914bc68c7efc2f672c3ea028e10ec321a9c68d5da7788ac",
	}
	item4 := hpywallet.OutPutItem{
		TxHash:   "ca2695a680d6e7bea7dc5155f9cbe13f3b230a648dd48135ff5b090ae9c89194",
		Value:    100000,
		Vout:     1,
		Pkscript: "76a914bc68c7efc2f672c3ea028e10ec321a9c68d5da7788ac",
	}
	item5 := hpywallet.OutPutItem{
		TxHash:   "761faedb198081b97478ae3bc6f85deefc43ab5d1e116fe2a83ff33bd9dbea14",
		Value:    15500000,
		Vout:     1,
		Pkscript: "76a914bc68c7efc2f672c3ea028e10ec321a9c68d5da7788ac",
	}
	outputs := []hpywallet.OutPutItem{item1, item2, item3, item4, item5}
	// fmt.Println("ltc outputs: ", outputs)

	jsonInputs, err := json.Marshal(outputs)
	if err != nil {
		//log.Fatal("Cannot encode to JSON ", err)
		fmt.Println("outputs err: ", err.Error())

	}
	// fmt.Println("ltc outputs: ", jsonInputs)

	signInput := &hpywallet.SignInput{
		Coin:       "ltc",
		Symbol:     "ltc",
		PrivateKey: ltcWallet.PrivateKey,
		SrcAddr:    ltcWallet.Address,
		DestAddr:   "LezCFqxL7NHKzAKiuwzE12QyNsF6rTe3rU",
		Fee:        200000,
		Amount:     100000,
		Change:     900000,
		Inputs:     jsonInputs,
	}
	tranferResult := hpywallet.SignRawTransaction(signInput)
	if tranferResult.ResCode == 0 {
		fmt.Println("Transfer ltc Msg: ", tranferResult.ErrMsg)
	} else {
		fmt.Println("Transfer ltc RawTX: ", tranferResult.RawTX)
	}
}

func Test_importBCH(t *testing.T) {
	bchWallet := hpywallet.GenerateWallet(mnemonic, "btc")
	fmt.Println("bch Address: ", bchWallet.Address)
	fmt.Println("bch Wif: ", bchWallet.PrivateKey)

	fmt.Println("bch PublicKey: ", bchWallet.PublicKey)

	importWallet := hpywallet.ImportPrivateWIF(bchWallet.PrivateKey, "bch")
	if importWallet.ResCode == 0 {
		fmt.Println("import bch Msg: ", importWallet.ErrMsg)
	} else {
		fmt.Println("import bch Address: ", importWallet.Address)
	}

}

func Test_importETH(t *testing.T) {
	ethWallet := hpywallet.GenerateWallet(testmnemonic, "eth")
	fmt.Println("eth Address: ", ethWallet.Address)

	destWallet := hpywallet.GenerateWallet(mnemonic, "eth")
	fmt.Println("收方地址：", destWallet.Address)

	signInput := &hpywallet.SignInput{
		Coin:       "eth",
		Symbol:     "eth",
		PrivateKey: ethWallet.PrivateKey,
		SrcAddr:    ethWallet.Address,
		DestAddr:   destWallet.Address,
		Amount:     10000000000000, //
		GasLimit:   25200,
		GasPrice:   20000000000,
	}

	tranferResult := hpywallet.SignRawTransaction(signInput)
	fmt.Println("ETH rawTx ", tranferResult.RawTX)

}

func Test_importETC(t *testing.T) {
	etcWallet := hpywallet.GenerateWallet(testmnemonic, "etc") // 0x95573e2ffD61A6c5e08Fc321A7e8754f41b6C471
	fmt.Println("etc Wallet: ", etcWallet)
	// importWallet := hpywallet.ImportPrivateWIF(etcWallet.PrivateKey, "etc")
	// fmt.Println("导入钱包：", importWallet)
	destWallet := hpywallet.GenerateWallet(mnemonic, "etc")
	fmt.Println("To Wallet：", destWallet)

	param := hpywallet.ETCParams{Nonce: 7} // Nonce 接口获取，每次取值为上次交易的 nonce+1
	jsonParam, err := json.Marshal(param)
	if err != nil {
		fmt.Println("jsonParam err: ", err.Error())
	}

	signInput := &hpywallet.SignInput{
		Coin:       "etc",
		Symbol:     "etc",
		PrivateKey: etcWallet.PrivateKey,
		SrcAddr:    etcWallet.Address,
		DestAddr:   destWallet.Address,
		Amount:     1e18 * 0.007, //
		GasLimit:   25200,
		GasPrice:   2e10, // 1 0025 2000 0000 0000
		Params:     jsonParam,
	}

	tranferResult := hpywallet.SignRawTransaction(signInput)
	fmt.Println("ETC 构造结果：", tranferResult)

	// https://gastracker.io/addr/0x95573e2ffd61a6c5e08fc321a7e8754f41b6c471
	// https://etherscan.io/pushTx?%3flang=zh-CN

	//ETC交易hash 等待结果 0xa97c24efe6abc6efc0e8ca7fbe44df830899420764b2180d1de3d0e1975eec0e
	// f86709808262709495573e2ffd61a6c5e08fc321a7e8754f41b6c471872386f26fc1000080819ea02ee84a3079b5ecbc97c30f8e2dbe06e4df4607ad42bfa0bb21e769a3a50eb775a063ec17d76f60198a3086f20b9d42e3163dda913bb2cd226d7912073d3c5a814f

}

func Test_importQTUM(t *testing.T) {
	hcWallet := hpywallet.GenerateWallet(mnemonic, "qtum")
	fmt.Println("qtum Address: ", hcWallet.Address)
	fmt.Println("qtum Wif: ", hcWallet.PrivateKey)

	fmt.Println("qtum PublicKey: ", hcWallet.PublicKey)

	importWallet := hpywallet.ImportPrivateWIF(hcWallet.PrivateKey, "qtum")
	if importWallet.ResCode == 0 {
		fmt.Println("import qtum Msg: ", importWallet.ErrMsg)
	} else {
		fmt.Println("import qtum Address: ", importWallet.Address)
	}

}

func Test_importLTC(t *testing.T) {
	ltcWallet := hpywallet.GenerateWallet(mnemonic, "ltc")
	fmt.Println("ltc Address: ", ltcWallet.Address)
	fmt.Println("ltc Wif: ", ltcWallet.PrivateKey)

	fmt.Println("ltc PublicKey: ", ltcWallet.PublicKey)

	importWallet := hpywallet.ImportPrivateWIF(ltcWallet.PrivateKey, "ltc")
	if importWallet.ResCode == 0 {
		fmt.Println("import ltc Msg: ", importWallet.ErrMsg)
	} else {
		fmt.Println("import ltc Address: ", importWallet.Address)
	}

}
