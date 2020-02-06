
# HPWalletCore
HPWalletCore is committed to building a simple and easy-to-use cross platform wallet library. It provides a unified API, which allows users to export private key, public key and address about BTC, ETH, ETC, LTC, DASH, DOGE, QTUM and USDT tokens. It provides corresponding methods to create raw sign transactions.

In addition, it is different from other third-party wallet schemes: when importing mnemonics or private keys, we choose to fill in the phone UDID and password attributes. Even if the mnemonics are leaked, it is difficult to steal your digital assets without your mobile phone or password, so as to ensure your digital assets are secure enough!

[中文版🇨🇳](https://github.com/hyperpayorg/hyperpaywallet/blob/master/README_CN.md)
# HPWalletCore Supports
Currently,HPWalletCore supports the mnemonics or importing private keys and creating raw sign transactions as follows:

|Coin|Mnemonics Support|PrivateKey Support|Transaction Support|Explore|Mark|
|:----:|:----:|:----:|:----:|:----:|:----:|
|BTC|✔️|✔️|✔️|[DecodeTx](https://live.blockcypher.com/btc/decodetx/)、[Broadcast](https://blockchair.com/broadcast)|
|BCH|✔️|✔️|✔️|[PushTx](https://bch.btc.com/16Lp3ZvcusRGtqy7DgF5gz6PGutvuEtwRt)|
|DASH|✔️|✔️|✔️|[Broadcast](https://insight.dash.org/insight/tx/send)、[DecodeTx](https://live.blockcypher.com/dash/decodetx/)|
|DOGE|✔️|✔️|✔️|[DecodeTx](https://live.blockcypher.com/doge/decodetx/)、[Broadcast](https://blockchair.com/broadcast)|
|ETH|✔️|✔️|✔️|[PushTx](https://etherscan.io/pushTx?%253Flang=zh-CN)、[Broadcast](https://badmofo.github.io/ethsend/)|Support ERC20|
|ETC|✔️|✔️|✔️|[PushTx](https://etherscan.io/pushTx?%253Flang=zh-CN)||
|LTC|✔️|✔️|✔️|[PushTx](https://bch.btc.com/16Lp3ZvcusRGtqy7DgF5gz6PGutvuEtwRt)|
|QTUM|✔️|✔️|✔️|[PushTx](https://qtum.info/misc/raw-tx)|Support QRC20|
|USDT|✔️|✔️|✔️|[DecodeTx](https://live.blockcypher.com/btc/decodetx/)、[Broadcast](https://blockchair.com/broadcast)|


<!-- |--|✔️|❌|❌| -->
## Installation

- [Go Environment Installation](https://www.runoob.com/go/go-environment.html)
- [Go&Gomobile Environment Construction](https://www.jianshu.com/p/d6d6af4cac4d)
- In the hpywallet directory, compile the Android Reference Library:`gomobile bind -target=android .`
- In the hpywallet directory, compile the iOS Reference Library:`gomobile bind -target=ios .`
- About the leaking librarys xxx  `go get xxx ..`


##  Mnemonics Generate Seed

Seed can be generated by 'importing' mnemonic & password.
Import mnemonics using the following methods:

```go
func GenerateSeed(mnemonic string, password string)
```

> Description of necessary parameters： mnemonic,   password 
Data structure returned, ` hex seed`
### GenerateSeed Example
```go
mnemonic := "xxx xxx"
seed := hpywallet.GenerateSeed(mnemonic, "")
fmt.Println("Seed = ", seed)
```

## Mnemonics Generate Wallet

Private key, public key and address can be generated by importing mnemonic.
Import mnemonics using the following methods:

```go
func GenerateWallet(mnemonic string, coin string)
```

> Description of necessary parameters: mnemonic,  coin
  
Data structure returned as follow：

```go
type WalletAccount struct {
	ResCode    int    // 0 fail 1 Success
	Address    string 
	PublicKey  string 
	PrivateKey string 
	Seed       string // root seed
	Coin       string 
	ErrMsg     string // fail messages
	ErrCode    int    // err code
	Params     []byte // reserved fields
}

```
### GenerateWallet Example
```go
mnemonic := "xxx xxx"
dogeWallet := hpywallet.GenerateWallet(mnemonic, "doge")
fmt.Println("dogeWallet: ", dogeWallet)
```
## Mnemonics & password Generate Wallet
Private key, public key and address can be generated by importing mnemonics & password.
Import mnemonics & password using the following methods:

```go
func GenerateMnemonicWallet(mnemonic, password, coin string)
```

>Description of necessary parameters: mnemonic, password,  coin
Data structure returned as `WalletAccount`

### GenerateMnemonicWallet Example
```go
mnemonic := "xxx xxx"
btcWallet := hpywallet.GenerateMnemonicWallet(mnemonic, "123456", "btc")
fmt.Println("btcWallet: ", btcWallet)
```
## Coin Root Seed Generate Wallet

Private key, public key and address can be generated by importing root seed & coin.
Import seed & coin using the following methods:


```go
func GenerateSeedWallet(seed string, coin string)
```
> Description of necessary parameters: Root Seed, coin
Data structure returned as `WalletAccount`
### GenerateSeedWallet Example
```go
mnemonic := "xxx xxx"
btcWallet := hpywallet.GenerateSeedWallet(seed, "btc")
fmt.Println("btcWallet: ", btcWallet)
```
## Import private key (WIF) to generate Wallet
Private key, public key and address can be generated by importing private key (WIF).

The following methods are used to create a wallet with a private key:

```go
func ImportPrivateWIF(wif string, coin string)
```
> Description of necessary parameters:PrivateKey (WIF),  coin

Data structure returned as `WalletAccount`。
### ImportPrivateWIF Example
```go
mnemonic := "xxx xxx"
dogeWallet := hpywallet.GenerateWallet(mnemonic, "doge")
importWallet := hpywallet.ImportPrivateWIF(dogeWallet.PrivateKey, "doge")
fmt.Println("importWallet: ", importWallet)
```
## Mnemonics Or PrivateKey Generate KeyStore
The keystore file is generated by  mnemonics or private keys, UDID of the device and password.

Generate keystore file, using the following methods:

```go
func EnKeystore(privateKey, password, udid string)
```

> Description of necessary parameters: mnemonic(privateKey), password , udid

Data structure returned as :

```go
type KeystoreResult struct {
	Result  string 
	ResCode int    // 0 fail 1 success
	ErrMsg  string // fail reason
}

```
### EnKeystore Example
```go
   privateKey := "L1oh9KNH4XpJgqDodxhjPgaEVS1qwXToWvPf2Zyn6bcm7xxxxxxx"
	pwd := "11111"
	udid := "AOIJF-QWEQR-VDFBET-YTAWWE"

	// Encode
	enResult := hpywallet.EnKeystore(privateKey, pwd, udid)
	fmt.Println("Keystore : \n", enResult.Result)
```
## KeyStore File Decrypt
The keystore file is decrypted by  json, udid  and password.

Decrypt keystore file, using the following methods:


```go
func DeKeystore(json, password, udid string)
```

> Description of necessary parameters:  KeyStore Json, password, udid

Data structure returned as `KeystoreResult`。

### DeKeystore Example
```go
   enResult := "xxxxxxx"
	pwd := "11111"
	udid := "AOIJF-QWEQR-VDFBET-YTAWWE"
  // Decode
	deResult := hpywallet.DeKeystore(enResult, pwd, udid)
	fmt.Println("PrivateKey : ", deResult.Result)
```
## Token Create Raw Sign Transaction

Build each token signature algorithm

**SignInput**  Some parameters can be selected.The data structure is as follows:

```go
type SignInput struct {
	PrivateKey   string 
	Coin         string 
	Symbol       string 
	Amount       int64  // transfer amount
	Change       int64  // transfer change amount
	Fee          int64  //transfer fee
	GasLimit     int64  
	GasPrice     int64  
	Type         string // contract type
	SrcAddr      string // send address
	DestAddr     string // destination address
	ContractAddr string // contract address
	Memo         string // memo mark
	Sequence     int64  
	Inputs       []byte // vins
	Params       []byte // reserved fields
}
```

签名方法名称：

```go
func SignRawTransaction(signIn *SignInput)
```

方法返回结构如下：

```go
type SignResult struct {
	ResCode int    // 0 fail 1 success
	Coin    string // chain token
	Symbol  string // symbol 
	RawTX   string //  rawtx
	TxHash  string // tx hash
	ErrMsg  string // fail reason
	ErrCode int    // err code

	Params []byte // reserved fields
}
```
### SignRawTransaction Example
```go
mnemonic := "xxx xxx"
btcWallet := hpywallet.GenerateWallet(mnemonic, "btc")
item1 := hpywallet.OutPutItem{
	TxHash:   "921784b1e11fcbfe267a04b9e54a45e597710d0f9413e658813737c06f44a987",
	Value:    1200000,
	Vout:     1,
	Pkscript: "76a914bc68c7efc2f672c3ea028e10ec321a9c68d5da7788ac",
}
outputs := []hpywallet.OutPutItem{item1}
jsonInputs, _ := json.Marshal(outputs)
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
```


In the currency of the signature algorithm, the main chain currency that the `Inputs` attribute must contain is:

- [x] BTC
- [x] USDT
- [x] LTC
- [x] QTUM
- [x] BCH
- [x] DASH

the `Inputs` attribute is `JsonArrayToByte[OutPutItem...].Bytes`

 The data structure about `OutPutItem`is as follows:

```go
type OutPutItem struct {
	TxHash   string 
	Vout     uint32
	Value    int64
	Pkscript string // lock script
}
```

Attention:

- About QRC20 Transaction: the `ContractAddr` attribute is a required parameter;

## TODO LIST

- [ ] Verify the token address
- [ ] Multi sign transaction
- [ ] More chains open source

## Thanks and more info.

Thanks `btcsuite`、`go-ethereum`、`blocktree` and others library.

[TOC]
