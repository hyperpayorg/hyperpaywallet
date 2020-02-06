
# HPWalletCore
HPWalletCore 致力于打造一款简单易用的跨平台钱包库。 它提供了统一的API,允许使用者在BTC、ETH、ETC、LTC、DASH、DOGE、QTUM、USDT代币上导出私钥、公钥和地址,并提供相应构造交易的方法。
另外,区别于其他第三方钱包方案:我们在导入助记词、私钥时,选填了手机UDID以及密码属性。即便是助记词遭遇泄漏,在没有您的手机或密码情况下,也难以盗取您的数字资产,确保您的数字资产足够安全!

# HPWalletCore Supports

当前 HPWalletCore 所支持的助记词/私钥导入和构造交易签名如下所示：

|币种名称|助记词导入|私钥导入|交易签名|构造交易查询|备注|
|:----:|:----:|:----:|:----:|:----:|:----:|
|BTC|✔️|✔️|✔️|[DecodeTx](https://live.blockcypher.com/btc/decodetx/)、[Broadcast](https://blockchair.com/broadcast)|
|BCH|✔️|✔️|✔️|[PushTx](https://bch.btc.com/16Lp3ZvcusRGtqy7DgF5gz6PGutvuEtwRt)|
|DASH|✔️|✔️|✔️|[Broadcast](https://insight.dash.org/insight/tx/send)、[DecodeTx](https://live.blockcypher.com/dash/decodetx/)|
|DOGE|✔️|✔️|✔️|[DecodeTx](https://live.blockcypher.com/doge/decodetx/)、[Broadcast](https://blockchair.com/broadcast)|
|ETH|✔️|✔️|✔️|[PushTx](https://etherscan.io/pushTx?%253Flang=zh-CN)、[Broadcast](https://badmofo.github.io/ethsend/)|支持ERC20|
|ETC|✔️|✔️|✔️|[PushTx](https://etherscan.io/pushTx?%253Flang=zh-CN)||
|LTC|✔️|✔️|✔️|[PushTx](https://bch.btc.com/16Lp3ZvcusRGtqy7DgF5gz6PGutvuEtwRt)|
|QTUM|✔️|✔️|✔️|[PushTx](https://qtum.info/misc/raw-tx)|支持QRC20|
|USDT|✔️|✔️|✔️|[DecodeTx](https://live.blockcypher.com/btc/decodetx/)、[Broadcast](https://blockchair.com/broadcast)|


<!-- |--|✔️|❌|❌| -->
## 环境安装
- [Go 语言环境安装](https://www.runoob.com/go/go-environment.html)
- [Go&Gomobile 环境搭建](https://www.jianshu.com/p/d6d6af4cac4d)
- 在 hpywallet 目录下,编译 Android 引用库:`gomobile bind -target=android .`
- 在 hpywallet 目录下,编译 iOS 引用库:`gomobile bind -target=ios .`
- 对于存在可能缺少的类库xxx  `go get xxx 即可`


## 根 Seed 生成方法

通过 `导入` 助记词&密码 可以产生 Seed。

导入助记词使用以下方法：

```go
func GenerateSeed(mnemonic string, password string)
```

> 必要参数说明：助记词 mnemonic,   password 密码

创建返回的数据结构, `十六进制 Seed`
### GenerateSeed Example
```go
mnemonic := "xxx xxx"
seed := hpywallet.GenerateSeed(mnemonic, "")
fmt.Println("Seed = ", seed)
```
## 助记词生成钱包

通过 `导入`助记词可以产生 私钥、公钥、地址。

导入助记词使用以下方法：

```go
func GenerateWallet(mnemonic string, coin string)
```

> 必要参数说明：助记词 mnemonic,  主链币名称 coin
  
创建返回的数据结构如下：

```go
type WalletAccount struct {
	ResCode    int    // 0 失败 1 成功
	Address    string // 成功必定包含地址
	PublicKey  string // 公钥
	PrivateKey string // 私钥
	Seed       string // 新增 根Seed
	Coin       string // 币种
	ErrMsg     string // 失败原因(便于排查问题,不是必定返回)
	ErrCode    int    //错误码(暂时保留)
	Params     []byte //预留字段
}

```
### GenerateWallet Example
```go
mnemonic := "xxx xxx"
dogeWallet := hpywallet.GenerateWallet(mnemonic, "doge")
fmt.Println("dogeWallet: ", dogeWallet)
```
## 助记词 & password 生成钱包

通过 `导入` 助记词&密码 可以产生 私钥、公钥、地址。

导入助记词使用以下方法：

```go
func GenerateMnemonicWallet(mnemonic, password, coin string)
```

> 必要参数说明：助记词 mnemonic, password 密码, 主链币名称 coin

创建返回的数据结构,同 `助记词生成钱包`
### GenerateMnemonicWallet Example
```go
mnemonic := "xxx xxx"
btcWallet := hpywallet.GenerateMnemonicWallet(mnemonic, "123456", "btc")
fmt.Println("btcWallet: ", btcWallet)
```
## 根 Seed 生成钱包

通过 `导入` Root Seed & 主链币 Coin 可以产生 私钥、公钥、地址。

导入助记词使用以下方法：

```go
func GenerateSeedWallet(seed string, coin string)
```

> 必要参数说明：根 Seed,  主链币名称 coin

创建返回的数据结构,同 `助记词生成钱包`
### GenerateSeedWallet Example
```go
mnemonic := "xxx xxx"
btcWallet := hpywallet.GenerateSeedWallet(seed, "btc")
fmt.Println("btcWallet: ", btcWallet)
```
## 导入私钥(WIF)生成钱包

通过导入私钥(WIF)可产生 `私钥、公钥、地址`。

通过私钥创建钱包使用以下方法：

```go
func ImportPrivateWIF(wif string, coin string)
```
> 必要参数说明：私钥(WIF), 主链币名称 coin

创建返回的数据结构同上 `WalletAccount`。
### ImportPrivateWIF Example
```go
mnemonic := "xxx xxx"
dogeWallet := hpywallet.GenerateWallet(mnemonic, "doge")
importWallet := hpywallet.ImportPrivateWIF(dogeWallet.PrivateKey, "doge")
fmt.Println("importWallet: ", importWallet)
```
## 助记词 Or 私钥生成 KeyStore
通过传递助记词或着私钥,设备的 UDID,以及 Password,产生 KeyStore 文件。
加密产生 KeyStore 文件,使用以下方法:

```go
func EnKeystore(privateKey, password, udid string)
```

> 必要参数说明： mnemonic(或privateKey), password 密码, 手机 udid

创建返回的数据结构如下：

```go
type KeystoreResult struct {
	Result  string // 加解密返回的字符串
	ResCode int    // 0 失败 1 成功
	ErrMsg  string // 失败原因(便于排查问题,不是必定返回)
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
## KeyStore 文件解密
通过传递 KeyStore Json 文件,设备的 UDID,以及 Password,解密 KeyStore 文件。
解密 KeyStore 文件,使用以下方法:

```go
func DeKeystore(json, password, udid string)
```

> 必要参数说明： KeyStore Json, password 密码, 手机 udid

解密返回的数据结构同上 `KeystoreResult`。

### DeKeystore Example
```go
   enResult := "xxxxxxx"
	pwd := "11111"
	udid := "AOIJF-QWEQR-VDFBET-YTAWWE"
  // Decode
	deResult := hpywallet.DeKeystore(enResult, pwd, udid)
	fmt.Println("PrivateKey : ", deResult.Result)
```
## Token 签名算法

构建各 Token 签名算法

**SignInput** 结构如下，部分参数可选，根据当前币种选择：

```go
type SignInput struct {
	PrivateKey   string //私钥
	Coin         string // 主链币
	Symbol       string // symbol
	Amount       int64  //转账数量
	Change       int64  //找零数量
	Fee          int64  //交易费用
	GasLimit     int64  //eth系 gas数量
	GasPrice     int64  //eth系 gas价格
	Type         string //交易合约类型
	SrcAddr      string //转账地址
	DestAddr     string //接受地址
	ContractAddr string //合约地址
	Memo         string //交易备注
	Sequence     int64  //序列号
	Inputs       []byte //Vin构造
	Params       []byte //预留字段
}
```

签名方法名称：

```go
func SignRawTransaction(signIn *SignInput)
```

方法返回结构如下：

```go
type SignResult struct {
	ResCode int    // 0 失败 1 成功
	Coin    string // 主链币
	Symbol  string // symbol 币种名称
	RawTX   string // 签名返回的 txID
	TxHash  string // 交易 Hash
	ErrMsg  string // 失败原因(便于排查问题,不是必定返回)
	ErrCode int    //错误码(暂时保留)

	Params []byte //预留字段
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


在以上支持签名算法的币种中， Inputs 必传的主链币有：

- [x] BTC
- [x] USDT
- [x] LTC
- [x] QTUM
- [x] BCH
- [x] DASH

UTXO Token 的 Inputs 传递的是 `JsonArrayToByte[OutPutItem...].Bytes`

OutPutItem 结构如下:

```go
type OutPutItem struct {
	TxHash   string
	Vout     uint32
	Value    int64
	Pkscript string
}
```

注意事项：

 - QTUM 的 QRC20 构造交易,ContractAddr 合约地址是必传参数;


## Token 构造原始交易算法

构建原始交易的数据结构同签名算法。

**SignInput** 入参同签名交易:`SignInput`

构造交易算法的方法名称：

```go
func CreateRawTransaction(signIn *SignInput)
```
构造交易返回结果的数据结构同签名交易:`SignInput`

## TODO LIST

**后续待完善的 Token 功能:**

- [ ] 校验地址是否正确
- [ ] 构造多签交易
- [ ] 更多币种整理开源

## 感谢支持
感谢 `btcsuite`、`go-ethereum`、`blocktree`等第三方库的支持。

[TOC]
