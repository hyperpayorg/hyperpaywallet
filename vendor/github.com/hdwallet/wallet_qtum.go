package hdwallet

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/blocktree/go-owcdrivers/addressEncoder"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

func init() {
	coins[QTUM] = newQTUM
}

type qtum struct {
	*btc
}

func newQTUM(key *Key) Wallet {
	token := newBTC(key).(*btc)
	token.name = "Qtum"
	token.symbol = "QTUM"
	token.key.opt.Params = &QTUMParams

	return &qtum{btc: token}
}

type Vcontract struct {
	ContractAddr string
	To           string
	SendAmount   int64
	GasLimit     string
	GasPrice     string
}

func (c *qtum) SignRawTransaction(signIn *SignInput) (*SignResult, error) {
	var vins []OutPutItem
	var vouts []OutPutItem
	json.Unmarshal(signIn.Inputs, &vins)
	fmt.Println("vins : ", vins)
	mtx := wire.NewMsgTx(1)
	isQRC20 := (strings.ToLower(signIn.Coin) != strings.ToLower(signIn.Symbol))

	// Add all outputs as inputs
	var spendValue int64 = 0
	amount := signIn.Amount + +signIn.Fee
	if isQRC20 {
		amount = signIn.Fee
		pkScript, err := createQTUMContractScript(&Vcontract{signIn.ContractAddr, signIn.DestAddr, signIn.Amount, "250000", "40"})
		if err != nil {
			return nil, err
		}
		output := &wire.TxOut{
			Value:    0,
			PkScript: pkScript,
		}
		mtx.AddTxOut(output)
	} else {
		///////////////
		dest_addr, err := btcutil.DecodeAddress(signIn.DestAddr, &QTUMParams)
		if err != nil {
			return nil, err
		}
		fmt.Println("dest_addr : ", dest_addr)
		dest_pkScript, err := txscript.PayToAddrScript(dest_addr)
		if err != nil {
			return nil, err
		}

		output := &wire.TxOut{
			Value:    signIn.Amount,
			PkScript: dest_pkScript,
		}
		mtx.AddTxOut(output)
	}
	for _, input := range vins {
		txHash, err := chainhash.NewHashFromStr(input.TxHash)
		if err != nil {
			return nil, fmt.Errorf("txid error")
		}
		prevOut := wire.NewOutPoint(txHash, input.Vout)
		txIn := wire.NewTxIn(prevOut, []byte{}, [][]byte{})
		mtx.AddTxIn(txIn)
		vouts = append(vouts, input)
		spendValue = spendValue + input.Value
		if spendValue >= signIn.Change+amount {
			break
		}
	}

	addrSrc, err := btcutil.DecodeAddress(signIn.SrcAddr, &QTUMParams)
	if err != nil {
		return nil, err
	}

	if signIn.Change > 0 {
		pkScriptSrc, err := txscript.PayToAddrScript(addrSrc)
		if err != nil {
			return nil, err
		}

		output := &wire.TxOut{
			Value:    signIn.Change,
			PkScript: pkScriptSrc,
		}
		mtx.AddTxOut(output)
	}
	a, err := btcutil.DecodeWIF(signIn.PrivateKey)

	for i, input := range vouts {
		pk, _ := hex.DecodeString(input.Pkscript)
		if err != nil {
			return nil, err
		}
		//sigScript, err := txscript.SignatureScript(mtx, i, input.Value, pk, txscript.SigHashAll, a.PrivKey, true)
		sigScript, err := txscript.SignatureScript(mtx, i, pk, txscript.SigHashAll, a.PrivKey, true)

		if err != nil {
			return nil, err
		}
		mtx.TxIn[i].SignatureScript = sigScript
	}

	// Serialize the transaction and convert to hex string.
	buf := bytes.NewBuffer(make([]byte, 0, mtx.SerializeSize()))
	if err := mtx.Serialize(buf); err != nil {
		return nil, err
	}
	txHex := hex.EncodeToString(buf.Bytes())
	//fmt.Println("txHex :", txHex)
	return &SignResult{
		Res:   1,
		RawTX: txHex,
	}, nil
}

func (c *qtum) GetWalletAccountFromWif() (*WalletAccount, error) {
	wif := c.GetKey().Wif
	if len(wif) > 0 {
		btcWif, err := btcutil.DecodeWIF(wif)
		if err != nil {
			//fmt.Println("Wif err : ", err.Error())
			return nil, err
		}
		//netID: btc 128 ltc 176
		isQtum := btcWif.IsForNet(&QTUMParams)
		if isQtum == false {
			return nil, errors.New("key type error")
		}
		pk := btcWif.SerializePubKey()
		//fmt.Println("pk : ", hex.EncodeToString(pk))
		address, err := btcutil.NewAddressPubKeyHash(btcutil.Hash160(pk), &QTUMParams)
		if err != nil {
			//fmt.Println("Wif err : ", err.Error())
			return nil, err

		}
		btcAddress := address.EncodeAddress()

		return &WalletAccount{
			Res:        1,
			PrivateKey: wif,
			PublicKey:  hex.EncodeToString(pk),
			Address:    btcAddress,
			Seed:       c.GetKey().Seed,
		}, nil
	}
	return &WalletAccount{
		Res: 0,
	}, nil
}

func createQTUMContractScript(vcontract *Vcontract) ([]byte, error) {
	res, err := createQTUMContractScriptPublicKey(vcontract, false)
	return res, err
}
func createQTUMContractScriptPublicKey(vcontract *Vcontract, isTestNet bool) ([]byte, error) {
	vmVersion, err := hex.DecodeString("0104")
	if err != nil {
		return nil, err
	}

	//十进制转十六进制
	//gasLimit
	gasLimitInt, err := strconv.ParseInt(vcontract.GasLimit, 10, 64)
	if err != nil {
		return nil, err
	}
	gasLimitHex := strconv.FormatInt(gasLimitInt, 16)
	if len(gasLimitHex)%2 == 1 {
		gasLimitHex = "0" + gasLimitHex
	}
	gasLimit, err := reverseStringToBytes(gasLimitHex)
	if err != nil {
		return nil, err
	}

	//Length of gasLimit

	lenGasLimitHex := strconv.FormatInt(int64(len(gasLimit)), 16)
	if len(lenGasLimitHex)%2 == 1 {
		lenGasLimitHex = "0" + lenGasLimitHex
	}
	lenGasLimit, err := hex.DecodeString(lenGasLimitHex)
	if err != nil {
		return nil, err
	}

	//gasPrice
	gasPriceInt, err := strconv.ParseInt(vcontract.GasPrice, 10, 64)

	if err != nil {
		return nil, err
	}

	gasPriceHex := strconv.FormatInt(gasPriceInt, 16)
	if len(gasPriceHex)%2 == 1 {
		gasPriceHex = "0" + gasPriceHex
	}
	gasPrice, err := reverseStringToBytes(gasPriceHex)
	if err != nil {
		return nil, err
	}

	//length of gasPrice
	lenGasPriceHex := strconv.FormatInt(int64(len(gasPrice)), 16)
	if len(lenGasPriceHex)%2 == 1 {
		lenGasPriceHex = "0" + lenGasPriceHex
	}

	lenGasPrice, err := hex.DecodeString(lenGasPriceHex)
	if err != nil {
		return nil, err
	}

	//AmountTo32ByteArg
	sotashiAmount := vcontract.SendAmount
	hexAmount := strconv.FormatInt(sotashiAmount, 16)
	defaultLen := 64
	addLen := defaultLen - len(hexAmount)
	var bytesArg string
	for i := 0; i < addLen; i++ {
		bytesArg = bytesArg + "0"
	}
	bytesArg = bytesArg + hexAmount

	//addrTo32bytesArg
	var addressToHash160 []byte

	addressToHash160, _ = addressEncoder.AddressDecode(vcontract.To, addressEncoder.QTUM_mainnetAddressP2PKH)

	//fmt.Printf("addressToHash160: %s\n", hex.EncodeToString(addressToHash160))
	addrTo32bytesArg := append([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, addressToHash160[:]...)
	//fmt.Printf("to32bytesArg: %s\n", hex.EncodeToString(addrTo32bytesArg))

	//dataHex
	combineString := hex.EncodeToString(append([]byte{0xa9, 0x05, 0x9c, 0xbb}, addrTo32bytesArg[:]...))
	dataHexString := combineString + bytesArg
	dataHex, err := hex.DecodeString(dataHexString)
	if err != nil {
		return nil, err
	}

	if int64(len(vcontract.ContractAddr))%2 == 1 {
		// log.Errorf("Contract address length error.")
	}
	lanAddressHex := strconv.FormatInt(int64(len(vcontract.ContractAddr))/2, 16)
	lanAddress, err := hex.DecodeString(lanAddressHex)
	if err != nil {
		return nil, err
	}

	contractAddr, err := hex.DecodeString(vcontract.ContractAddr)
	if err != nil {
		return nil, err
	}

	opCall := []byte{0xC2}

	//ret = TxContract{vmVersion, lenGasLimit, gasLimit, lenGasPrice, gasPrice, dataHex, lanAddress, contractAddr, opCall}

	ret := []byte{}
	//contract
	//ret = append(ret, byte(0x02), 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63)
	ret = append(ret, vmVersion...)
	ret = append(ret, lenGasLimit...)
	ret = append(ret, gasLimit...)
	ret = append(ret, lenGasPrice...)
	ret = append(ret, gasPrice...)
	ret = append(ret, 0x44)
	ret = append(ret, dataHex...)
	ret = append(ret, lanAddress...)
	ret = append(ret, contractAddr...)
	ret = append(ret, opCall...)

	//scriptHex := hex.EncodeToString(ret)
	return ret, nil
}

//reverseBytes endian reverse
func reverseBytes(s []byte) []byte {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}

//reverseHexToBytes decode a hex string to an byte array,then change the endian
func reverseHexToBytes(hexVar string) ([]byte, error) {
	if len(hexVar)%2 == 1 {
		return nil, errors.New("Invalid TxHash!")
	}
	ret, err := hex.DecodeString(hexVar)
	if err != nil {
		return nil, err
	}
	return reverseBytes(ret), nil
}

func reverseStringToBytes(hexVar string) ([]byte, error) {
	ret, err := hex.DecodeString(hexVar)
	if err != nil {
		return nil, err
	}
	return reverseBytes(ret), nil
}
