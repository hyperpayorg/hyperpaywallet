package hdwallet

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

func init() {
	coins[DASH] = newDASH
}

type dash struct {
	*btc
}

func newDASH(key *Key) Wallet {
	token := newBTC(key).(*btc)
	token.name = "Dash"
	token.symbol = "DASH"
	token.key.opt.Params = &DASHParams

	return &dash{btc: token}
}

func (c *dash) CreateRawTransaction(signIn *SignInput) (*SignResult, error) {
	return &SignResult{
		Res: 0,
	}, nil
}

func (c *dash) SignRawTransaction(signIn *SignInput) (*SignResult, error) {

	var vins []OutPutItem
	var vouts []OutPutItem
	json.Unmarshal(signIn.Inputs, &vins)
	fmt.Println("vins : ", vins)
	mtx := wire.NewMsgTx(1)

	///////////////
	dest_addr, err := btcutil.DecodeAddress(signIn.DestAddr, &DASHParams)
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
	// Add all outputs as inputs
	var spendValue int64 = 0
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
		if spendValue >= signIn.Change+signIn.Amount+signIn.Fee {
			break
		}
	}

	addrSrc, err := btcutil.DecodeAddress(signIn.SrcAddr, &DASHParams)
	if err != nil {
		return nil, err
	}

	if signIn.Change > 0 {
		pkScriptSrc, err := txscript.PayToAddrScript(addrSrc)
		if err != nil {
			return nil, err
		}

		output = &wire.TxOut{
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
	fmt.Println("txHex :", txHex)
	return &SignResult{
		Res:   1,
		RawTX: txHex,
	}, nil
}

func (c *dash) GetWalletAccountFromWif() (*WalletAccount, error) {
	wif := c.GetKey().Wif
	if len(wif) > 0 {
		btcWif, err := btcutil.DecodeWIF(wif)
		if err != nil {
			fmt.Println("Wif err : ", err.Error())
			return nil, err
		}
		//netID: btc 128 ltc 176
		isLtc := btcWif.IsForNet(&DASHParams)
		if isLtc == false {
			return nil, errors.New("key type error")
		}
		pk := btcWif.SerializePubKey()
		fmt.Println("pk : ", hex.EncodeToString(pk))
		address, err := btcutil.NewAddressPubKeyHash(btcutil.Hash160(pk), &DASHParams)
		if err != nil {
			fmt.Println("Wif err : ", err.Error())
			return nil, err

		}
		btcAddress := address.EncodeAddress()

		return &WalletAccount{
			Res:        1,
			PrivateKey: wif,
			PublicKey:  hex.EncodeToString(pk),
			Address:    btcAddress,
		}, nil
	}
	return &WalletAccount{
		Res: 0,
	}, nil
}
