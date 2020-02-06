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
	coins[BCH] = newBCH
}

type bch struct {
	*btc
}

func newBCH(key *Key) Wallet {
	token := newBTC(key).(*btc)
	token.name = "Bitcoin Cash"
	token.symbol = "BCH"
	token.key.opt.Params = &BCHParams

	return &bch{btc: token}
}

func (c *bch) SignRawTransaction(signIn *SignInput) (*SignResult, error) {
	var vins []OutPutItem
	var vouts []OutPutItem
	json.Unmarshal(signIn.Inputs, &vins)
	//fmt.Println("vins : ", vins)
	mtx := wire.NewMsgTx(2)

	///////////////
	dest_addr, err := btcutil.DecodeAddress(signIn.DestAddr, &BCHParams)
	if err != nil {
		return nil, err
	}
	//	fmt.Println("dest_addr : ", dest_addr)
	dest_pkScript, err := txscript.PayToAddrScript(dest_addr)
	if err != nil {
		return nil, err
	}
	//fmt.Println("dest_pkScript : ", dest_pkScript)

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
		//fmt.Println("vins txhash : ", txHash)

		prevOut := wire.NewOutPoint(txHash, input.Vout)
		txIn := wire.NewTxIn(prevOut, []byte{}, [][]byte{})
		mtx.AddTxIn(txIn)
		vouts = append(vouts, input)
		spendValue = spendValue + input.Value
		if spendValue >= signIn.Change+signIn.Amount+signIn.Fee {
			break
		}
	}

	addrSrc, err := btcutil.DecodeAddress(signIn.SrcAddr, &BCHParams)
	if err != nil {
		return nil, err
	}
	//	fmt.Println("scr_addr : ", addrSrc)

	if signIn.Change > 0 {
		pkScriptSrc, err := txscript.PayToAddrScript(addrSrc)
		if err != nil {
			return nil, err
		}
		//	fmt.Println("scr_pkScript : ", pkScriptSrc)

		output = &wire.TxOut{
			Value:    signIn.Change,
			PkScript: pkScriptSrc,
		}
		mtx.AddTxOut(output)
	}
	a, err := btcutil.DecodeWIF(signIn.PrivateKey)
	// privKey1, err := dcr_util.DecodeWIFEx(signIn.PrivateKey)
	if err != nil {
		//		fmt.Println("err = ", err)

		return nil, err
	}
	fmt.Println("privateKey = ", a.PrivKey)

	for i, input := range vouts {
		pk, err := hex.DecodeString(input.Pkscript)
		if err != nil {
			return nil, err
		}
		//	fmt.Println("privateKey = ", a.PrivKey)

		//sigScript, err := txscript.SignatureScript(mtx, i, input.Value, pk, txscript.SigHashAll, a.PrivKey, true)
		sigScript, err := txscript.BCHSignatureScript(mtx, i, pk, txscript.SigHashAll|txscript.SigHashForkID, a.PrivKey, input.Value, true)
		fmt.Println("vins sigScript : ", sigScript)

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

func (c *bch) GetWalletAccountFromWif() (*WalletAccount, error) {
	wif := c.GetKey().Wif
	if len(wif) > 0 {
		btcWif, err := btcutil.DecodeWIF(wif)
		if err != nil {
			fmt.Println("Wif err : ", err.Error())
			return nil, err
		}
		//netID: btc 128 ltc 176
		isBch := btcWif.IsForNet(&BCHParams)
		if isBch == false {
			return nil, errors.New("key type error")
		}
		pk := btcWif.SerializePubKey()
		fmt.Println("pk : ", hex.EncodeToString(pk))
		address, err := btcutil.NewAddressPubKeyHash(btcutil.Hash160(pk), &BCHParams)
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
