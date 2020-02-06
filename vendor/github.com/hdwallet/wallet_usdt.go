package hdwallet

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/blocktree/go-owcdrivers/omniTransaction"
	"github.com/btcsuite/btcutil"
)

func init() {
	coins[USDT] = newUSDT
}

type usdt struct {
	*btc
}

func newUSDT(key *Key) Wallet {
	token := newBTC(key).(*btc)
	token.name = "Tether"
	token.symbol = "USDT"
	token.key.opt.Params = &USDTParams

	return &usdt{btc: token}
}

func (c *usdt) SignRawTransaction(signIn *SignInput) (*SignResult, error) {
	var vins []OutPutItem
	json.Unmarshal(signIn.Inputs, &vins)
	wif := signIn.PrivateKey
	btcWif, err := btcutil.DecodeWIF(wif)
	if err != nil {
		fmt.Println("Wif err : ", err.Error())
		return nil, err
	}
	//netID: btc 128 ltc 176
	isUsdt := btcWif.IsForNet(&USDTParams)
	if isUsdt == false {
		return nil, errors.New("key type error")
	}
	///////////////
	_, err = btcutil.DecodeAddress(signIn.DestAddr, &USDTParams)
	if err != nil {
		return nil, err
	}

	omniVins := []omniTransaction.Vin{}
	totalSpend := int64(0)
	for i := 0; i < len(vins); i++ {
		omniVins = append(omniVins, omniTransaction.Vin{vins[i].TxHash, vins[i].Vout})
		totalSpend = totalSpend + vins[i].Value
		if totalSpend >= signIn.Fee+signIn.Change {
			break
		}
	}
	fmt.Println("omniVins : ", omniVins)
	omniVouts := []omniTransaction.Vout{}
	// 目标地址与数额
	// 向 mwmXzRM19gg5AB5Vu16dvfuhWujTq5PzvK 发送
	// out 单位为聪
	to := omniTransaction.Vout{signIn.DestAddr, uint64(signIn.Fee)}
	omniVouts = append(omniVouts, to)
	if signIn.Change > 0 {
		omniVouts = append(omniVouts, omniTransaction.Vout{signIn.SrcAddr, uint64(signIn.Change)})
	}

	omniDetail := omniTransaction.OmniStruct{omniTransaction.SimpleSend, omniTransaction.MainTetherUS_01, uint64(signIn.Amount), 0, "", signIn.DestAddr}
	//锁定时间
	lockTime := uint32(0)

	//追加手续费支持
	replaceable := false

	/////////构建空交易单
	emptyTrans, err := omniTransaction.CreateEmptyRawTransaction(omniVins, omniVouts, omniDetail, lockTime, replaceable, omniTransaction.BTCMainnetAddressPrefix)
	if err != nil {
		return nil, err
	} else {
		fmt.Println("空交易单：")
		fmt.Println(emptyTrans)
	}
	omniUnlocks := []omniTransaction.TxUnlock{}
	for i := 0; i < len(omniVins); i++ {
		omniUnlocks = append(omniUnlocks, omniTransaction.TxUnlock{vins[i].Pkscript, "", uint64(0), omniTransaction.SigHashAll})

		//omniUnlocks = append(omniUnlocks, omniTransaction.TxUnlock{vins[i].Pkscript, "", uint64(vins[i].Value), omniTransaction.SigHashAll})
	}

	////////构建用于签名的交易单哈希
	transHash, err := omniTransaction.CreateRawTransactionHashForSig(emptyTrans, omniUnlocks, omniTransaction.BTCMainnetAddressPrefix)
	if err != nil {
		return nil, err
	}
	inPrikey := btcWif.PrivKey.Serialize()
	for i := 0; i < len(transHash); i++ {
		sigPub, err := omniTransaction.SignRawTransactionHash(transHash[i].Hash, inPrikey)
		if err != nil {
			return nil, err
		}
		transHash[i].Normal.SigPub = *sigPub
	}

	//回填后，将签名插入空交易单
	signedTrans, err := omniTransaction.InsertSignatureIntoEmptyTransaction(emptyTrans, transHash, omniUnlocks)
	if err != nil {
		return nil, err
	}

	// 验证交易单
	pass := omniTransaction.VerifyRawTransaction(signedTrans, omniUnlocks, omniTransaction.BTCMainnetAddressPrefix)
	if pass {
		return &SignResult{
			Res:   1,
			RawTX: signedTrans,
		}, nil
	}
	return &SignResult{
		Res:    0,
		ErrMsg: "Can not decode signin struct!",
	}, nil
}
