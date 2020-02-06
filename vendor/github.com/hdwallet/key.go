package hdwallet

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/hdkeychain"
)

// Key struct
type Key struct {
	opt      *Options
	Extended *hdkeychain.ExtendedKey

	Wif      string //for import
	Mnemonic string //助记词
	Seed     string //根种子
	// for btc
	Private *btcec.PrivateKey
	Public  *btcec.PublicKey
	// for eth
	PrivateECDSA *ecdsa.PrivateKey
	PublicECDSA  *ecdsa.PublicKey
}

// params: [Mnemonic], [wif]
func NewKeyFromWif(opts ...Option) (*Key, error) {
	var (
		o = newOptions(opts...)
	)
	key := &Key{
		opt: o,
		Wif: o.WIF,
	}
	return key, nil
}

func NewKey(opts ...Option) (*Key, error) {

	var (
		err error
		o   = newOptions(opts...)
	)

	if len(o.Seed) <= 0 {
		o.Seed, err = NewSeed(o.Mnemonic, o.Password, o.Language)
	}

	if err != nil {
		return nil, err
	}
	switch o.CoinType {
	// case BTM:
	// 	o.AddressIndex = 1
	// 	break
	case BTC:
		o.AddressIndex = 0
		break
	case HC:
		o.Seed = exchangeSeed64BitsTo32(o.Seed)
		break
	default:
		break
	}

	fmt.Println("masterSeed = ", hex.EncodeToString(o.Seed))
	// if hex.EncodeToString(o.Seed) == "c185e3b00fc010c6d24402694f1f50fe55344b19fc29069a8e279fb5c0313338dab28948d2dc8b41a28658734248e8d649c37ebcca6ec48a69f6d21fe48e7d16" {
	// 	fmt.Println("seed = ", "相等")
	// } else {
	// 	fmt.Println("seed = ", "不相等")
	// }

	extended, err := hdkeychain.NewMaster(o.Seed, o.Params)
	if err != nil {
		return nil, err
	}

	key := &Key{
		opt:      o,
		Extended: extended,
		Mnemonic: o.Mnemonic,
		Seed:     hex.EncodeToString(o.Seed),
	}

	err = key.init()
	if err != nil {
		return nil, err
	}

	return key, nil
}
func NewHCKey(opts ...Option) (*Key, error) {
	var (
		err error
		o   = newOptions(opts...)
	)

	if len(o.Seed) <= 0 {
		o.Seed, err = NewSeed(o.Mnemonic, o.Password, o.Language)
	}

	if err != nil {
		return nil, err
	}

	o.Seed = exchangeSeed64BitsTo32(o.Seed)
	extended, err := hdkeychain.NewMaster(o.Seed, o.Params)
	if err != nil {
		return nil, err
	}

	key := &Key{
		opt:      o,
		Extended: extended,
		Mnemonic: o.Mnemonic,
		Seed:     hex.EncodeToString(o.Seed),
	}

	err = key.init()
	if err != nil {
		return nil, err
	}

	return key, nil
}
func exchangeSeed64BitsTo32(seed []byte) []byte {
	if len(seed) != 64 {
		return seed[:]
	}
	hcSeed := [32]byte{0}
	seedLen := len(seed)
	for i := 0; i < seedLen/2; i++ {
		hcSeed[i] = uint8((uint16(seed[i]) + uint16(seed[seedLen-i-1])) >> 1)
	}
	return hcSeed[:]
}

func (k *Key) init() error {
	var err error

	k.Private, err = k.Extended.ECPrivKey()
	if err != nil {
		return err
	}

	k.Public, err = k.Extended.ECPubKey()
	if err != nil {
		return err
	}

	k.PrivateECDSA = k.Private.ToECDSA()
	k.PublicECDSA = &k.PrivateECDSA.PublicKey
	return nil
}

// GetChildKey return a key from master key
// params: [Purpose], [CoinType], [Account], [Change], [AddressIndex], [Path]
func (k *Key) GetChildKey(opts ...Option) (*Key, error) {
	var (
		err error
		o   = newOptions(opts...)
		no  = o
	)

	typ, ok := coinTypes[o.CoinType]
	if ok {
		no = newOptions(append(opts, CoinType(typ))...)
	}

	extended := k.Extended
	for _, i := range no.GetPath() {
		extended, err = extended.Child(i)
		if err != nil {
			return nil, err
		}
	}

	key := &Key{
		opt:      o,
		Extended: extended,
		Mnemonic: k.Mnemonic,
		Seed:     hex.EncodeToString(o.Seed),
	}

	err = key.init()
	if err != nil {
		return nil, err
	}

	return key, nil
}

// GetChildKey return a key from master key
// params: [Purpose], [CoinType], [Account], [Change], [AddressIndex], [Path]
func (k *Key) GetQTUMChildKey(opts ...Option) (*Key, error) {
	var (
		err error
		o   = newOptions(opts...)
		no  = o
	)

	typ, ok := coinTypes[o.CoinType]
	if ok {
		no = newOptions(append(opts, CoinType(typ))...)
	}

	extended := k.Extended
	paths := no.GetQTUMPath()
	for _, i := range paths {
		extended, err = extended.Child(i)
		if err != nil {
			return nil, err
		}
	}

	key := &Key{
		opt:      o,
		Extended: extended,
		Mnemonic: k.Mnemonic,
		Seed:     hex.EncodeToString(o.Seed),
	}

	err = key.init()
	if err != nil {
		return nil, err
	}

	return key, nil
}

func (k *Key) GetBTMChildKey(opts ...Option) (*Key, error) {
	var (
		err error
		o   = newOptions(opts...)
		no  = o
	)

	typ, ok := coinTypes[o.CoinType]
	if ok {
		no = newOptions(append(opts, CoinType(typ))...)
	}

	extended := k.Extended

	paths := no.GetBTMPath()
	for _, i := range paths {
		extended, err = extended.Child(i)
		if err != nil {
			return nil, err
		}
	}
	key := &Key{
		opt:      o,
		Extended: extended,
		Mnemonic: k.Mnemonic,
		Seed:     hex.EncodeToString(o.Seed),
	}

	err = key.init()
	if err != nil {
		return nil, err
	}

	return key, nil
}

// GetWallet return wallet from master key
// params: [Purpose], [CoinType], [Account], [Change], [AddressIndex], [Path]
func (k *Key) GetWallet(opts ...Option) (Wallet, error) {
	var (
		err error
		o   = newOptions(opts...)
	)
	switch o.CoinType {
	case QTUM:
		return k.GetQTUMWallet(opts...)
	case BTM:
		return k.GetBTMWallet(opts...)
	default:
		break
	}
	key, err := k.GetChildKey(opts...)
	if err != nil {
		return nil, err
	}

	coin, ok := coins[key.opt.CoinType]
	if !ok {
		return nil, ErrCoinTypeUnknow
	}

	return coin(key), nil
}

// GetWallet return wallet from master key
// params: [Purpose], [CoinType], [Account], [Change], [AddressIndex], [Path]
func (k *Key) GetImportWallet(CoinType uint32) (Wallet, error) {

	coin, ok := coins[CoinType]
	if !ok {
		return nil, ErrCoinTypeUnknow
	}

	return coin(k), nil
}

// GetWallet return wallet from master key
// params: [Purpose], [CoinType], [Account], [Change], [AddressIndex], [Path]
func (k *Key) GetQTUMWallet(opts ...Option) (Wallet, error) {
	key, err := k.GetQTUMChildKey(opts...)
	if err != nil {
		return nil, err
	}

	coin, ok := coins[key.opt.CoinType]
	if !ok {
		return nil, ErrCoinTypeUnknow
	}

	return coin(key), nil
}

func (k *Key) GetBTMWallet(opts ...Option) (Wallet, error) {
	key, err := k.GetBTMChildKey(opts...)
	if err != nil {
		return nil, err
	}

	coin, ok := coins[key.opt.CoinType]
	if !ok {
		return nil, ErrCoinTypeUnknow
	}

	return coin(key), nil
}

// PrivateHex generate private key to string by hex
func (k *Key) PrivateHex() string {
	return hex.EncodeToString(k.Private.Serialize())
}

// PrivateWIF generate private key to string by wif
func (k *Key) PrivateWIF(compress bool) (string, error) {
	wif, err := btcutil.NewWIF(k.Private, k.opt.Params, compress)
	if err != nil {
		return "", err
	}

	return wif.String(), nil
}

// PublicHex generate public key to string by hex
func (k *Key) PublicHex(compress bool) string {
	if compress {
		return hex.EncodeToString(k.Public.SerializeCompressed())
	}

	return hex.EncodeToString(k.Public.SerializeUncompressed())
}

// PublicHash generate public key by hash160
func (k *Key) PublicHash() ([]byte, error) {
	address, err := k.Extended.Address(k.opt.Params)
	if err != nil {
		return nil, err
	}

	return address.ScriptAddress(), nil
}

// AddressBTC generate public key to btc style address
func (k *Key) AddressBTC() (string, error) {
	address, err := k.Extended.Address(k.opt.Params)
	if err != nil {
		return "", err
	}

	return address.EncodeAddress(), nil
}

// AddressBCH generate public key to bch style address
// func (k *Key) AddressBCH() (string, error) {
//  address, err := k.Extended.Address(k.opt.Params)
//  if err != nil {
// 	 return "", err
//  }

//  addr, err := bchutil.NewCashAddressPubKeyHash(address.ScriptAddress(), k.opt.Params)
//  if err != nil {
// 	 return "", err
//  }

//  data := addr.EncodeAddress()
//  prefix := bchutil.Prefixes[k.opt.Params.Name]
//  return prefix + ":" + data, nil
// }

// AddressP2WPKH generate public key to p2wpkh style address
func (k *Key) AddressP2WPKH() (string, error) {
	pubHash, err := k.PublicHash()
	if err != nil {
		return "", err
	}

	addr, err := btcutil.NewAddressWitnessPubKeyHash(pubHash, k.opt.Params)
	if err != nil {
		return "", err
	}

	return addr.EncodeAddress(), nil
}

// AddressP2WPKHInP2SH generate public key to p2wpkh nested within p2sh style address
func (k *Key) AddressP2WPKHInP2SH() (string, error) {
	pubHash, err := k.PublicHash()
	if err != nil {
		return "", err
	}

	addr, err := btcutil.NewAddressWitnessPubKeyHash(pubHash, k.opt.Params)
	if err != nil {
		return "", err
	}

	script, err := txscript.PayToAddrScript(addr)
	if err != nil {
		return "", err
	}

	addr1, err := btcutil.NewAddressScriptHash(script, k.opt.Params)
	if err != nil {
		return "", err
	}

	return addr1.EncodeAddress(), nil
}
