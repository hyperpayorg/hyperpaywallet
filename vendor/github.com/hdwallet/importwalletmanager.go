package hdwallet

// NewKey creates a master key
// params: [Mnemonic], [Password], [Language], [Seed]

func NewWalletFromWif(wif string, coinType uint32) (*WalletAccount, error) {
	master, _ := NewKeyFromWif(
		WIF(wif),
	)
	switch coinType {

	case Libra:
		break
	default:

		break
	}
	wallet, err := master.GetImportWallet(coinType)
	if err != nil {
		return nil, err
	}
	acc, err1 := wallet.GetWalletAccountFromWif()
	if err1 != nil {
		return nil, err1
	}
	return &WalletAccount{
		Res:        acc.Res,
		PrivateKey: acc.PrivateKey,
		Address:    acc.Address,
		PublicKey:  acc.PublicKey,
		ErrMsg:     acc.ErrMsg,
	}, nil
}
func CreateRawTransaction(signInput *SignInput, coinType uint32) (*SignResult, error) {
	master, _ := NewKeyFromWif(
		WIF(signInput.PrivateKey),
	)
	switch coinType {

	case Libra:
		break
	default:
		break
	}
	wallet, err := master.GetImportWallet(coinType)
	if err != nil {
		return nil, err
	}
	sign, err1 := wallet.CreateRawTransaction(signInput)
	if err1 != nil {
		return nil, err1
	}
	return &SignResult{
		Res:    sign.Res,
		RawTX:  sign.RawTX,
		ErrMsg: sign.ErrMsg,
		Params: sign.Params,
	}, nil
}

func SignTxHash(signInput *SignTxHashInput, coinType uint32) (*TxHashResult, error) {
	master, _ := NewKeyFromWif(
		WIF(""),
	)
	switch coinType {

	case Libra:
		break
	default:

		break
	}
	wallet, err := master.GetImportWallet(coinType)
	if err != nil {
		return nil, err
	}
	sign, err1 := wallet.SignTxHash(signInput)
	if err1 != nil {
		return nil, err1
	}
	return &TxHashResult{
		ResCode:  sign.ResCode,
		RawTX:    sign.RawTX,
		TxHash:   sign.TxHash,
		TxRawHex: sign.TxRawHex,
		ErrMsg:   sign.ErrMsg,
		Params:   sign.Params,
	}, nil
}
func GenerateTxHash(signInput *SignInput, coinType uint32) (*TxHashResult, error) {
	master, _ := NewKeyFromWif(
		WIF(""),
	)
	switch coinType {

	case Libra:
		break
	default:

		break
	}
	wallet, err := master.GetImportWallet(coinType)
	if err != nil {
		return nil, err
	}
	sign, err1 := wallet.GenerateTxHash(signInput)
	if err1 != nil {
		return nil, err1
	}
	return &TxHashResult{
		ResCode:  sign.ResCode,
		RawTX:    sign.RawTX,
		TxHash:   sign.TxHash,
		TxRawHex: sign.TxRawHex,
		ErrMsg:   sign.ErrMsg,
		Params:   sign.Params,
	}, nil
}

func SignRawTransaction(signInput *SignInput, coinType uint32) (*SignResult, error) {
	master, _ := NewKeyFromWif(
		WIF(signInput.PrivateKey),
	)
	switch coinType {

	case Libra:
		break
	default:

		break
	}
	wallet, err := master.GetImportWallet(coinType)
	if err != nil {
		return nil, err
	}
	sign, err1 := wallet.SignRawTransaction(signInput)
	if err1 != nil {
		return nil, err1
	}
	return &SignResult{
		Res:    sign.Res,
		RawTX:  sign.RawTX,
		TxHash: sign.TxHash,
		ErrMsg: sign.ErrMsg,
		Params: sign.Params,
	}, nil
}
