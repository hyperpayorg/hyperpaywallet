// Copyright (c) 2013-2015 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package txscript

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcutil"
)

// RawTxInWitnessSignature returns the serialized ECDA signature for the input
// idx of the given transaction, with the hashType appended to it. This
// function is identical to RawTxInSignature, however the signature generated
// signs a new sighash digest defined in BIP0143.
func RawTxInWitnessSignature(tx *wire.MsgTx, sigHashes *TxSigHashes, idx int,
	amt int64, subScript []byte, hashType SigHashType,
	key *btcec.PrivateKey) ([]byte, error) {

	parsedScript, err := parseScript(subScript)
	if err != nil {
		return nil, fmt.Errorf("cannot parse output script: %v", err)
	}

	hash, err := calcWitnessSignatureHash(parsedScript, sigHashes, hashType, tx,
		idx, amt)
	if err != nil {
		return nil, err
	}

	signature, err := key.Sign(hash)
	if err != nil {
		return nil, fmt.Errorf("cannot sign tx input: %s", err)
	}

	return append(signature.Serialize(), byte(hashType)), nil
}

// WitnessSignature creates an input witness stack for tx to spend BTC sent
// from a previous output to the owner of privKey using the p2wkh script
// template. The passed transaction must contain all the inputs and outputs as
// dictated by the passed hashType. The signature generated observes the new
// transaction digest algorithm defined within BIP0143.
func WitnessSignature(tx *wire.MsgTx, sigHashes *TxSigHashes, idx int, amt int64,
	subscript []byte, hashType SigHashType, privKey *btcec.PrivateKey,
	compress bool) (wire.TxWitness, error) {

	sig, err := RawTxInWitnessSignature(tx, sigHashes, idx, amt, subscript,
		hashType, privKey)
	if err != nil {
		return nil, err
	}

	pk := (*btcec.PublicKey)(&privKey.PublicKey)
	var pkData []byte
	if compress {
		pkData = pk.SerializeCompressed()
	} else {
		pkData = pk.SerializeUncompressed()
	}

	// A witness script is actually a stack, so we return an array of byte
	// slices here, rather than a single byte slice.
	return wire.TxWitness{sig, pkData}, nil
}

// RawTxInSignature returns the serialized ECDSA signature for the input idx of
// the given transaction, with hashType appended to it.
func RawTxInSignature(tx *wire.MsgTx, idx int, subScript []byte,
	hashType SigHashType, key *btcec.PrivateKey) ([]byte, error) {

	hash, err := CalcSignatureHash(subScript, hashType, tx, idx)
	if err != nil {
		return nil, err
	}
	signature, err := key.Sign(hash)
	if err != nil {
		return nil, fmt.Errorf("cannot sign tx input: %s", err)
	}

	return append(signature.Serialize(), byte(hashType)), nil
}

// SignatureScript creates an input signature script for tx to spend BTC sent
// from a previous output to the owner of privKey. tx must include all
// transaction inputs and outputs, however txin scripts are allowed to be filled
// or empty. The returned script is calculated to be used as the idx'th txin
// sigscript for tx. subscript is the PkScript of the previous output being used
// as the idx'th input. privKey is serialized in either a compressed or
// uncompressed format based on compress. This format must match the same format
// used to generate the payment address, or the script validation will fail.
func SignatureScript(tx *wire.MsgTx, idx int, subscript []byte, hashType SigHashType, privKey *btcec.PrivateKey, compress bool) ([]byte, error) {
	sig, err := RawTxInSignature(tx, idx, subscript, hashType, privKey)
	if err != nil {
		return nil, err
	}

	pk := (*btcec.PublicKey)(&privKey.PublicKey)
	var pkData []byte
	if compress {
		pkData = pk.SerializeCompressed()
	} else {
		pkData = pk.SerializeUncompressed()
	}

	return NewScriptBuilder().AddData(sig).AddData(pkData).Script()
}

func p2pkSignatureScript(tx *wire.MsgTx, idx int, subScript []byte, hashType SigHashType, privKey *btcec.PrivateKey) ([]byte, error) {
	sig, err := RawTxInSignature(tx, idx, subScript, hashType, privKey)
	if err != nil {
		return nil, err
	}

	return NewScriptBuilder().AddData(sig).Script()
}

// signMultiSig signs as many of the outputs in the provided multisig script as
// possible. It returns the generated script and a boolean if the script fulfils
// the contract (i.e. nrequired signatures are provided).  Since it is arguably
// legal to not be able to sign any of the outputs, no error is returned.
func signMultiSig(tx *wire.MsgTx, idx int, subScript []byte, hashType SigHashType,
	addresses []btcutil.Address, nRequired int, kdb KeyDB) ([]byte, bool) {
	// We start with a single OP_FALSE to work around the (now standard)
	// but in the reference implementation that causes a spurious pop at
	// the end of OP_CHECKMULTISIG.
	builder := NewScriptBuilder().AddOp(OP_FALSE)
	signed := 0
	for _, addr := range addresses {
		key, _, err := kdb.GetKey(addr)
		if err != nil {
			continue
		}
		sig, err := RawTxInSignature(tx, idx, subScript, hashType, key)
		if err != nil {
			continue
		}

		builder.AddData(sig)
		signed++
		if signed == nRequired {
			break
		}

	}

	script, _ := builder.Script()
	return script, signed == nRequired
}

func sign(chainParams *chaincfg.Params, tx *wire.MsgTx, idx int,
	subScript []byte, hashType SigHashType, kdb KeyDB, sdb ScriptDB) ([]byte,
	ScriptClass, []btcutil.Address, int, error) {

	class, addresses, nrequired, err := ExtractPkScriptAddrs(subScript,
		chainParams)
	if err != nil {
		return nil, NonStandardTy, nil, 0, err
	}

	switch class {
	case PubKeyTy:
		// look up key for address
		key, _, err := kdb.GetKey(addresses[0])
		if err != nil {
			return nil, class, nil, 0, err
		}

		script, err := p2pkSignatureScript(tx, idx, subScript, hashType,
			key)
		if err != nil {
			return nil, class, nil, 0, err
		}

		return script, class, addresses, nrequired, nil
	case PubKeyHashTy:
		// look up key for address
		key, compressed, err := kdb.GetKey(addresses[0])
		if err != nil {
			return nil, class, nil, 0, err
		}

		script, err := SignatureScript(tx, idx, subScript, hashType,
			key, compressed)
		if err != nil {
			return nil, class, nil, 0, err
		}

		return script, class, addresses, nrequired, nil
	case ScriptHashTy:
		script, err := sdb.GetScript(addresses[0])
		if err != nil {
			return nil, class, nil, 0, err
		}

		return script, class, addresses, nrequired, nil
	case MultiSigTy:
		script, _ := signMultiSig(tx, idx, subScript, hashType,
			addresses, nrequired, kdb)
		return script, class, addresses, nrequired, nil
	case NullDataTy:
		return nil, class, nil, 0,
			errors.New("can't sign NULLDATA transactions")
	default:
		return nil, class, nil, 0,
			errors.New("can't sign unknown transactions")
	}
}

// mergeScripts merges sigScript and prevScript assuming they are both
// partial solutions for pkScript spending output idx of tx. class, addresses
// and nrequired are the result of extracting the addresses from pkscript.
// The return value is the best effort merging of the two scripts. Calling this
// function with addresses, class and nrequired that do not match pkScript is
// an error and results in undefined behaviour.
func mergeScripts(chainParams *chaincfg.Params, tx *wire.MsgTx, idx int,
	pkScript []byte, class ScriptClass, addresses []btcutil.Address,
	nRequired int, sigScript, prevScript []byte) []byte {

	// TODO: the scripthash and multisig paths here are overly
	// inefficient in that they will recompute already known data.
	// some internal refactoring could probably make this avoid needless
	// extra calculations.
	switch class {
	case ScriptHashTy:
		// Remove the last push in the script and then recurse.
		// this could be a lot less inefficient.
		sigPops, err := parseScript(sigScript)
		if err != nil || len(sigPops) == 0 {
			return prevScript
		}
		prevPops, err := parseScript(prevScript)
		if err != nil || len(prevPops) == 0 {
			return sigScript
		}

		// assume that script in sigPops is the correct one, we just
		// made it.
		script := sigPops[len(sigPops)-1].data

		// We already know this information somewhere up the stack.
		class, addresses, nrequired, _ :=
			ExtractPkScriptAddrs(script, chainParams)

		// regenerate scripts.
		sigScript, _ := unparseScript(sigPops)
		prevScript, _ := unparseScript(prevPops)

		// Merge
		mergedScript := mergeScripts(chainParams, tx, idx, script,
			class, addresses, nrequired, sigScript, prevScript)

		// Reappend the script and return the result.
		builder := NewScriptBuilder()
		builder.AddOps(mergedScript)
		builder.AddData(script)
		finalScript, _ := builder.Script()
		return finalScript
	case MultiSigTy:
		return mergeMultiSig(tx, idx, addresses, nRequired, pkScript,
			sigScript, prevScript)

	// It doesn't actually make sense to merge anything other than multiig
	// and scripthash (because it could contain multisig). Everything else
	// has either zero signature, can't be spent, or has a single signature
	// which is either present or not. The other two cases are handled
	// above. In the conflict case here we just assume the longest is
	// correct (this matches behaviour of the reference implementation).
	default:
		if len(sigScript) > len(prevScript) {
			return sigScript
		}
		return prevScript
	}
}

// mergeMultiSig combines the two signature scripts sigScript and prevScript
// that both provide signatures for pkScript in output idx of tx. addresses
// and nRequired should be the results from extracting the addresses from
// pkScript. Since this function is internal only we assume that the arguments
// have come from other functions internally and thus are all consistent with
// each other, behaviour is undefined if this contract is broken.
func mergeMultiSig(tx *wire.MsgTx, idx int, addresses []btcutil.Address,
	nRequired int, pkScript, sigScript, prevScript []byte) []byte {

	// This is an internal only function and we already parsed this script
	// as ok for multisig (this is how we got here), so if this fails then
	// all assumptions are broken and who knows which way is up?
	pkPops, _ := parseScript(pkScript)

	sigPops, err := parseScript(sigScript)
	if err != nil || len(sigPops) == 0 {
		return prevScript
	}

	prevPops, err := parseScript(prevScript)
	if err != nil || len(prevPops) == 0 {
		return sigScript
	}

	// Convenience function to avoid duplication.
	extractSigs := func(pops []parsedOpcode, sigs [][]byte) [][]byte {
		for _, pop := range pops {
			if len(pop.data) != 0 {
				sigs = append(sigs, pop.data)
			}
		}
		return sigs
	}

	possibleSigs := make([][]byte, 0, len(sigPops)+len(prevPops))
	possibleSigs = extractSigs(sigPops, possibleSigs)
	possibleSigs = extractSigs(prevPops, possibleSigs)

	// Now we need to match the signatures to pubkeys, the only real way to
	// do that is to try to verify them all and match it to the pubkey
	// that verifies it. we then can go through the addresses in order
	// to build our script. Anything that doesn't parse or doesn't verify we
	// throw away.
	addrToSig := make(map[string][]byte)
sigLoop:
	for _, sig := range possibleSigs {

		// can't have a valid signature that doesn't at least have a
		// hashtype, in practise it is even longer than this. but
		// that'll be checked next.
		if len(sig) < 1 {
			continue
		}
		tSig := sig[:len(sig)-1]
		hashType := SigHashType(sig[len(sig)-1])

		pSig, err := btcec.ParseDERSignature(tSig, btcec.S256())
		if err != nil {
			continue
		}

		// We have to do this each round since hash types may vary
		// between signatures and so the hash will vary. We can,
		// however, assume no sigs etc are in the script since that
		// would make the transaction nonstandard and thus not
		// MultiSigTy, so we just need to hash the full thing.
		hash := calcSignatureHash(pkPops, hashType, tx, idx)

		for _, addr := range addresses {
			// All multisig addresses should be pubkey addresses
			// it is an error to call this internal function with
			// bad input.
			pkaddr := addr.(*btcutil.AddressPubKey)

			pubKey := pkaddr.PubKey()

			// If it matches we put it in the map. We only
			// can take one signature per public key so if we
			// already have one, we can throw this away.
			if pSig.Verify(hash, pubKey) {
				aStr := addr.EncodeAddress()
				if _, ok := addrToSig[aStr]; !ok {
					addrToSig[aStr] = sig
				}
				continue sigLoop
			}
		}
	}

	// Extra opcode to handle the extra arg consumed (due to previous bugs
	// in the reference implementation).
	builder := NewScriptBuilder().AddOp(OP_FALSE)
	doneSigs := 0
	// This assumes that addresses are in the same order as in the script.
	for _, addr := range addresses {
		sig, ok := addrToSig[addr.EncodeAddress()]
		if !ok {
			continue
		}
		builder.AddData(sig)
		doneSigs++
		if doneSigs == nRequired {
			break
		}
	}

	// padding for missing ones.
	for i := doneSigs; i < nRequired; i++ {
		builder.AddOp(OP_0)
	}

	script, _ := builder.Script()
	return script
}

// KeyDB is an interface type provided to SignTxOutput, it encapsulates
// any user state required to get the private keys for an address.
type KeyDB interface {
	GetKey(btcutil.Address) (*btcec.PrivateKey, bool, error)
}

// KeyClosure implements KeyDB with a closure.
type KeyClosure func(btcutil.Address) (*btcec.PrivateKey, bool, error)

// GetKey implements KeyDB by returning the result of calling the closure.
func (kc KeyClosure) GetKey(address btcutil.Address) (*btcec.PrivateKey,
	bool, error) {
	return kc(address)
}

// ScriptDB is an interface type provided to SignTxOutput, it encapsulates any
// user state required to get the scripts for an pay-to-script-hash address.
type ScriptDB interface {
	GetScript(btcutil.Address) ([]byte, error)
}

// ScriptClosure implements ScriptDB with a closure.
type ScriptClosure func(btcutil.Address) ([]byte, error)

// GetScript implements ScriptDB by returning the result of calling the closure.
func (sc ScriptClosure) GetScript(address btcutil.Address) ([]byte, error) {
	return sc(address)
}

// SignTxOutput signs output idx of the given tx to resolve the script given in
// pkScript with a signature type of hashType. Any keys required will be
// looked up by calling getKey() with the string of the given address.
// Any pay-to-script-hash signatures will be similarly looked up by calling
// getScript. If previousScript is provided then the results in previousScript
// will be merged in a type-dependent manner with the newly generated.
// signature script.
func SignTxOutput(chainParams *chaincfg.Params, tx *wire.MsgTx, idx int,
	pkScript []byte, hashType SigHashType, kdb KeyDB, sdb ScriptDB,
	previousScript []byte) ([]byte, error) {

	sigScript, class, addresses, nrequired, err := sign(chainParams, tx,
		idx, pkScript, hashType, kdb, sdb)
	if err != nil {
		return nil, err
	}

	if class == ScriptHashTy {
		// TODO keep the sub addressed and pass down to merge.
		realSigScript, _, _, _, err := sign(chainParams, tx, idx,
			sigScript, hashType, kdb, sdb)
		if err != nil {
			return nil, err
		}

		// Append the p2sh script as the last push in the script.
		builder := NewScriptBuilder()
		builder.AddOps(realSigScript)
		builder.AddData(sigScript)

		sigScript, _ = builder.Script()
		// TODO keep a copy of the script for merging.
	}

	// Merge scripts. with any previous data, if any.
	mergedScript := mergeScripts(chainParams, tx, idx, pkScript, class,
		addresses, nrequired, sigScript, previousScript)
	return mergedScript, nil
}

// SignatureScript creates an input signature script for tx to spend BTC sent
// from a previous output to the owner of privKey. tx must include all
// transaction inputs and outputs, however txin scripts are allowed to be filled
// or empty. The returned script is calculated to be used as the idx'th txin
// sigscript for tx. subscript is the PkScript of the previous output being used
// as the idx'th input. privKey is serialized in either a compressed or
// uncompressed format based on compress. This format must match the same format
// used to generate the payment address, or the script validation will fail.
func BCHSignatureScript(tx *wire.MsgTx, idx int, subscript []byte, hashType SigHashType, privKey *btcec.PrivateKey, amt int64, compress bool) ([]byte, error) {
	sig, err := BCHRawTxInSchnorrSignature(tx, idx, subscript, hashType, privKey, amt)
	if err != nil {
		return nil, err
	}

	pk := (*btcec.PublicKey)(&privKey.PublicKey)
	var pkData []byte
	if compress {
		pkData = pk.SerializeCompressed()
	} else {
		pkData = pk.SerializeUncompressed()
	}

	return NewScriptBuilder().AddData(sig).AddData(pkData).Script()
}

func BCHRawTxInSchnorrSignature(tx *wire.MsgTx, idx int, subScript []byte,
	hashType SigHashType, key *btcec.PrivateKey, amt int64) ([]byte, error) {

	// If the forkID was not passed in with the hashtype then add it here
	if hashType&SigHashForkID != SigHashForkID {
		hashType |= SigHashForkID
	}

	sigHashes := NewTxSigHashes(tx)
	fmt.Println("sigHashes :", sigHashes)
	hash, err := BCHCalcSignatureHash(subScript, sigHashes, hashType, tx, idx, amt, true)
	if err != nil {
		return nil, err
	}
	fmt.Println("hash :", hash)

	signature, err := key.SignSchnorr(hash)
	fmt.Println("signature :", signature)

	if err != nil {
		return nil, fmt.Errorf("cannot sign tx input: %s", err)
	}

	return append(signature.BCHSerialize(), byte(hashType)), nil
}

// CalcSignatureHash returns a signature hash which can then be signed by the
// input. Since Bitcoin Cash uses a different signature hashing algorithm
// before and after the Uahf fork, the 'useBip143SigHashAlgo' bool is used
// to specify which algorithm to use.
func BCHCalcSignatureHash(script []byte, sigHashes *TxSigHashes, hType SigHashType,
	tx *wire.MsgTx, idx int, amt int64, useBip143SigHashAlgo bool) ([]byte, error) {

	parsedScript, err := parseScript(script)
	if err != nil {
		return nil, fmt.Errorf("cannot parse output script: %v", err)
	}
	return bchCalcSignatureHash(parsedScript, sigHashes, hType, tx, idx, amt, useBip143SigHashAlgo)
}

// CalcSignatureHash will, given a script and hash type for the current script
// engine instance, calculate the signature hash to be used for signing and
// verification using the given signature hashing algorithm.
func bchCalcSignatureHash(script []parsedOpcode, sigHashes *TxSigHashes, hType SigHashType,
	tx *wire.MsgTx, idx int, amt int64, useBip143SigHashAlgo bool) ([]byte, error) {
	return bchCalcBip143SignatureHash(script, sigHashes, hType, tx, idx, amt)
}

// calcBip143SignatureHash computes the sighash digest of a transaction's
// input using the new, optimized digest calculation algorithm defined
// in BIP0143: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki.
// This function makes use of pre-calculated sighash fragments stored within
// the passed HashCache to eliminate duplicate hashing computations when
// calculating the final digest, reducing the complexity from O(N^2) to O(N).
// Additionally, signatures now cover the input value of the referenced unspent
// output. This allows offline, or hardware wallets to compute the exact amount
// being spent, in addition to the final transaction fee. In the case the
// wallet if fed an invalid input amount, the real sighash will differ causing
// the produced signature to be invalid.
func bchCalcBip143SignatureHash(subScript []parsedOpcode, sigHashes *TxSigHashes,
	hashType SigHashType, tx *wire.MsgTx, idx int, amt int64) ([]byte, error) {

	// As a sanity check, ensure the passed input index for the transaction
	// is valid.
	if idx > len(tx.TxIn)-1 {
		return nil, fmt.Errorf("idx %d but %d txins", idx, len(tx.TxIn))
	}

	// We'll utilize this buffer throughout to incrementally calculate
	// the signature hash for this transaction.
	var sigHash bytes.Buffer

	// First write out, then encode the transaction's version number.
	var bVersion [4]byte
	binary.LittleEndian.PutUint32(bVersion[:], uint32(tx.Version))
	sigHash.Write(bVersion[:])

	// Next write out the possibly pre-calculated hashes for the sequence
	// numbers of all inputs, and the hashes of the previous outs for all
	// outputs.
	var zeroHash chainhash.Hash

	// If anyone can pay isn't active, then we can use the cached
	// hashPrevOuts, otherwise we just write zeroes for the prev outs.
	if hashType&SigHashAnyOneCanPay == 0 {
		sigHash.Write(sigHashes.HashPrevOuts[:])
	} else {
		sigHash.Write(zeroHash[:])
	}

	// If the sighash isn't anyone can pay, single, or none, the use the
	// cached hash sequences, otherwise write all zeroes for the
	// hashSequence.
	if hashType&SigHashAnyOneCanPay == 0 &&
		hashType&sigHashMask != SigHashSingle &&
		hashType&sigHashMask != SigHashNone {
		sigHash.Write(sigHashes.HashSequence[:])
	} else {
		sigHash.Write(zeroHash[:])
	}

	// Next, write the outpoint being spent.
	sigHash.Write(tx.TxIn[idx].PreviousOutPoint.Hash[:])
	var bIndex [4]byte
	binary.LittleEndian.PutUint32(bIndex[:], tx.TxIn[idx].PreviousOutPoint.Index)
	sigHash.Write(bIndex[:])

	scriptBytes, _ := unparseScript(subScript)

	wire.WriteVarBytes(&sigHash, 0, scriptBytes)

	// Next, add the input amount, and sequence number of the input being
	// signed.
	var bAmount [8]byte
	binary.LittleEndian.PutUint64(bAmount[:], uint64(amt))
	sigHash.Write(bAmount[:])
	var bSequence [4]byte
	binary.LittleEndian.PutUint32(bSequence[:], tx.TxIn[idx].Sequence)
	sigHash.Write(bSequence[:])

	// If the current signature mode isn't single, or none, then we can
	// re-use the pre-generated hashoutputs sighash fragment. Otherwise,
	// we'll serialize and add only the target output index to the signature
	// pre-image.
	if hashType&sigHashMask != SigHashSingle &&
		hashType&sigHashMask != SigHashNone {
		sigHash.Write(sigHashes.HashOutputs[:])
	} else if hashType&sigHashMask == SigHashSingle && idx < len(tx.TxOut) {
		var b bytes.Buffer
		wire.WriteTxOut(&b, 0, 0, tx.TxOut[idx])
		sigHash.Write(chainhash.DoubleHashB(b.Bytes()))
	} else {
		sigHash.Write(zeroHash[:])
	}

	// Finally, write out the transaction's locktime, and the sig hash
	// type.
	var bLockTime [4]byte
	binary.LittleEndian.PutUint32(bLockTime[:], tx.LockTime)
	sigHash.Write(bLockTime[:])
	var bHashType [4]byte
	binary.LittleEndian.PutUint32(bHashType[:], uint32(hashType))
	sigHash.Write(bHashType[:])

	return chainhash.DoubleHashB(sigHash.Bytes()), nil
}
