
package wire

import (
	"bytes"
	"fmt"
	"io"
	"strconv"

	"github.com/btcsuite/btcd/chaincfg/chainhash"

)

const (
	 HCMaxBlockPayloadV3 = 1000000 // Not actually 1MB which would be 1024 * 1024

	// TxVersion is the current latest supported transaction version.
	HCTxVersion uint16 = 1

	// MaxHCTxInSequenceNum is the maximum sequence number the sequence field
	// of a transaction input can be.
	HCMaxHCTxInSequenceNum uint32 = 0xffffffff

	// MaxPrevOutIndex is the maximum index the index field of a previous
	// HCOutPoint can be.
	HCMaxPrevOutIndex uint32 = 0xffffffff

	// NoExpiryValue is the value of expiry that indicates the transaction
	// has no expiry.
	HCNoExpiryValue uint32 = 0

	// NullValueIn is a null value for an input witness.
	HCNullValueIn int64 = -1

	// NullBlockHeight is the null value for an input witness. It references
	// the genesis block.
	HCNullBlockHeight uint32 = 0x00000000

	// NullBlockIndex is the null transaction index in a block for an input
	// witness.
	HCNullBlockIndex uint32 = 0xffffffff

	// DefaultPkScriptVersion is the default pkScript version, referring to
	// extended Decred script.
	HCDefaultPkScriptVersion uint16 = 0x0000

	// TxTreeUnknown is the value returned for a transaction tree that is
	// unknown.  This is typically because the transaction has not been
	// inserted into a block yet.
	HCTxTreeUnknown int8 = -1

	// TxTreeRegular is the value for a normal transaction tree for a
	// transaction's location in a block.
	HCTxTreeRegular int8 = 0

	// TxTreeStake is the value for a stake transaction tree for a
	// transaction's location in a block.
	HCTxTreeStake int8 = 1

	// SequenceLockTimeDisabled is a flag that if set on a transaction
	// input's sequence number, the sequence number will not be interpreted
	// as a relative locktime.
	HCSequenceLockTimeDisabled = 1 << 31

	// SequenceLockTimeIsSeconds is a flag that if set on a transaction
	// input's sequence number, the relative locktime has units of 512
	// seconds.
	HCSequenceLockTimeIsSeconds = 1 << 22

	// SequenceLockTimeMask is a mask that extracts the relative locktime
	// when masked against the transaction input sequence number.
	HCSequenceLockTimeMask = 0x0000ffff

	// SequenceLockTimeGranularity is the defined time based granularity
	// for seconds-based relative time locks.  When converting from seconds
	// to a sequence number, the value is right shifted by this amount,
	// therefore the granularity of relative time locks in 512 or 2^9
	// seconds.  Enforced relative lock times are multiples of 512 seconds.
	HCSequenceLockTimeGranularity = 9
)

const (
	// defaultHCTxInOutAlloc is the default size used for the backing array
	// for transaction inputs and outputs.  The array will dynamically grow
	// as needed, but this figure is intended to provide enough space for
	// the number of inputs and outputs in a typical transaction without
	// needing to grow the backing array multiple times.
	defaultHCTxInOutAlloc = 15

	// minHCTxInPayload is the minimum payload size for a transaction input.
	// PreviousHCOutPoint.Hash + PreviousHCOutPoint.Index 4 bytes +
	// PreviousHCOutPoint.Tree 1 byte + Varint for SignatureScript length 1
	// byte + Sequence 4 bytes.
	minHCTxInPayload = 11 + chainhash.HashSize

	// maxHCTxInPerMessage is the maximum number of transactions inputs that
	// a transaction which fits into a message could possibly have.
	maxHCTxInPerMessage = (MaxMessagePayload / minHCTxInPayload) + 1

	// minHCTxOutPayload is the minimum payload size for a transaction output.
	// Value 8 bytes + Varint for PkScript length 1 byte.
	minHCTxOutPayload = 9

	// maxHCTxOutPerMessage is the maximum number of transactions outputs that
	// a transaction which fits into a message could possibly have.
	maxHCTxOutPerMessage = (MaxMessagePayload / minHCTxOutPayload) + 1

	// minTxPayload is the minimum payload size for any full encoded
	// (prefix and witness transaction). Note that any realistically
	// usable transaction must have at least one input or output, but
	// that is a rule enforced at a higher layer, so it is intentionally
	// not included here.
	// Version 4 bytes + Varint number of transaction inputs 1 byte + Varint
	// number of transaction outputs 1 byte + Varint representing the number
	// of transaction signatures + LockTime 4 bytes + Expiry 4 bytes + min
	// input payload + min output payload.
	hcMinTxPayload = 4 + 1 + 1 + 1 + 4 + 4

	// freeListMaxScriptSize is the size of each buffer in the free list
	// that	is used for deserializing scripts from the wire before they are
	// concatenated into a single contiguous buffers.  This value was chosen
	// because it is slightly more than twice the size of the vast majority
	// of all "standard" scripts.  Larger scripts are still deHCSerialized
	// properly as the free list will simply be bypassed for them.
	hcFreeListMaxScriptSize = 512

	// freeListMaxItems is the number of buffers to keep in the free list
	// to use for script deserialization.  This value allows up to 100
	// scripts per transaction being simultaneously deHCSerialized by 125
	// peers.  Thus, the peak usage of the free list is 12,500 * 512 =
	// 6,400,000 bytes.
	hcFreeListMaxItems = 12500
)

// TxHCSerializeType represents the HCSerialized type of a transaction.
type TxHCSerializeType uint16

const (
	// TxHCSerializeFull indicates a transaction be HCSerialized with the prefix
	// and all witness data.
	TxHCSerializeFull TxHCSerializeType = iota

	// TxHCSerializeNoWitness indicates a transaction be HCSerialized with only
	// the prefix.
	TxHCSerializeNoWitness

	// TxHCSerializeOnlyWitness indicates a transaction be HCSerialized with
	// only the witness data.
	TxHCSerializeOnlyWitness
)

// hcScriptFreeList defines a free list of byte slices (up to the maximum number
// defined by the freeListMaxItems constant) that have a cap according to the
// freeListMaxScriptSize constant.  It is used to provide temporary buffers for
// deserializing scripts in order to greatly reduce the number of allocations
// required.
//
// The caller can obtain a buffer from the free list by calling the HCBorrow
// function and should return it via the Return function when done using it.
type hcScriptFreeList chan []byte

// HCBorrow returns a byte slice from the free list with a length according the
// provided size.  A new buffer is allocated if there are any items available.
//
// When the size is larger than the max size allowed for items on the free list
// a new buffer of the appropriate size is allocated and returned.  It is safe
// to attempt to return said buffer via the Return function as it will be
// ignored and allowed to go the garbage collector.
func (c hcScriptFreeList) HCBorrow(size uint64) []byte {
	if size > freeListMaxScriptSize {
		return make([]byte, size)
	}

	var buf []byte
	select {
	case buf = <-c:
	default:
		buf = make([]byte, freeListMaxScriptSize)
	}
	return buf[:size]
}

// Return puts the provided byte slice back on the free list when it has a cap
// of the expected length.  The buffer is expected to have been obtained via
// the HCBorrow function.  Any slices that are not of the appropriate size, such
// as those whose size is greater than the largest allowed free list item size
// are simply ignored so they can go to the garbage collector.
func (c hcScriptFreeList) Return(buf []byte) {
	// Ignore any buffers returned that aren't the expected size for the
	// free list.
	if cap(buf) != freeListMaxScriptSize {
		return
	}

	// Return the buffer to the free list when it's not full.  Otherwise let
	// it be garbage collected.
	select {
	case c <- buf:
	default:
		// Let it go to the garbage collector.
	}
}

// Create the concurrent safe free list to use for script deserialization.  As
// previously described, this free list is maintained to significantly reduce
// the number of allocations.
var hcScriptPool hcScriptFreeList = make(chan []byte, freeListMaxItems)

// hcReadScript reads a variable length byte array that represents a transaction
// script.  It is encoded as a varInt containing the length of the array
// followed by the bytes themselves.  An error is returned if the length is
// greater than the passed maxAllowed parameter which helps protect against
// memory exhaustion attacks and forced panics thorugh malformed messages.  The
// fieldName parameter is only used for the error message so it provides more
// context in the error.
func hcReadScript(r io.Reader, pver uint32, maxAllowed uint32, fieldName string) ([]byte, error) {
	count, err := ReadVarInt(r, pver)
	if err != nil {
		return nil, err
	}

	// Prevent byte array larger than the max message size.  It would
	// be possible to cause memory exhaustion and panics without a sane
	// upper bound on this count.
	if count > uint64(maxAllowed) {
		str := fmt.Sprintf("%s is larger than the max allowed size "+
			"[count %d, max %d]", fieldName, count, maxAllowed)
		return nil, messageError("hcReadScript", str)
	}

	b := hcScriptPool.HCBorrow(count)
	_, err = io.ReadFull(r, b)
	if err != nil {
		hcScriptPool.Return(b)
		return nil, err
	}
	return b, nil
}

// HCOutPoint defines a Decred data type that is used to track previous
// transaction outputs.
type HCOutPoint struct {
	Hash  chainhash.Hash
	Index uint32
	Tree  int8
}

// NewHCHCOutPoint returns a new Decred transaction HCOutPoint point with the
// provided hash and index.
func NewHCOutPoint(hash *chainhash.Hash, index uint32, tree int8) *HCOutPoint {
	return &HCOutPoint{
		Hash:  *hash,
		Index: index,
		Tree:  tree,
	}
}

// String returns the HCOutPoint in the human-readable form "hash:index".
func (o HCOutPoint) String() string {
	// Allocate enough for hash string, colon, and 10 digits.  Although
	// at the time of writing, the number of digits can be no greater than
	// the length of the decimal representation of maxHCTxOutPerMessage, the
	// maximum message payload may increase in the future and this
	// optimization may go unnoticed, so allocate space for 10 decimal
	// digits, which will fit any uint32.
	buf := make([]byte, 2*chainhash.HashSize+1, 2*chainhash.HashSize+1+10)
	copy(buf, o.Hash.String())
	buf[2*chainhash.HashSize] = ':'
	buf = strconv.AppendUint(buf, uint64(o.Index), 10)
	return string(buf)
}

// HCTxIn defines a Decred transaction input.
type HCTxIn struct {
	// Non-witness
	PreviousHCOutPoint HCOutPoint
	Sequence         uint32

	// Witness
	ValueIn         int64
	BlockHeight     uint32
	BlockIndex      uint32
	SignatureScript []byte
}

// HCSerializeSizePrefix returns the number of bytes it would take to HCSerialize
// the transaction input for a prefix.
func (t *HCTxIn) HCSerializeSizePrefix() int {
	// HCOutPoint Hash 32 bytes + HCOutPoint Index 4 bytes + HCOutPoint Tree 1 byte +
	// Sequence 4 bytes.
	return 41
}

// HCSerializeSizeWitness returns the number of bytes it would take to HCSerialize the
// transaction input for a witness.
func (t *HCTxIn) HCSerializeSizeWitness() int {
	// ValueIn (8 bytes) + BlockHeight (4 bytes) + BlockIndex (4 bytes) +
	// HCSerialized varint size for the length of SignatureScript +
	// SignatureScript bytes.
	return 8 + 4 + 4 + VarIntSerializeSize(uint64(len(t.SignatureScript))) +
		len(t.SignatureScript)
}

// NewHCTxIn returns a new Decred transaction input with the provided
// previous HCOutPoint point and signature script with a default sequence of
// MaxHCTxInSequenceNum.
func NewHCTxIn(prevOut *HCOutPoint, valueIn int64, signatureScript []byte) *HCTxIn {
	return &HCTxIn{
		PreviousHCOutPoint: *prevOut,
		Sequence:         HCMaxHCTxInSequenceNum,
		SignatureScript:  signatureScript,
		ValueIn:          valueIn,
		BlockHeight:      HCNullBlockHeight,
		BlockIndex:       HCNullBlockIndex,
	}
}

// HCTxOut defines a Decred transaction output.
type HCTxOut struct {
	Value    int64
	Version  uint16
	PkScript []byte
}

// HCSerializeSize returns the number of bytes it would take to HCSerialize the
// the transaction output.
func (t *HCTxOut) HCSerializeSize() int {
	// Value 8 bytes + Version 2 bytes + HCSerialized varint size for
	// the length of PkScript + PkScript bytes.
	return 8 + 2 + VarIntSerializeSize(uint64(len(t.PkScript))) + len(t.PkScript)
}

// NewHCTxOut returns a new Decred transaction output with the provided
// transaction value and public key script.
func NewHCTxOut(value int64, pkScript []byte) *HCTxOut {
	return &HCTxOut{
		Value:    value,
		Version:  HCDefaultPkScriptVersion,
		PkScript: pkScript,
	}
}

// HCMsgTx implements the Message interface and represents a Decred tx message.
// It is used to deliver transaction information in response to a getdata
// message (MsgGetData) for a given transaction.
//
// Use the AddHCTxIn and AddHCTxOut functions to build up the list of transaction
// inputs and outputs.
type HCMsgTx struct {
	CachedHash *chainhash.Hash
	SerType    TxHCSerializeType
	Version    uint16
	HCTxIn       []*HCTxIn
	HCTxOut      []*HCTxOut
	LockTime   uint32
	Expiry     uint32
}

// AddHCTxIn adds a transaction input to the message.
func (msg *HCMsgTx) AddHCTxIn(ti *HCTxIn) {
	msg.HCTxIn = append(msg.HCTxIn, ti)
}

// AddHCTxOut adds a transaction output to the message.
func (msg *HCMsgTx) AddHCTxOut(to *HCTxOut) {
	msg.HCTxOut = append(msg.HCTxOut, to)
}
func (msg *HCMsgTx) serialize(serType TxHCSerializeType) ([]byte, error) {
	// Shallow copy so the serialization type can be changed without
	// modifying the original transaction.
	mtxCopy := *msg
	mtxCopy.SerType = serType
	buf := bytes.NewBuffer(make([]byte, 0, mtxCopy.HCSerializeSize()))
	err := mtxCopy.HCSerialize(buf)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// mustHCSerialize returns the serialization of the transaction for the provided
// serialization type without modifying the original transaction.  It will panic
// if any errors occur.
func (msg *HCMsgTx) mustHCSerialize(serType TxHCSerializeType) []byte {
	HCSerialized, err := msg.serialize(serType)
	if err != nil {
		panic(fmt.Sprintf("HCMsgTx failed serializing for type %v",
			serType))
	}
	return HCSerialized
}

// TxHash generates the hash for the transaction prefix.  Since it does not
// contain any witness data, it is not malleable and therefore is stable for
// use in unconfirmed transaction chains.
func (msg *HCMsgTx) TxHash() chainhash.Hash {
	// TxHash should always calculate a non-witnessed hash.
	return chainhash.HashH(msg.mustHCSerialize(TxHCSerializeNoWitness))
}

// CachedTxHash is equivalent to calling TxHash, however it caches the result so
// subsequent calls do not have to recalculate the hash.  It can be recalculated
// later with RecacheTxHash.
func (msg *HCMsgTx) CachedTxHash() *chainhash.Hash {
	if msg.CachedHash == nil {
		h := msg.TxHash()
		msg.CachedHash = &h
	}

	return msg.CachedHash
}

// RecacheTxHash is equivalent to calling TxHash, however it replaces the cached
// result so future calls to CachedTxHash will return this newly calculated
// hash.
func (msg *HCMsgTx) RecacheTxHash() *chainhash.Hash {
	h := msg.TxHash()
	msg.CachedHash = &h

	return msg.CachedHash
}

// TxHashWitness generates the hash for the transaction witness.
func (msg *HCMsgTx) TxHashWitness() chainhash.Hash {
	// TxHashWitness should always calculate a witnessed hash.
	return chainhash.HashH(msg.mustHCSerialize(TxHCSerializeOnlyWitness))
}

// TxHashFull generates the hash for the transaction prefix || witness. It first
// obtains the hashes for both the transaction prefix and witness, then
// concatenates them and hashes the result.
func (msg *HCMsgTx) TxHashFull() chainhash.Hash {
	// Note that the inputs to the hashes, the HCSerialized prefix and
	// witness, have different HCSerialized versions because the HCSerialized
	// encoding of the version includes the real transaction version in the
	// lower 16 bits and the transaction serialization type in the upper 16
	// bits.  The real transaction version (lower 16 bits) will be the same
	// in both serializations.
	concat := make([]byte, chainhash.HashSize*2)
	prefixHash := msg.TxHash()
	witnessHash := msg.TxHashWitness()
	copy(concat[0:], prefixHash[:])
	copy(concat[chainhash.HashSize:], witnessHash[:])

	return chainhash.HashH(concat)
}

// Copy creates a deep copy of a transaction so that the original does not get
// modified when the copy is manipulated.
func (msg *HCMsgTx) Copy() *HCMsgTx {
	// Create new tx and start by copying primitive values and making space
	// for the transaction inputs and outputs.
	newTx := HCMsgTx{
		SerType:  msg.SerType,
		Version:  msg.Version,
		HCTxIn:     make([]*HCTxIn, 0, len(msg.HCTxIn)),
		HCTxOut:    make([]*HCTxOut, 0, len(msg.HCTxOut)),
		LockTime: msg.LockTime,
		Expiry:   msg.Expiry,
	}

	// Deep copy the old HCTxIn data.
	for _, oldHCTxIn := range msg.HCTxIn {
		// Deep copy the old previous HCOutPoint.
		oldHCOutPoint := oldHCTxIn.PreviousHCOutPoint
		newHCOutPoint := HCOutPoint{}
		newHCOutPoint.Hash.SetBytes(oldHCOutPoint.Hash[:])
		newHCOutPoint.Index = oldHCOutPoint.Index
		newHCOutPoint.Tree = oldHCOutPoint.Tree

		// Deep copy the old signature script.
		var newScript []byte
		oldScript := oldHCTxIn.SignatureScript
		oldScriptLen := len(oldScript)
		if oldScriptLen > 0 {
			newScript = make([]byte, oldScriptLen)
			copy(newScript, oldScript[:oldScriptLen])
		}

		// Create new HCTxIn with the deep copied data and append it to
		// new Tx.
		newHCTxIn := HCTxIn{
			PreviousHCOutPoint: newHCOutPoint,
			Sequence:         oldHCTxIn.Sequence,
			ValueIn:          oldHCTxIn.ValueIn,
			BlockHeight:      oldHCTxIn.BlockHeight,
			BlockIndex:       oldHCTxIn.BlockIndex,
			SignatureScript:  newScript,
		}
		newTx.HCTxIn = append(newTx.HCTxIn, &newHCTxIn)
	}

	// Deep copy the old HCTxOut data.
	for _, oldHCTxOut := range msg.HCTxOut {
		// Deep copy the old PkScript
		var newScript []byte
		oldScript := oldHCTxOut.PkScript
		oldScriptLen := len(oldScript)
		if oldScriptLen > 0 {
			newScript = make([]byte, oldScriptLen)
			copy(newScript, oldScript[:oldScriptLen])
		}

		// Create new HCTxOut with the deep copied data and append it to
		// new Tx.
		newHCTxOut := HCTxOut{
			Value:    oldHCTxOut.Value,
			Version:  oldHCTxOut.Version,
			PkScript: newScript,
		}
		newTx.HCTxOut = append(newTx.HCTxOut, &newHCTxOut)
	}

	return &newTx
}

// writeTxScriptsToHCMsgTx allocates the memory for variable length fields in a
// HCMsgTx HCTxIns, HCTxOuts, or both as a contiguous chunk of memory, then fills
// in these fields for the HCMsgTx by copying to a contiguous piece of memory
// and setting the pointer.
//
// NOTE: It is no longer valid to return any previously HCBorrowed script
// buffers after this function has run because it is already done and the
// scripts in the transaction inputs and outputs no longer point to the
// buffers.
func writeTxScriptsToHCMsgTx(msg *HCMsgTx, totalScriptSize uint64, serType TxHCSerializeType) {
	// Create a single allocation to house all of the scripts and set each
	// input signature scripts and output public key scripts to the
	// appropriate subslice of the overall contiguous buffer.  Then, return
	// each individual script buffer back to the pool so they can be reused
	// for future deserializations.  This is done because it significantly
	// reduces the number of allocations the garbage collector needs to track,
	// which in turn improves performance and drastically reduces the amount
	// of runtime overhead that would otherwise be needed to keep track of
	// millions of small allocations.
	//
	// Closures around writing the HCTxIn and HCTxOut scripts are used in Decred
	// because, depending on the serialization type desired, only input or
	// output scripts may be required.
	var offset uint64
	scripts := make([]byte, totalScriptSize)
	writeHCTxIns := func() {
		for i := 0; i < len(msg.HCTxIn); i++ {
			// Copy the signature script into the contiguous buffer at the
			// appropriate offset.
			signatureScript := msg.HCTxIn[i].SignatureScript
			copy(scripts[offset:], signatureScript)

			// Reset the signature script of the transaction input to the
			// slice of the contiguous buffer where the script lives.
			scriptSize := uint64(len(signatureScript))
			end := offset + scriptSize
			msg.HCTxIn[i].SignatureScript = scripts[offset:end:end]
			offset += scriptSize

			// Return the temporary script buffer to the pool.
			hcScriptPool.Return(signatureScript)
		}
	}
	writeHCTxOuts := func() {
		for i := 0; i < len(msg.HCTxOut); i++ {
			// Copy the public key script into the contiguous buffer at the
			// appropriate offset.
			pkScript := msg.HCTxOut[i].PkScript
			copy(scripts[offset:], pkScript)

			// Reset the public key script of the transaction output to the
			// slice of the contiguous buffer where the script lives.
			scriptSize := uint64(len(pkScript))
			end := offset + scriptSize
			msg.HCTxOut[i].PkScript = scripts[offset:end:end]
			offset += scriptSize

			// Return the temporary script buffer to the pool.
			hcScriptPool.Return(pkScript)
		}
	}

	// Handle the serialization types accordingly.
	switch serType {
	case TxHCSerializeNoWitness:
		writeHCTxOuts()
	case TxHCSerializeOnlyWitness:
		fallthrough
	case TxHCSerializeFull:
		writeHCTxIns()
		writeHCTxOuts()
	}
}

// decodePrefix decodes a transaction prefix and stores the contents
// in the embedded HCMsgTx.
func (msg *HCMsgTx) decodePrefix(r io.Reader, pver uint32) (uint64, error) {
	count, err := ReadVarInt(r, pver)
	if err != nil {
		return 0, err
	}

	// Prevent more input transactions than could possibly fit into a
	// message.  It would be possible to cause memory exhaustion and panics
	// without a sane upper bound on this count.
	if count > uint64(maxHCTxInPerMessage) {
		str := fmt.Sprintf("too many input transactions to fit into "+
			"max message size [count %d, max %d]", count,
			maxHCTxInPerMessage)
		return 0, messageError("HCMsgTx.decodePrefix", str)
	}

	// HCTxIns.
	HCTxIns := make([]HCTxIn, count)
	msg.HCTxIn = make([]*HCTxIn, count)
	for i := uint64(0); i < count; i++ {
		// The pointer is set now in case a script buffer is HCBorrowed
		// and needs to be returned to the pool on error.
		ti := &HCTxIns[i]
		msg.HCTxIn[i] = ti
		err = readHCTxInPrefix(r, pver, msg.SerType, msg.Version, ti)
		if err != nil {
			return 0, err
		}
	}

	count, err = ReadVarInt(r, pver)
	if err != nil {
		return 0, err
	}

	// Prevent more output transactions than could possibly fit into a
	// message.  It would be possible to cause memory exhaustion and panics
	// without a sane upper bound on this count.
	if count > uint64(maxHCTxOutPerMessage) {
		str := fmt.Sprintf("too many output transactions to fit into "+
			"max message size [count %d, max %d]", count,
			maxHCTxOutPerMessage)
		return 0, messageError("HCMsgTx.decodePrefix", str)
	}

	// HCTxOuts.
	var totalScriptSize uint64
	HCTxOuts := make([]HCTxOut, count)
	msg.HCTxOut = make([]*HCTxOut, count)
	for i := uint64(0); i < count; i++ {
		// The pointer is set now in case a script buffer is HCBorrowed
		// and needs to be returned to the pool on error.
		to := &HCTxOuts[i]
		msg.HCTxOut[i] = to
		err = readHCTxOut(r, pver, msg.Version, to)
		if err != nil {
			return 0, err
		}
		totalScriptSize += uint64(len(to.PkScript))
	}

	// Locktime and expiry.
	msg.LockTime, err = binarySerializer.Uint32(r, littleEndian)
	if err != nil {
		return 0, err
	}

	msg.Expiry, err = binarySerializer.Uint32(r, littleEndian)
	if err != nil {
		return 0, err
	}

	return totalScriptSize, nil
}

func (msg *HCMsgTx) decodeWitness(r io.Reader, pver uint32, isFull bool) (uint64, error) {
	// Witness only; generate the HCTxIn list and fill out only the
	// sigScripts.
	var totalScriptSize uint64
	if !isFull {
		count, err := ReadVarInt(r, pver)
		if err != nil {
			return 0, err
		}

		// Prevent more input transactions than could possibly fit into a
		// message.  It would be possible to cause memory exhaustion and panics
		// without a sane upper bound on this count.
		if count > uint64(maxHCTxInPerMessage) {
			str := fmt.Sprintf("too many input transactions to fit into "+
				"max message size [count %d, max %d]", count,
				maxHCTxInPerMessage)
			return 0, messageError("HCMsgTx.decodeWitness", str)
		}

		HCTxIns := make([]HCTxIn, count)
		msg.HCTxIn = make([]*HCTxIn, count)
		for i := uint64(0); i < count; i++ {
			// The pointer is set now in case a script buffer is HCBorrowed
			// and needs to be returned to the pool on error.
			ti := &HCTxIns[i]
			msg.HCTxIn[i] = ti
			err = readHCTxInWitness(r, pver, msg.Version, ti)
			if err != nil {
				return 0, err
			}
			totalScriptSize += uint64(len(ti.SignatureScript))
		}
		msg.HCTxOut = make([]*HCTxOut, 0)
	} else {
		// We're decoding witnesses from a full transaction, so read in
		// the number of signature scripts, check to make sure it's the
		// same as the number of HCTxIns we currently have, then fill in
		// the signature scripts.
		count, err := ReadVarInt(r, pver)
		if err != nil {
			return 0, err
		}

		// Don't allow the deHCSerializer to panic by accessing memory
		// that doesn't exist.
		if int(count) != len(msg.HCTxIn) {
			str := fmt.Sprintf("non equal witness and prefix HCTxIn quantities "+
				"(witness %v, prefix %v)", count,
				len(msg.HCTxIn))
			return 0, messageError("HCMsgTx.decodeWitness", str)
		}

		// Prevent more input transactions than could possibly fit into a
		// message.  It would be possible to cause memory exhaustion and panics
		// without a sane upper bound on this count.
		if count > uint64(maxHCTxInPerMessage) {
			str := fmt.Sprintf("too many input transactions to fit into "+
				"max message size [count %d, max %d]", count,
				maxHCTxInPerMessage)
			return 0, messageError("HCMsgTx.decodeWitness", str)
		}

		// Read in the witnesses, and copy them into the already generated
		// by decodePrefix HCTxIns.
		HCTxIns := make([]HCTxIn, count)
		for i := uint64(0); i < count; i++ {
			ti := &HCTxIns[i]
			err = readHCTxInWitness(r, pver, msg.Version, ti)
			if err != nil {
				return 0, err
			}
			totalScriptSize += uint64(len(ti.SignatureScript))

			msg.HCTxIn[i].ValueIn = ti.ValueIn
			msg.HCTxIn[i].BlockHeight = ti.BlockHeight
			msg.HCTxIn[i].BlockIndex = ti.BlockIndex
			msg.HCTxIn[i].SignatureScript = ti.SignatureScript
		}
	}

	return totalScriptSize, nil
}
func (msg *HCMsgTx) HCDeserialize(r io.Reader) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of BtcDecode.
	return msg.BtcDecode(r, 0)
}
// BtcDecode decodes r using the Decred protocol encoding into the receiver.
// This is part of the Message interface implementation.
// See DeHCSerialize for decoding transactions stored to disk, such as in a
// database, as opposed to decoding transactions from the wire.
func (msg *HCMsgTx) BtcDecode(r io.Reader, pver uint32) error {
	// The HCSerialized encoding of the version includes the real transaction
	// version in the lower 16 bits and the transaction serialization type
	// in the upper 16 bits.
	version, err := binarySerializer.Uint32(r, littleEndian)
	if err != nil {
		return err
	}
	msg.Version = uint16(version & 0xffff)
	msg.SerType = TxHCSerializeType(version >> 16)

	// returnScriptBuffers is a closure that returns any script buffers that
	// were HCBorrowed from the pool when there are any deserialization
	// errors.  This is only valid to call before the final step which
	// replaces the scripts with the location in a contiguous buffer and
	// returns them.
	returnScriptBuffers := func() {
		for _, HCTxIn := range msg.HCTxIn {
			if HCTxIn == nil || HCTxIn.SignatureScript == nil {
				continue
			}
			hcScriptPool.Return(HCTxIn.SignatureScript)
		}
		for _, HCTxOut := range msg.HCTxOut {
			if HCTxOut == nil || HCTxOut.PkScript == nil {
				continue
			}
			hcScriptPool.Return(HCTxOut.PkScript)
		}
	}

	// HCSerialize the transactions depending on their serialization
	// types.  Write the transaction scripts at the end of each
	// serialization procedure using the more efficient contiguous
	// memory allocations, which reduces the amount of memory that
	// must be handled by the GC tremendously.  If any of these
	// serializations fail, free the relevant memory.
	switch txSerType := msg.SerType; txSerType {
	case TxHCSerializeNoWitness:
		totalScriptSize, err := msg.decodePrefix(r, pver)
		if err != nil {
			returnScriptBuffers()
			return err
		}
		writeTxScriptsToHCMsgTx(msg, totalScriptSize, txSerType)

	case TxHCSerializeOnlyWitness:
		totalScriptSize, err := msg.decodeWitness(r, pver, false)
		if err != nil {
			returnScriptBuffers()
			return err
		}
		writeTxScriptsToHCMsgTx(msg, totalScriptSize, txSerType)

	case TxHCSerializeFull:
		totalScriptSizeIns, err := msg.decodePrefix(r, pver)
		if err != nil {
			returnScriptBuffers()
			return err
		}
		totalScriptSizeOuts, err := msg.decodeWitness(r, pver, true)
		if err != nil {
			returnScriptBuffers()
			return err
		}
		writeTxScriptsToHCMsgTx(msg, totalScriptSizeIns+
			totalScriptSizeOuts, txSerType)

	default:
		return messageError("HCMsgTx.BtcDecode", "unsupported transaction type")
	}

	return nil
}

// DeHCSerialize decodes a transaction from r into the receiver using a format
// that is suitable for long-term storage such as a database while respecting
// the Version field in the transaction.  This function differs from BtcDecode
// in that BtcDecode decodes from the Decred wire protocol as it was sent
// across the network.  The wire encoding can technically differ depending on
// the protocol version and doesn't even really need to match the format of a
// stored transaction at all.  As of the time this comment was written, the
// encoded transaction is the same in both instances, but there is a distinct
// difference and separating the two allows the API to be flexible enough to
// deal with changes.
func (msg *HCMsgTx) DeHCSerialize(r io.Reader) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of BtcDecode.
	return msg.BtcDecode(r, 0)
}

// FromBytes deHCSerializes a transaction byte slice.
func (msg *HCMsgTx) FromBytes(b []byte) error {
	r := bytes.NewReader(b)
	return msg.DeHCSerialize(r)
}

// encodePrefix encodes a transaction prefix into a writer.
func (msg *HCMsgTx) encodePrefix(w io.Writer, pver uint32) error {
	count := uint64(len(msg.HCTxIn))
	fmt.Println("encodePrefix txin count = ", count)
	err := WriteVarInt(w, pver, count)
	if err != nil {
		return err
	}

	for _, ti := range msg.HCTxIn {
		fmt.Println("encodePrefix txin writeTxInPrefix = ", ti)
		err = writeHCTxInPrefix(w, pver, msg.Version, ti)
		if err != nil {
			return err
		}
	}

	count = uint64(len(msg.HCTxOut))
	err = WriteVarInt(w, pver, count)
	fmt.Println("encodePrefix txout count = ", count)

	if err != nil {
		return err
	}

	for _, to := range msg.HCTxOut {
		fmt.Println("encodePrefix TxOut writeTxInPrefix = ", to)

		err = writeHCTxOut(w, pver, msg.Version, to)
		if err != nil {
			return err
		}
	}

	err = binarySerializer.PutUint32(w, littleEndian, msg.LockTime)
	if err != nil {
		return err
	}

	return binarySerializer.PutUint32(w, littleEndian, msg.Expiry)
}

// encodeWitness encodes a transaction witness into a writer.
func (msg *HCMsgTx) encodeWitness(w io.Writer, pver uint32) error {
	count := uint64(len(msg.HCTxIn))
	err := WriteVarInt(w, pver, count)
	if err != nil {
		return err
	}

	for _, ti := range msg.HCTxIn {
		err = writeHCTxInWitness(w, pver, msg.Version, ti)
		if err != nil {
			return err
		}
	}

	return nil
}

// BtcEncode encodes the receiver to w using the Decred protocol encoding.
// This is part of the Message interface implementation.
// See HCSerialize for encoding transactions to be stored to disk, such as in a
// database, as opposed to encoding transactions for the wire.
func (msg *HCMsgTx) BtcEncode(w io.Writer, pver uint32) error {
	// The HCSerialized encoding of the version includes the real transaction
	// version in the lower 16 bits and the transaction serialization type
	// in the upper 16 bits.
	HCSerializedVersion := uint32(msg.Version) | uint32(msg.SerType)<<16
	err := binarySerializer.PutUint32(w, littleEndian, HCSerializedVersion)
	if err != nil {
		return err
	}

	switch msg.SerType {
	case TxHCSerializeNoWitness:
		err := msg.encodePrefix(w, pver)
		if err != nil {
			return err
		}

	case TxHCSerializeOnlyWitness:
		err := msg.encodeWitness(w, pver)
		if err != nil {
			return err
		}

	case TxHCSerializeFull:
		err := msg.encodePrefix(w, pver)
		if err != nil {
			return err
		}
		
		err = msg.encodeWitness(w, pver)

		if err != nil {
			return err
		}

	default:
		return messageError("HCMsgTx.BtcEncode", "unsupported transaction type")
	}

	return nil
}

// HCSerialize encodes the transaction to w using a format that suitable for
// long-term storage such as a database while respecting the Version field in
// the transaction.  This function differs from BtcEncode in that BtcEncode
// encodes the transaction to the Decred wire protocol in order to be sent
// across the network.  The wire encoding can technically differ depending on
// the protocol version and doesn't even really need to match the format of a
// stored transaction at all.  As of the time this comment was written, the
// encoded transaction is the same in both instances, but there is a distinct
// difference and separating the two allows the API to be flexible enough to
// deal with changes.
func (msg *HCMsgTx) HCSerialize(w io.Writer) error {
	// At the current time, there is no difference between the wire encoding
	// at protocol version 0 and the stable long-term storage format.  As
	// a result, make use of BtcEncode.
	return msg.BtcEncode(w, 0)
}

// Bytes returns the HCSerialized form of the transaction in bytes.
func (msg *HCMsgTx) Bytes() ([]byte, error) {
	buf := bytes.NewBuffer(make([]byte, 0, msg.HCSerializeSize()))
	err := msg.HCSerialize(buf)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// BytesPrefix returns the HCSerialized form of the transaction prefix in bytes.
func (msg *HCMsgTx) BytesPrefix() ([]byte, error) {
	return msg.serialize(TxHCSerializeNoWitness)
}

// BytesWitness returns the HCSerialized form of the transaction prefix in bytes.
func (msg *HCMsgTx) BytesWitness() ([]byte, error) {
	return msg.serialize(TxHCSerializeOnlyWitness)
}

// HCSerializeSize returns the number of bytes it would take to HCSerialize the
// the transaction.
func (msg *HCMsgTx) HCSerializeSize() int {
	// Unknown type return 0.
	n := 0
	switch msg.SerType {
	case TxHCSerializeNoWitness:
		// Version 4 bytes + LockTime 4 bytes + Expiry 4 bytes +
		// HCSerialized varint size for the number of transaction
		// inputs and outputs.
		n = 12 + VarIntSerializeSize(uint64(len(msg.HCTxIn))) +
			VarIntSerializeSize(uint64(len(msg.HCTxOut)))

		for _, HCTxIn := range msg.HCTxIn {
			n += HCTxIn.HCSerializeSizePrefix()
		}
		for _, HCTxOut := range msg.HCTxOut {
			n += HCTxOut.HCSerializeSize()
		}

	case TxHCSerializeOnlyWitness:
		// Version 4 bytes + HCSerialized varint size for the
		// number of transaction signatures.
		n = 4 + VarIntSerializeSize(uint64(len(msg.HCTxIn)))

		for _, HCTxIn := range msg.HCTxIn {
			n += HCTxIn.HCSerializeSizeWitness()
		}

	case TxHCSerializeFull:
		// Version 4 bytes + LockTime 4 bytes + Expiry 4 bytes + HCSerialized
		// varint size for the number of transaction inputs (x2) and
		// outputs. The number of inputs is added twice because it's
		// encoded once in both the witness and the prefix.
		n = 12 + VarIntSerializeSize(uint64(len(msg.HCTxIn))) +
			VarIntSerializeSize(uint64(len(msg.HCTxIn))) +
			VarIntSerializeSize(uint64(len(msg.HCTxOut)))

		for _, HCTxIn := range msg.HCTxIn {
			n += HCTxIn.HCSerializeSizePrefix()
		}
		for _, HCTxIn := range msg.HCTxIn {
			n += HCTxIn.HCSerializeSizeWitness()
		}
		for _, HCTxOut := range msg.HCTxOut {
			n += HCTxOut.HCSerializeSize()
		}
	}

	return n
}

// Command returns the protocol command string for the message.  This is part
// of the Message interface implementation.
func (msg *HCMsgTx) Command() string {
	return CmdTx
}

// MaxPayloadLength returns the maximum length the payload can be for the
// receiver.  This is part of the Message interface implementation.
func (msg *HCMsgTx) MaxPayloadLength(pver uint32) uint32 {
	// Protocol version 3 and lower have a different max block payload.
	if pver <= 3 {
		return HCMaxBlockPayloadV3
	}

	return MaxBlockPayload
}

// PkScriptLocs returns a slice containing the start of each public key script
// within the raw HCSerialized transaction.  The caller can easily obtain the
// length of each script by using len on the script available via the
// appropriate transaction output entry.
// TODO: Make this work for all serialization types, not just the full
// serialization type.
func (msg *HCMsgTx) PkScriptLocs() []int {
	// Return nil for witness-only tx.
	numHCTxOut := len(msg.HCTxOut)
	if numHCTxOut == 0 {
		return nil
	}

	// The starting offset in the HCSerialized transaction of the first
	// transaction output is:
	//
	// Version 4 bytes + HCSerialized varint size for the number of
	// transaction inputs and outputs + HCSerialized size of each transaction
	// input.
	n := 4 + VarIntSerializeSize(uint64(len(msg.HCTxIn))) +
		VarIntSerializeSize(uint64(numHCTxOut))
	for _, HCTxIn := range msg.HCTxIn {
		n += HCTxIn.HCSerializeSizePrefix()
	}

	// Calculate and set the appropriate offset for each public key script.
	pkScriptLocs := make([]int, numHCTxOut)
	for i, HCTxOut := range msg.HCTxOut {
		// The offset of the script in the transaction output is:
		//
		// Value 8 bytes + version 2 bytes + HCSerialized varint size
		// for the length of PkScript.
		n += 8 + 2 + VarIntSerializeSize(uint64(len(HCTxOut.PkScript)))
		pkScriptLocs[i] = n
		n += len(HCTxOut.PkScript)
	}

	return pkScriptLocs
}

// NewHCMsgTx returns a new Decred tx message that conforms to the Message
// interface.  The return instance has a default version of TxVersion and there
// are no transaction inputs or outputs.  Also, the lock time is set to zero
// to indicate the transaction is valid immediately as opposed to some time in
// future.
func NewHCMsgTx() *HCMsgTx {
	return &HCMsgTx{
		SerType: TxHCSerializeFull,
		Version: TxVersion,
		HCTxIn:    make([]*HCTxIn, 0, defaultHCTxInOutAlloc),
		HCTxOut:   make([]*HCTxOut, 0, defaultHCTxInOutAlloc),
	}
}

// ReadHCOutPoint reads the next sequence of bytes from r as an HCOutPoint.
func ReadHCOutPoint(r io.Reader, pver uint32, version uint16, op *HCOutPoint) error {
	_, err := io.ReadFull(r, op.Hash[:])
	if err != nil {
		return err
	}

	op.Index, err = binarySerializer.Uint32(r, littleEndian)
	if err != nil {
		return err
	}

	tree, err := binarySerializer.Uint8(r)
	if err != nil {
		return err
	}
	op.Tree = int8(tree)

	return nil
}

// WriteHCOutPoint encodes op to the Decred protocol encoding for an HCOutPoint
// to w.
func WriteHCOutPoint(w io.Writer, pver uint32, version uint16, op *HCOutPoint) error {
	_, err := w.Write(op.Hash[:])
	if err != nil {
		return err
	}

	err = binarySerializer.PutUint32(w, littleEndian, op.Index)
	if err != nil {
		return err
	}

	return binarySerializer.PutUint8(w, uint8(op.Tree))
}

// readHCTxInPrefix reads the next sequence of bytes from r as a transaction input
// (HCTxIn) in the transaction prefix.
func readHCTxInPrefix(r io.Reader, pver uint32, serType TxHCSerializeType, version uint16, ti *HCTxIn) error {
	if serType == TxHCSerializeOnlyWitness {
		return messageError("readHCTxInPrefix",
			"tried to read a prefix input for a witness only tx")
	}

	// HCOutPoint.
	err := ReadHCOutPoint(r, pver, version, &ti.PreviousHCOutPoint)
	if err != nil {
		return err
	}

	// Sequence.
	ti.Sequence, err = binarySerializer.Uint32(r, littleEndian)
	return err
}

// readHCTxInWitness reads the next sequence of bytes from r as a transaction input
// (HCTxIn) in the transaction witness.
func readHCTxInWitness(r io.Reader, pver uint32, version uint16, ti *HCTxIn) error {
	// ValueIn.
	valueIn, err := binarySerializer.Uint64(r, littleEndian)
	if err != nil {
		return err
	}
	ti.ValueIn = int64(valueIn)

	// BlockHeight.
	ti.BlockHeight, err = binarySerializer.Uint32(r, littleEndian)
	if err != nil {
		return err
	}

	// BlockIndex.
	ti.BlockIndex, err = binarySerializer.Uint32(r, littleEndian)
	if err != nil {
		return err
	}

	// Signature script.
	ti.SignatureScript, err = hcReadScript(r, pver, MaxMessagePayload,
		"transaction input signature script")
	return err
}

// writeHCTxInPrefixs encodes ti to the Decred protocol encoding for a transaction
// input (HCTxIn) prefix to w.
func writeHCTxInPrefix(w io.Writer, pver uint32, version uint16, ti *HCTxIn) error {
	err := WriteHCOutPoint(w, pver, version, &ti.PreviousHCOutPoint)
	if err != nil {
		return err
	}

	return binarySerializer.PutUint32(w, littleEndian, ti.Sequence)
}

// writeTxWitness encodes ti to the Decred protocol encoding for a transaction
// input (HCTxIn) witness to w.
func writeHCTxInWitness(w io.Writer, pver uint32, version uint16, ti *HCTxIn) error {
	// ValueIn.
	err := binarySerializer.PutUint64(w, littleEndian, uint64(ti.ValueIn))
	if err != nil {
		return err
	}

	// BlockHeight.
	err = binarySerializer.PutUint32(w, littleEndian, ti.BlockHeight)
	if err != nil {
		return err
	}

	// BlockIndex.
	binarySerializer.PutUint32(w, littleEndian, ti.BlockIndex)
	if err != nil {
		return err
	}

	// Write the signature script.
	return WriteVarBytes(w, pver, ti.SignatureScript)
}

// readHCTxOut reads the next sequence of bytes from r as a transaction output
// (HCTxOut).
func readHCTxOut(r io.Reader, pver uint32, version uint16, to *HCTxOut) error {
	value, err := binarySerializer.Uint64(r, littleEndian)
	if err != nil {
		return err
	}
	to.Value = int64(value)

	to.Version, err = binarySerializer.Uint16(r, littleEndian)
	if err != nil {
		return err
	}

	to.PkScript, err = hcReadScript(r, pver, MaxMessagePayload,
		"transaction output public key script")
	return err
}

// writeHCTxOut encodes to into the Decred protocol encoding for a transaction
// output (HCTxOut) to w.
func writeHCTxOut(w io.Writer, pver uint32, version uint16, to *HCTxOut) error {
	err := binarySerializer.PutUint64(w, littleEndian, uint64(to.Value))
	if err != nil {
		return err
	}

	err = binarySerializer.PutUint16(w, littleEndian, to.Version)
	if err != nil {
		return err
	}

	return WriteVarBytes(w, pver, to.PkScript)
}
