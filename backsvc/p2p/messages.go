package p2p

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"go.instapay.kr/instacoin"
	"go.instapay.kr/instacoin/consensus"
)

const (
	typInvalid = iota
	typGetHeaders
	typHeaders
	typGetTransactions
	typTransactions
	typRelayBlock
	typRelayTransactionSet
	typGetCheckpoint
	typCheckpoint
)

// A Message is a p2p message sent to (or received from) a Peer.
type Message interface {
	encodedSize() int
	encodeTo(b *msgBuffer)
	decodeFrom(b *msgBuffer)
}

func msgType(m Message) uint8 {
	switch m.(type) {
	case *MsgGetHeaders:
		return typGetHeaders
	case *MsgHeaders:
		return typHeaders
	case *MsgGetBlocks:
		return typGetTransactions
	case *MsgBlocks:
		return typTransactions
	case *MsgRelayBlock:
		return typRelayBlock
	case *MsgRelayTransactionSet:
		return typRelayTransactionSet
	case *MsgGetCheckpoint:
		return typGetCheckpoint
	case *MsgCheckpoint:
		return typCheckpoint
	default:
		panic(fmt.Sprintf("unhandled message type: %T", m))
	}
}

func isRelayMessage(m Message) bool {
	switch m.(type) {
	case *MsgRelayBlock:
		return true
	case *MsgRelayTransactionSet:
		return true
	default:
		return false
	}
}

func newMsg(typ uint8) Message {
	switch typ {
	case typGetHeaders:
		return new(MsgGetHeaders)
	case typHeaders:
		return new(MsgHeaders)
	case typGetTransactions:
		return new(MsgGetBlocks)
	case typTransactions:
		return new(MsgBlocks)
	case typRelayBlock:
		return new(MsgRelayBlock)
	case typRelayTransactionSet:
		return new(MsgRelayTransactionSet)
	case typGetCheckpoint:
		return new(MsgGetCheckpoint)
	case typCheckpoint:
		return new(MsgCheckpoint)
	default:
		return nil
	}
}

type taggedMessage struct {
	id uint32
	m  Message
}

func readMessageHeader(r io.Reader) (typ uint8, id uint32, err error) {
	// read type and id
	hdr := make([]byte, 5)
	if n, err := io.ReadFull(r, hdr); err != nil {
		return 0, 0, fmt.Errorf("could not read message type and length (%v/%v bytes): %w", n, len(hdr), err)
	} else if hdr[0] > typCheckpoint {
		return 0, 0, fmt.Errorf("unrecognized message type (%v)", hdr[0])
	}
	return hdr[0], binary.LittleEndian.Uint32(hdr[1:]), nil
}

func readMessage(r io.Reader, recv Message) error {
	// read length prefix
	// TODO: reject too-large messages based on type
	lenBuf := make([]byte, 4)
	if n, err := io.ReadFull(r, lenBuf); err != nil {
		return fmt.Errorf("could not read message length (%v/%v bytes): %w", n, len(lenBuf), err)
	}

	// read message
	msgLen := binary.LittleEndian.Uint32(lenBuf)
	buf := make([]byte, msgLen)
	if n, err := io.ReadFull(r, buf); err != nil {
		return fmt.Errorf("could not read %T (%v/%v bytes): %w", recv, n, len(buf), err)
	}
	var b msgBuffer
	b.write(buf)
	recv.decodeFrom(&b)
	return b.err
}

func writeMessage(w io.Writer, tm taggedMessage) error {
	buf := make([]byte, 9)
	buf[0] = msgType(tm.m)
	binary.LittleEndian.PutUint32(buf[1:], tm.id)
	binary.LittleEndian.PutUint32(buf[5:], uint32(tm.m.encodedSize()))
	var mb msgBuffer
	mb.write(buf)
	tm.m.encodeTo(&mb)
	_, err := w.Write(mb.buf.Bytes())
	return err
}

type msgBuffer struct {
	buf bytes.Buffer
	err error // sticky
}

func (b *msgBuffer) write(p []byte) {
	b.buf.Write(p)
}

func (b *msgBuffer) read(p []byte) {
	if b.err != nil {
		return
	}
	_, b.err = io.ReadFull(&b.buf, p)
}

func (b *msgBuffer) writeHash(p [32]byte) {
	b.buf.Write(p[:])
}

func (b *msgBuffer) readHash() (p [32]byte) {
	b.read(p[:])
	return
}

func (b *msgBuffer) writeBool(p bool) {
	if p {
		b.buf.WriteByte(1)
	} else {
		b.buf.WriteByte(0)
	}
}

func (b *msgBuffer) readBool() bool {
	if b.err != nil {
		return false
	}
	p, err := b.buf.ReadByte()
	if err != nil {
		b.err = err
		return false
	} else if p > 1 {
		b.err = fmt.Errorf("invalid boolean (%d)", p)
		return false
	}
	return p == 1
}

func (b *msgBuffer) writeUint64(u uint64) {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint64(buf, u)
	b.buf.Write(buf)
}

func (b *msgBuffer) readUint64() uint64 {
	if b.err != nil {
		return 0
	}
	buf := b.buf.Next(8)
	if len(buf) < 8 {
		b.err = io.ErrUnexpectedEOF
		return 0
	}
	return binary.LittleEndian.Uint64(buf)
}

func (b *msgBuffer) writePrefix(i int) {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(i))
	b.buf.Write(buf)
}

func (b *msgBuffer) readPrefix(elemSize int) int {
	if b.err != nil {
		return 0
	}
	buf := b.buf.Next(4)
	if len(buf) < 4 {
		b.err = io.ErrUnexpectedEOF
		return 0
	}
	n := binary.LittleEndian.Uint32(buf)
	if n > uint32(b.buf.Len()/elemSize) {
		b.err = fmt.Errorf("msg contains invalid length prefix (%v elems x %v bytes/elem > %v bytes left in message)", n, elemSize, b.buf.Len())
		return 0
	}
	return int(n)
}

func (b *msgBuffer) writeCurrency(c instacoin.Currency) {
	b.writeUint64(c.Lo)
	b.writeUint64(c.Hi)
}

func (b *msgBuffer) readCurrency() instacoin.Currency {
	return instacoin.NewCurrency(b.readUint64(), b.readUint64())
}

// MsgGetHeaders requests a chain of contiguous headers, beginning at the most
// recent index in History known to the peer.
type MsgGetHeaders struct {
	History []instacoin.ChainIndex
}

func (m *MsgGetHeaders) encodedSize() int {
	return 4 + len(m.History)*msgChainIndexSize
}

func (m *MsgGetHeaders) encodeTo(b *msgBuffer) {
	b.writePrefix(len(m.History))
	for i := range m.History {
		(*msgChainIndex)(&m.History[i]).encodeTo(b)
	}
}

func (m *MsgGetHeaders) decodeFrom(b *msgBuffer) {
	m.History = make([]instacoin.ChainIndex, b.readPrefix(msgChainIndexSize))
	for i := range m.History {
		(*msgChainIndex)(&m.History[i]).decodeFrom(b)
	}
}

// MsgHeaders is a response to MsgGetHeaders, containing a chain of contiguous
// headers.
type MsgHeaders struct {
	Headers []instacoin.BlockHeader
}

func (m *MsgHeaders) encodedSize() int {
	return 4 + len(m.Headers)*msgBlockHeaderSize
}

func (m *MsgHeaders) encodeTo(b *msgBuffer) {
	b.writePrefix(len(m.Headers))
	for i := range m.Headers {
		(*msgBlockHeader)(&m.Headers[i]).encodeTo(b)
	}
}

func (m *MsgHeaders) decodeFrom(b *msgBuffer) {
	m.Headers = make([]instacoin.BlockHeader, b.readPrefix(msgBlockHeaderSize))
	for i := range m.Headers {
		(*msgBlockHeader)(&m.Headers[i]).decodeFrom(b)
	}
}

// MsgGetBlocks requests the referenced blocks.
type MsgGetBlocks struct {
	Blocks []instacoin.ChainIndex
}

func (m *MsgGetBlocks) encodedSize() int {
	return 4 + len(m.Blocks)*msgChainIndexSize
}

func (m *MsgGetBlocks) encodeTo(b *msgBuffer) {
	b.writePrefix(len(m.Blocks))
	for i := range m.Blocks {
		(*msgChainIndex)(&m.Blocks[i]).encodeTo(b)
	}
}

func (m *MsgGetBlocks) decodeFrom(b *msgBuffer) {
	m.Blocks = make([]instacoin.ChainIndex, b.readPrefix(msgChainIndexSize))
	for i := range m.Blocks {
		(*msgChainIndex)(&m.Blocks[i]).decodeFrom(b)
	}
}

// MsgBlocks is a response to MsgGetBlocks, containing the requested
// blocks.
type MsgBlocks struct {
	Blocks []instacoin.Block
}

func (m *MsgBlocks) encodedSize() int {
	size := 4
	for i := range m.Blocks {
		size += (*msgBlock)(&m.Blocks[i]).encodedSize()
	}
	return size
}

func (m *MsgBlocks) encodeTo(b *msgBuffer) {
	b.writePrefix(len(m.Blocks))
	for i := range m.Blocks {
		(*msgBlock)(&m.Blocks[i]).encodeTo(b)
	}
}

func (m *MsgBlocks) decodeFrom(b *msgBuffer) {
	m.Blocks = make([]instacoin.Block, b.readPrefix(4))
	for i := range m.Blocks {
		(*msgBlock)(&m.Blocks[i]).decodeFrom(b)
	}
}

// MsgRelayBlock relays a block.
type MsgRelayBlock struct {
	Block instacoin.Block
}

func (m *MsgRelayBlock) encodedSize() int {
	return (*msgBlock)(&m.Block).encodedSize()
}

func (m *MsgRelayBlock) encodeTo(b *msgBuffer) {
	(*msgBlock)(&m.Block).encodeTo(b)
}

func (m *MsgRelayBlock) decodeFrom(b *msgBuffer) {
	(*msgBlock)(&m.Block).decodeFrom(b)
}

// MsgRelayTransactionSet relays a transaction set for inclusion in the txpool.
// All proofs in the set must be up-to-date as of the same block.
type MsgRelayTransactionSet struct {
	Transactions []instacoin.Transaction
}

func (m *MsgRelayTransactionSet) encodedSize() int {
	size := 4
	for i := range m.Transactions {
		size += (*msgTransaction)(&m.Transactions[i]).encodedSize()
	}
	size += consensus.MultiproofSize(m.Transactions) * 32
	return size
}

func (m *MsgRelayTransactionSet) encodeTo(b *msgBuffer) {
	b.writePrefix(len(m.Transactions))
	for i := range m.Transactions {
		(*msgTransaction)(&m.Transactions[i]).encodeTo(b)
	}
	proof := consensus.ComputeMultiproof(m.Transactions)
	for i := range proof {
		b.writeHash(proof[i])
	}
}

func (m *MsgRelayTransactionSet) decodeFrom(b *msgBuffer) {
	m.Transactions = make([]instacoin.Transaction, b.readPrefix(minTxnSize))
	for i := range m.Transactions {
		(*msgTransaction)(&m.Transactions[i]).decodeFrom(b)
	}
	proofLen := consensus.MultiproofSize(m.Transactions)
	proof := make([]instacoin.Hash256, proofLen)
	for i := range proof {
		proof[i] = b.readHash()
	}
	consensus.ExpandMultiproof(m.Transactions, proof)
}

// MsgGetCheckpoint requests a Block and its ValidationContext.
type MsgGetCheckpoint struct {
	Index instacoin.ChainIndex
}

func (m *MsgGetCheckpoint) encodedSize() int {
	return msgChainIndexSize
}

func (m *MsgGetCheckpoint) encodeTo(b *msgBuffer) {
	(*msgChainIndex)(&m.Index).encodeTo(b)
}

func (m *MsgGetCheckpoint) decodeFrom(b *msgBuffer) {
	(*msgChainIndex)(&m.Index).decodeFrom(b)
}

// MsgCheckpoint is a response to MsgGetCheckpoint, containing the requested
// Block and its parent ValidationContext.
type MsgCheckpoint struct {
	Block         instacoin.Block
	ParentContext consensus.ValidationContext
}

func (m *MsgCheckpoint) encodedSize() int {
	n := (*msgBlock)(&m.Block).encodedSize()
	n += (*msgValidationContext)(&m.ParentContext).encodedSize()
	return n
}

func (m *MsgCheckpoint) encodeTo(b *msgBuffer) {
	(*msgBlock)(&m.Block).encodeTo(b)
	(*msgValidationContext)(&m.ParentContext).encodeTo(b)
}

func (m *MsgCheckpoint) decodeFrom(b *msgBuffer) {
	(*msgBlock)(&m.Block).decodeFrom(b)
	(*msgValidationContext)(&m.ParentContext).decodeFrom(b)
}

// helpers

type msgChainIndex instacoin.ChainIndex

const msgChainIndexSize = 8 + 32

func (m *msgChainIndex) encodeTo(b *msgBuffer) {
	b.writeUint64(m.Height)
	b.writeHash(m.ID)
}

func (m *msgChainIndex) decodeFrom(b *msgBuffer) {
	m.Height = b.readUint64()
	m.ID = b.readHash()
}

type msgOutputID instacoin.OutputID

const msgOutputIDSize = 32 + 8

func (m *msgOutputID) encodeTo(b *msgBuffer) {
	b.writeHash(m.TransactionID)
	b.writeUint64(m.Index)
}

func (m *msgOutputID) decodeFrom(b *msgBuffer) {
	m.TransactionID = b.readHash()
	m.Index = b.readUint64()
}

type msgBlockHeader instacoin.BlockHeader

const msgBlockHeaderSize = 8 + 32 + 8 + 8 + 32 + 32

func (m *msgBlockHeader) encodeTo(b *msgBuffer) {
	b.writeUint64(m.Height)
	b.writeHash(m.ParentID)
	b.write(m.Nonce[:])
	b.writeUint64(uint64(m.Timestamp.Unix()))
	b.writeHash(m.MinerAddress)
	b.writeHash(m.Commitment)
}

func (m *msgBlockHeader) decodeFrom(b *msgBuffer) {
	m.Height = b.readUint64()
	m.ParentID = b.readHash()
	b.read(m.Nonce[:])
	m.Timestamp = time.Unix(int64(b.readUint64()), 0)
	m.MinerAddress = b.readHash()
	m.Commitment = b.readHash()
}

type msgTransaction instacoin.Transaction // proofs not included; must use multiproofs

const minTxnSize = 4 + 4 + 16 // for readPrefix

func (m *msgTransaction) encodedSize() int {
	size := 4 + len(m.Inputs)*(32+8+16+32+8+4+8+32+64) // inputs
	size += 4 + len(m.Outputs)*(16+32)                 // outputs
	size += 16                                         // miner fee
	return size
}

func (m *msgTransaction) encodeTo(b *msgBuffer) {
	b.writePrefix(len(m.Inputs))
	for i := range m.Inputs {
		in := &m.Inputs[i]
		(*msgOutputID)(&in.Parent.ID).encodeTo(b)
		b.writeCurrency(in.Parent.Value)
		b.writeHash(in.Parent.Address)
		b.writeUint64(in.Parent.Timelock)
		b.writePrefix(len(in.Parent.MerkleProof))
		b.writeUint64(in.Parent.LeafIndex)
		b.write(in.PublicKey[:])
		b.write(in.Signature[:])
	}
	b.writePrefix(len(m.Outputs))
	for j := range m.Outputs {
		out := &m.Outputs[j]
		b.writeCurrency(out.Value)
		b.writeHash(out.Address)
	}
	b.writeCurrency(m.MinerFee)
}

func (m *msgTransaction) decodeFrom(b *msgBuffer) {
	const minInputSize = 32 + 8 + 16 + 32 + 8 + 4 + 8 + 32 + 64
	m.Inputs = make([]instacoin.Input, b.readPrefix(minInputSize))
	for j := range m.Inputs {
		in := &m.Inputs[j]
		(*msgOutputID)(&in.Parent.ID).decodeFrom(b)
		in.Parent.Value = b.readCurrency()
		in.Parent.Address = b.readHash()
		in.Parent.Timelock = b.readUint64()
		in.Parent.MerkleProof = make([]instacoin.Hash256, b.readPrefix(32))
		in.Parent.LeafIndex = b.readUint64()
		b.read(in.PublicKey[:])
		b.read(in.Signature[:])
	}
	m.Outputs = make([]instacoin.Beneficiary, b.readPrefix(48))
	for j := range m.Outputs {
		out := &m.Outputs[j]
		out.Value = b.readCurrency()
		out.Address = b.readHash()
	}
	m.MinerFee = b.readCurrency()
}

type msgBlock instacoin.Block

func (m *msgBlock) encodedSize() int {
	size := msgBlockHeaderSize
	size += 4
	for i := range m.Transactions {
		size += (*msgTransaction)(&m.Transactions[i]).encodedSize()
	}
	size += consensus.MultiproofSize(m.Transactions) * 32
	return size
}

func (m *msgBlock) encodeTo(b *msgBuffer) {
	(*msgBlockHeader)(&m.Header).encodeTo(b)
	b.writePrefix(len(m.Transactions))
	for i := range m.Transactions {
		(*msgTransaction)(&m.Transactions[i]).encodeTo(b)
	}
	proof := consensus.ComputeMultiproof(m.Transactions)
	for i := range proof {
		b.writeHash(proof[i])
	}
}

func (m *msgBlock) decodeFrom(b *msgBuffer) {
	(*msgBlockHeader)(&m.Header).decodeFrom(b)
	m.Transactions = make([]instacoin.Transaction, b.readPrefix(minTxnSize))
	for i := range m.Transactions {
		(*msgTransaction)(&m.Transactions[i]).decodeFrom(b)
	}
	proofLen := consensus.MultiproofSize(m.Transactions)
	proof := make([]instacoin.Hash256, proofLen)
	for i := range proof {
		proof[i] = b.readHash()
	}
	consensus.ExpandMultiproof(m.Transactions, proof)
}

type msgValidationContext consensus.ValidationContext

func (m *msgValidationContext) encodedSize() int {
	n := msgChainIndexSize
	n += 8
	for i := range m.State.Trees {
		if m.State.HasTreeAtHeight(i) {
			n += 32
		}
	}
	n += 8
	for i := range m.History.Trees {
		if m.History.HasTreeAtHeight(i) {
			n += 32
		}
	}
	n += 32
	n += 32
	n += 8
	n += len(m.PrevTimestamps) * 8
	return n
}

func (m *msgValidationContext) encodeTo(b *msgBuffer) {
	(*msgChainIndex)(&m.Index).encodeTo(b)
	b.writeUint64(m.State.NumLeaves)
	for i := range m.State.Trees {
		if m.State.HasTreeAtHeight(i) {
			b.writeHash(m.State.Trees[i])
		}
	}
	b.writeUint64(m.History.NumLeaves)
	for i := range m.History.Trees {
		if m.History.HasTreeAtHeight(i) {
			b.writeHash(m.History.Trees[i])
		}
	}
	b.writeHash(m.TotalWork.NumHashes)
	b.writeHash(m.Difficulty.NumHashes)
	b.writeUint64(uint64(m.LastAdjust.Unix()))
	for i := range m.PrevTimestamps {
		b.writeUint64(uint64(m.PrevTimestamps[i].Unix()))
	}
}

func (m *msgValidationContext) decodeFrom(b *msgBuffer) {
	(*msgChainIndex)(&m.Index).decodeFrom(b)
	m.State.NumLeaves = b.readUint64()
	for i := range m.State.Trees {
		if m.State.HasTreeAtHeight(i) {
			m.State.Trees[i] = b.readHash()
		}
	}
	m.History.NumLeaves = b.readUint64()
	for i := range m.History.Trees {
		if m.History.HasTreeAtHeight(i) {
			m.History.Trees[i] = b.readHash()
		}
	}
	m.TotalWork.NumHashes = b.readHash()
	m.Difficulty.NumHashes = b.readHash()
	m.LastAdjust = time.Unix(int64(b.readUint64()), 0)
	for i := range m.PrevTimestamps {
		m.PrevTimestamps[i] = time.Unix(int64(b.readUint64()), 0)
	}
}
