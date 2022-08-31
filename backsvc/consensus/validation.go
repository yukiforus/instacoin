// Package consensus implements the instacoin consensus algorithms.
package consensus

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"go.instapay.kr/instacoin"
)

var (
	// ErrFutureBlock is returned by AppendHeader if a block's timestamp is too far
	// in the future. The block may be valid at a later time.
	ErrFutureBlock = errors.New("timestamp is too far in the future")

	// ErrOverweight is returned when a block's weight exceeds MaxBlockWeight.
	ErrOverweight = errors.New("block is too heavy")

	// ErrInvalidInputProof is returned when a transaction contains an input
	// with an invalid Merkle proof.
	ErrInvalidInputProof = errors.New("transaction contains an invalid input proof")
)

// Pool for reducing heap allocations when hashing. This are only necessary
// because sha512.New512_256 returns a hash.Hash interface, which prevents the
// compiler from doing escape analysis. Can be removed if we switch to an
// implementation whose constructor returns a concrete type.
var hasherPool = &sync.Pool{New: func() interface{} { return instacoin.NewHasher() }}

// ValidationContext contains the necessary context to fully validate a block.
type ValidationContext struct {
	Index          instacoin.ChainIndex
	State          StateAccumulator
	History        HistoryAccumulator
	TotalWork      instacoin.Work
	Difficulty     instacoin.Work
	LastAdjust     time.Time
	PrevTimestamps [11]time.Time
}

// BlockReward returns the reward for mining a child block.
func (vc *ValidationContext) BlockReward() instacoin.Currency {
	r := instacoin.BaseUnitsPerCoin.Mul64(50)
	n := (vc.Index.Height + 1) / 210000
	return instacoin.NewCurrency(r.Lo>>n|r.Hi<<(64-n), r.Hi>>n) // r >> n
}

// BlockRewardTimelock is the height at which a child block's reward becomes
// spendable.
func (vc *ValidationContext) BlockRewardTimelock() uint64 {
	return (vc.Index.Height + 1) + 144
}

// MaxBlockWeight is the maximum "weight" of a valid child block.
func (vc *ValidationContext) MaxBlockWeight() uint64 {
	return 100e3
}

// TransactionWeight computes the weight of a txn.
func (vc *ValidationContext) TransactionWeight(txn instacoin.Transaction) uint64 {
	return uint64(4*len(txn.Inputs) + len(txn.Outputs))
}

// BlockWeight computes the combined weight of a block's txns.
func (vc *ValidationContext) BlockWeight(txns []instacoin.Transaction) uint64 {
	var weight uint64
	for _, txn := range txns {
		weight += vc.TransactionWeight(txn)
	}
	return weight
}

// Commitment computes the commitment hash for a child block.
func (vc *ValidationContext) Commitment(minerAddr instacoin.Address, txns []instacoin.Transaction) instacoin.Hash256 {
	h := hasherPool.Get().(*instacoin.Hasher)
	defer hasherPool.Put(h)
	h.Reset()

	// instead of hashing all the data together, hash vc and txns separately;
	// this makes it possible to cheaply verify *just* the txns, or *just* the
	// minerAddr, etc.

	h.WriteChainIndex(vc.Index)
	h.WriteUint64(vc.State.NumLeaves)
	for i, root := range vc.State.Trees {
		if vc.State.HasTreeAtHeight(i) {
			h.WriteHash(root)
		}
	}
	h.WriteUint64(vc.History.NumLeaves)
	for i, root := range vc.History.Trees {
		if vc.History.HasTreeAtHeight(i) {
			h.WriteHash(root)
		}
	}
	h.WriteHash(vc.TotalWork.NumHashes)
	h.WriteHash(vc.Difficulty.NumHashes)
	h.WriteTime(vc.LastAdjust)
	for _, ts := range vc.PrevTimestamps {
		h.WriteTime(ts)
	}
	ctxHash := h.Sum()

	h.Reset()
	for _, txn := range txns {
		for _, in := range txn.Inputs {
			h.WriteOutputID(in.Parent.ID)
			h.WriteCurrency(in.Parent.Value)
			h.WriteHash(in.Parent.Address)
			h.WriteUint64(in.Parent.Timelock)
			for _, p := range in.Parent.MerkleProof {
				h.WriteHash(p)
			}
			h.WriteUint64(in.Parent.LeafIndex)
			h.WriteHash(in.PublicKey)
			h.Write(in.Signature[:])
		}
		for _, out := range txn.Outputs {
			h.WriteCurrency(out.Value)
			h.WriteHash(out.Address)
		}
		h.WriteCurrency(txn.MinerFee)
	}
	txnsHash := h.Sum()

	h.Reset()
	h.WriteHash(ctxHash)
	h.WriteHash(minerAddr)
	h.WriteHash(txnsHash)
	return h.Sum()
}

// SigHash returns the hash that must be signed for each transaction input.
func (vc *ValidationContext) SigHash(txn instacoin.Transaction) instacoin.Hash256 {
	h := hasherPool.Get().(*instacoin.Hasher)
	defer hasherPool.Put(h)
	h.Reset()
	for _, in := range txn.Inputs {
		h.WriteOutputID(in.Parent.ID)
	}
	for i := range txn.Outputs {
		h.WriteCurrency(txn.Outputs[i].Value)
		h.WriteHash(txn.Outputs[i].Address)
	}
	h.WriteCurrency(txn.MinerFee)
	return h.Sum()
}

func (vc *ValidationContext) numTimestamps() int {
	if vc.Index.Height+1 < uint64(len(vc.PrevTimestamps)) {
		return int(vc.Index.Height + 1)
	}
	return len(vc.PrevTimestamps)
}

func (vc *ValidationContext) medianTimestamp() time.Time {
	prevCopy := vc.PrevTimestamps
	ts := prevCopy[:vc.numTimestamps()]
	sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
	if len(ts)%2 != 0 {
		return ts[len(ts)/2]
	}
	l, r := ts[len(ts)/2-1], ts[len(ts)/2]
	return l.Add(r.Sub(l) / 2)
}

func (vc *ValidationContext) validateHeader(h instacoin.BlockHeader) error {
	if h.Height != vc.Index.Height+1 {
		return errors.New("wrong height")
	} else if h.ParentID != vc.Index.ID {
		return errors.New("wrong parent ID")
	} else if instacoin.WorkRequiredForHash(h.ID()).Cmp(vc.Difficulty) < 0 {
		return errors.New("insufficient work")
	} else if time.Until(h.Timestamp) > 2*time.Hour {
		return ErrFutureBlock
	} else if h.Timestamp.Before(vc.medianTimestamp()) {
		return errors.New("timestamp is too far in the past")
	}
	return nil
}

func (vc *ValidationContext) containsZeroValuedOutputs(txn instacoin.Transaction) bool {
	for _, out := range txn.Outputs {
		if out.Value.IsZero() {
			return true
		}
	}
	return false
}

func (vc *ValidationContext) validTimeLocks(txn instacoin.Transaction) bool {
	blockHeight := vc.Index.Height + 1
	for _, in := range txn.Inputs {
		if in.Parent.Timelock > blockHeight {
			return false
		}
	}
	return true
}

func (vc *ValidationContext) validPubkeys(txn instacoin.Transaction) bool {
	for _, in := range txn.Inputs {
		if in.PublicKey.Address() != in.Parent.Address {
			return false
		}
	}
	return true
}

func (vc *ValidationContext) outputsEqualInputs(txn instacoin.Transaction) bool {
	var inputSum, outputSum instacoin.Currency
	var overflowed bool
	for _, in := range txn.Inputs {
		inputSum, overflowed = inputSum.AddWithOverflow(in.Parent.Value)
		if overflowed {
			return false
		}
	}
	for _, out := range txn.Outputs {
		outputSum, overflowed = outputSum.AddWithOverflow(out.Value)
		if overflowed {
			return false
		}
	}
	outputSum, overflowed = outputSum.AddWithOverflow(txn.MinerFee)
	return !overflowed && inputSum == outputSum
}

func (vc *ValidationContext) validInputMerkleProofs(txn instacoin.Transaction) bool {
	for _, in := range txn.Inputs {
		if in.Parent.LeafIndex != instacoin.EphemeralLeafIndex && !vc.State.ContainsUnspentOutput(in.Parent) {
			return false
		}
	}
	return true
}

func (vc *ValidationContext) validSignatures(txn instacoin.Transaction) bool {
	sigHash := vc.SigHash(txn)
	for _, in := range txn.Inputs {
		if !ed25519.Verify(in.PublicKey[:], sigHash[:], in.Signature[:]) {
			return false
		}
	}
	return true
}

// ValidateTransaction partially validates txn for inclusion in a child block.
// It does not validate ephemeral outputs.
func (vc *ValidationContext) ValidateTransaction(txn instacoin.Transaction) error {
	switch {
	case vc.containsZeroValuedOutputs(txn):
		return errors.New("transaction contains zero-valued outputs")
	case !vc.validTimeLocks(txn):
		return errors.New("transaction spends time-locked outputs")
	case !vc.outputsEqualInputs(txn):
		return errors.New("outputs of transaction do not equal its inputs")
	case !vc.validPubkeys(txn):
		return errors.New("transaction contains unlock conditions that do not hash to the correct address")
	case !vc.validInputMerkleProofs(txn):
		return ErrInvalidInputProof
	case !vc.validSignatures(txn):
		return errors.New("transaction contains an invalid signature")
	}
	return nil
}

func (vc *ValidationContext) validEphemeralOutputs(txns []instacoin.Transaction) error {
	// TODO: this is rather inefficient. Definitely need a better algorithm.
	available := make(map[instacoin.OutputID]instacoin.Beneficiary)
	for txnIndex, txn := range txns {
		txid := txn.ID()
		for _, in := range txn.Inputs {
			if in.Parent.LeafIndex == instacoin.EphemeralLeafIndex {
				oid := in.Parent.ID
				if out, ok := available[oid]; !ok {
					return fmt.Errorf("transaction set is invalid: transaction %v claims a non-existent ephemeral output", txnIndex)
				} else if in.Parent.Value != out.Value {
					return fmt.Errorf("transaction set is invalid: transaction %v claims wrong value for ephemeral output", txnIndex)
				} else if in.Parent.Address != out.Address {
					return fmt.Errorf("transaction set is invalid: transaction %v claims wrong address for ephemeral output", txnIndex)
				}
				delete(available, oid)
			}
		}
		for i, out := range txn.Outputs {
			oid := instacoin.OutputID{
				TransactionID: txid,
				Index:         uint64(i),
			}
			available[oid] = out
		}
	}
	return nil
}

func (vc *ValidationContext) noDoubleSpends(txns []instacoin.Transaction) error {
	spent := make(map[uint64]struct{})
	for i := range txns {
		for j := range txns[i].Inputs {
			index := txns[i].Inputs[j].Parent.LeafIndex
			if _, ok := spent[index]; ok && index != instacoin.EphemeralLeafIndex {
				return fmt.Errorf("transaction set is invalid: transaction %v double-spends output %v", i, index)
			}
			spent[index] = struct{}{}
		}
	}
	return nil
}

// ValidateTransactionSet validates txns in their corresponding validation context.
func (vc *ValidationContext) ValidateTransactionSet(txns []instacoin.Transaction) error {
	if vc.BlockWeight(txns) > vc.MaxBlockWeight() {
		return ErrOverweight
	} else if err := vc.validEphemeralOutputs(txns); err != nil {
		return err
	} else if err := vc.noDoubleSpends(txns); err != nil {
		return err
	}
	for i, txn := range txns {
		if err := vc.ValidateTransaction(txn); err != nil {
			return fmt.Errorf("transaction %v is invalid: %w", i, err)
		}
	}
	return nil
}

// ValidateBlock validates b in the context of vc.
func (vc *ValidationContext) ValidateBlock(b instacoin.Block) error {
	h := b.Header
	if err := vc.validateHeader(h); err != nil {
		return err
	} else if vc.Commitment(h.MinerAddress, b.Transactions) != h.Commitment {
		return errors.New("commitment hash does not match header")
	} else if err := vc.ValidateTransactionSet(b.Transactions); err != nil {
		return err
	}
	return nil
}

// A Checkpoint pairs a block with the context used to validate its children.
type Checkpoint struct {
	Block   instacoin.Block
	Context ValidationContext
}
