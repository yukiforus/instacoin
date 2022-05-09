package consensus

import (
	"math/big"
	"time"

	"go.instapay.kr/instacoin"
)

// BlockInterval is the expected wall clock time between consecutive blocks.
const BlockInterval = 10 * time.Minute

// DifficultyAdjustmentInterval is the number of blocks between adjustments to
// the block mining target.
const DifficultyAdjustmentInterval = 2016

func adjustDifficulty(w instacoin.Work, interval time.Duration) instacoin.Work {
	if interval.Round(time.Second) != interval {
		// developer error; interval should be the difference between two Unix
		// timestamps
		panic("interval not rounded to nearest second")
	}
	const maxInterval = BlockInterval * DifficultyAdjustmentInterval * 4
	const minInterval = BlockInterval * DifficultyAdjustmentInterval / 4
	if interval > maxInterval {
		interval = maxInterval
	} else if interval < minInterval {
		interval = minInterval
	}
	workInt := new(big.Int).SetBytes(w.NumHashes[:])
	workInt.Mul(workInt, big.NewInt(int64(BlockInterval*DifficultyAdjustmentInterval)))
	workInt.Div(workInt, big.NewInt(int64(interval)))
	quo := workInt.Bytes()
	copy(w.NumHashes[32-len(quo):], quo)
	return w
}

func applyHeader(vc ValidationContext, h instacoin.BlockHeader) ValidationContext {
	if h.Height == 0 {
		// special handling for GenesisUpdate
		vc.LastAdjust = h.Timestamp
		vc.PrevTimestamps[0] = h.Timestamp
		vc.History.AppendLeaf(h.Index())
		vc.Index = h.Index()
		return vc
	}

	blockWork := instacoin.WorkRequiredForHash(h.ID())
	if h.Height > 0 && h.Height%DifficultyAdjustmentInterval == 0 {
		vc.Difficulty = adjustDifficulty(vc.Difficulty, h.Timestamp.Sub(vc.LastAdjust))
		vc.LastAdjust = h.Timestamp
	}
	vc.TotalWork = vc.TotalWork.Add(blockWork)
	if vc.numTimestamps() < len(vc.PrevTimestamps) {
		vc.PrevTimestamps[vc.numTimestamps()] = h.Timestamp
	} else {
		copy(vc.PrevTimestamps[:], vc.PrevTimestamps[1:])
		vc.PrevTimestamps[len(vc.PrevTimestamps)-1] = h.Timestamp
	}
	vc.Index = h.Index()
	vc.History.AppendLeaf(vc.Index)
	return vc
}

func updatedInBlock(vc ValidationContext, b instacoin.Block) (outputs []instacoin.Output, objects []stateObject) {
	addObject := func(so stateObject) {
		// copy proofs so we don't mutate transaction data
		so.proof = append([]instacoin.Hash256(nil), so.proof...)
		objects = append(objects, so)
	}

	for _, txn := range b.Transactions {
		for _, in := range txn.Inputs {
			outputs = append(outputs, in.Parent)
			if in.Parent.LeafIndex != instacoin.EphemeralLeafIndex {
				addObject(outputStateObject(in.Parent, flagSpent))
			}
		}
	}

	return
}

func createdInBlock(vc ValidationContext, b instacoin.Block) (outputs []instacoin.Output, objects []stateObject) {
	flags := make(map[instacoin.OutputID]uint64)
	for _, txn := range b.Transactions {
		for _, in := range txn.Inputs {
			if in.Parent.LeafIndex == instacoin.EphemeralLeafIndex {
				flags[in.Parent.ID] = flagSpent
			}
		}
	}
	addOutput := func(o instacoin.Output) {
		outputs = append(outputs, o)
		objects = append(objects, outputStateObject(o, flags[o.ID]))
	}

	addOutput(instacoin.Output{
		ID: instacoin.OutputID{
			TransactionID: instacoin.TransactionID(b.ID()),
			Index:         0,
		},
		Value:    vc.BlockReward(),
		Address:  b.Header.MinerAddress,
		Timelock: vc.BlockRewardTimelock(),
	})
	for _, txn := range b.Transactions {
		txid := txn.ID()
		for i, out := range txn.Outputs {
			addOutput(instacoin.Output{
				ID: instacoin.OutputID{
					TransactionID: txid,
					Index:         uint64(i),
				},
				Value:    out.Value,
				Address:  out.Address,
				Timelock: 0,
			})
		}
	}

	return
}

// A StateApplyUpdate reflects the changes to consensus state resulting from the
// application of a block.
type StateApplyUpdate struct {
	Context        ValidationContext
	SpentOutputs   []instacoin.Output
	NewOutputs     []instacoin.Output
	updatedObjects [64][]stateObject
	treeGrowth     [64][]instacoin.Hash256
}

// OutputWasSpent returns true if the given Output was spent.
func (sau *StateApplyUpdate) OutputWasSpent(o instacoin.Output) bool {
	for i := range sau.SpentOutputs {
		if sau.SpentOutputs[i].LeafIndex == o.LeafIndex {
			return true
		}
	}
	return false
}

// UpdateOutputProof updates the Merkle proof of the supplied output to
// incorporate the changes made to the state tree. The output's proof must be
// up-to-date; if it is not, UpdateOutputProof may panic.
func (sau *StateApplyUpdate) UpdateOutputProof(o *instacoin.Output) {
	updateProof(o.MerkleProof, o.LeafIndex, &sau.updatedObjects)
	o.MerkleProof = append(o.MerkleProof, sau.treeGrowth[len(o.MerkleProof)]...)
}

// ApplyBlock integrates a block into the current consensus state, producing
// a StateApplyUpdate detailing the resulting changes. The block is assumed to
// be fully validated.
func ApplyBlock(vc ValidationContext, b instacoin.Block) (sau StateApplyUpdate) {
	sau.Context = applyHeader(vc, b.Header)

	var updated, created []stateObject
	sau.SpentOutputs, updated = updatedInBlock(vc, b)
	sau.NewOutputs, created = createdInBlock(vc, b)

	sau.updatedObjects = sau.Context.State.updateExistingObjects(updated)
	sau.treeGrowth = sau.Context.State.addNewObjects(created)
	for i := range sau.NewOutputs {
		sau.NewOutputs[i].LeafIndex = created[0].leafIndex
		sau.NewOutputs[i].MerkleProof = created[0].proof
		created = created[1:]
	}

	return
}

// GenesisUpdate returns the StateApplyUpdate for the genesis block b.
func GenesisUpdate(b instacoin.Block, initialDifficulty instacoin.Work) StateApplyUpdate {
	return ApplyBlock(ValidationContext{
		Difficulty: initialDifficulty,
	}, b)
}

// A StateRevertUpdate reflects the changes to consensus state resulting from the
// removal of a block.
type StateRevertUpdate struct {
	Context        ValidationContext
	SpentOutputs   []instacoin.Output
	NewOutputs     []instacoin.Output
	updatedObjects [64][]stateObject
}

// OutputWasRemoved returns true if the specified Output was reverted.
func (sru *StateRevertUpdate) OutputWasRemoved(o instacoin.Output) bool {
	return o.LeafIndex >= sru.Context.State.NumLeaves
}

// UpdateOutputProof updates the Merkle proof of the supplied output to
// incorporate the changes made to the state tree. The output's proof must be
// up-to-date; if it is not, UpdateOutputProof may panic.
func (sru *StateRevertUpdate) UpdateOutputProof(o *instacoin.Output) {
	if mh := mergeHeight(sru.Context.State.NumLeaves, o.LeafIndex); mh <= len(o.MerkleProof) {
		o.MerkleProof = o.MerkleProof[:mh-1]
	}
	updateProof(o.MerkleProof, o.LeafIndex, &sru.updatedObjects)
}

// RevertBlock produces a StateRevertUpdate from a block and the
// ValidationContext prior to that block.
func RevertBlock(vc ValidationContext, b instacoin.Block) (sru StateRevertUpdate) {
	sru.Context = vc
	sru.SpentOutputs, _ = updatedInBlock(vc, b)
	sru.NewOutputs, _ = createdInBlock(vc, b)
	sru.updatedObjects = objectsByTree(b.Transactions)
	return
}
