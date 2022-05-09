package chainutil

import (
	"crypto/ed25519"
	"encoding/binary"
	"time"

	"go.instapay.kr/instacoin"
	"go.instapay.kr/instacoin/consensus"
)

func FindBlockNonce(h *instacoin.BlockHeader, target instacoin.BlockID) {
	for !h.ID().MeetsTarget(target) {
		binary.LittleEndian.PutUint64(h.Nonce[:], binary.LittleEndian.Uint64(h.Nonce[:])+1)
	}
}

func JustHeaders(blocks []instacoin.Block) []instacoin.BlockHeader {
	headers := make([]instacoin.BlockHeader, len(blocks))
	for i := range headers {
		headers[i] = blocks[i].Header
	}
	return headers
}

func JustTransactions(blocks []instacoin.Block) [][]instacoin.Transaction {
	txns := make([][]instacoin.Transaction, len(blocks))
	for i := range txns {
		txns[i] = blocks[i].Transactions
	}
	return txns
}

func JustTransactionIDs(blocks []instacoin.Block) [][]instacoin.TransactionID {
	txns := make([][]instacoin.TransactionID, len(blocks))
	for i := range txns {
		txns[i] = make([]instacoin.TransactionID, len(blocks[i].Transactions))
		for j := range txns[i] {
			txns[i][j] = blocks[i].Transactions[j].ID()
		}
	}
	return txns
}

func JustChainIndexes(blocks []instacoin.Block) []instacoin.ChainIndex {
	cis := make([]instacoin.ChainIndex, len(blocks))
	for i := range cis {
		cis[i] = blocks[i].Index()
	}
	return cis
}

type ChainSim struct {
	Genesis consensus.Checkpoint
	Chain   []instacoin.Block
	Context consensus.ValidationContext

	nonce [8]byte // for distinguishing forks

	// for simulating transactions
	pubkey  instacoin.PublicKey
	privkey ed25519.PrivateKey
	outputs []instacoin.Output
}

func (cs *ChainSim) Fork() *ChainSim {
	cs2 := *cs
	cs2.Chain = append([]instacoin.Block(nil), cs2.Chain...)
	cs2.outputs = append([]instacoin.Output(nil), cs2.outputs...)
	if cs.nonce[7]++; cs.nonce[7] == 0 {
		cs.nonce[6]++
	}
	return &cs2
}

func (cs *ChainSim) MineBlockWithTxns(txns ...instacoin.Transaction) instacoin.Block {
	prev := cs.Genesis.Block.Header
	if len(cs.Chain) > 0 {
		prev = cs.Chain[len(cs.Chain)-1].Header
	}
	b := instacoin.Block{
		Header: instacoin.BlockHeader{
			Height:       prev.Height + 1,
			ParentID:     prev.ID(),
			Nonce:        cs.nonce,
			Timestamp:    prev.Timestamp.Add(time.Second),
			MinerAddress: instacoin.VoidAddress,
		},
		Transactions: txns,
	}
	b.Header.Commitment = cs.Context.Commitment(b.Header.MinerAddress, b.Transactions)
	FindBlockNonce(&b.Header, instacoin.HashRequiringWork(cs.Context.Difficulty))

	sau := consensus.ApplyBlock(cs.Context, b)
	cs.Context = sau.Context
	cs.Chain = append(cs.Chain, b)

	// update our outputs
	for i := range cs.outputs {
		sau.UpdateOutputProof(&cs.outputs[i])
	}
	for _, out := range sau.NewOutputs {
		if out.Address == cs.pubkey.Address() {
			cs.outputs = append(cs.outputs, out)
		}
	}

	return b
}

func (cs *ChainSim) TxnWithBeneficiaries(bs ...instacoin.Beneficiary) instacoin.Transaction {
	txn := instacoin.Transaction{
		Outputs:  bs,
		MinerFee: instacoin.NewCurrency64(cs.Context.Index.Height),
	}

	totalOut := txn.MinerFee
	for _, b := range bs {
		totalOut = totalOut.Add(b.Value)
	}

	// select inputs and compute change output
	var totalIn instacoin.Currency
	for i, out := range cs.outputs {
		txn.Inputs = append(txn.Inputs, instacoin.Input{
			Parent:    out,
			PublicKey: cs.pubkey,
		})
		totalIn = totalIn.Add(out.Value)
		if totalIn.Cmp(totalOut) >= 0 {
			cs.outputs = cs.outputs[i+1:]
			break
		}
	}

	if totalIn.Cmp(totalOut) < 0 {
		panic("insufficient funds")
	} else if totalIn.Cmp(totalOut) > 0 {
		// add change output
		txn.Outputs = append(txn.Outputs, instacoin.Beneficiary{
			Address: cs.pubkey.Address(),
			Value:   totalIn.Sub(totalOut),
		})
	}

	// sign
	sigHash := cs.Context.SigHash(txn)
	for i := range txn.Inputs {
		txn.Inputs[i].Signature = instacoin.SignTransaction(cs.privkey, sigHash)
	}
	return txn
}

func (cs *ChainSim) MineBlockWithBeneficiaries(bs ...instacoin.Beneficiary) instacoin.Block {
	return cs.MineBlockWithTxns(cs.TxnWithBeneficiaries(bs...))
}

func (cs *ChainSim) MineBlock() instacoin.Block {
	// simulate chain activity by sending our existing outputs to new addresses
	var txns []instacoin.Transaction
	for _, out := range cs.outputs {
		txn := instacoin.Transaction{
			Inputs: []instacoin.Input{{
				Parent:    out,
				PublicKey: cs.pubkey,
			}},
			Outputs: []instacoin.Beneficiary{
				{Address: cs.pubkey.Address(), Value: out.Value.Sub(instacoin.NewCurrency64(cs.Context.Index.Height + 1))},
				{Address: instacoin.Address{cs.nonce[6], cs.nonce[7], 1, 2, 3}, Value: instacoin.NewCurrency64(1)},
			},
			MinerFee: instacoin.NewCurrency64(cs.Context.Index.Height),
		}
		sigHash := cs.Context.SigHash(txn)
		for i := range txn.Inputs {
			txn.Inputs[i].Signature = instacoin.SignTransaction(cs.privkey, sigHash)
		}

		txns = append(txns, txn)
	}
	cs.outputs = cs.outputs[:0]
	return cs.MineBlockWithTxns(txns...)
}

func (cs *ChainSim) MineBlocks(n int) []instacoin.Block {
	blocks := make([]instacoin.Block, n)
	for i := range blocks {
		blocks[i] = cs.MineBlock()
	}
	return blocks
}

func NewChainSim() *ChainSim {
	// gift ourselves some coins in the genesis block
	privkey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	var pubkey instacoin.PublicKey
	copy(pubkey[:], privkey[32:])
	ourAddr := pubkey.Address()
	gift := make([]instacoin.Beneficiary, 10)
	for i := range gift {
		gift[i] = instacoin.Beneficiary{
			Address: ourAddr,
			Value:   instacoin.BaseUnitsPerCoin.Mul64(10 * uint64(i+1)),
		}
	}
	genesisTxns := []instacoin.Transaction{{Outputs: gift}}
	genesis := instacoin.Block{
		Header: instacoin.BlockHeader{
			Timestamp: time.Unix(734600000, 0),
		},
		Transactions: genesisTxns,
	}
	sau := consensus.GenesisUpdate(genesis, instacoin.Work{NumHashes: [32]byte{31: 4}})
	var outputs []instacoin.Output
	for _, out := range sau.NewOutputs {
		if out.Address == pubkey.Address() {
			outputs = append(outputs, out)
		}
	}
	return &ChainSim{
		Genesis: consensus.Checkpoint{
			Block:   genesis,
			Context: sau.Context,
		},
		Context: sau.Context,
		privkey: privkey,
		pubkey:  pubkey,
		outputs: outputs,
	}
}
