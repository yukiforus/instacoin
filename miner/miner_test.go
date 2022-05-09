package miner

import (
	"crypto/ed25519"
	"testing"
	"time"

	"go.instapay.kr/instacoin"
	"go.instapay.kr/instacoin/consensus"
	"go.instapay.kr/instacoin/txpool"
)

var testingDifficulty = instacoin.Work{NumHashes: [32]byte{31: 1}}

func testingKeypair() (instacoin.PublicKey, ed25519.PrivateKey) {
	var pubkey instacoin.PublicKey
	privkey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	copy(pubkey[:], privkey[32:])
	return pubkey, privkey
}

func genesisWithBeneficiaries(beneficiaries ...instacoin.Beneficiary) instacoin.Block {
	return instacoin.Block{
		Header:       instacoin.BlockHeader{Timestamp: time.Unix(734600000, 0)},
		Transactions: []instacoin.Transaction{{Outputs: beneficiaries}},
	}
}

func signAllInputs(txn *instacoin.Transaction, vc consensus.ValidationContext, priv ed25519.PrivateKey) {
	sigHash := vc.SigHash(*txn)
	for i := range txn.Inputs {
		txn.Inputs[i].Signature = instacoin.SignTransaction(priv, sigHash)
	}
}

// buildTransaction builds a transaction using the provided inputs divided
// between the number of beneficiaries to create ephemeral outputs.
func buildTransaction(pub instacoin.PublicKey, inputs []instacoin.Output, beneficiaries int) (txn instacoin.Transaction, outputs []instacoin.Output) {
	var total instacoin.Currency
	for _, input := range inputs {
		total = total.Add(input.Value)
		txn.Inputs = append(txn.Inputs, instacoin.Input{
			Parent:    input,
			PublicKey: pub,
		})
	}

	value := total.Div64(uint64(beneficiaries))
	addr := pub.Address()
	for i := 0; i < beneficiaries; i++ {
		txn.Outputs = append(txn.Outputs, instacoin.Beneficiary{
			Value:   value,
			Address: addr,
		})
	}
	txid := txn.ID()
	for i, o := range txn.Outputs {
		outputs = append(outputs, instacoin.Output{
			ID: instacoin.OutputID{
				TransactionID: txid,
				Index:         uint64(i),
			},
			Value:     o.Value,
			Address:   o.Address,
			LeafIndex: instacoin.EphemeralLeafIndex,
		})
	}
	return
}

func TestMineBlock(t *testing.T) {
	pub, priv := testingKeypair()
	beneficiaries := make([]instacoin.Beneficiary, 5)
	for i := 0; i < len(beneficiaries); i++ {
		beneficiaries[i].Value = instacoin.BaseUnitsPerCoin
		beneficiaries[i].Address = pub.Address()
	}
	genesis := genesisWithBeneficiaries(beneficiaries...)
	update := consensus.GenesisUpdate(genesis, testingDifficulty)
	vc := update.Context
	outputs := update.NewOutputs[1:]
	tp := txpool.New(vc)
	miner := New(vc, pub.Address(), tp, CPU)

	fundTxn := func(inputs, beneficiaries int) instacoin.Transaction {
		txn, created := buildTransaction(pub, outputs[:inputs], beneficiaries)
		outputs = append(outputs[inputs:], created...)
		signAllInputs(&txn, vc, priv)
		return txn
	}

	// Add 10 transactions that spend 1 output each. Half of these transactions
	// will spend ephemeral outputs.
	for i := 0; i < 10; i++ {
		if err := tp.AddTransaction(fundTxn(1, 1)); err != nil {
			t.Fatalf("failed to add transaction: %s", err)
		}
	}
	block := miner.MineBlock()
	if len(block.Transactions) != 10 {
		t.Fatalf("expected 10 transactions, got %d", len(block.Transactions))
	}
	if err := vc.ValidateBlock(block); err != nil {
		t.Fatalf("block failed validation: %s", err)
	}

	// Create a transaction that will be dependent on 2 parents.
	if err := tp.AddTransaction(fundTxn(2, 2)); err != nil {
		t.Fatalf("failed to add transaction: %s", err)
	}
	block = miner.MineBlock()
	if len(block.Transactions) != 11 {
		t.Fatalf("expected 11 transactions, got %d", len(block.Transactions))
	}
	if err := vc.ValidateBlock(block); err != nil {
		t.Fatalf("block failed validation: %s", err)
	}

	// Create a transaction that will be dependent on all of our previous
	// transactions.
	if err := tp.AddTransaction(fundTxn(len(outputs), 1)); err != nil {
		t.Fatalf("failed to add transaction: %s", err)
	}

	block = miner.MineBlock()
	if len(block.Transactions) != 12 {
		t.Fatalf("expected 12 transactions, got %d", len(block.Transactions))
	}
	if err := vc.ValidateBlock(block); err != nil {
		t.Fatalf("block failed validation: %s", err)
	}
}

func BenchmarkTransactions(b *testing.B) {
	pub, priv := testingKeypair()
	beneficiaries := make([]instacoin.Beneficiary, 150)
	for i := 0; i < len(beneficiaries); i++ {
		beneficiaries[i].Value = instacoin.BaseUnitsPerCoin
		beneficiaries[i].Address = pub.Address()
	}
	genesis := genesisWithBeneficiaries(beneficiaries...)
	update := consensus.GenesisUpdate(genesis, testingDifficulty)
	vc := update.Context
	outputs := update.NewOutputs[1:]
	tp := txpool.New(vc)
	miner := New(vc, pub.Address(), tp, CPU)

	fundTxn := func(inputs, beneficiaries int) instacoin.Transaction {
		txn, created := buildTransaction(pub, outputs[:inputs], beneficiaries)
		outputs = append(outputs[inputs:], created...)
		signAllInputs(&txn, vc, priv)
		return txn
	}

	for i := 0; i < 1000; i++ {
		if err := tp.AddTransaction(fundTxn(1, 1)); err != nil {
			b.Fatalf("failed to add transaction: %s", err)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		miner.txnsForBlock()
	}
}
