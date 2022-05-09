package consensus

import (
	"crypto/ed25519"
	"testing"
	"time"

	"go.instapay.kr/instacoin"
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

func signAllInputs(txn *instacoin.Transaction, vc ValidationContext, priv ed25519.PrivateKey) {
	sigHash := vc.SigHash(*txn)
	for i := range txn.Inputs {
		txn.Inputs[i].Signature = instacoin.SignTransaction(priv, sigHash)
	}
}

func TestEphemeralOutputs(t *testing.T) {
	pubkey, privkey := testingKeypair()
	sau := GenesisUpdate(genesisWithBeneficiaries(instacoin.Beneficiary{
		Address: pubkey.Address(),
		Value:   instacoin.BaseUnitsPerCoin,
	}), testingDifficulty)

	// create an ephemeral output
	parentTxn := instacoin.Transaction{
		Inputs: []instacoin.Input{{
			Parent:    sau.NewOutputs[1],
			PublicKey: pubkey,
		}},
		Outputs: []instacoin.Beneficiary{{
			Address: pubkey.Address(),
			Value:   instacoin.BaseUnitsPerCoin,
		}},
	}
	signAllInputs(&parentTxn, sau.Context, privkey)
	ephemeralOutput := instacoin.Output{
		ID: instacoin.OutputID{
			TransactionID: parentTxn.ID(),
			Index:         0,
		},
		Value:     parentTxn.Outputs[0].Value,
		Address:   pubkey.Address(),
		LeafIndex: instacoin.EphemeralLeafIndex,
	}

	// create a transaction that spends the ephemeral output
	childTxn := instacoin.Transaction{
		Inputs: []instacoin.Input{{
			Parent:    ephemeralOutput,
			PublicKey: pubkey,
		}},
		Outputs: []instacoin.Beneficiary{{
			Address: pubkey.Address(),
			Value:   ephemeralOutput.Value,
		}},
	}
	signAllInputs(&childTxn, sau.Context, privkey)

	// the transaction set should be valid
	err := sau.Context.ValidateTransactionSet([]instacoin.Transaction{parentTxn, childTxn})
	if err != nil {
		t.Fatal(err)
	}

	// change the value of the output and attempt to spend it
	mintTxn := childTxn.DeepCopy()
	mintTxn.Inputs[0].Parent.Value = instacoin.BaseUnitsPerCoin.Mul64(1e6)
	mintTxn.Outputs[0].Value = mintTxn.Inputs[0].Parent.Value
	signAllInputs(&mintTxn, sau.Context, privkey)

	err = sau.Context.ValidateTransactionSet([]instacoin.Transaction{parentTxn, mintTxn})
	if err == nil {
		t.Fatal("ephemeral output with wrong value should be rejected")
	}

	// add another transaction to the set that double-spends the output
	doubleSpendTxn := childTxn.DeepCopy()
	doubleSpendTxn.Outputs[0].Address = instacoin.VoidAddress
	signAllInputs(&doubleSpendTxn, sau.Context, privkey)

	err = sau.Context.ValidateTransactionSet([]instacoin.Transaction{parentTxn, childTxn, doubleSpendTxn})
	if err == nil {
		t.Fatal("ephemeral output double-spend not rejected")
	}
}
