package txpool_test

import (
	"testing"

	"go.instapay.kr/instacoin"
	"go.instapay.kr/instacoin/chain"
	"go.instapay.kr/instacoin/internal/chainutil"
	"go.instapay.kr/instacoin/txpool"
)

func TestPoolFlexibility(t *testing.T) {
	sim := chainutil.NewChainSim()

	cm := chain.NewManager(chainutil.NewEphemeralStore(sim.Genesis), sim.Context)
	tp := txpool.New(sim.Genesis.Context)
	cm.AddSubscriber(tp, cm.Tip())

	// Create three transactions that are valid as of the current block.
	txns := make([]instacoin.Transaction, 3)
	for i := range txns {
		txns[i] = sim.TxnWithBeneficiaries(instacoin.Beneficiary{Value: instacoin.BaseUnitsPerCoin})
	}

	// Add the first transaction to the pool; it should be accepted.
	if err := tp.AddTransaction(txns[0]); err != nil {
		t.Fatal("pool rejected control transaction:", err)
	}

	// Mine a block and add the second transaction. Its proofs are now outdated,
	// but only by one block, so the pool should still accept it.
	if err := cm.AddTipBlock(sim.MineBlock()); err != nil {
		t.Fatal(err)
	} else if err := tp.AddTransaction(txns[1]); err != nil {
		t.Fatal("pool rejected slightly outdated transaction:", err)
	}

	// Mine another block and add the third transaction. Its proofs are now
	// outdated by two blocks, so the pool should reject it.
	if err := cm.AddTipBlock(sim.MineBlock()); err != nil {
		t.Fatal(err)
	} else if err := tp.AddTransaction(txns[2]); err == nil {
		t.Fatal("pool did not reject very outdated transaction")
	}
}
