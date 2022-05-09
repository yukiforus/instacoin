package wallet_test

import (
	"testing"

	"go.instapay.kr/instacoin"
	"go.instapay.kr/instacoin/chain"
	"go.instapay.kr/instacoin/internal/chainutil"
	"go.instapay.kr/instacoin/internal/walletutil"
	"go.instapay.kr/instacoin/wallet"
)

func TestWallet(t *testing.T) {
	sim := chainutil.NewChainSim()

	cm := chain.NewManager(chainutil.NewEphemeralStore(sim.Genesis), sim.Context)
	store := walletutil.NewEphemeralStore()
	cm.AddSubscriber(store, cm.Tip())
	w := wallet.NewHotWallet(store, wallet.NewSeed())

	// fund the wallet with 100 coins
	ourAddr := w.NextAddress()
	fund := instacoin.Beneficiary{Value: instacoin.BaseUnitsPerCoin.Mul64(100), Address: ourAddr}
	if err := cm.AddTipBlock(sim.MineBlockWithBeneficiaries(fund)); err != nil {
		t.Fatal(err)
	}

	// wallet should now have a transaction, and output, and a non-zero balance
	if len(store.Transactions()) != 1 {
		t.Fatal("expected a single transaction, got", store.Transactions())
	} else if len(store.SpendableOutputs()) != 1 {
		t.Fatal("expected a single spendable output, got", store.SpendableOutputs())
	} else if w.Balance().IsZero() {
		t.Fatal("expected non-zero balance after mining")
	}

	// mine 5 blocks, each containing a transaction that sends some coins to
	// the void and some to ourself
	for i := 0; i < 5; i++ {
		sendAmount := instacoin.BaseUnitsPerCoin.Mul64(7)
		txn := instacoin.Transaction{
			Outputs: []instacoin.Beneficiary{{
				Address: instacoin.VoidAddress,
				Value:   sendAmount,
			}},
		}
		if toSign, _, err := w.FundTransaction(&txn, sendAmount, nil); err != nil {
			t.Fatal(err)
		} else if err := w.SignTransaction(&txn, toSign); err != nil {
			t.Fatal(err)
		}
		prevBalance := w.Balance()

		if err := cm.AddTipBlock(sim.MineBlockWithTxns(txn)); err != nil {
			t.Fatal(err)
		}

		if !prevBalance.Sub(w.Balance()).Equals(sendAmount) {
			t.Fatal("after send, balance should have decreased accordingly")
		}
	}
}
