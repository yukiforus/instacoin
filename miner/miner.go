// Package miner provides a basic miner for instacoin, suitable for testing and as
// a basis for more sophisticated implementations.
package miner

import (
	"crypto/rand"
	"sync"
	"time"
	"unsafe"

	"go.instapay.kr/instacoin"
	"go.instapay.kr/instacoin/chain"
	"go.instapay.kr/instacoin/consensus"
	"go.instapay.kr/instacoin/txpool"
)

// A NonceGrinder sets the value of h.Nonce such that h.ID().MeetsTarget(target)
// returns true.
type NonceGrinder interface {
	GrindNonce(h *instacoin.BlockHeader, target instacoin.BlockID)
}

// A Miner mines blocks.
type Miner struct {
	genesis instacoin.Block
	addr    instacoin.Address
	tp      *txpool.Pool
	grinder NonceGrinder

	mu    sync.Mutex
	vc    consensus.ValidationContext
	mined int
	rate  float64
}

// Stats reports various mining statistics.
func (m *Miner) Stats() (mined int, rate float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mined, m.rate
}

func (m *Miner) txnsForBlock() (blockTxns []instacoin.Transaction) {
	poolTxns := make(map[instacoin.TransactionID]instacoin.Transaction)
	for _, txn := range m.tp.Transactions() {
		poolTxns[txn.ID()] = txn
	}

	// define a helper function that returns the unmet dependencies of a given
	// transaction
	calcDeps := func(txn instacoin.Transaction) (deps []instacoin.Transaction) {
		added := make(map[instacoin.TransactionID]bool)
		var addDeps func(txn instacoin.Transaction)
		addDeps = func(txn instacoin.Transaction) {
			added[txn.ID()] = true
			for _, in := range txn.Inputs {
				parentID := in.Parent.ID.TransactionID
				if parent, inPool := poolTxns[parentID]; inPool && !added[parentID] {
					// NOTE: important that we add the parent's deps before the
					// parent itself
					addDeps(parent)
					deps = append(deps, parent)
				}
			}
			return
		}
		addDeps(txn)
		return
	}

	capacity := m.vc.MaxBlockWeight()
	for _, txn := range poolTxns {
		// prepend the txn with its dependencies
		group := append(calcDeps(txn), txn)
		// if the weight of the group exceeds the remaining capacity of the
		// block, skip it
		groupWeight := m.vc.BlockWeight(group)
		if groupWeight > capacity {
			continue
		}
		// add the group to the block
		blockTxns = append(blockTxns, group...)
		capacity -= groupWeight
		for _, txn := range group {
			delete(poolTxns, txn.ID())
		}
	}

	return
}

// MineBlock mines a valid block, using transactions drawn from the txpool.
func (m *Miner) MineBlock() instacoin.Block {
	for {
		// TODO: if the miner and txpool don't have the same tip, we'll
		// construct an invalid block
		m.mu.Lock()
		parent := m.vc.Index
		target := instacoin.HashRequiringWork(m.vc.Difficulty)
		addr := m.addr
		txns := m.txnsForBlock()
		commitment := m.vc.Commitment(addr, txns)
		m.mu.Unlock()
		b := instacoin.Block{
			Header: instacoin.BlockHeader{
				Height:       parent.Height + 1,
				ParentID:     parent.ID,
				Timestamp:    instacoin.CurrentTimestamp(),
				Commitment:   commitment,
				MinerAddress: addr,
			},
			Transactions: txns,
		}
		rand.Read(b.Header.Nonce[:])

		// grind
		start := time.Now()
		m.grinder.GrindNonce(&b.Header, target)
		elapsed := time.Since(start)

		// update stats, and check whether the tip has changed since we started
		// grinding; if it has, we need to start over
		m.mu.Lock()
		m.mined++
		m.rate = 1 / elapsed.Seconds()
		tipChanged := m.vc.Index != parent
		m.mu.Unlock()
		if !tipChanged {
			return b
		}
	}
}

// ProcessChainApplyUpdate implements chain.Subscriber.
func (m *Miner) ProcessChainApplyUpdate(cau *chain.ApplyUpdate, _ bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.vc = cau.Context
	return nil
}

// ProcessChainRevertUpdate implements chain.Subscriber.
func (m *Miner) ProcessChainRevertUpdate(cru *chain.RevertUpdate) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.vc = cru.Context
	return nil
}

// New returns a Miner initialized with the provided state.
func New(vc consensus.ValidationContext, addr instacoin.Address, tp *txpool.Pool, ng NonceGrinder) *Miner {
	return &Miner{
		vc:      vc,
		addr:    addr,
		tp:      tp,
		grinder: ng,
	}
}

// CPU grinds nonces with a single CPU thread.
var CPU cpuGrinder

type cpuGrinder struct{}

// GrindNonce implements NonceGrinder.
func (cpuGrinder) GrindNonce(h *instacoin.BlockHeader, target instacoin.BlockID) {
	for !h.ID().MeetsTarget(target) {
		// NOTE: an unsafe cast is fine here; we don't care about endianness,
		// only that the nonce is changing
		*(*uint64)(unsafe.Pointer(&h.Nonce))++
	}
}
