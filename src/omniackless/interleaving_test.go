package main

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func flipAad(a []byte) []byte {
	b := append([]byte(nil), a...)
	b[0] ^= 0xFF
	return b
}

func corruptMac(f []byte) []byte {
	c := append([]byte(nil), f...)
	c[len(c)-1] ^= 0xFF
	return c
}

func TestAcklessConcurrentHandleRejectsReplayForged(t *testing.T) {
	rx, aadTx := mkRx(t)
	const n = 2000
	const ep = uint64(7000)
	body := []byte("data")
	good := make([][]byte, n)
	wrongAad := make([][]byte, n)
	forged := make([][]byte, n)
	bad := flipAad(aadTx)
	for i := 0; i < n; i++ {
		good[i] = buildFrame(aadTx, tData, ep, uint32(i+1), body)
		wrongAad[i] = buildFrame(bad, tData, ep, uint32(i+1), body)
		forged[i] = corruptMac(buildFrame(aadTx, tData, ep, uint32(i+1), body))
	}
	var wg sync.WaitGroup
	for g := 0; g < 6; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < n; i++ {
				rx.handle(good[i])
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			rx.handle(wrongAad[i])
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			rx.handle(forged[i])
		}
	}()
	wg.Wait()
	if d := atomic.LoadUint64(&rx.nDeliv); d != n {
		t.Fatalf("exactly-once under concurrency violated: delivered %d, want %d", d, n)
	}
	if af := atomic.LoadUint64(&rx.nAuthFail); af == 0 {
		t.Fatalf("forged/misdirected frames must fail MAC verification; nAuthFail=0")
	}
}

func TestAcklessEpochMonotonicOneSidedRestart(t *testing.T) {
	rx, aadTx := mkRx(t)
	const e1 = uint64(7000)
	const e2 = uint64(9000)
	body := []byte("d")
	rx.handle(buildFrame(aadTx, tData, e2, 1, body))
	if atomic.LoadUint64(&rx.nDeliv) != 1 {
		t.Fatalf("setup: first live-epoch frame should deliver; nDeliv=%d", rx.nDeliv)
	}
	const n = 1500
	stale := make([][]byte, n)
	fresh := make([][]byte, n)
	for i := 0; i < n; i++ {
		stale[i] = buildFrame(aadTx, tData, e1, uint32(i+1), body)
		fresh[i] = buildFrame(aadTx, tData, e2, uint32(i+2), body)
	}
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < n; i++ {
				rx.handle(stale[i])
			}
		}()
	}
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < n; i++ {
				rx.handle(fresh[i])
			}
		}()
	}
	wg.Wait()
	rx.eg.mu.Lock()
	floor := rx.eg.floor
	rx.eg.mu.Unlock()
	if floor != e2 {
		t.Fatalf("epoch floor must stay monotonic at %d, got %d", e2, floor)
	}
	rx.mu.Lock()
	ce := rx.curEpoch
	rx.mu.Unlock()
	if ce != e2 {
		t.Fatalf("curEpoch must remain the live epoch %d, got %d", e2, ce)
	}
	if d := atomic.LoadUint64(&rx.nDeliv); d != uint64(n+1) {
		t.Fatalf("exactly-once across a one-sided restart violated: delivered %d, want %d", d, n+1)
	}
	if r := atomic.LoadUint64(&rx.nReplay); r == 0 {
		t.Fatalf("stale old-epoch frames after the restart must be rejected as replay; nReplay=0")
	}
}

func TestAcklessCtrlNonceMonotonicUnderConcurrency(t *testing.T) {
	rx, aadTx := mkRx(t)
	const ep = uint64(7000)
	rx.handle(buildFrame(aadTx, tData, ep, 1, []byte("d")))
	const n = 2000
	acks := make([][]byte, n)
	cum := make([]byte, 4)
	for i := 0; i < n; i++ {
		acks[i] = buildFrame(aadTx, tAck, ep, uint32(i+1), cum)
	}
	var wg sync.WaitGroup
	for g := 0; g < 6; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < n; i++ {
				rx.handle(acks[i])
			}
		}()
	}
	wg.Wait()
	rx.mu.Lock()
	nonce := rx.rxAckNonce
	rx.mu.Unlock()
	if nonce != uint32(n) {
		t.Fatalf("control nonce must advance monotonically to the max under concurrency: got %d want %d", nonce, n)
	}
	if atomic.LoadUint64(&rx.nCtrlDrop) == 0 {
		t.Fatalf("out-of-order control frames must be dropped by the nonce gate; nCtrlDrop=0")
	}
}

func TestAcklessTxbufSendAckInterleaved(t *testing.T) {
	snd, err := newSender(ip4("10.0.0.1"), ip4("10.0.0.2"), 49001, 49002)
	if err != nil {
		t.Skip("raw socket needs root:", err)
	}
	tx := newTxbuf(snd, aadFor(0, ip4("10.0.0.1"), 49001, ip4("10.0.0.2"), 49002))
	sb := &sendBase{path: t.TempDir() + "/base"}
	if !tx.initSendBase(sb, 0) {
		t.Fatal("initSendBase failed")
	}
	const base = uint32(65536)
	const total = 8000
	var rwg sync.WaitGroup
	stop := make(chan struct{})
	rwg.Add(1)
	go func() {
		defer rwg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			tx.mu.Lock()
			ls := tx.lastSent
			tx.mu.Unlock()
			tx.setAckedCum(ls)
		}
	}()
	rwg.Add(1)
	go func() {
		defer rwg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			tx.mu.Lock()
			_ = tx.seq - tx.ackedCum
			_ = tx.lastSent
			tx.mu.Unlock()
		}
	}()
	done := make(chan struct{})
	go func() {
		for i := 0; i < total; i++ {
			tx.sendData(make([]byte, 40))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		close(stop)
		rwg.Wait()
		t.Fatal("writer blocked: send window never drained under concurrency (deadlock)")
	}
	close(stop)
	rwg.Wait()
	tx.mu.Lock()
	ls := tx.lastSent
	tx.mu.Unlock()
	tx.setAckedCum(ls)
	tx.mu.Lock()
	seq := tx.seq
	acked := tx.ackedCum
	tx.mu.Unlock()
	if seq != base+total {
		t.Fatalf("every sendData must take a unique seq (none lost/overwritten under concurrent ack ingest): seq=%d want %d", seq, base+total)
	}
	if acked != seq {
		t.Fatalf("after acking lastSent, ackedCum=%d must equal seq=%d (window fully drained)", acked, seq)
	}
}
