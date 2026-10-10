package main

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func setTestKey(s string) {
	k := sha256.Sum256([]byte(s))
	macKey = k[:]
}

func buildFrame(aad []byte, typ byte, ep uint64, seq uint32, body []byte) []byte {
	p := make([]byte, hdrLen+len(body)+macLen)
	putHdr(p, typ, ep, seq, uint16(len(body)))
	copy(p[hdrLen:], body)
	frameMac(aad, p)
	return p
}

func verifyFrame(aad, f []byte) bool {
	plen := int(binary.BigEndian.Uint16(f[16:]))
	return verifyMac(aad, f[:hdrLen+plen], f[hdrLen+plen:hdrLen+plen+macLen])
}

func TestMacAndDirectionBinding(t *testing.T) {
	setTestKey("testpsk")
	cIP := ip4("10.0.0.1")
	sIP := ip4("10.0.0.2")
	aadClientTx := aadFor(0, cIP, 49001, sIP, 49002)
	aadServerRx := aadFor(0, cIP, 49001, sIP, 49002)
	aadClientRx := aadFor(1, sIP, 49003, cIP, 49004)
	body := []byte("inner-ip-packet-payload")
	f := buildFrame(aadClientTx, tData, 100, 7, body)

	if !verifyFrame(aadServerRx, f) {
		t.Fatal("valid client->server frame must verify at server rx")
	}
	if verifyFrame(aadClientRx, f) {
		t.Fatal("REFLECTED frame (opposite direction) must NOT verify")
	}
	wrongTuple := aadFor(0, cIP, 49005, sIP, 49006)
	if verifyFrame(wrongTuple, f) {
		t.Fatal("frame with different outer 5-tuple must NOT verify")
	}
	f2 := buildFrame(aadClientTx, tData, 100, 7, body)
	f2[hdrLen+3] ^= 0xFF
	if verifyFrame(aadServerRx, f2) {
		t.Fatal("corrupted body must fail MAC")
	}
	f3 := buildFrame(aadClientTx, tData, 100, 7, body)
	f3[12] ^= 0x01
	if verifyFrame(aadServerRx, f3) {
		t.Fatal("tampered seq must fail MAC")
	}
}

func TestReplayWindowFormula(t *testing.T) {
	maxSeq := uint32(200000)
	if !(int32(maxSeq-uint32(200)) >= arqW) {
		t.Fatal("seq 200 vs max 200000 must be outside replay window")
	}
	if int32(maxSeq-uint32(200000-100)) >= arqW {
		t.Fatal("seq within 100 of max must be inside window")
	}
}

func TestEpochAndNonceMonotonic(t *testing.T) {
	if !(uint64(2000) > uint64(1000)) {
		t.Fatal("newer epoch greater -> adopt")
	}
	if !(uint64(1000) < uint64(2000)) {
		t.Fatal("older epoch lesser -> stale reject")
	}
	last := uint32(5)
	if !seqGt(6, last) {
		t.Fatal("nonce 6 after 5 accepted")
	}
	if seqGt(5, last) {
		t.Fatal("nonce 5 replay rejected")
	}
	if seqGt(4, last) {
		t.Fatal("nonce 4 replay rejected")
	}
}

func TestFprogLayout(t *testing.T) {
	want := 16
	if unsafe.Sizeof(uintptr(0)) == 4 {
		want = 8
	}
	prog := bpfProg(ip4("10.0.0.2"), ip4("10.0.0.1"), 49003, 49004)
	ptr := uintptr(unsafe.Pointer(&prog[0]))
	var buf []byte
	if unsafe.Sizeof(uintptr(0)) == 8 {
		buf = make([]byte, 16)
		binary.LittleEndian.PutUint16(buf[0:], uint16(len(prog)))
		binary.LittleEndian.PutUint64(buf[8:], uint64(ptr))
	} else {
		buf = make([]byte, 8)
		binary.LittleEndian.PutUint16(buf[0:], uint16(len(prog)))
		binary.LittleEndian.PutUint32(buf[4:], uint32(ptr))
	}
	if len(buf) != want {
		t.Fatalf("sock_fprog size %d, want %d for this arch", len(buf), want)
	}
	if binary.LittleEndian.Uint16(buf[0:]) != uint16(len(prog)) {
		t.Fatal("fprog length field wrong")
	}
}

func TestAttachFilterFunctional(t *testing.T) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(0x0003)))
	if err != nil {
		t.Skip("AF_PACKET needs root/CAP_NET_RAW:", err)
	}
	defer syscall.Close(fd)
	if err := attachFilter(fd, bpfProg(ip4("10.0.0.2"), ip4("10.0.0.1"), 49003, 49004)); err != nil {
		t.Fatal("attachFilter failed:", err)
	}
}

func TestHandleRejectPaths(t *testing.T) {
	setTestKey("testpsk")
	devnull, err := syscall.Open("/dev/null", syscall.O_WRONLY, 0)
	if err != nil {
		t.Skip("cannot open /dev/null")
	}
	defer syscall.Close(devnull)
	snd, err := newSender(ip4("10.0.0.1"), ip4("10.0.0.2"), 49001, 49002)
	if err != nil {
		t.Skip("raw socket needs root:", err)
	}
	cIP := ip4("10.0.0.1")
	sIP := ip4("10.0.0.2")
	aadClientTx := aadFor(0, cIP, 49001, sIP, 49002)
	aadServerRx := aadFor(0, cIP, 49001, sIP, 49002)
	tx := newTxbuf(snd, aadFor(1, sIP, 49003, cIP, 49004))
	rx := newArqRx(devnull, snd, tx, aadServerRx, aadFor(1, sIP, 49003, cIP, 49004), nil)
	body := []byte("hello-inner-packet")

	rx.handle(buildFrame(aadClientTx, tData, 1000, 100, body))
	if rx.nDeliv != 1 {
		t.Fatalf("valid frame: nDeliv=%d want 1", rx.nDeliv)
	}
	rx.handle(buildFrame(aadClientTx, tData, 1000, 100, body))
	if rx.nDup != 1 {
		t.Fatalf("duplicate frame: nDup=%d want 1", rx.nDup)
	}
	bad := buildFrame(aadClientTx, tData, 1000, 101, body)
	bad[hdrLen] ^= 0xFF
	rx.handle(bad)
	if rx.nAuthFail != 1 {
		t.Fatalf("forged frame: authFail=%d want 1", rx.nAuthFail)
	}
	refl := buildFrame(aadFor(1, sIP, 49003, cIP, 49004), tData, 1000, 102, body)
	rx.handle(refl)
	if rx.nAuthFail != 2 {
		t.Fatalf("reflected frame must be rejected: authFail=%d want 2", rx.nAuthFail)
	}
	rx.handle(buildFrame(aadClientTx, tData, 1000, 500000, body))
	stale := buildFrame(aadClientTx, tData, 1000, 300, body)
	rx.handle(stale)
	if rx.nReplay < 1 {
		t.Fatalf("old-seq frame must be replay-rejected: nReplay=%d", rx.nReplay)
	}
	preReset := rx.nEpochReset
	rx.handle(buildFrame(aadClientTx, tData, 2000, 10, body))
	if rx.nEpochReset != preReset+1 {
		t.Fatalf("higher epoch must reset: epochReset=%d want %d", rx.nEpochReset, preReset+1)
	}
	preReplay := rx.nReplay
	rx.handle(buildFrame(aadClientTx, tData, 1000, 999, body))
	if rx.nReplay != preReplay+1 {
		t.Fatalf("lower-epoch (post-restart) frame must be rejected: nReplay=%d want %d", rx.nReplay, preReplay+1)
	}
	if rx.nDeliv != 3 {
		t.Fatalf("only 3 valid frames should have been delivered: nDeliv=%d", rx.nDeliv)
	}
}

func TestControllerDeltaSaneAcrossShed(t *testing.T) {
	flows := make([]*flow, 6)
	for i := range flows {
		flows[i] = &flow{tx: &txbuf{}, q: make(chan []byte, 1024)}
	}
	sumAll := func() uint64 {
		var d uint64
		for i := 0; i < 6; i++ {
			d += atomic.LoadUint64(&flows[i].tx.nData)
		}
		return d
	}
	for i := 0; i < 6; i++ {
		atomic.StoreUint64(&flows[i].tx.nData, 1000)
	}
	lastData := sumAll()
	atomic.StoreUint64(&flows[0].tx.nData, 1200)
	atomic.StoreUint64(&flows[1].tx.nData, 1200)
	data := sumAll()
	dData := data - lastData
	if int64(dData) < 0 {
		t.Fatalf("controller delta underflowed after shed: %d", dData)
	}
	if dData != 400 {
		t.Fatalf("expected monotonic delta 400 across shed, got %d", dData)
	}
}

func TestNftRangeCoversFmax(t *testing.T) {
	base := 49000
	for _, capN := range []int{1, 2, 6, 24, 25, 100} {
		lo, hi := nftRange(base, capN)
		maxPort := base + 4*capN
		if lo != base {
			t.Fatalf("nft lo %d != base %d", lo, base)
		}
		if hi < maxPort {
			t.Fatalf("Fmax=%d: nft hi %d does not cover max flow port %d", capN, hi, maxPort)
		}
	}
}

func TestSetupNftAbortsOnRuleFailure(t *testing.T) {
	old := nftRun
	defer func() { nftRun = old }()
	var installed, teardowns int
	nftRun = func(args ...string) error {
		if len(args) >= 2 && args[0] == "delete" && args[1] == "table" {
			teardowns++
			return nil
		}
		installed++
		if installed == 3 {
			return fmt.Errorf("simulated nft rule failure")
		}
		return nil
	}
	err := setupNft("10.0.0.2", 49000, 49099)
	if err == nil {
		t.Fatal("setupNft must return an error when an nft RST-drop rule fails to install")
	}
	if teardowns == 0 {
		t.Fatal("setupNft must tear down the partial table when a rule fails")
	}
}

func TestSetupNftSucceedsWhenRulesInstall(t *testing.T) {
	old := nftRun
	defer func() { nftRun = old }()
	nftRun = func(args ...string) error { return nil }
	if err := setupNft("10.0.0.2", 49000, 49099); err != nil {
		t.Fatalf("setupNft must succeed when every rule installs: %v", err)
	}
}

func TestEnqueueBlocksUntilSpaceNeverDrops(t *testing.T) {
	f := &flow{q: make(chan []byte, 1)}
	f.q <- []byte("a")
	done := make(chan struct{})
	go func() {
		f.enqueue([]byte("b"))
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("enqueue completed while the queue stayed full: pre-seq packet dropped instead of backpressured")
	case <-time.After(300 * time.Millisecond):
	}
	if string(<-f.q) != "a" {
		t.Fatal("unexpected queue head")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("enqueue did not complete after space freed")
	}
	if string(<-f.q) != "b" {
		t.Fatal("enqueued packet was lost")
	}
}

func TestDispatchNeverRemapsUnderConcurrentScaling(t *testing.T) {
	capN := 6
	var ip []byte
	for seed := 0; seed < 4096; seed++ {
		p := make([]byte, 24)
		p[0] = 0x45
		p[9] = 6
		binary.BigEndian.PutUint32(p[12:], 0x0a000000|uint32(seed))
		binary.BigEndian.PutUint32(p[16:], 0x5db8d822)
		binary.BigEndian.PutUint16(p[20:], uint16(seed))
		binary.BigEndian.PutUint16(p[22:], 443)
		if flowHash(p)%uint32(capN) != flowHash(p)%1 {
			ip = p
			break
		}
	}
	if ip == nil {
		t.Skip("no ip distinguishing capN vs 1 found")
	}
	want := dispatchIndex(ip, capN)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			atomic.StoreInt32(&activeN, 1)
			atomic.StoreInt32(&activeN, int32(capN))
		}
	}()
	bad := int32(-1)
	for i := 0; i < 500000; i++ {
		if l := dispatchIndex(ip, capN); l != want {
			bad = int32(l)
			break
		}
	}
	close(stop)
	<-done
	if bad >= 0 {
		t.Fatalf("flow remapped from lane %d to lane %d while activeN was being scaled", want, bad)
	}
}

func TestIdleLaneRejectsStaleEpochViaSharedFloor(t *testing.T) {
	setTestKey("testpsk")
	devnull, err := syscall.Open("/dev/null", syscall.O_WRONLY, 0)
	if err != nil {
		t.Skip("no /dev/null")
	}
	defer syscall.Close(devnull)
	snd, err := newSender(ip4("10.0.0.1"), ip4("10.0.0.2"), 49001, 49002)
	if err != nil {
		t.Skip("raw socket needs root:", err)
	}
	cIP := ip4("10.0.0.1")
	sIP := ip4("10.0.0.2")
	aadTx := aadFor(0, cIP, 49001, sIP, 49002)
	shared := &epochGuard{}
	rxA := newArqRx(devnull, snd, newTxbuf(snd, aadFor(1, sIP, 49003, cIP, 49004)), aadTx, aadFor(1, sIP, 49003, cIP, 49004), shared)
	rxB := newArqRx(devnull, snd, newTxbuf(snd, aadFor(1, sIP, 49003, cIP, 49004)), aadTx, aadFor(1, sIP, 49003, cIP, 49004), shared)
	body := []byte("x")

	rxA.handle(buildFrame(aadTx, tData, 2000, 1, body))
	if atomic.LoadUint64(&rxA.nDeliv) != 1 {
		t.Fatalf("current-epoch frame must be delivered on lane A: nDeliv=%d", rxA.nDeliv)
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := uint32(2); i < 2000; i++ {
			rxA.handle(buildFrame(aadTx, tData, 2000, i, body))
		}
	}()
	go func() {
		defer wg.Done()
		stale := buildFrame(aadTx, tData, 1000, 1, body)
		for i := 0; i < 4000; i++ {
			rxB.handle(stale)
		}
	}()
	wg.Wait()

	if atomic.LoadUint64(&rxB.nDeliv) != 0 {
		t.Fatalf("idle lane B must REJECT every stale-epoch replay below the shared floor even under concurrency: nDeliv=%d", rxB.nDeliv)
	}
	if atomic.LoadUint64(&rxB.nReplay) == 0 {
		t.Fatal("stale-epoch replay on idle lane B must be counted as a replay")
	}
}

func TestWriteFailLeavesSeqUnackedForRetransmit(t *testing.T) {
	setTestKey("testpsk")
	good, err := syscall.Open("/dev/null", syscall.O_WRONLY, 0)
	if err != nil {
		t.Skip("no /dev/null")
	}
	defer syscall.Close(good)
	snd, err := newSender(ip4("10.0.0.1"), ip4("10.0.0.2"), 49001, 49002)
	if err != nil {
		t.Skip("raw socket needs root:", err)
	}
	cIP := ip4("10.0.0.1")
	sIP := ip4("10.0.0.2")
	aadTx := aadFor(0, cIP, 49001, sIP, 49002)
	rx := newArqRx(-1, snd, newTxbuf(snd, aadFor(1, sIP, 49003, cIP, 49004)), aadTx, aadFor(1, sIP, 49003, cIP, 49004), nil)
	body := []byte("payload-one")

	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			rx.mu.Lock()
			_ = rx.cumAck
			rx.mu.Unlock()
		}
	}()

	rx.handle(buildFrame(aadTx, tData, 1000, 1, body))
	if atomic.LoadUint64(&rx.nDeliv) != 0 {
		t.Fatalf("failed TUN write must not be counted as delivered: nDeliv=%d", rx.nDeliv)
	}
	rx.mu.Lock()
	c := rx.cumAck
	rx.mu.Unlock()
	if c != 0 {
		t.Fatalf("failed TUN write must NOT advance cumAck: cumAck=%d", c)
	}

	rx.tunFD = good
	rx.handle(buildFrame(aadTx, tData, 1000, 1, body))
	if atomic.LoadUint64(&rx.nDeliv) != 1 {
		t.Fatalf("retransmit after a failed write must be delivered: nDeliv=%d", rx.nDeliv)
	}
	if atomic.LoadUint64(&rx.nDup) != 0 {
		t.Fatalf("retransmit after a FAILED write must NOT be dropped as duplicate: nDup=%d", rx.nDup)
	}
	rx.mu.Lock()
	c = rx.cumAck
	rx.mu.Unlock()
	if c != 1 {
		t.Fatalf("after a successful write cumAck must advance to 1: cumAck=%d", c)
	}
	close(stop)
	<-done
}

func TestInitialGapRecordedWhenFirstSeqLost(t *testing.T) {
	setTestKey("testpsk")
	devnull, err := syscall.Open("/dev/null", syscall.O_WRONLY, 0)
	if err != nil {
		t.Skip("no /dev/null")
	}
	defer syscall.Close(devnull)
	snd, err := newSender(ip4("10.0.0.1"), ip4("10.0.0.2"), 49001, 49002)
	if err != nil {
		t.Skip("raw socket needs root:", err)
	}
	cIP := ip4("10.0.0.1")
	sIP := ip4("10.0.0.2")
	aadTx := aadFor(0, cIP, 49001, sIP, 49002)
	rx := newArqRx(devnull, snd, newTxbuf(snd, aadFor(1, sIP, 49003, cIP, 49004)), aadTx, aadFor(1, sIP, 49003, cIP, 49004), nil)
	body := []byte("second-packet")

	rx.handle(buildFrame(aadTx, tData, 1000, 2, body))
	rx.mu.Lock()
	_, missing1 := rx.miss[1]
	nmiss := len(rx.miss)
	ms := rx.maxSeq
	rx.mu.Unlock()
	if !missing1 {
		t.Fatalf("epoch-start gap: seq 1 lost before first-seen seq 2 must be recorded missing (miss=%d maxSeq=%d)", nmiss, ms)
	}

	rx.handle(buildFrame(aadTx, tData, 1000, 1, body))
	rx.mu.Lock()
	_, stillMissing := rx.miss[1]
	cum := rx.cumAck
	rx.mu.Unlock()
	if stillMissing {
		t.Fatal("after seq 1 is retransmitted it must be cleared from the missing set")
	}
	if cum != 2 {
		t.Fatalf("after seq 1 and 2 received cumAck must be 2: %d", cum)
	}
}

func TestReorderInitialGapDeliveredWhenFirstSeqLost(t *testing.T) {
	setTestKey("testpsk")
	old := *reorderMs
	*reorderMs = 20
	defer func() { *reorderMs = old }()
	devnull, err := syscall.Open("/dev/null", syscall.O_WRONLY, 0)
	if err != nil {
		t.Skip("no /dev/null")
	}
	defer syscall.Close(devnull)
	snd, err := newSender(ip4("10.0.0.1"), ip4("10.0.0.2"), 49001, 49002)
	if err != nil {
		t.Skip("raw socket needs root:", err)
	}
	cIP := ip4("10.0.0.1")
	sIP := ip4("10.0.0.2")
	aadTx := aadFor(0, cIP, 49001, sIP, 49002)
	rx := newArqRx(devnull, snd, newTxbuf(snd, aadFor(1, sIP, 49003, cIP, 49004)), aadTx, aadFor(1, sIP, 49003, cIP, 49004), nil)
	body := []byte("payload")

	rx.handle(buildFrame(aadTx, tData, 1000, 2, body))
	if atomic.LoadUint64(&rx.nDeliv) != 0 {
		t.Fatalf("reorder: seq 2 must be buffered until the lost seq 1 fills the hole: nDeliv=%d", rx.nDeliv)
	}
	rx.handle(buildFrame(aadTx, tData, 1000, 1, body))
	if atomic.LoadUint64(&rx.nDeliv) != 2 {
		t.Fatalf("reorder: retransmit of the lost first seq must deliver it then drain seq 2: nDeliv=%d", rx.nDeliv)
	}
}

func TestReorderWriteFailLeavesSeqUnacked(t *testing.T) {
	setTestKey("testpsk")
	old := *reorderMs
	*reorderMs = 20
	defer func() { *reorderMs = old }()
	good, err := syscall.Open("/dev/null", syscall.O_WRONLY, 0)
	if err != nil {
		t.Skip("no /dev/null")
	}
	defer syscall.Close(good)
	snd, err := newSender(ip4("10.0.0.1"), ip4("10.0.0.2"), 49001, 49002)
	if err != nil {
		t.Skip("raw socket needs root:", err)
	}
	cIP := ip4("10.0.0.1")
	sIP := ip4("10.0.0.2")
	aadTx := aadFor(0, cIP, 49001, sIP, 49002)
	rx := newArqRx(-1, snd, newTxbuf(snd, aadFor(1, sIP, 49003, cIP, 49004)), aadTx, aadFor(1, sIP, 49003, cIP, 49004), nil)
	body := []byte("payload")

	rx.handle(buildFrame(aadTx, tData, 1000, 1, body))
	if atomic.LoadUint64(&rx.nDeliv) != 0 {
		t.Fatalf("reorder: a failed TUN write must not be counted as delivered: nDeliv=%d", rx.nDeliv)
	}
	rx.mu.Lock()
	c := rx.cumAck
	rx.mu.Unlock()
	if c != 0 {
		t.Fatalf("reorder: a failed TUN write must not advance cumAck: cumAck=%d", c)
	}
	rx.tunFD = good
	rx.handle(buildFrame(aadTx, tData, 1000, 1, body))
	if atomic.LoadUint64(&rx.nDeliv) != 1 {
		t.Fatalf("reorder: retransmit after a failed write must be delivered: nDeliv=%d", rx.nDeliv)
	}
	rx.mu.Lock()
	c = rx.cumAck
	rx.mu.Unlock()
	if c != 1 {
		t.Fatalf("reorder: cumAck must advance only after a successful write: cumAck=%d", c)
	}
}

func mkRx(t *testing.T) (*arqRx, []byte) { return mkRxG(t, nil) }

func mkRxG(t *testing.T, eg *epochGuard) (*arqRx, []byte) {
	t.Helper()
	setTestKey("testpsk")
	devnull, err := syscall.Open("/dev/null", syscall.O_WRONLY, 0)
	if err != nil {
		t.Skip("no /dev/null")
	}
	t.Cleanup(func() { syscall.Close(devnull) })
	snd, err := newSender(ip4("10.0.0.1"), ip4("10.0.0.2"), 49001, 49002)
	if err != nil {
		t.Skip("raw socket needs root:", err)
	}
	cIP := ip4("10.0.0.1")
	sIP := ip4("10.0.0.2")
	aadTx := aadFor(0, cIP, 49001, sIP, 49002)
	rx := newArqRx(devnull, snd, newTxbuf(snd, aadFor(1, sIP, 49003, cIP, 49004)), aadTx, aadFor(1, sIP, 49003, cIP, 49004), eg)
	return rx, aadTx
}

func TestGuardBoundAtConstructionNoStartupWindow(t *testing.T) {
	path := t.TempDir() + "/floor"
	if err := os.WriteFile(path, []byte("5000\n"), 0600); err != nil {
		t.Skip("cannot write temp floor")
	}
	eg := &epochGuard{}
	eg.load(path)
	rx, aadTx := mkRxG(t, eg)
	rx.handle(buildFrame(aadTx, tData, 3000, 1, []byte("old")))
	if atomic.LoadUint64(&rx.nDeliv) != 0 {
		t.Fatalf("a flow constructed with the shared loaded guard must reject an old-epoch frame from the first packet (no startup floor-0 window): nDeliv=%d", rx.nDeliv)
	}
}

func TestFloorPersistFailClosed(t *testing.T) {
	eg := &epochGuard{}
	eg.load("/proc/omnitunnel-nonexistent-dir/floor")
	if eg.admit(5000) {
		t.Fatal("admit must fail closed when the floor cannot be persisted durably")
	}
	eg.mu.Lock()
	f := eg.floor
	eg.mu.Unlock()
	if f != 0 {
		t.Fatalf("floor must not advance when persist fails: %d", f)
	}
}

func TestFloorConcurrentAdmitsConverge(t *testing.T) {
	path := t.TempDir() + "/floor"
	eg := &epochGuard{}
	eg.load(path)
	var wg sync.WaitGroup
	for _, e := range []uint64{7000, 5000, 9000, 6000, 8000, 9000, 5500} {
		wg.Add(1)
		go func(e uint64) { defer wg.Done(); eg.admit(e) }(e)
	}
	wg.Wait()
	eg.mu.Lock()
	mem := eg.floor
	eg.mu.Unlock()
	if mem != 9000 {
		t.Fatalf("concurrent admits must converge to the max: %d", mem)
	}
	b, _ := os.ReadFile(path)
	var disk uint64
	fmt.Sscan(string(b), &disk)
	if disk != mem {
		t.Fatalf("persisted floor %d must equal in-memory floor %d (serialized, no out-of-order persist)", disk, mem)
	}
}

func TestFloorEnforcedOnAlreadyActiveLane(t *testing.T) {
	shared := &epochGuard{}
	rxA, aadTx := mkRxG(t, shared)
	rxA.handle(buildFrame(aadTx, tData, 7000, 1, []byte("a")))
	if atomic.LoadUint64(&rxA.nDeliv) != 1 {
		t.Fatalf("setup: epoch 7000 should deliver on lane A: nDeliv=%d", rxA.nDeliv)
	}
	shared.admit(9000)
	rxA.handle(buildFrame(aadTx, tData, 7000, 2, []byte("a2")))
	if atomic.LoadUint64(&rxA.nDeliv) != 1 {
		t.Fatalf("lane A must reject its old epoch after the shared floor advanced past it: nDeliv=%d", rxA.nDeliv)
	}
	if atomic.LoadUint64(&rxA.nReplay) == 0 {
		t.Fatal("the stale-epoch frame on the active lane must be counted as replay")
	}
}

func TestEpochAdoptionPersistsFloorOnly(t *testing.T) {
	path := t.TempDir() + "/floor"
	eg := &epochGuard{}
	eg.load(path)
	if !eg.admit(9000) {
		t.Fatal("admit should succeed")
	}
	b, _ := os.ReadFile(path)
	lines := len(strings.Split(strings.TrimSpace(string(b)), "\n"))
	if lines != 1 {
		t.Fatalf("epoch adoption must persist the floor ONLY (no per-lane cumAck to poison a restart): file=%q", string(b))
	}
}

func TestReorderStaleBatchNotCommittedAfterEpochChange(t *testing.T) {
	rx, _ := mkRx(t)
	rx.mu.Lock()
	rx.gen = 5
	rx.mu.Unlock()
	batch := []dentry{{seq: 10, body: []byte("x")}, {seq: 11, body: []byte("y")}}
	rx.mu.Lock()
	rx.gen = 6
	rx.mu.Unlock()
	n := rx.flushDeliver(batch, 5)
	if n != 0 {
		t.Fatalf("a delivery batch from a superseded epoch (built at gen 5, now gen 6) must not be written/committed: delivered=%d", n)
	}
	if atomic.LoadUint64(&rx.nDeliv) != 0 {
		t.Fatal("a superseded-epoch batch must not count as delivered")
	}
}

func TestFlushDeliverHoldsLockAcrossWrite(t *testing.T) {
	rx, _ := mkRx(t)
	rx.mu.Lock()
	rx.gen = 7
	rx.mu.Unlock()
	writing := make(chan struct{})
	release := make(chan struct{})
	rx.wr = func(b []byte) error {
		close(writing)
		<-release
		return nil
	}
	batch := []dentry{{seq: 1, body: []byte("x")}}
	go rx.flushDeliver(batch, 7)
	<-writing
	locked := make(chan struct{})
	go func() {
		rx.mu.Lock()
		close(locked)
		rx.mu.Unlock()
	}()
	select {
	case <-locked:
		t.Fatal("flushDeliver must hold r.mu across the TUN write so an epoch adoption cannot interleave and a superseded-epoch batch cannot be written")
	case <-time.After(150 * time.Millisecond):
	}
	close(release)
	<-locked
}

func TestAckAdvancesWindowNoWedge(t *testing.T) {
	snd, err := newSender(ip4("10.0.0.1"), ip4("10.0.0.2"), 49001, 49002)
	if err != nil {
		t.Skip("raw socket needs root:", err)
	}
	tx := newTxbuf(snd, aadFor(0, ip4("10.0.0.1"), 49001, ip4("10.0.0.2"), 49002))
	tx.mu.Lock()
	tx.seq = txWindow
	tx.lastSent = txWindow
	tx.ackedCum = 0
	tx.mu.Unlock()
	done := make(chan struct{})
	go func() { tx.sendData([]byte("x")); close(done) }()
	select {
	case <-done:
		t.Fatal("sendData must block while the unacked window is full")
	case <-time.After(100 * time.Millisecond):
	}
	tx.setAckedCum(1)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("any peer's ACK must advance the window so the sender never wedges, regardless of version")
	}
}

func TestAckRejectsCumBeyondLastSent(t *testing.T) {
	snd, err := newSender(ip4("10.0.0.1"), ip4("10.0.0.2"), 49001, 49002)
	if err != nil {
		t.Skip("raw socket needs root:", err)
	}
	tx := newTxbuf(snd, aadFor(0, ip4("10.0.0.1"), 49001, ip4("10.0.0.2"), 49002))
	tx.mu.Lock()
	tx.seq = 100
	tx.lastSent = 100
	tx.ackedCum = 0
	tx.mu.Unlock()
	tx.setAckedCum(100000)
	tx.mu.Lock()
	a := tx.ackedCum
	tx.mu.Unlock()
	if a != 0 {
		t.Fatalf("an ACK with a cumulative beyond lastSent must be rejected: ackedCum=%d", a)
	}
	tx.setAckedCum(50)
	tx.mu.Lock()
	a = tx.ackedCum
	tx.mu.Unlock()
	if a != 50 {
		t.Fatalf("an ACK within lastSent must advance: ackedCum=%d", a)
	}
}

func TestDelayedOldEpochAckDoesNotWedgeLegacyFlow(t *testing.T) {
	rx, aadIn := mkRx(t)
	rx.tx.mu.Lock()
	rx.tx.seq = 1000
	rx.tx.lastSent = 1000
	rx.tx.ackedCum = 0
	rx.tx.mu.Unlock()
	var old12 [12]byte
	binary.BigEndian.PutUint32(old12[:4], 300)
	binary.BigEndian.PutUint64(old12[4:], 6000)
	rx.handle(buildFrame(aadIn, tAck, 7000, 1, old12[:]))
	var b4 [4]byte
	binary.BigEndian.PutUint32(b4[:], 400)
	rx.handle(buildFrame(aadIn, tAck, 7000, 2, b4[:]))
	rx.tx.mu.Lock()
	a := rx.tx.ackedCum
	rx.tx.mu.Unlock()
	if a != 400 {
		t.Fatalf("a delayed old-epoch 12-byte ACK must not wedge subsequent legacy ACKs: ackedCum=%d want 400", a)
	}
}

func TestSenderRestartDoesNotReuseSeqAndRejectsStaleAck(t *testing.T) {
	setTestKey("testpsk")
	path := t.TempDir() + "/sendbase"
	cIP := ip4("10.0.0.1")
	sIP := ip4("10.0.0.2")
	aad := aadFor(0, cIP, 49001, sIP, 49002)

	snd1, err := newSender(cIP, sIP, 49001, 49002)
	if err != nil {
		t.Skip("raw socket needs root:", err)
	}
	tx1 := newTxbuf(snd1, aad)
	sb1 := &sendBase{}
	start1, ok := sb1.load(path)
	if !ok {
		t.Fatal("fresh send-base load must be ok")
	}
	tx1.initSendBase(sb1, start1)
	for i := 0; i < 10; i++ {
		tx1.sendData(make([]byte, 40))
	}
	tx1.mu.Lock()
	staleCum := tx1.lastSent
	tx1.mu.Unlock()

	snd2, err := newSender(cIP, sIP, 49001, 49002)
	if err != nil {
		t.Skip("raw socket needs root:", err)
	}
	tx2 := newTxbuf(snd2, aad)
	sb2 := &sendBase{}
	start2, ok := sb2.load(path)
	if !ok {
		t.Fatal("reload of send-base must be ok")
	}
	tx2.initSendBase(sb2, start2)
	tx2.mu.Lock()
	base2 := tx2.seq
	tx2.mu.Unlock()
	if !seqGt(base2, staleCum) {
		t.Fatalf("new session base %d must be strictly ahead of the previous session's last sent %d (no seq reuse across restart)", base2, staleCum)
	}
	for i := 0; i < 10; i++ {
		tx2.sendData(make([]byte, 40))
	}
	tx2.mu.Lock()
	before := tx2.ackedCum
	tx2.mu.Unlock()
	tx2.setAckedCum(staleCum)
	tx2.mu.Lock()
	after := tx2.ackedCum
	tx2.mu.Unlock()
	if after != before {
		t.Fatalf("a stale ACK from the previous session (cum=%d) must be rejected by the new session (base=%d); ackedCum moved %d->%d (would free unreceived packets)", staleCum, base2, before, after)
	}
}

func TestNackLoopDoesNotEmitStaleCumAfterEpochAdoption(t *testing.T) {
	rx, _ := mkRx(t)
	var got []uint32
	rx.ctrlCapture = func(b []byte) { got = append(got, binary.BigEndian.Uint32(b)) }
	rx.mu.Lock()
	rx.have = true
	rx.cumAck = 500
	rx.gen = 5
	snapGen := rx.gen
	rx.mu.Unlock()
	rx.mu.Lock()
	rx.resetEpochState(2000)
	rx.mu.Unlock()
	rx.emitAck(snapGen)
	if len(got) != 0 {
		t.Fatalf("after an epoch adoption reset, no ACK must be emitted; got cum=%v", got)
	}
}

func TestFreshFlowEarlyLossNotFalseAcked(t *testing.T) {
	rx, aadIn := mkRx(t)
	const base = uint32(65536)
	var bb [4]byte
	binary.BigEndian.PutUint32(bb[:], base)
	rx.handle(buildFrame(aadIn, tBase, 7000, 0, bb[:]))
	rx.handle(buildFrame(aadIn, tData, 7000, base+2, []byte("p2")))
	rx.mu.Lock()
	c := rx.cumAck
	_, missing := rx.miss[base+1]
	rx.mu.Unlock()
	if !seqGt(base+1, c) {
		t.Fatalf("a lost fresh-flow seq %d must NOT be cum-acked; cumAck=%d", base+1, c)
	}
	if !missing {
		t.Fatalf("a lost fresh-flow seq %d must be recorded missing for NACK recovery", base+1)
	}
}

func TestInitSendBaseRefusesOnPersistFailure(t *testing.T) {
	snd, err := newSender(ip4("10.0.0.1"), ip4("10.0.0.2"), 49001, 49002)
	if err != nil {
		t.Skip("raw socket needs root:", err)
	}
	tx := newTxbuf(snd, aadFor(0, ip4("10.0.0.1"), 49001, ip4("10.0.0.2"), 49002))
	sb := &sendBase{}
	start, ok := sb.load("/nonexistent-omnitun-dir-xyz/base")
	if !ok {
		t.Fatal("load of a missing file must be ok (fresh)")
	}
	if tx.initSendBase(sb, start) {
		t.Fatalf("initSendBase must refuse (return false) when the initial durable reservation write fails")
	}
}

func TestExtendReserveBlocksBeyondDurableCeiling(t *testing.T) {
	snd, err := newSender(ip4("10.0.0.1"), ip4("10.0.0.2"), 49001, 49002)
	if err != nil {
		t.Skip("raw socket needs root:", err)
	}
	tx := newTxbuf(snd, aadFor(0, ip4("10.0.0.1"), 49001, ip4("10.0.0.2"), 49002))
	sb := &sendBase{path: t.TempDir() + "/base"}
	tx.sb = sb
	tx.reserved = 100000
	tx.seq = 100000
	var failing int32
	old := durableWrite
	durableWrite = func(path string, v uint64) bool {
		if atomic.LoadInt32(&failing) == 1 {
			return false
		}
		return old(path, v)
	}
	defer func() { durableWrite = old }()
	atomic.StoreInt32(&failing, 1)
	done := make(chan struct{})
	go func() { tx.ensureReserve(tx.seq + 1); close(done) }()
	select {
	case <-done:
		t.Fatalf("ensureReserve must BLOCK when it cannot durably extend past the reserved ceiling")
	case <-time.After(200 * time.Millisecond):
	}
	atomic.StoreInt32(&failing, 0)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatalf("ensureReserve must proceed once a durable extend succeeds")
	}
	if !seqGt(tx.reserved, tx.seq) {
		t.Fatalf("reserved=%d must advance past seq=%d after a successful extend", tx.reserved, tx.seq)
	}
}

func TestEmitAckAtomicVsEpochAdoption(t *testing.T) {
	for iter := 0; iter < 300; iter++ {
		rx, _ := mkRx(t)
		rx.mu.Lock()
		rx.have = true
		rx.cumAck = 500
		rx.gen = 5
		rx.mu.Unlock()
		var stale int32
		rx.ctrlCapture = func(b []byte) {
			if binary.BigEndian.Uint32(b) == 500 && rx.gen != 5 {
				atomic.AddInt32(&stale, 1)
			}
		}
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); rx.emitAck(5) }()
		go func() {
			defer wg.Done()
			rx.mu.Lock()
			rx.resetEpochState(2000)
			rx.mu.Unlock()
		}()
		wg.Wait()
		if atomic.LoadInt32(&stale) != 0 {
			t.Fatalf("iter %d: emitAck emitted a stale cumulative after the epoch changed", iter)
		}
	}
}

func TestFloorPersistFailsIfDirSyncFails(t *testing.T) {
	old := syncParentDir
	syncParentDir = func(string) error { return fmt.Errorf("simulated dir sync failure") }
	defer func() { syncParentDir = old }()
	path := t.TempDir() + "/floor"
	eg := &epochGuard{}
	eg.load(path)
	if eg.admit(5000) {
		t.Fatal("floor persist must fail closed when the parent-directory sync (durability of the rename) fails")
	}
	eg.mu.Lock()
	f := eg.floor
	eg.mu.Unlock()
	if f == 5000 {
		t.Fatalf("floor must not advance when its durability cannot be guaranteed: %d", f)
	}
}

func TestMalformedFloorFileFailsClosed(t *testing.T) {
	path := t.TempDir() + "/floor"
	if err := os.WriteFile(path, []byte("not-a-number\n"), 0600); err != nil {
		t.Skip("cannot write temp floor")
	}
	eg := &epochGuard{}
	eg.load(path)
	if eg.admit(5000) {
		t.Fatal("a present-but-malformed floor file must fail closed (reject epoch adoption), not reset to 0")
	}
	eg.mu.Lock()
	f := eg.floor
	eg.mu.Unlock()
	if f == 0 {
		t.Fatal("a malformed floor file must not be silently treated as 0")
	}
}

func TestMissingFloorFileFreshStart(t *testing.T) {
	path := t.TempDir() + "/does-not-exist"
	eg := &epochGuard{}
	eg.load(path)
	if !eg.admit(5000) {
		t.Fatal("a missing floor file is a fresh first boot: epoch adoption must succeed")
	}
}

func TestStaleMultilineFloorFileIgnored(t *testing.T) {
	path := t.TempDir() + "/floor"
	if err := os.WriteFile(path, []byte("9000\n50000\n50000\n"), 0600); err != nil {
		t.Skip("cannot write temp floor")
	}
	eg := &epochGuard{}
	eg.load(path)
	rx, aadTx := mkRxG(t, eg)
	rx.handle(buildFrame(aadTx, tData, 9000, 1, []byte("x")))
	if atomic.LoadUint64(&rx.nDeliv) != 1 {
		t.Fatalf("a low new-epoch seq must deliver after restart; a stale persisted per-lane mark must not blackhole it: nDeliv=%d", rx.nDeliv)
	}
}

func TestFreshStartGapRecoveredNotAcked(t *testing.T) {
	rx, aadTx := mkRx(t)
	rx.handle(buildFrame(aadTx, tData, 7000, 2, []byte("two")))
	rx.mu.Lock()
	_, miss1 := rx.miss[1]
	cum := rx.cumAck
	rx.mu.Unlock()
	if !miss1 {
		t.Fatal("a fresh-start gap (seq 1 lost, seq 2 first) must be recorded missing, not ACKed")
	}
	if cum != 0 {
		t.Fatalf("a fresh-start gap must NOT advance cumAck past the undelivered seq 1: cumAck=%d", cum)
	}
	rx.handle(buildFrame(aadTx, tData, 7000, 1, []byte("one")))
	rx.mu.Lock()
	cum = rx.cumAck
	rx.mu.Unlock()
	if cum != 2 {
		t.Fatalf("after seq 1 is recovered cumAck should reach 2: %d", cum)
	}
}

func TestAcklessRestartResyncBootstrapsFromFirstSeq(t *testing.T) {
	rx, aadTx := mkRx(t)
	body := []byte("resync")
	rx.handle(buildFrame(aadTx, tData, 7000, 100000, body))
	if atomic.LoadUint64(&rx.nDeliv) != 1 {
		t.Fatalf("surviving-sender high seq after a receiver restart must be delivered: nDeliv=%d", rx.nDeliv)
	}
	var bb [4]byte
	binary.BigEndian.PutUint32(bb[:], 1)
	rx.handle(buildFrame(aadTx, tBase, 7000, 0, bb[:]))
	rx.mu.Lock()
	nmiss := len(rx.miss)
	cum := rx.cumAck
	rx.mu.Unlock()
	if nmiss != 0 {
		t.Fatalf("a restart resync must NOT fabricate missing pre-history seqs: miss=%d", nmiss)
	}
	if cum != 100000 {
		t.Fatalf("after the surviving sender's base advert, a mid-stream resync must bootstrap cumAck to the current seq so the sender is not stuck: cumAck=%d", cum)
	}
}

func TestSendDataBackpressureOnFullWindow(t *testing.T) {
	snd, err := newSender(ip4("10.0.0.1"), ip4("10.0.0.2"), 49001, 49002)
	if err != nil {
		t.Skip("raw socket needs root:", err)
	}
	tx := newTxbuf(snd, aadFor(0, ip4("10.0.0.1"), 49001, ip4("10.0.0.2"), 49002))
	tx.mu.Lock()
	tx.seq = txWindow
	tx.lastSent = txWindow
	tx.ackedCum = 0
	tx.mu.Unlock()
	done := make(chan struct{})
	go func() { tx.sendData([]byte("x")); close(done) }()
	select {
	case <-done:
		t.Fatal("sendData must block when the unacked window is full (would overwrite an unacked ring slot)")
	case <-time.After(150 * time.Millisecond):
	}
	tx.setAckedCum(1)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("sendData must resume once the window opens")
	}
}

func TestMissingSeqNotAbandoned(t *testing.T) {
	rx, _ := mkRx(t)
	rx.mu.Lock()
	rx.miss[42] = &missInfo{first: time.Now().Add(-5 * time.Second), tries: 50}
	rx.mu.Unlock()
	list := rx.nackDue(time.Now(), 6*time.Millisecond, 55*time.Millisecond)
	found := false
	for _, s := range list {
		if s == 42 {
			found = true
		}
	}
	if !found {
		t.Fatal("a long-missing seq must keep being NACK-requested, never silently abandoned")
	}
	rx.mu.Lock()
	_, still := rx.miss[42]
	rx.mu.Unlock()
	if !still {
		t.Fatal("a long-missing seq must stay in the miss set until it is received")
	}
}

func TestReorderKeepsRequestingGapNoSkip(t *testing.T) {
	old := *reorderMs
	*reorderMs = 20
	defer func() { *reorderMs = old }()
	rx, aadTx := mkRx(t)
	body := []byte("p")
	rx.handle(buildFrame(aadTx, tData, 8000, 2, body))
	rx.reorderTimeout(time.Now().Add(time.Hour))
	rx.handle(buildFrame(aadTx, tData, 8000, 1, body))
	if n := atomic.LoadUint64(&rx.nDeliv); n != 2 {
		t.Fatalf("reliable reorder must keep the hole and deliver the late seq, not skip it: nDeliv=%d", n)
	}
}

func TestEpochChangeConcurrentWithDeliveryRaceSafe(t *testing.T) {
	rx, aadTx := mkRx(t)
	body := []byte("d")
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := uint32(1); i <= 400; i++ {
			rx.handle(buildFrame(aadTx, tData, 9000, i, body))
		}
	}()
	go func() {
		defer wg.Done()
		for e := uint64(9001); e < 9401; e++ {
			rx.handle(buildFrame(aadTx, tData, e, 1, body))
		}
	}()
	wg.Wait()
	rx.mu.Lock()
	ce := rx.curEpoch
	rx.mu.Unlock()
	if ce < 9000 {
		t.Fatalf("epoch state corrupted under concurrent epoch change + delivery: curEpoch=%d", ce)
	}
}

func TestPersistedFloorRejectsColdStartReplay(t *testing.T) {
	path := t.TempDir() + "/floor"
	if err := os.WriteFile(path, []byte("5000"), 0600); err != nil {
		t.Skip("cannot write temp floor")
	}
	rx, aadTx := mkRx(t)
	rx.eg.load(path)
	body := []byte("stale")
	rx.handle(buildFrame(aadTx, tData, 3000, 1, body))
	if atomic.LoadUint64(&rx.nDeliv) != 0 {
		t.Fatalf("a captured old-epoch frame at cold start (below the persisted floor) must be rejected: nDeliv=%d", rx.nDeliv)
	}
	if atomic.LoadUint64(&rx.nReplay) == 0 {
		t.Fatal("the stale cold-start frame must be counted as a replay")
	}
	rx.handle(buildFrame(aadTx, tData, 6000, 1, body))
	if atomic.LoadUint64(&rx.nDeliv) != 1 {
		t.Fatalf("a fresh epoch above the persisted floor must be accepted: nDeliv=%d", rx.nDeliv)
	}
}

func TestConcurrentDupCounter(t *testing.T) {
	setTestKey("testpsk")
	devnull, err := syscall.Open("/dev/null", syscall.O_WRONLY, 0)
	if err != nil {
		t.Skip("no /dev/null")
	}
	defer syscall.Close(devnull)
	snd, err := newSender(ip4("10.0.0.1"), ip4("10.0.0.2"), 49001, 49002)
	if err != nil {
		t.Skip("raw socket needs root")
	}
	cIP := ip4("10.0.0.1")
	sIP := ip4("10.0.0.2")
	aadTx := aadFor(0, cIP, 49001, sIP, 49002)
	rx := newArqRx(devnull, snd, newTxbuf(snd, aadFor(1, sIP, 49003, cIP, 49004)), aadTx, aadFor(1, sIP, 49003, cIP, 49004), nil)
	body := []byte("x")
	rx.handle(buildFrame(aadTx, tData, 1000, 50, body))
	done := make(chan bool)
	go func() {
		for i := 0; i < 3000; i++ {
			rx.handle(buildFrame(aadTx, tData, 1000, 50, body))
		}
		done <- true
	}()
	for i := 0; i < 3000; i++ {
		_ = atomic.LoadUint64(&rx.nDup)
	}
	<-done
	if atomic.LoadUint64(&rx.nDup) == 0 {
		t.Fatal("expected duplicate counter to increment")
	}
}

func TestDataBeforeBaseDefersThenRecovers(t *testing.T) {
	rx, aadIn := mkRx(t)
	const base = uint32(65536)
	rx.handle(buildFrame(aadIn, tData, 7000, base+2, []byte("p2")))
	rx.mu.Lock()
	cBefore := rx.cumAck
	deferred := rx.rxDeferred
	rx.mu.Unlock()
	if !deferred {
		t.Fatalf("a high first seq with no authenticated base yet must defer, not resync-anchor")
	}
	if !seqGt(base+1, cBefore) {
		t.Fatalf("before tBase, cumAck=%d must be below the lost seq %d (not acked)", cBefore, base+1)
	}
	var bb [4]byte
	binary.BigEndian.PutUint32(bb[:], base)
	rx.handle(buildFrame(aadIn, tBase, 7000, 0, bb[:]))
	rx.mu.Lock()
	c := rx.cumAck
	_, missing := rx.miss[base+1]
	rx.mu.Unlock()
	if !seqGt(base+1, c) {
		t.Fatalf("after tBase, the lost seq %d must still NOT be cum-acked; cumAck=%d", base+1, c)
	}
	if !missing {
		t.Fatalf("after tBase, the lost seq %d must be recorded missing for NACK recovery", base+1)
	}
}

func TestDataBeforeBaseDefersThenRecoversReorder(t *testing.T) {
	old := *reorderMs
	*reorderMs = 20
	defer func() { *reorderMs = old }()
	rx, aadIn := mkRx(t)
	const base = uint32(65536)
	rx.handle(buildFrame(aadIn, tData, 7000, base+2, []byte("p2")))
	var bb [4]byte
	binary.BigEndian.PutUint32(bb[:], base)
	rx.handle(buildFrame(aadIn, tBase, 7000, 0, bb[:]))
	rx.mu.Lock()
	c := rx.cumAck
	_, missing := rx.miss[base+1]
	_, pend2 := rx.pend[base+2]
	rx.mu.Unlock()
	if !seqGt(base+1, c) {
		t.Fatalf("reorder: lost seq %d must not be acked; cumAck=%d", base+1, c)
	}
	if !missing {
		t.Fatalf("reorder: lost seq %d must be recorded missing", base+1)
	}
	if !pend2 {
		t.Fatalf("reorder: base+2 must stay buffered until base+1 is recovered")
	}
	rx.handle(buildFrame(aadIn, tData, 7000, base+1, []byte("p1")))
	rx.mu.Lock()
	c2 := rx.cumAck
	rx.mu.Unlock()
	if seqGt(base+2, c2) {
		t.Fatalf("reorder: after seq %d recovers, cumAck must reach %d; got %d", base+1, base+2, c2)
	}
}

func TestSendDataSingleWriterVsAckIngestNoRace(t *testing.T) {
	snd, err := newSender(ip4("10.0.0.1"), ip4("10.0.0.2"), 49001, 49002)
	if err != nil {
		t.Skip("raw socket needs root:", err)
	}
	tx := newTxbuf(snd, aadFor(0, ip4("10.0.0.1"), 49001, ip4("10.0.0.2"), 49002))
	sb := &sendBase{path: t.TempDir() + "/base"}
	if !tx.initSendBase(sb, 0) {
		t.Fatal("initSendBase failed")
	}
	done := make(chan struct{})
	go func() {
		for i := 0; i < 3000; i++ {
			tx.sendData(make([]byte, 40))
		}
		close(done)
	}()
	go func() {
		for {
			select {
			case <-done:
				return
			default:
				tx.mu.Lock()
				ls := tx.lastSent
				tx.mu.Unlock()
				tx.setAckedCum(ls)
			}
		}
	}()
	<-done
}
