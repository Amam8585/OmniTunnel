package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func tun(t *testing.T) *os.File {
	t.Helper()
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("devnull: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func client(t *testing.T, key string) *Tunnel {
	return newTunnel("relay", tun(t), 4096, 1, 64, 300*time.Millisecond, 2*time.Millisecond, 30, []byte(key))
}

func server(t *testing.T, key string) *Tunnel {
	return newTunnel("turkey", tun(t), 4096, 1, 64, 300*time.Millisecond, 2*time.Millisecond, 30, []byte(key))
}

func dataChunk(inner []byte) []byte {
	out := []byte{byte(len(inner) >> 8), byte(len(inner))}
	return append(out, inner...)
}

func TestFrameAuthAcceptsOwnKey(t *testing.T) {
	c := client(t, "shared")
	s := server(t, "shared")
	if !s.apply(c.build(0, 0, 0, nil)) {
		t.Fatal("authentic client->server frame rejected")
	}
}

func TestFrameAuthRejectsTamper(t *testing.T) {
	c := client(t, "shared")
	s := server(t, "shared")
	f := c.build(0, 0, 0, nil)
	f[20] ^= 0xff
	if s.apply(f) {
		t.Fatal("tampered frame accepted")
	}
	if s.authFail == 0 {
		t.Fatal("authFail not counted")
	}
}

func TestFrameAuthRejectsWrongKey(t *testing.T) {
	c := client(t, "key-A")
	s := server(t, "key-B")
	if s.apply(c.build(0, 0, 0, nil)) {
		t.Fatal("frame from wrong key accepted")
	}
}

func TestReflectedFrameRejected(t *testing.T) {
	c := client(t, "shared")
	f := c.build(0, 0, 0, nil)
	if c.apply(f) {
		t.Fatal("client accepted its own reflected (dir=0) frame")
	}
}

func TestDirectionMismatchRejected(t *testing.T) {
	s := server(t, "shared")
	s2 := server(t, "shared")
	if s.apply(s2.build(0, 1, 0, nil)) {
		t.Fatal("server accepted a dir=1 frame")
	}
}

func TestFrameReplayRejected(t *testing.T) {
	c := client(t, "k")
	s := server(t, "k")
	f := c.build(0, 0, 0, nil)
	if !s.apply(f) {
		t.Fatal("first delivery rejected")
	}
	if s.apply(f) {
		t.Fatal("replayed frame accepted")
	}
	if s.replayDrop == 0 {
		t.Fatal("replayDrop not counted")
	}
}

func TestReplayWindow(t *testing.T) {
	w := newReplayWindow(1024)
	if !w.check(5) || w.check(5) {
		t.Fatal("basic replay semantics wrong")
	}
	if !w.check(3) || w.check(3) {
		t.Fatal("in-window replay semantics wrong")
	}
	if w.check(0) {
		t.Fatal("nonce 0 accepted")
	}
	if !w.check(2000) || w.check(2000-1024) {
		t.Fatal("advance / too-old semantics wrong")
	}
	w.reset()
	if !w.check(5) {
		t.Fatal("reset did not clear the window")
	}
}

func TestEpochResetsReplayAndRejectsStale(t *testing.T) {
	s := server(t, "k")
	e1 := client(t, "k")
	e1.txEpoch = 1000
	if !s.apply(e1.build(0, 0, 0, nil)) {
		t.Fatal("epoch-1 frame rejected")
	}
	if !s.apply(e1.build(0, 0, 0, nil)) {
		t.Fatal("epoch-1 second frame rejected")
	}
	e2 := client(t, "k")
	e2.txEpoch = 2000
	if !s.apply(e2.build(0, 0, 0, nil)) {
		t.Fatal("higher-epoch restart frame rejected (replay not reset)")
	}
	e0 := client(t, "k")
	e0.txEpoch = 500
	if s.apply(e0.build(0, 0, 0, nil)) {
		t.Fatal("stale lower-epoch frame accepted")
	}
}

func TestAckAppliedOnlyWhenEchoMatches(t *testing.T) {
	s := server(t, "k")
	s.lanes[0].tx.addChunk([]byte("down-payload"))
	if seq, _ := s.lanes[0].tx.getSend(time.Second); seq != 1 {
		t.Fatalf("unexpected seq %d", seq)
	}
	bad := client(t, "k")
	bad.txEpoch = 5000
	bad.peerEpoch = s.txEpoch + 999
	if !s.apply(withCum(bad, bad.build(0, 0, 0, nil), 1)) {
		t.Fatal("frame rejected")
	}
	if !s.lanes[0].tx.stillInflight(1) {
		t.Fatal("ACK with mismatched epoch echo was applied")
	}
	good := client(t, "k")
	good.txEpoch = 6000
	good.peerEpoch = s.txEpoch
	if !s.apply(withCum(good, good.build(0, 0, 0, nil), 1)) {
		t.Fatal("frame rejected")
	}
	if s.lanes[0].tx.stillInflight(1) {
		t.Fatal("ACK with matching epoch echo was NOT applied")
	}
}

func withCum(tn *Tunnel, frame []byte, cum uint64) []byte {
	setU64(frame, 14, cum)
	off := hdrFixed + sackBytes + int(u16(frame, 12)) + tailSize
	copy(frame[off:], hmacTag(tn.sendKey, frame[:off]))
	return frame
}

func setU64(b []byte, off int, v uint64) {
	for i := 0; i < 8; i++ {
		b[off+i] = byte(v >> (56 - 8*i))
	}
}
func u16(b []byte, off int) uint16 { return uint16(b[off])<<8 | uint16(b[off+1]) }

func TestAckOnlyAfterSuccessfulWrite(t *testing.T) {
	c := client(t, "k")
	s := server(t, "k")
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	pr.Close()
	s.tun = pw
	f := c.build(0, 0, 1, dataChunk([]byte("abcd")))
	if !s.apply(f) {
		t.Fatal("frame rejected")
	}
	if s.lanes[0].rx.have(1) {
		t.Fatal("seq marked received despite failed TUN write")
	}
	cum, _, _ := s.lanes[0].rx.encode()
	if cum != 0 {
		t.Fatalf("cumulative ACK advanced to %d despite failed write", cum)
	}
	if s.bytesIn != 0 {
		t.Fatal("bytesIn counted a failed delivery")
	}
}

func TestDeliverThenAck(t *testing.T) {
	c := client(t, "k")
	s := server(t, "k")
	f := c.build(0, 0, 1, dataChunk([]byte("abcd")))
	if !s.apply(f) {
		t.Fatal("frame rejected")
	}
	if !s.lanes[0].rx.have(1) {
		t.Fatal("seq not received after successful write")
	}
}

func TestConcurrentApply(t *testing.T) {
	c := client(t, "k")
	s := server(t, "k")
	const n = 200
	frames := make([][]byte, n)
	for i := 0; i < n; i++ {
		frames[i] = c.build(0, 0, uint64(i+1), dataChunk([]byte("pkt")))
	}
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(f []byte) {
			defer wg.Done()
			s.apply(f)
		}(frames[i])
	}
	wg.Wait()
	for i := uint64(1); i <= n; i++ {
		if !s.lanes[0].rx.have(i) {
			t.Fatalf("seq %d lost under concurrent apply", i)
		}
	}
}

func TestTupleSchedulerCooldown(t *testing.T) {
	cd := 200 * time.Millisecond
	s := newTupleSched(100, 100, 200, 201, cd, 0)
	t0 := time.Now()
	a1, _, ok1 := s.acquire(t0)
	_, _, ok2 := s.acquire(t0)
	if !ok1 || !ok2 {
		t.Fatal("initial mint failed")
	}
	if _, _, ok := s.acquire(t0); ok {
		t.Fatal("acquired beyond pool space with none released")
	}
	s.release(a1, 200, t0)
	if _, _, ok := s.acquire(t0); ok {
		t.Fatal("released tuple reused before cooldown elapsed")
	}
	if _, _, ok := s.acquire(t0.Add(cd + time.Millisecond)); !ok {
		t.Fatal("released tuple not reusable after cooldown")
	}
}

func TestStripeBuildWaitsForEpochAdoption(t *testing.T) {
	s := server(t, "shared")
	s.epochMu.Lock()
	done := make(chan []byte, 1)
	go func() { done <- s.build(0, 1, 0, nil) }()
	select {
	case <-done:
		t.Fatal("build must not snapshot (ack,epoch) while an epoch adoption holds epochMu")
	case <-time.After(100 * time.Millisecond):
	}
	atomic.StoreUint64(&s.peerEpoch, 5000)
	s.epochMu.Unlock()
	f := <-done
	if echo := binary.BigEndian.Uint64(f[46:]); echo != 5000 {
		t.Fatalf("build after the adoption completes must echo the new epoch, not a torn old snapshot: echo=%d", echo)
	}
}

func TestStripeFloorPersistFailsIfDirSyncFails(t *testing.T) {
	old := syncParentDir
	syncParentDir = func(string) error { return fmt.Errorf("simulated dir sync failure") }
	defer func() { syncParentDir = old }()
	path := t.TempDir() + "/floor"
	s := server(t, "shared")
	s.loadFloor(path)
	c := client(t, "shared")
	c.txEpoch = 6000
	before := atomic.LoadInt64(&s.bytesIn)
	s.apply(c.build(0, 0, 1, dataChunk([]byte("x"))))
	if atomic.LoadUint64(&s.peerEpoch) == 6000 {
		t.Fatal("epoch adoption must fail closed when the floor parent-dir sync (rename durability) fails")
	}
	if atomic.LoadInt64(&s.bytesIn) != before {
		t.Fatal("no payload may be delivered when epoch adoption fails closed on a dir-sync failure")
	}
}

func TestStripeMalformedFloorFailsClosed(t *testing.T) {
	path := t.TempDir() + "/floor"
	if err := os.WriteFile(path, []byte("garbage\n"), 0600); err != nil {
		t.Skip("cannot write temp floor")
	}
	s := server(t, "shared")
	s.loadFloor(path)
	c := client(t, "shared")
	c.txEpoch = 6000
	before := atomic.LoadInt64(&s.bytesIn)
	s.apply(c.build(0, 0, 1, dataChunk([]byte("x"))))
	if atomic.LoadInt64(&s.bytesIn) != before {
		t.Fatal("a malformed floor file must fail closed: no epoch adopted, no payload delivered")
	}
	if atomic.LoadUint64(&s.peerEpoch) == 6000 {
		t.Fatal("a malformed floor file must not let an epoch be adopted (must not reset to 0)")
	}
}

func TestStripeAdoptionPersistsFloorOnly(t *testing.T) {
	path := t.TempDir() + "/floor"
	s := server(t, "shared")
	s.loadFloor(path)
	c := client(t, "shared")
	c.txEpoch = 9000
	if !s.apply(c.build(0, 0, 1, dataChunk([]byte("x")))) {
		t.Fatal("fresh epoch should be adopted")
	}
	b, _ := os.ReadFile(path)
	lines := len(strings.Split(strings.TrimSpace(string(b)), "\n"))
	if lines != 1 {
		t.Fatalf("epoch adoption must persist the floor ONLY (no per-lane base to poison a restart): file=%q", string(b))
	}
}

func TestStripeFloorPersistFailClosed(t *testing.T) {
	s := server(t, "shared")
	s.loadFloor("/proc/omnitunnel-nonexistent-dir/floor")
	c := client(t, "shared")
	c.txEpoch = 6000
	before := atomic.LoadInt64(&s.bytesIn)
	s.apply(c.build(0, 0, 1, dataChunk([]byte("x"))))
	if atomic.LoadUint64(&s.peerEpoch) == 6000 {
		t.Fatal("peerEpoch must not advance when the floor cannot be persisted (fail closed)")
	}
	if atomic.LoadInt64(&s.bytesIn) != before {
		t.Fatal("payload must not be delivered when epoch adoption fails closed")
	}
}

func TestStripeRestartResyncBootstrapsBase(t *testing.T) {
	r := newRxDedup(400)
	if !r.reserve(100000) {
		t.Fatal("a surviving sender's high seq after a receiver restart must be reservable (base bootstrap), not dropped as out-of-window")
	}
	r.commit(100000)
	r.mu.Lock()
	base := r.base
	r.mu.Unlock()
	if base != 100000 {
		t.Fatalf("base must bootstrap/advance to the resynced seq so the sender is not stuck: base=%d", base)
	}
}

func TestStripePersistedFloorRejectsColdStartReplay(t *testing.T) {
	path := t.TempDir() + "/floor"
	if err := os.WriteFile(path, []byte("5000"), 0600); err != nil {
		t.Skip("cannot write temp floor")
	}
	s := server(t, "shared")
	s.loadFloor(path)

	stale := client(t, "shared")
	stale.txEpoch = 3000
	before := atomic.LoadInt64(&s.bytesIn)
	if s.apply(stale.build(0, 0, 1, dataChunk([]byte("old")))) {
		t.Fatal("a captured old-epoch frame at cold start (below the persisted floor) must be rejected")
	}
	if atomic.LoadInt64(&s.bytesIn) != before {
		t.Fatal("stale cold-start frame must not deliver inner payload")
	}
	if atomic.LoadInt64(&s.replayDrop) == 0 {
		t.Fatal("stale cold-start frame must be counted as a replay drop")
	}

	fresh := client(t, "shared")
	fresh.txEpoch = 6000
	if !s.apply(fresh.build(0, 0, 1, dataChunk([]byte("new")))) {
		t.Fatal("a fresh epoch above the persisted floor must be accepted")
	}
}

func TestInflightKeptUntilAckedPastMaxTries(t *testing.T) {
	s := newSender(4, time.Millisecond, 3)
	s.addChunk([]byte("user-data"))
	deadline := time.Now().Add(2 * time.Second)
	for i := 0; i < 200 && s.stillInflight(1); i++ {
		s.getSend(0)
		time.Sleep(2 * time.Millisecond)
		s.requeueTimeouts()
		if time.Now().After(deadline) {
			break
		}
	}
	if !s.stillInflight(1) {
		t.Fatal("unacked chunk was discarded after maxTries sustained failed round trips (silent data loss)")
	}
	s.applyAck(1, 2, make([]byte, sackBytes))
	if s.stillInflight(1) {
		t.Fatal("chunk must clear once acknowledged")
	}
}

func TestCompleteOnlyWhenAcked(t *testing.T) {
	s := newSender(16, 300*time.Millisecond, 30)
	s.addChunk([]byte("payload"))
	seq, buf := s.getSend(time.Second)
	if buf == nil || seq != 1 {
		t.Fatalf("unexpected getSend seq=%d", seq)
	}
	if !s.stillInflight(seq) {
		t.Fatal("seq should be inflight before ack")
	}
	s.applyAck(seq, seq+1, make([]byte, sackBytes))
	if s.stillInflight(seq) {
		t.Fatal("seq should be cleared after cumulative ack")
	}
}

func TestFrameFitsSegmentBudget(t *testing.T) {
	if headerLen+maxPayload > hardWireCap {
		t.Fatalf("max frame %d exceeds %d-segment budget %d", headerLen+maxPayload, safeSegs, hardWireCap)
	}
	frame := headerLen + 6600
	segs := (frame + mssFloor - 1) / mssFloor
	if segs > safeSegs {
		t.Fatalf("default chunk -> %d segments (> %d)", segs, safeSegs)
	}
}

func TestServerRejectsForeignSourceIP(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	s := server(t, "k")
	s.peerIP = net.ParseIP("10.77.77.77")
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		s.handleConn(conn, 2*time.Second)
	}()
	c := client(t, "k")
	conn, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_, _ = conn.Write(c.build(0, 0, 0, nil))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("server responded to a foreign source IP")
	}
}

func TestServerAcceptsPeerSourceIP(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	s := server(t, "k")
	s.peerIP = net.ParseIP("127.0.0.1")
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		s.handleConn(conn, 2*time.Second)
	}()
	c := client(t, "k")
	conn, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	_, _ = conn.Write(c.build(0, 0, 0, nil))
	frame, ok := readFrame(conn)
	if !ok {
		t.Fatal("server did not respond to the authorized peer IP")
	}
	if !c.apply(frame) {
		t.Fatal("server response failed client verification")
	}
}

func TestNoCumAckOverHole(t *testing.T) {
	rcv := newTunnel("turkey", tun(t), 4096, 1, 32, 300*time.Millisecond, 2*time.Millisecond, 30, []byte("k"))
	builder := client(t, "k")
	const hi = 300
	frames := make([][]byte, 0, hi)
	for seq := 2; seq <= hi; seq++ {
		frames = append(frames, builder.build(0, 0, uint64(seq), dataChunk([]byte("x"))))
	}
	var wg sync.WaitGroup
	for _, f := range frames {
		wg.Add(1)
		go func(fr []byte) { defer wg.Done(); rcv.apply(fr) }(f)
	}
	wg.Wait()
	if cum, _, _ := rcv.lanes[0].rx.encode(); cum != 0 {
		t.Fatalf("cumulative ACK advanced to %d past the missing seq 1 (data-loss)", cum)
	}
	if !rcv.apply(builder.build(0, 0, 1, dataChunk([]byte("x")))) {
		t.Fatal("seq 1 frame rejected")
	}
	if cum, _, _ := rcv.lanes[0].rx.encode(); cum != hi {
		t.Fatalf("after filling the hole, cum=%d want %d", cum, hi)
	}
}

func TestExactlyOnceSameSeqDistinctNonces(t *testing.T) {
	rcv := server(t, "k")
	builder := client(t, "k")
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	rcv.tun = pw
	var got int64
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 4096)
		for {
			n, rerr := pr.Read(buf)
			if n > 0 {
				atomic.AddInt64(&got, int64(n))
			}
			if rerr != nil {
				close(done)
				return
			}
		}
	}()
	const k = 128
	frames := make([][]byte, k)
	for i := 0; i < k; i++ {
		frames[i] = builder.build(0, 0, 7, dataChunk([]byte("data")))
	}
	distinct := map[[8]byte]bool{}
	for _, f := range frames {
		var n [8]byte
		copy(n[:], f[30:38])
		distinct[n] = true
	}
	if len(distinct) != k {
		t.Fatalf("expected %d distinct nonces, got %d", k, len(distinct))
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < k; i++ {
		wg.Add(1)
		go func(f []byte) {
			defer wg.Done()
			<-start
			rcv.apply(f)
		}(frames[i])
	}
	close(start)
	wg.Wait()
	_ = pw.Close()
	<-done
	if got != 4 {
		t.Fatalf("inner packet written to TUN %d bytes; want 4 (exactly-once across %d same-seq retransmits)", got, k)
	}
	if rcv.bytesIn != 6 {
		t.Fatalf("bytesIn=%d; want 6 (one chunk delivered once)", rcv.bytesIn)
	}
}

func TestRxReserveExactlyOnce(t *testing.T) {
	r := newRxDedup(512)
	const k = 256
	var won int64
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < k; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if r.reserve(42) {
				atomic.AddInt64(&won, 1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if won != 1 {
		t.Fatalf("reserve(42) granted to %d goroutines concurrently; want exactly 1", won)
	}
	if !r.have(42) {
		r.commit(42)
	}
}

func TestDeliverChunkNoDuplicateOnPartialWrite(t *testing.T) {
	tn := &Tunnel{}
	var writes [][]byte
	failedOnce := false
	tn.wr = func(p []byte) error {
		if !failedOnce && len(p) == 1 && p[0] == 0xB2 {
			failedOnce = true
			return fmt.Errorf("simulated tun write error")
		}
		writes = append(writes, append([]byte(nil), p...))
		return nil
	}
	pkts := [][]byte{{0xA1}, {0xB2}, {0xC3}}
	var chunk []byte
	for _, p := range pkts {
		chunk = append(chunk, byte(len(p)>>8), byte(len(p)))
		chunk = append(chunk, p...)
	}
	written, ok := tn.deliverChunk(chunk, 0)
	if ok {
		t.Fatalf("expected a partial failure at the mid-chunk write")
	}
	if _, ok2 := tn.deliverChunk(chunk, written); !ok2 {
		t.Fatalf("resumed delivery must complete after the write recovers")
	}
	if len(writes) != 3 {
		t.Fatalf("each inner packet must be written exactly once; got %d writes: %v", len(writes), writes)
	}
	want := []byte{0xA1, 0xB2, 0xC3}
	for i := range want {
		if len(writes[i]) != 1 || writes[i][0] != want[i] {
			t.Fatalf("packet %d mismatch: got %v want %x", i, writes[i], want[i])
		}
	}
}
