package main

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// The benchmark reader uses in-memory frames; no port is opened.
type benchFrameConn struct {
	net.Conn
	reader *bytes.Reader
}

func (c *benchFrameConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func TestReadFrameSingleBufferEqualsSenderFrame(t *testing.T) {
	frame := client(t, "phase2-key").build(0, 0, 0, nil)
	conn := &benchFrameConn{reader: bytes.NewReader(frame)}
	got, ok := readFrame(conn)
	if !ok || !bytes.Equal(got, frame) {
		t.Fatal("frame data changed, truncated or rejected")
	}
}

func TestReadFrameRejectsTruncatedAndCorruptHeaders(t *testing.T) {
	frame := client(t, "phase2-key").build(0, 0, 0, nil)
	for _, n := range []int{0, 2, 12, len(frame) - 1} {
		_, ok := readFrame(&benchFrameConn{reader: bytes.NewReader(frame[:n])})
		if ok {
			t.Fatalf("truncated frame of size %d accepted", n)
		}
	}
	corrupted := bytes.Clone(frame)
	corrupted[0] ^= 0x80
	if _, ok := readFrame(&benchFrameConn{reader: bytes.NewReader(corrupted)}); ok {
		t.Fatal("invalid protocol marker accepted")
	}
}

func BenchmarkReadFrame(b *testing.B) {
	// Isolated microbenchmark; not network throughput or tail latency.
	t := newTunnel("relay", nil, 4096, 1, 64, time.Second, time.Millisecond, 30, []byte("phase2-key"))
	frame := t.build(0, 0, 0, nil)
	conn := &benchFrameConn{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn.reader = bytes.NewReader(frame)
		if _, ok := readFrame(conn); !ok {
			b.Fatal("read frame failed")
		}
	}
}
