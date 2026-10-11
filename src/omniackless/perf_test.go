package main

import "testing"

func TestTCPChecksumPseudoHeaderDoesNotMutateInputs(t *testing.T) {
	segment := make([]byte, 23)
	for i := range segment {
		segment[i] = byte(i + 1)
	}
	original := append([]byte(nil), segment...)
	a := tcpcsum(0x0a010101, 0x0a010102, segment)
	b := tcpcsum(0x0a010101, 0x0a010102, segment)
	if a != b {
		t.Fatal("TCP checksum changed between identical inputs")
	}
	for i := range segment {
		if original[i] != segment[i] {
			t.Fatal("TCP checksum modified its packet input")
		}
	}
	if a == tcpcsum(0x0a010101, 0x0a010103, segment) {
		t.Fatal("checksum does not bind destination address")
	}
}

func BenchmarkTCPChecksum(b *testing.B) {
	segment := make([]byte, 1320)
	b.ReportAllocs()
	var sum uint16
	for i := 0; i < b.N; i++ {
		sum = tcpcsum(0x0a010101, 0x0a010102, segment)
	}
	_ = sum
}

func BenchmarkDirectFlowHash(b *testing.B) {
	packet := make([]byte, 64)
	packet[0] = 0x45
	packet[9] = 6
	b.ReportAllocs()
	var h uint32
	for i := 0; i < b.N; i++ {
		h = flowHash(packet)
	}
	_ = h
}
