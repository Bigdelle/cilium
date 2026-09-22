// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package threefour

import (
	"testing"

	"github.com/gopacket/gopacket/layers"

	pb "github.com/cilium/cilium/api/v1/flow"
)

// The decoded messages are assigned to package-level sinks so that they escape,
// exactly as they do in production where the result is stored on the pb.Flow.
// Without the sink the compiler proves the result is dead, stack-allocates the
// whole object graph and both sides of the comparison report 0 allocs/op.
var (
	sinkLayer4    *pb.Layer4
	sinkEventType *pb.CiliumEventType
)

func BenchmarkDecodeTCP(b *testing.B) {
	tcp := &layers.TCP{SrcPort: 1000, DstPort: 2000, SYN: true, ACK: true}
	b.ReportAllocs()

	for b.Loop() {
		l4, _, _ := decodeTCP(tcp)
		sinkLayer4 = l4
	}
}

func BenchmarkDecodeUDP(b *testing.B) {
	udp := &layers.UDP{SrcPort: 1000, DstPort: 2000}
	b.ReportAllocs()

	for b.Loop() {
		l4, _, _ := decodeUDP(udp)
		sinkLayer4 = l4
	}
}

func BenchmarkDecodeCiliumEventType(b *testing.B) {
	b.ReportAllocs()

	for b.Loop() {
		sinkEventType = decodeCiliumEventType(4, 1)
	}
}
