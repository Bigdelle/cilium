// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package threefour

import (
	"testing"

	"github.com/gopacket/gopacket/layers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	pb "github.com/cilium/cilium/api/v1/flow"
)

// TestDecodeCiliumEventTypeMatchesUncached pins the shared event-type table to
// the value the uncached construction would have produced, for every possible
// (type, subtype) pair -- including the out-of-table pairs that must fall
// through to a fresh allocation rather than index out of range.
func TestDecodeCiliumEventTypeMatchesUncached(t *testing.T) {
	for typ := range 256 {
		for sub := range 256 {
			got := decodeCiliumEventType(uint8(typ), uint8(sub))
			want := &pb.CiliumEventType{Type: int32(typ), SubType: int32(sub)}
			if !proto.Equal(got, want) {
				t.Fatalf("decodeCiliumEventType(%d, %d) = %v, want %v", typ, sub, got, want)
			}
		}
	}
}

// TestDecodeCiliumEventTypeIsShared documents that in-table pairs deliberately
// return one shared instance. If this ever needs to change, every caller that
// might mutate the returned message has to be audited first.
func TestDecodeCiliumEventTypeIsShared(t *testing.T) {
	a := decodeCiliumEventType(4, 1)
	b := decodeCiliumEventType(4, 1)
	assert.Same(t, a, b, "in-table event types should be shared")

	// Out-of-table pairs are freshly allocated.
	c := decodeCiliumEventType(200, 1)
	d := decodeCiliumEventType(200, 1)
	assert.NotSame(t, c, d, "out-of-table event types should not be shared")
}

// TestSharedConstantProtosAreNotMutated guards the invariant that makes sharing
// safe: nothing in the decode path may write to the shared constant messages.
// It checks them before and after exercising the decoders that hand them out.
func TestSharedConstantProtosAreNotMutated(t *testing.T) {
	require.True(t, boolValueTrue.GetValue())
	require.False(t, boolValueFalse.GetValue())

	for range 100 {
		_ = decodeIsReply(nil, nil)
		_ = decodeCiliumEventType(4, 1)
		_, _, _ = decodeTCP(&layers.TCP{SYN: true, ACK: true})
		_, _, _ = decodeUDP(&layers.UDP{})
	}

	assert.True(t, boolValueTrue.GetValue(), "boolValueTrue was mutated")
	assert.False(t, boolValueFalse.GetValue(), "boolValueFalse was mutated")
	for typ := range 16 {
		for sub := range 32 {
			et := eventTypeCache[typ][sub]
			assert.Equal(t, int32(typ), et.GetType())
			assert.Equal(t, int32(sub), et.GetSubType())
		}
	}
}

// TestDecodeTCPCoAllocationIsIndependent verifies that the co-allocated Layer4
// struct still yields fully independent messages per call: two decodes must not
// alias, or one flow's ports would change when another is decoded.
func TestDecodeTCPCoAllocationIsIndependent(t *testing.T) {
	l4a, srcA, dstA := decodeTCP(&layers.TCP{SrcPort: 1000, DstPort: 2000, SYN: true})
	l4b, srcB, dstB := decodeTCP(&layers.TCP{SrcPort: 3000, DstPort: 4000, FIN: true})

	assert.Equal(t, uint16(1000), srcA)
	assert.Equal(t, uint16(2000), dstA)
	assert.Equal(t, uint16(3000), srcB)
	assert.Equal(t, uint16(4000), dstB)

	assert.NotSame(t, l4a, l4b)
	assert.NotSame(t, l4a.GetTCP(), l4b.GetTCP())
	assert.NotSame(t, l4a.GetTCP().GetFlags(), l4b.GetTCP().GetFlags())

	assert.Equal(t, uint32(1000), l4a.GetTCP().GetSourcePort())
	assert.Equal(t, uint32(2000), l4a.GetTCP().GetDestinationPort())
	assert.True(t, l4a.GetTCP().GetFlags().GetSYN())
	assert.False(t, l4a.GetTCP().GetFlags().GetFIN())

	assert.Equal(t, uint32(3000), l4b.GetTCP().GetSourcePort())
	assert.Equal(t, uint32(4000), l4b.GetTCP().GetDestinationPort())
	assert.True(t, l4b.GetTCP().GetFlags().GetFIN())
	assert.False(t, l4b.GetTCP().GetFlags().GetSYN())
}

// TestDecodeUDPCoAllocationIsIndependent is the UDP equivalent.
func TestDecodeUDPCoAllocationIsIndependent(t *testing.T) {
	l4a, srcA, dstA := decodeUDP(&layers.UDP{SrcPort: 1000, DstPort: 2000})
	l4b, srcB, dstB := decodeUDP(&layers.UDP{SrcPort: 3000, DstPort: 4000})

	assert.Equal(t, uint16(1000), srcA)
	assert.Equal(t, uint16(2000), dstA)
	assert.Equal(t, uint16(3000), srcB)
	assert.Equal(t, uint16(4000), dstB)

	assert.NotSame(t, l4a, l4b)
	assert.NotSame(t, l4a.GetUDP(), l4b.GetUDP())

	assert.Equal(t, uint32(1000), l4a.GetUDP().GetSourcePort())
	assert.Equal(t, uint32(4000), l4b.GetUDP().GetDestinationPort())
}
