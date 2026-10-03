// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"slices"
	"strconv"
	"sync"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"k8s.io/apimachinery/pkg/util/rand"

	"github.com/cilium/cilium/pkg/lock"
)

const (
	fnv32Offset = 2166136261
	fnv32Prime  = 16777619

	// maxVersionHashDepth bounds recursion through nested messages and Any
	// payloads.
	maxVersionHashDepth = 64

	anyFullName protoreflect.FullName = "google.protobuf.Any"
)

var versionBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 4096)
		return &b
	},
}

// versionHasher computes resource-set versions by hashing the protobuf wire
// encoding of each resource with FNV-1a, canonicalizing the parts of the
// encoding that are not deterministic:
//
//   - map entries are combined order-independently (Go marshals maps in
//     random order unless Deterministic is set, and Deterministic does not
//     reach inside Any payloads);
//   - google.protobuf.Any payloads are resolved via the global registry and
//     walked with their own descriptor, so their (opaque) bytes are
//     canonicalized too.
//
// Every item fed to the hash is length-delimited or terminated, so distinct
// inputs never produce the same hashed byte stream (e.g. resource names
// cannot run into resource payloads).
type versionHasher struct {
	h uint32
}

func newVersionHasher() versionHasher { return versionHasher{h: fnv32Offset} }

func (vh *versionHasher) byte(b byte) {
	vh.h ^= uint32(b)
	vh.h *= fnv32Prime
}

func (vh *versionHasher) uvarint(x uint64) {
	for x >= 0x80 {
		vh.byte(byte(x) | 0x80)
		x >>= 7
	}
	vh.byte(byte(x))
}

func (vh *versionHasher) string(s string) {
	vh.uvarint(uint64(len(s)))
	for i := 0; i < len(s); i++ {
		vh.byte(s[i])
	}
}

func (vh *versionHasher) bytes(b []byte) {
	vh.uvarint(uint64(len(b)))
	for _, c := range b {
		vh.byte(c)
	}
}

func (vh *versionHasher) version() string {
	return rand.SafeEncodeString(strconv.FormatUint(uint64(vh.h), 10))
}

// resource hashes one resource message.
func (vh *versionHasher) resource(res proto.Message) error {
	if res == nil {
		vh.uvarint(0)
		return nil
	}
	bp := versionBufPool.Get().(*[]byte)
	buf, err := proto.MarshalOptions{}.MarshalAppend((*bp)[:0], res)
	if err == nil {
		vh.wire(res.ProtoReflect().Descriptor(), buf, 0)
	}
	if cap(buf) <= 1<<20 {
		*bp = buf[:0]
		versionBufPool.Put(bp)
	}
	return err
}

// mapAgg accumulates the order-independent combination of one map field's
// entries.
type mapAgg struct {
	num        protowire.Number
	n          uint64
	sum, sumSq uint64
}

// wire hashes the wire-encoded message b of type md (md may be nil when the
// type is unknown, in which case fields are hashed verbatim). Fields are
// hashed in encoding order as (number, wire type, value); message-typed
// fields recurse; map fields are aggregated and flushed at the end in field
// number order; the message is terminated by a 0 (field numbers are >= 1).
func (vh *versionHasher) wire(md protoreflect.MessageDescriptor, b []byte, depth int) {
	var aggStack [8]mapAgg
	aggs := aggStack[:0]
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			vh.bytes(b) // malformed: hash the remainder verbatim
			break
		}
		b = b[n:]
		m := protowire.ConsumeFieldValue(num, typ, b)
		if m < 0 {
			vh.bytes(b)
			break
		}
		val := b[:m]
		b = b[m:]

		var fd protoreflect.FieldDescriptor
		if md != nil {
			fd = md.Fields().ByNumber(num)
		}
		if fd != nil && typ == protowire.BytesType && depth < maxVersionHashDepth &&
			(fd.Kind() == protoreflect.MessageKind || fd.Kind() == protoreflect.GroupKind) {
			payload, _ := protowire.ConsumeBytes(val)
			if fd.IsMap() {
				sub := newVersionHasher()
				sub.wire(fd.Message(), payload, depth+1)
				i := slices.IndexFunc(aggs, func(a mapAgg) bool { return a.num == num })
				if i < 0 {
					aggs = append(aggs, mapAgg{num: num})
					i = len(aggs) - 1
				}
				h := uint64(sub.h)
				aggs[i].n++
				aggs[i].sum += h
				aggs[i].sumSq += h * h
				continue
			}
			vh.uvarint(uint64(num))
			vh.uvarint(uint64(typ))
			if fd.Message().FullName() == anyFullName {
				vh.anyPayload(payload, depth+1)
			} else {
				vh.wire(fd.Message(), payload, depth+1)
			}
			continue
		}
		vh.uvarint(uint64(num))
		vh.uvarint(uint64(typ))
		vh.bytes(val)
	}
	if len(aggs) > 0 {
		slices.SortFunc(aggs, func(a, b mapAgg) int { return int(a.num) - int(b.num) })
		for _, a := range aggs {
			vh.uvarint(uint64(a.num))
			vh.uvarint(uint64(protowire.BytesType) | 0x10) // map marker, distinct from wire types
			vh.uvarint(a.n)
			vh.uvarint(a.sum)
			vh.uvarint(a.sumSq)
		}
	}
	vh.uvarint(0)
}

// anyPayload hashes a google.protobuf.Any: its type URL, then its value
// walked with the resolved message descriptor (verbatim if unresolvable).
func (vh *versionHasher) anyPayload(b []byte, depth int) {
	var url, value []byte
	rest := b
	for len(rest) > 0 {
		num, typ, n := protowire.ConsumeTag(rest)
		if n < 0 {
			break
		}
		rest = rest[n:]
		m := protowire.ConsumeFieldValue(num, typ, rest)
		if m < 0 {
			break
		}
		if typ == protowire.BytesType {
			v, _ := protowire.ConsumeBytes(rest[:m])
			switch num {
			case 1:
				url = v
			case 2:
				value = v
			}
		}
		rest = rest[m:]
	}
	md := anyMessageDescriptor(url)
	if md == nil || len(rest) != 0 {
		vh.wire(nil, b, depth) // unknown payload type: hash the Any verbatim
		return
	}
	vh.bytes(url)
	vh.wire(md, value, depth)
}

var anyTypes = struct {
	lock.RWMutex
	byURL map[string]protoreflect.MessageDescriptor
}{byURL: map[string]protoreflect.MessageDescriptor{}}

// anyMessageDescriptor resolves an Any type URL via the global registry,
// caching hits so the steady state does not allocate.
func anyMessageDescriptor(url []byte) protoreflect.MessageDescriptor {
	anyTypes.RLock()
	md, ok := anyTypes.byURL[string(url)]
	anyTypes.RUnlock()
	if ok {
		return md
	}
	mt, err := protoregistry.GlobalTypes.FindMessageByURL(string(url))
	if err != nil {
		return nil
	}
	md = mt.Descriptor()
	anyTypes.Lock()
	anyTypes.byURL[string(url)] = md
	anyTypes.Unlock()
	return md
}
