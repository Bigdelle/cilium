// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package parser

import (
	"testing"
	"time"

	"github.com/cilium/hive/hivetest"
	"github.com/google/uuid"

	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
	observerTypes "github.com/cilium/cilium/pkg/hubble/observer/types"
	"github.com/cilium/cilium/pkg/hubble/testutils"
	"github.com/cilium/cilium/pkg/monitor"
	"github.com/cilium/cilium/pkg/monitor/api"
)

// sinkEvent keeps the decoded event alive so that it escapes, as it does in
// production where it is pushed onto the observer ring buffer. Without the sink
// the compiler can stack-allocate the whole object graph and the benchmark
// reports an allocation count that has nothing to do with the real one.
var sinkEvent *v1.Event

func benchmarkDecodePerfEvent(b *testing.B, msgType int) {
	p, err := New(hivetest.Logger(b), nil, nil, nil, nil, nil, nil, nil)
	if err != nil {
		b.Fatal(err)
	}

	tn := monitor.TraceNotify{Type: byte(msgType)}
	data, err := testutils.CreateL3L4Payload(tn)
	if err != nil {
		b.Fatal(err)
	}

	ev := &observerTypes.MonitorEvent{
		Timestamp: time.Now(),
		NodeName:  "node-1",
		UUID:      uuid.New(),
		Payload: &observerTypes.PerfEvent{
			Data: data,
			CPU:  0,
		},
	}

	b.ReportAllocs()
	b.ResetTimer()

	for b.Loop() {
		out, err := p.Decode(ev)
		if err != nil {
			b.Fatal(err)
		}
		sinkEvent = out
	}
}

func BenchmarkDecodeTraceNotify(b *testing.B) {
	benchmarkDecodePerfEvent(b, api.MessageTypeTrace)
}
