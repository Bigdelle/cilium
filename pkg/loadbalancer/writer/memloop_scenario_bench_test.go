// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Memloop scenario: service-lb
//
// Intent: offline, in-process reproduction of the control-plane memory
// behaviour of the load-balancer StateDB tables (services, frontends,
// backends) under Kubernetes Service/EndpointSlice churn. No network, BPF,
// root or sleeps are involved; all randomness uses fixed seeds.
//
// GKE workload mirrored: memloop 'service-lb' workload, i.e. 150 ClusterIP
// services with 3 named ports each, whose endpoints are churned in waves
// (pods coming and going, so the active backend set of every service toggles
// on each wave).
//
// Benchmarks:
//   - BenchmarkMemloopScenario_ServiceLB: per iteration, upsert 150x3
//     services/frontends, run several backend churn waves and then tear
//     everything down. Measures transient allocation (B/op, allocs/op) and the
//     residual heap left behind after teardown (inuse-B/op, ideally ~0).
//   - BenchmarkMemloopScenario_ServiceLB_Inuse: per iteration, add a fresh
//     namespace of 150x3 services and churn their backends, without teardown,
//     so retained state grows across iterations. inuse-B/op is the retained
//     heap per batch of 150 services.
//
// Hot packages/functions stressed:
//   - pkg/loadbalancer/writer: Writer.UpsertServiceAndFrontends,
//     Writer.SetBackends/SetBackendsOfCluster, Writer.updateBackends,
//     Writer.RefreshFrontends/refreshFrontend, Writer.DefaultSelectBackends,
//     Writer.DeleteServiceAndFrontends, Writer.DeleteBackendsOfService.
//   - pkg/loadbalancer: Backend/Frontend/Service objects, L3n4Addr,
//     ListBackendsByServiceName, BackendKey/index keys.
//   - github.com/cilium/statedb (+ part/radix tree): WriteTxn Insert/Delete,
//     index updates, Commit, txn node cloning.

package writer

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"runtime"
	"testing"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/source"
)

const (
	memloopServices     = 150
	memloopPorts        = 3
	memloopPodsPerSvc   = 12 // backend pool per service (each pod exposes all ports)
	memloopWaves        = 4  // backend churn waves per iteration
	memloopActiveMin    = 6  // min active pods per wave
	memloopSvcsPerTxn   = 50 // services written per write transaction
	memloopSeed1        = 0x5e7c1b
	memloopSeed2        = 0x10ad
	memloopBaseFEAddr   = 0x0a60_0000 // 10.96.0.0/12 ClusterIP range
	memloopBaseBEAddr   = 0x0a00_0000 // 10.0.0.0/8 pod range (offset)
	memloopBasePortNum  = 8080
	memloopFEPortOffset = 80
)

var memloopPortNames = [memloopPorts]string{"http", "https", "metrics"}

func memloopAddr(base uint32, i int) cmtypes.AddrCluster {
	var a [4]byte
	binary.BigEndian.PutUint32(a[:], base+uint32(i))
	return cmtypes.AddrClusterFrom(netip.AddrFrom4(a), 0)
}

type memloopSvc struct {
	name     loadbalancer.ServiceName
	svc      *loadbalancer.Service
	fes      []loadbalancer.FrontendParams
	backends [memloopPodsPerSvc][]loadbalancer.Backend // per pod, one backend per port
}

// memloopBuildServices deterministically builds 'memloopServices' service
// specs in namespace 'ns'. 'batch' makes addresses unique across batches.
func memloopBuildServices(ns string, batch int) []memloopSvc {
	svcs := make([]memloopSvc, memloopServices)
	for i := range svcs {
		g := batch*memloopServices + i
		name := loadbalancer.NewServiceName(ns, fmt.Sprintf("svc-%d", i))
		portNames := make(map[string]uint16, memloopPorts)
		fes := make([]loadbalancer.FrontendParams, memloopPorts)
		feAddr := memloopAddr(memloopBaseFEAddr, g)
		for p := range memloopPorts {
			port := uint16(memloopFEPortOffset + p)
			portNames[memloopPortNames[p]] = uint16(memloopBasePortNum + p)
			fes[p] = loadbalancer.FrontendParams{
				Address:     loadbalancer.NewL3n4Addr(loadbalancer.TCP, feAddr, port, loadbalancer.ScopeExternal),
				Type:        loadbalancer.SVCTypeClusterIP,
				PortName:    loadbalancer.FEPortName(memloopPortNames[p]),
				ServicePort: port,
			}
		}
		s := memloopSvc{
			name: name,
			svc: &loadbalancer.Service{
				Name:      name,
				Source:    source.Kubernetes,
				PortNames: portNames,
			},
			fes: fes,
		}
		for pod := range memloopPodsPerSvc {
			podAddr := memloopAddr(memloopBaseBEAddr, g*memloopPodsPerSvc+pod)
			bes := make([]loadbalancer.Backend, memloopPorts)
			for p := range memloopPorts {
				bes[p] = loadbalancer.Backend{
					Address:   loadbalancer.NewL3n4Addr(loadbalancer.TCP, podAddr, uint16(memloopBasePortNum+p), loadbalancer.ScopeExternal),
					PortNames: []string{memloopPortNames[p]},
					Weight:    loadbalancer.DefaultBackendWeight,
					NodeName:  fmt.Sprintf("node-%d", pod%8),
					State:     loadbalancer.BackendStateActive,
				}
			}
			s.backends[pod] = bes
		}
		svcs[i] = s
	}
	return svcs
}

// memloopUpsertServices writes services and frontends in batches of
// memloopSvcsPerTxn per transaction (mirrors reflector batching).
func memloopUpsertServices(b *testing.B, w *Writer, svcs []memloopSvc) {
	for start := 0; start < len(svcs); start += memloopSvcsPerTxn {
		wtxn := w.WriteTxn()
		for _, s := range svcs[start:min(start+memloopSvcsPerTxn, len(svcs))] {
			if err := w.UpsertServiceAndFrontends(wtxn, s.svc, s.fes...); err != nil {
				wtxn.Abort()
				b.Fatal(err)
			}
		}
		wtxn.Commit()
	}
}

// memloopChurnWaves runs memloopWaves waves; in each wave every service gets a
// freshly (deterministically) chosen subset of its pod pool as backends.
func memloopChurnWaves(b *testing.B, w *Writer, svcs []memloopSvc, rng *rand.Rand) {
	bes := make([]loadbalancer.Backend, 0, memloopPodsPerSvc*memloopPorts)
	for range memloopWaves {
		for start := 0; start < len(svcs); start += memloopSvcsPerTxn {
			wtxn := w.WriteTxn()
			for _, s := range svcs[start:min(start+memloopSvcsPerTxn, len(svcs))] {
				bes = bes[:0]
				nActive := memloopActiveMin + rng.IntN(memloopPodsPerSvc-memloopActiveMin+1)
				for _, pod := range rng.Perm(memloopPodsPerSvc)[:nActive] {
					bes = append(bes, s.backends[pod]...)
				}
				if err := w.SetBackends(wtxn, s.name, source.Kubernetes, bes...); err != nil {
					wtxn.Abort()
					b.Fatal(err)
				}
			}
			wtxn.Commit()
		}
	}
}

func memloopTeardown(b *testing.B, w *Writer, svcs []memloopSvc) {
	wtxn := w.WriteTxn()
	for _, s := range svcs {
		if err := w.DeleteBackendsOfService(wtxn, s.name, source.Kubernetes); err != nil {
			wtxn.Abort()
			b.Fatal(err)
		}
		if _, err := w.DeleteServiceAndFrontends(wtxn, s.name); err != nil {
			wtxn.Abort()
			b.Fatal(err)
		}
	}
	wtxn.Commit()
}

func memloopHeapAlloc() uint64 {
	var ms runtime.MemStats
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}

func memloopVerifyCounts(b *testing.B, p testParams, wantSvcs int) {
	txn := p.DB.ReadTxn()
	if n := p.ServiceTable.NumObjects(txn); n != wantSvcs {
		b.Fatalf("services: got %d, want %d", n, wantSvcs)
	}
	if n := p.FrontendTable.NumObjects(txn); n != wantSvcs*memloopPorts {
		b.Fatalf("frontends: got %d, want %d", n, wantSvcs*memloopPorts)
	}
}

// BenchmarkMemloopScenario_ServiceLB: upsert 150 services x 3 ports, churn
// backend sets in waves, then tear down. Retained heap after teardown is
// reported as inuse-B/op (should stay near zero; growth indicates a leak).
func BenchmarkMemloopScenario_ServiceLB(b *testing.B) {
	p := fixture(b)
	svcs := memloopBuildServices("memloop", 0)
	rng := rand.New(rand.NewPCG(memloopSeed1, memloopSeed2))

	b.ReportAllocs()
	before := memloopHeapAlloc()
	b.ResetTimer()
	for b.Loop() {
		memloopUpsertServices(b, p.Writer, svcs)
		memloopChurnWaves(b, p.Writer, svcs, rng)
		memloopTeardown(b, p.Writer, svcs)
	}
	b.StopTimer()
	memloopVerifyCounts(b, p, 0)
	after := memloopHeapAlloc()
	inuseDelta := int64(after) - int64(before)
	runtime.KeepAlive(p.DB)
	runtime.KeepAlive(svcs)
	b.ReportMetric(float64(inuseDelta)/float64(b.N), "inuse-B/op")
}

// BenchmarkMemloopScenario_ServiceLB_Inuse: each iteration adds a new batch of
// 150 services x 3 ports (new namespace) and churns its backends, without
// teardown. inuse-B/op is the retained heap per batch.
func BenchmarkMemloopScenario_ServiceLB_Inuse(b *testing.B) {
	p := fixture(b)
	rng := rand.New(rand.NewPCG(memloopSeed1, memloopSeed2))

	// Pre-build service specs outside the measured section so that only the
	// StateDB retained state is attributed to inuse-B/op. A classic b.N loop
	// is used (rather than b.Loop) since b.N must be known up front.
	batches := make([][]memloopSvc, b.N)
	for i := range batches {
		batches[i] = memloopBuildServices(fmt.Sprintf("memloop-%d", i), i)
	}

	b.ReportAllocs()
	before := memloopHeapAlloc()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		memloopUpsertServices(b, p.Writer, batches[i])
		memloopChurnWaves(b, p.Writer, batches[i], rng)
	}
	b.StopTimer()
	memloopVerifyCounts(b, p, b.N*memloopServices)
	after := memloopHeapAlloc()
	inuseDelta := int64(after) - int64(before)
	runtime.KeepAlive(p.DB)
	runtime.KeepAlive(batches)
	b.ReportMetric(float64(inuseDelta)/float64(b.N), "inuse-B/op")
}
