// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Memloop offline scenario: "cidr-policy" (ipcache half)
//
// Intent: provide a cheap, deterministic, in-process memory signal (B/op,
// allocs/op and post-GC retained heap "inuse-B/op") for the ipcache side of
// CIDR policies: the policy importer upserting CIDR prefix metadata
// (labels.GetCIDRLabels) for every prefix referenced by toCIDRSet rules
// (including "except" holes), the asynchronous label injection that allocates
// local CIDR identities and pushes ipcache entries, and the pruning of stale
// prefixes when policies are replaced.
//
// GKE workload mirrored: memloop "cidr-policy" workload — 25 CNPs per wave,
// each with toCIDRSet of 5 /20 blocks x 22 /28 except holes, i.e. 2,875
// prefixes per wave; every wave replaces the previous wave's CIDRs.
//
// Hot packages / functions stressed:
//   - pkg/ipcache: (*IPCache).UpsertMetadataBatch / RemoveMetadataBatch,
//     prefixRefCounter, (*metadata).upsertLocked / remove /
//     enqueuePrefixUpdates, (*IPCache).InjectLabels / doInjectLabels,
//     resolveIdentity, UpsertPrefixes-equivalent ipToIdentityCache updates,
//     WaitForRevision.
//   - pkg/labels: GetCIDRLabels.
//   - pkg/identity (mock allocator): AllocateLocalIdentity / Release
//     (testutils MockIdentityAllocator; the real local allocator is covered by
//     the identity-churn scenario).
//
// The policy half of this scenario (rule translation, selector cache,
// distillation) lives in pkg/policy/memloop_scenario_cidr_bench_test.go.
//
// Run:
//
//	go test ./pkg/ipcache/ -run='^$' -bench='^BenchmarkMemloopScenario_' -benchtime=1x -benchmem

package ipcache

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"runtime"
	"testing"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/identity"
	ipcacheTypes "github.com/cilium/cilium/pkg/ipcache/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
)

const (
	memloopIPCPoliciesPerWave = 25
	memloopIPCBlocksPerPolicy = 5
	memloopIPCHolesPerBlock   = 22
	memloopIPCWaves           = 3
	memloopIPCPrefixesPerWave = memloopIPCPoliciesPerWave * memloopIPCBlocksPerPolicy * (1 + memloopIPCHolesPerBlock)
)

// memloopIPCWavePrefixes returns, per policy resource, the prefixes referenced
// by its toCIDRSet (the /20 blocks and their /28 except holes). Mirrors the
// generator in pkg/policy/memloop_scenario_cidr_bench_test.go.
func memloopIPCWavePrefixes(wave int) map[ipcacheTypes.ResourceID][]netip.Prefix {
	out := make(map[ipcacheTypes.ResourceID][]netip.Prefix, memloopIPCPoliciesPerWave)
	for pol := range memloopIPCPoliciesPerWave {
		res := ipcacheTypes.NewResourceID(ipcacheTypes.ResourceKindCNP, "memloop",
			fmt.Sprintf("cidr-wave-%d-pol-%d", wave, pol))
		prefixes := make([]netip.Prefix, 0, memloopIPCBlocksPerPolicy*(1+memloopIPCHolesPerBlock))
		for blk := range memloopIPCBlocksPerPolicy {
			n := (wave*memloopIPCPoliciesPerWave+pol)*memloopIPCBlocksPerPolicy + blk
			b := [4]byte{byte(100 + n/4096), byte(n / 16 % 256), byte(n % 16 << 4), 0}
			prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom4(b), 20))
			for h := range memloopIPCHolesPerBlock {
				idx := h * 11
				hole := [4]byte{b[0], b[1], b[2] + byte(idx/16), byte(idx%16) << 4}
				prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom4(hole), 28))
			}
		}
		out[res] = prefixes
	}
	return out
}

// memloopIPCUpsertWave mirrors policy_importer.go's allocatePrefixes: one
// batched UpsertMetadataBatch with CIDR labels for all prefixes of a wave,
// then wait for the ipcache to inject labels / allocate identities.
func memloopIPCUpsertWave(b *testing.B, ipc *IPCache, wave int) {
	byRes := memloopIPCWavePrefixes(wave)
	updates := make([]MU, 0, memloopIPCPrefixesPerWave)
	for pol := range memloopIPCPoliciesPerWave {
		res := ipcacheTypes.NewResourceID(ipcacheTypes.ResourceKindCNP, "memloop",
			fmt.Sprintf("cidr-wave-%d-pol-%d", wave, pol))
		for _, p := range byRes[res] {
			updates = append(updates, MU{
				Prefix:   cmtypes.NewLocalPrefixCluster(p),
				Source:   source.Generated,
				Resource: res,
				Metadata: []IPMetadata{labels.GetCIDRLabels(p)},
				IsCIDR:   true,
			})
		}
	}
	if err := ipc.WaitForRevision(context.Background(), ipc.UpsertMetadataBatch(updates...)); err != nil {
		b.Fatal(err)
	}
}

// memloopIPCPruneWave mirrors policy_importer.go's prunePrefixes.
func memloopIPCPruneWave(b *testing.B, ipc *IPCache, wave int) {
	byRes := memloopIPCWavePrefixes(wave)
	updates := make([]MU, 0, memloopIPCPrefixesPerWave)
	for pol := range memloopIPCPoliciesPerWave {
		res := ipcacheTypes.NewResourceID(ipcacheTypes.ResourceKindCNP, "memloop",
			fmt.Sprintf("cidr-wave-%d-pol-%d", wave, pol))
		for _, p := range byRes[res] {
			updates = append(updates, MU{
				Prefix:   cmtypes.NewLocalPrefixCluster(p),
				Resource: res,
				Metadata: []IPMetadata{labels.Labels{}},
				IsCIDR:   true,
			})
		}
	}
	if err := ipc.WaitForRevision(context.Background(), ipc.RemoveMetadataBatch(updates...)); err != nil {
		b.Fatal(err)
	}
}

func memloopIPCHeapAlloc() uint64 {
	var ms runtime.MemStats
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}

// memloopIPCNopUpdater is an IdentityUpdater (SelectorCache stand-in) that
// does not retain identities. The package's mockUpdater keeps every added
// identity forever because local identity deletions reach the SelectorCache
// through the identity allocator's observer, which the mock allocator does
// not implement; that would pollute the retained-heap signal.
type memloopIPCNopUpdater struct{}

func (memloopIPCNopUpdater) UpdateIdentities(_, _ identity.IdentityMap) <-chan struct{} {
	out := make(chan struct{})
	close(out)
	return out
}

func memloopIPCSetup(b *testing.B) *IPCacheTestSuite {
	prevRoutingMode := option.Config.RoutingMode
	b.Cleanup(func() { option.Config.RoutingMode = prevRoutingMode })
	option.Config.RoutingMode = option.RoutingModeNative

	s := &IPCacheTestSuite{
		Allocator: testidentity.NewMockIdentityAllocator(nil),
	}
	s.IPIdentityCache = NewIPCache(&Configuration{
		Context:           b.Context(),
		Logger:            slog.New(slog.DiscardHandler),
		IdentityAllocator: s.Allocator,
		IdentityUpdater:   memloopIPCNopUpdater{},
	})
	s.IPIdentityCache.metadata.upsertLocked(worldPrefix, source.KubeAPIServer, "kube-uid", labels.LabelKubeAPIServer)
	s.IPIdentityCache.metadata.upsertLocked(worldPrefix, source.Local, "host-uid", labels.LabelHost)
	b.Cleanup(func() { s.IPIdentityCache.Shutdown() })
	return s
}

// BenchmarkMemloopScenario_CIDRPolicy_IPCache runs memloopIPCWaves waves per
// iteration on a fresh IPCache: upsert a wave's 2,875 CIDR prefixes, wait for
// label injection, then prune the previous wave. At the end of the iteration
// the last wave is pruned too, so "inuse-B/op" (heap retained between the
// start and the end of an iteration) exposes leaked metadata / identities.
func BenchmarkMemloopScenario_CIDRPolicy_IPCache(b *testing.B) {
	b.ReportAllocs()
	var inuseTotal int64
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		s := memloopIPCSetup(b)
		ipc := s.IPIdentityCache
		baseEntries := len(ipc.ipToIdentityCache)
		before := memloopIPCHeapAlloc()
		b.StartTimer()

		for wave := range memloopIPCWaves {
			memloopIPCUpsertWave(b, ipc, wave)
			if got := len(ipc.ipToIdentityCache) - baseEntries; wave == 0 && got != memloopIPCPrefixesPerWave {
				b.Fatalf("expected %d ipcache entries, got %d", memloopIPCPrefixesPerWave, got)
			}
			if wave > 0 {
				memloopIPCPruneWave(b, ipc, wave-1)
			}
		}
		memloopIPCPruneWave(b, ipc, memloopIPCWaves-1)

		b.StopTimer()
		if got := len(ipc.ipToIdentityCache) - baseEntries; got != 0 {
			b.Fatalf("expected all CIDR ipcache entries to be pruned, %d left", got)
		}
		after := memloopIPCHeapAlloc()
		inuseTotal += int64(after) - int64(before)
		runtime.KeepAlive(s)
		b.StartTimer()
	}
	b.ReportMetric(float64(inuseTotal)/float64(b.N), "inuse-B/op")
}

// BenchmarkMemloopScenario_CIDRPolicy_IPCache_Inuse upserts one new wave of
// 2,875 CIDR prefixes per iteration into one long-lived IPCache without
// pruning. "inuse-B/op" is the retained heap per wave (metadata, prefix
// refcounts, ipcache entries and identities).
func BenchmarkMemloopScenario_CIDRPolicy_IPCache_Inuse(b *testing.B) {
	b.ReportAllocs()
	s := memloopIPCSetup(b)
	ipc := s.IPIdentityCache
	before := memloopIPCHeapAlloc()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		memloopIPCUpsertWave(b, ipc, i)
	}
	b.StopTimer()
	after := memloopIPCHeapAlloc()
	runtime.KeepAlive(s)
	b.ReportMetric(float64(int64(after)-int64(before))/float64(b.N), "inuse-B/op")
}
