// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Memloop scenario: identity-churn
//
// Intent: offline, in-process reproduction of the memory behaviour of the
// cilium-agent while pods with unique label sets are created and deleted in
// waves (e.g. Jobs / Deployments rolling with a unique pod-template-hash).
// Every wave allocates a batch of unique global security identities through
// the CachingIdentityAllocator, propagates them to a policy SelectorCache via
// the IdentityAllocatorOwner callback (as the agent does), then releases them,
// simulates the operator identity GC by deleting the CiliumIdentity objects,
// and waits until the allocator cache and the SelectorCache have converged
// back to empty.
//
// GKE workload mirrored: memloop "identity-churn" (pods with unique labels
// created/deleted repeatedly on a DPv2 cluster, which uses CRD identity
// allocation mode).
//
// Backend: CRD identity allocation mode on top of the fake k8s clientset
// (pkg/k8s/client/testutils). The kvstore backend cannot be used offline: the
// etcd dummy backend requires a running etcd and the in-memory kvstore client
// panics in LockPath, which the kvstore allocator needs.
//
// Hot packages / functions:
//   - pkg/identity/cache: CachingIdentityAllocator.AllocateIdentity / Release,
//     identityWatcher (event batching to the owner)
//   - pkg/allocator: Allocator.Allocate / Release, cache.OnUpsert / OnDelete
//   - pkg/k8s/identitybackend: crdBackend.AllocateID / Get / ListAndWatch
//   - pkg/policy: SelectorCache.UpdateIdentities, identitySelector.matches
//
// Benchmarks:
//   - BenchmarkMemloopScenario_IdentityChurn: one allocate/release wave per
//     iteration, full teardown each wave (inuse-B/op approximates leaked
//     bytes per wave).
//   - BenchmarkMemloopScenario_IdentityChurn_Inuse: identities retained across
//     waves (no release), inuse-B/op approximates retained bytes per wave.

package cache

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/allocator"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/idpool"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
)

const (
	// memloopIDWaveSize is the number of unique identities allocated per wave.
	memloopIDWaveSize = 500
	// memloopIDNamespaces / memloopIDApps control label cardinality and
	// therefore how many selectors match each identity.
	memloopIDNamespaces = 8
	memloopIDApps       = 16
	// memloopIDConvergeTimeout bounds waiting for async watcher events.
	memloopIDConvergeTimeout = 30 * time.Second
)

// memloopIDOwner implements IdentityAllocatorOwner and forwards identity
// updates synchronously to a policy SelectorCache, mimicking the agent's
// policy identity updater.
type memloopIDOwner struct {
	sc   *policy.SelectorCache
	mu   lock.Mutex
	live map[identity.NumericIdentity]struct{}
}

func (o *memloopIDOwner) UpdateIdentities(added, deleted identity.IdentityMap) <-chan struct{} {
	wg := &sync.WaitGroup{}
	o.sc.UpdateIdentities(added, deleted, wg)
	wg.Wait()
	o.mu.Lock()
	for id := range added {
		o.live[id] = struct{}{}
	}
	for id := range deleted {
		delete(o.live, id)
	}
	o.mu.Unlock()
	out := make(chan struct{})
	close(out)
	return out
}

func (o *memloopIDOwner) GetNodeSuffix() string { return "memloop" }

func (o *memloopIDOwner) liveCount() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.live)
}

type memloopIDEnv struct {
	mgr    *CachingIdentityAllocator
	owner  *memloopIDOwner
	client *k8sClient.FakeClientset
}

func memloopIDSetup(b *testing.B) *memloopIDEnv {
	b.Helper()
	logger := slog.New(slog.DiscardHandler)

	prevMode := option.Config.IdentityAllocationMode
	option.Config.IdentityAllocationMode = option.IdentityAllocationModeCRD
	b.Cleanup(func() { option.Config.IdentityAllocationMode = prevMode })

	sc := policy.NewSelectorCache(logger, nil)
	user := &testpolicy.DummySelectorCacheUser{}
	for i := range memloopIDApps {
		sc.AddIdentitySelectorForTest(user, api.NewESFromLabels(labels.ParseSelectLabel(fmt.Sprintf("k8s:app=churn-%d", i))))
	}
	for i := range memloopIDNamespaces {
		sc.AddIdentitySelectorForTest(user, api.NewESFromLabels(labels.ParseSelectLabel(fmt.Sprintf("k8s:io.kubernetes.pod.namespace=ns-%d", i))))
	}
	sc.AddIdentitySelectorForTest(user, api.WildcardEndpointSelector)

	owner := &memloopIDOwner{sc: sc, live: map[identity.NumericIdentity]struct{}{}}
	fakeCS, cs := k8sClient.NewFakeClientset(logger)
	mgr := NewCachingIdentityAllocator(logger, owner, testAllocatorConfig(false, 0))
	<-mgr.InitIdentityAllocator(cs, nil)
	ctx, cancel := context.WithTimeout(context.Background(), memloopIDConvergeTimeout)
	defer cancel()
	if err := mgr.WaitForInitialGlobalIdentities(ctx); err != nil {
		b.Fatalf("WaitForInitialGlobalIdentities: %v", err)
	}
	b.Cleanup(mgr.Close)
	return &memloopIDEnv{mgr: mgr, owner: owner, client: fakeCS}
}

// memloopIDLabels returns a deterministic pod-like label set that is unique
// per (wave, idx) thanks to the pod-template-hash label.
func memloopIDLabels(wave, idx int) labels.Labels {
	return labels.NewLabelsFromModel([]string{
		"k8s:app=churn-" + strconv.Itoa(idx%memloopIDApps),
		"k8s:io.kubernetes.pod.namespace=ns-" + strconv.Itoa(idx%memloopIDNamespaces),
		"k8s:io.cilium.k8s.policy.serviceaccount=default",
		"k8s:io.cilium.k8s.policy.cluster=default",
		"k8s:pod-template-hash=w" + strconv.Itoa(wave) + "-" + strconv.Itoa(idx),
	})
}

func (e *memloopIDEnv) allocateWave(b *testing.B, wave int) []*identity.Identity {
	ctx := context.Background()
	ids := make([]*identity.Identity, 0, memloopIDWaveSize)
	for i := range memloopIDWaveSize {
		id, _, err := e.mgr.AllocateIdentity(ctx, memloopIDLabels(wave, i), true, identity.InvalidIdentity)
		if err != nil {
			b.Fatalf("AllocateIdentity(wave=%d, idx=%d): %v", wave, i, err)
		}
		ids = append(ids, id)
	}
	return ids
}

func (e *memloopIDEnv) cacheCount() int {
	n := 0
	e.mgr.IdentityAllocator.ForeachCache(func(idpool.ID, allocator.AllocatorKey) { n++ })
	return n
}

// waitFor spins (yielding, no sleeping) until cond holds or a deadline passes.
func (e *memloopIDEnv) waitFor(b *testing.B, what string, cond func() bool) {
	deadline := time.Now().Add(memloopIDConvergeTimeout)
	for !cond() {
		if time.Now().After(deadline) {
			b.Fatalf("timed out waiting for %s (cache=%d live=%d)", what, e.cacheCount(), e.owner.liveCount())
		}
		runtime.Gosched()
	}
}

// releaseWave releases the identities locally and then simulates the
// operator identity GC by deleting the CiliumIdentity objects.
func (e *memloopIDEnv) releaseWave(b *testing.B, ids []*identity.Identity) {
	ctx := context.Background()
	for _, id := range ids {
		if _, err := e.mgr.Release(ctx, id, true); err != nil {
			b.Fatalf("Release(%d): %v", id.ID, err)
		}
	}
	cids := e.client.CiliumFakeClientset.CiliumV2().CiliumIdentities()
	for _, id := range ids {
		if err := cids.Delete(ctx, id.ID.String(), metav1.DeleteOptions{}); err != nil {
			b.Fatalf("Delete CiliumIdentity %d: %v", id.ID, err)
		}
	}
}

func memloopIDHeap() uint64 {
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}

func BenchmarkMemloopScenario_IdentityChurn(b *testing.B) {
	env := memloopIDSetup(b)

	// Warm-up wave so that one-off lazy initialisation is not attributed
	// to the measured waves.
	env.releaseWave(b, env.allocateWave(b, -1))
	env.waitFor(b, "warm-up convergence", func() bool { return env.cacheCount() == 0 && env.owner.liveCount() == 0 })

	before := memloopIDHeap()
	b.ReportAllocs()
	wave := 0
	for b.Loop() {
		ids := env.allocateWave(b, wave)
		env.waitFor(b, "allocator cache fill", func() bool { return env.cacheCount() == len(ids) })
		env.releaseWave(b, ids)
		env.waitFor(b, "wave teardown", func() bool { return env.cacheCount() == 0 && env.owner.liveCount() == 0 })
		wave++
	}
	b.StopTimer()
	after := memloopIDHeap()
	runtime.KeepAlive(env)
	b.ReportMetric(float64(int64(after)-int64(before))/float64(b.N), "inuse-B/op")
}

func BenchmarkMemloopScenario_IdentityChurn_Inuse(b *testing.B) {
	env := memloopIDSetup(b)

	env.releaseWave(b, env.allocateWave(b, -1))
	env.waitFor(b, "warm-up convergence", func() bool { return env.cacheCount() == 0 && env.owner.liveCount() == 0 })

	retained := make([][]*identity.Identity, 0, 16)
	before := memloopIDHeap()
	b.ReportAllocs()
	wave := 0
	for b.Loop() {
		ids := env.allocateWave(b, wave)
		retained = append(retained, ids)
		total := (wave + 1) * memloopIDWaveSize
		env.waitFor(b, "allocator cache fill", func() bool { return env.cacheCount() == total })
		wave++
	}
	b.StopTimer()
	after := memloopIDHeap()
	runtime.KeepAlive(retained)
	runtime.KeepAlive(env)
	b.ReportMetric(float64(int64(after)-int64(before))/float64(b.N), "inuse-B/op")
}
