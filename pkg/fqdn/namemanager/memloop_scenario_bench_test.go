// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Memloop offline scenario: "dns"
//
// Intent: provide a cheap, deterministic, in-process memory signal (B/op,
// allocs/op and post-GC retained heap "inuse-B/op") for the FQDN / toFQDNs
// policy path, so that memory optimizations of the agent's DNS handling can be
// evaluated without a GKE cluster.
//
// GKE workload mirrored: memloop "dns" workload — client pods resolving 500
// wave-indexed service names (svc-NNN.wave-W.memloop.test), each resolving to
// 4 IPs, with toFQDNs policies (matchName + matchPattern) selecting them, IPs
// rotating every wave so that DNS cache entries expire into zombies and are
// garbage collected.
//
// Hot packages / functions stressed:
//   - pkg/fqdn/namemanager: (*manager).RegisterFQDNSelector,
//     UnregisterFQDNSelector, UpdateGenerateDNS, updateDNSIPs,
//     deriveLabelsForName(s), mapSelectorsToNamesLocked, updateMetadata,
//     maybeRemoveMetadata.
//   - pkg/fqdn: DNSCache.Update / Lookup / LookupIP / LookupByRegexp / GC /
//     ReplaceFromCacheByNames / RemoveKnown, DNSZombieMappings.Upsert /
//     MarkAlive / GC.
//   - pkg/fqdn/matchpattern + pkg/fqdn/re: pattern sanitization, anchored
//     regexp generation and the regexp compile LRU.
//
// The DNS proxy itself (pkg/fqdn/dnsproxy) is not exercised because it needs
// real sockets; the ipcache is the in-memory testipcache mock, so ipcache
// metadata memory is not included here (see the cidr-policy scenario).
//
// Run:
//
//	go test ./pkg/fqdn/namemanager/ -run='^$' -bench='^BenchmarkMemloopScenario_' -benchtime=1x -benchmem

package namemanager

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"regexp"
	"runtime"
	"testing"

	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/pkg/fqdn"
	"github.com/cilium/cilium/pkg/fqdn/matchpattern"
	"github.com/cilium/cilium/pkg/policy/api"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
	"github.com/cilium/cilium/pkg/time"
)

const (
	memloopDNSNamesPerWave = 500
	memloopDNSIPsPerName   = 4
	memloopDNSWaves        = 4
	memloopDNSEndpoints    = 8
	memloopDNSTTL          = 30 // seconds
	memloopDNSDomain       = "memloop.test"
)

// memloopDNSEndpoint is a minimal stand-in for an endpoint's DNS state
// (ep.DNSHistory + ep.DNSZombies).
type memloopDNSEndpoint struct {
	history *fqdn.DNSCache
	zombies *fqdn.DNSZombieMappings
}

type memloopDNSState struct {
	mgr *manager
	eps []memloopDNSEndpoint
}

func memloopDNSNewState() *memloopDNSState {
	logger := slog.New(slog.DiscardHandler)
	s := &memloopDNSState{
		mgr: New(ManagerParams{
			Logger: logger,
			Config: NameManagerConfig{
				MinTTL:            1,
				DNSProxyLockCount: 131,
			},
			IPCache: testipcache.NewMockIPCache(),
		}),
	}
	for range memloopDNSEndpoints {
		s.eps = append(s.eps, memloopDNSEndpoint{
			// Same defaults as the agent: tofqdns-endpoint-max-ip-per-hostname=1000
			history: fqdn.NewDNSCacheWithLimit(1, 1000),
			// tofqdns-max-deferred-connection-deletes=10000
			zombies: fqdn.NewDNSZombieMappings(logger, 10000, 1000),
		})
	}
	return s
}

func memloopDNSName(wave, i int) string {
	return fmt.Sprintf("svc-%03d.wave-%d.%s.", i, wave, memloopDNSDomain)
}

// memloopDNSIPs returns deterministic IPv4s for (wave, name, rotation). The
// rotation changes every wave so that previously returned IPs become stale.
func memloopDNSIPs(wave, i, rotation int) []netip.Addr {
	ips := make([]netip.Addr, 0, memloopDNSIPsPerName)
	for k := range memloopDNSIPsPerName {
		n := (wave*memloopDNSNamesPerWave+i)*memloopDNSIPsPerName + k
		ips = append(ips, netip.AddrFrom4([4]byte{
			byte(10 + rotation%64),
			byte(n >> 16),
			byte(n >> 8),
			byte(n),
		}))
	}
	return ips
}

// memloopDNSSelectors returns the toFQDNs selectors of a wave: one matchName
// per 5th name, a per-wave matchPattern and a few prefix patterns.
func memloopDNSSelectors(wave int) []api.FQDNSelector {
	sels := make([]api.FQDNSelector, 0, memloopDNSNamesPerWave/5+6)
	for i := 0; i < memloopDNSNamesPerWave; i += 5 {
		sels = append(sels, api.FQDNSelector{MatchName: memloopDNSName(wave, i)})
	}
	sels = append(sels, api.FQDNSelector{
		MatchPattern: fmt.Sprintf("*.wave-%d.%s", wave, memloopDNSDomain),
	})
	for p := range 5 {
		sels = append(sels, api.FQDNSelector{
			MatchPattern: fmt.Sprintf("svc-%d*.wave-%d.%s", p, wave, memloopDNSDomain),
		})
	}
	return sels
}

// memloopDNSResolveWave simulates the DNS proxy observing responses for all
// names of a wave (one response per name, attributed to one endpoint).
func (s *memloopDNSState) resolveWave(ctx context.Context, now time.Time, wave, rotation int) {
	for i := range memloopDNSNamesPerWave {
		name := memloopDNSName(wave, i)
		ips := memloopDNSIPs(wave, i, rotation)
		ep := s.eps[i%len(s.eps)]
		ep.history.Update(now, name, ips, memloopDNSTTL)
		// Drain the returned channel, otherwise the goroutine spawned
		// by UpdateGenerateDNS leaks.
		<-s.mgr.UpdateGenerateDNS(ctx, now, name, &fqdn.DNSIPRecords{
			TTL: memloopDNSTTL,
			IPs: ips,
		}, ep.history)
	}
}

// lookups exercises the read paths used by the API handlers and policy
// (forward, reverse and regexp lookups).
func (s *memloopDNSState) lookups(wave, rotation int) int {
	found := 0
	for i := 0; i < memloopDNSNamesPerWave; i += 10 {
		found += len(s.mgr.cache.Lookup(memloopDNSName(wave, i)))
		found += len(s.mgr.cache.LookupIP(memloopDNSIPs(wave, i, rotation)[0]))
	}
	re := regexp.MustCompile(matchpattern.ToAnchoredRegexp(
		matchpattern.Sanitize(fmt.Sprintf("svc-1*.wave-%d.%s", wave, memloopDNSDomain))))
	found += len(s.mgr.cache.LookupByRegexp(re))
	return found
}

// gc mirrors (*manager).doGC with a synthetic clock: per-endpoint DNS cache
// GC into zombies, zombie GC (with aliveIPs marked alive by a fake CT GC),
// collection into the global cache and ipcache metadata removal.
func (s *memloopDNSState) gc(now time.Time, aliveIPs []netip.Addr) {
	namesToClean := sets.New[string]()
	initialNames := s.mgr.cache.DumpNames()
	allEndpointNames := sets.New[string]()
	activeConnections := fqdn.NewDNSCache(2 * memloopDNSTTL)

	for _, ep := range s.eps {
		allEndpointNames.Insert(ep.history.DumpNames().UnsortedList()...)
		namesToClean = namesToClean.Union(ep.history.GC(now, ep.zombies))

		// Fake CT GC: mark the IPs with active connections as alive.
		for _, ip := range aliveIPs {
			ep.zombies.MarkAlive(now, ip)
		}
		ep.zombies.SetCTGCTime(now.Add(-time.Second), now.Add(time.Minute))

		alive, dead := ep.zombies.GC()
		for _, z := range alive {
			for _, name := range z.Names {
				namesToClean.Insert(name)
				activeConnections.Update(now, name, []netip.Addr{z.IP}, 2*memloopDNSTTL)
			}
		}
		for _, z := range dead {
			namesToClean.Insert(z.Names...)
		}
	}
	namesToClean = namesToClean.Union(initialNames.Difference(allEndpointNames))
	if namesToClean.Len() == 0 {
		return
	}
	caches := []*fqdn.DNSCache{activeConnections}
	for _, ep := range s.eps {
		caches = append(caches, ep.history)
	}
	stale := s.mgr.cache.ReplaceFromCacheByNames(namesToClean.UnsortedList(), caches...)
	s.mgr.maybeRemoveMetadata(stale)
}

func memloopDNSHeapAlloc() uint64 {
	var ms runtime.MemStats
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}

// BenchmarkMemloopScenario_DNS runs the full dns churn cycle per iteration:
// for each wave register selectors, resolve 500 names x 4 IPs, look them up,
// re-resolve with rotated IPs (old IPs become zombies), GC, then unregister
// the previous wave's selectors. All state is discarded at the end of each
// iteration; "inuse-B/op" reports the heap retained by the state at the end
// of an iteration (before teardown).
func BenchmarkMemloopScenario_DNS(b *testing.B) {
	ctx := context.Background()
	b.ReportAllocs()

	var inuseTotal int64
	found := 0
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		before := memloopDNSHeapAlloc()
		b.StartTimer()

		s := memloopDNSNewState()
		// Fixed offsets relative to a base time; DNSCache.Lookup uses
		// the wall clock so the base must be "now".
		base := time.Now()
		for wave := range memloopDNSWaves {
			now := base.Add(time.Duration(wave) * 2 * memloopDNSTTL * time.Second)
			for _, sel := range memloopDNSSelectors(wave) {
				s.mgr.RegisterFQDNSelector(sel)
			}
			s.resolveWave(ctx, now, wave, 0)
			found += s.lookups(wave, 0)
			// IP rotation half-way through the wave.
			s.resolveWave(ctx, now.Add(memloopDNSTTL/2*time.Second), wave, 1)
			found += s.lookups(wave, 1)
			// GC after the first set of IPs expired.
			// 10% of the stale IPs still have active connections.
			var aliveIPs []netip.Addr
			for n := 0; n < memloopDNSNamesPerWave; n += 10 {
				aliveIPs = append(aliveIPs, memloopDNSIPs(wave, n, 0)[0])
			}
			s.gc(now.Add((memloopDNSTTL+1)*time.Second), aliveIPs)
			if wave > 0 {
				for _, sel := range memloopDNSSelectors(wave - 1) {
					s.mgr.UnregisterFQDNSelector(sel)
				}
			}
		}

		b.StopTimer()
		after := memloopDNSHeapAlloc()
		inuseTotal += int64(after) - int64(before)
		runtime.KeepAlive(s)
		b.StartTimer()
	}
	if found == 0 {
		b.Fatal("no DNS lookups succeeded")
	}
	b.ReportMetric(float64(inuseTotal)/float64(b.N), "inuse-B/op")
}

// BenchmarkMemloopScenario_DNS_Inuse grows retained state across iterations:
// every iteration adds a brand new wave (new selectors, 500 new names x 4 new
// IPs) to one long-lived name manager without GC or unregistering, so the
// reported "inuse-B/op" is the retained heap per wave. Leaks or bloat in the
// DNS cache / selector bookkeeping show up as an increase of this metric.
func BenchmarkMemloopScenario_DNS_Inuse(b *testing.B) {
	ctx := context.Background()
	b.ReportAllocs()

	s := memloopDNSNewState()
	base := time.Now()
	before := memloopDNSHeapAlloc()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		now := base.Add(time.Duration(i) * time.Second)
		for _, sel := range memloopDNSSelectors(i) {
			s.mgr.RegisterFQDNSelector(sel)
		}
		s.resolveWave(ctx, now, i, 0)
	}
	b.StopTimer()
	after := memloopDNSHeapAlloc()
	runtime.KeepAlive(s)
	b.ReportMetric(float64(int64(after)-int64(before))/float64(b.N), "inuse-B/op")
}
