// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Memloop offline scenario: "cidr-policy" (policy half)
//
// Intent: provide a cheap, deterministic, in-process memory signal (B/op,
// allocs/op and post-GC retained heap "inuse-B/op") for the CIDR policy path
// of the agent: translating toCIDRSet rules with "except" holes into policy
// entries and selectors, extracting the referenced prefixes, allocating CIDR
// identities for them into the SelectorCache, and resolving + distilling the
// resulting endpoint policy.
//
// GKE workload mirrored: memloop "cidr-policy" workload — 25 CiliumNetworkPolicies
// per wave, each with an egress toCIDRSet of 5 /20 blocks, each with 22 /28
// "except" holes, i.e. 25 * 5 * (1 + 22) = 2,875 prefixes per wave. Every
// wave replaces the previous wave's policies (new CIDRs), so prefixes and
// their CIDR identities churn.
//
// Hot packages / functions stressed:
//   - pkg/policy/utils: RulesToPolicyEntries (mergeEndpointSelectors / CIDRSet
//     to selector translation including except holes).
//   - pkg/policy/types: CIDR selectors, (*PolicyEntry) L3 GetCIDRPrefixes.
//   - pkg/policy: GetCIDRPrefixes, (*Repository).ReplaceByResource,
//     (*SelectorCache).AddSelectors / UpdateIdentities / RemoveSelectors,
//     (*Repository).resolvePolicyLocked, (*selectorPolicy).DistillPolicy,
//     mapState insertion.
//   - pkg/labels: GetCIDRLabels (CIDR identity labels for every prefix).
//
// The ipcache half of this scenario (prefix metadata upserts and identity
// allocation for ~2,875 prefixes per wave) lives in
// pkg/ipcache/memloop_scenario_bench_test.go.
//
// Run:
//
//	go test ./pkg/policy/ -run='^$' -bench='^BenchmarkMemloopScenario_CIDRPolicy' -benchtime=1x -benchmem

package policy

import (
	"fmt"
	"log/slog"
	"net/netip"
	"runtime"
	"sync"
	"testing"

	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/identity"
	ipcachetypes "github.com/cilium/cilium/pkg/ipcache/types"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	policyutils "github.com/cilium/cilium/pkg/policy/utils"
)

const (
	memloopCIDRPoliciesPerWave = 25
	memloopCIDRBlocksPerPolicy = 5
	memloopCIDRHolesPerBlock   = 22
	memloopCIDRWaves           = 3
	// identity numbers per wave; must exceed the prefixes per wave (2,875)
	memloopCIDRIDsPerWave = 4096
)

// memloopCIDRSubject is the (namespaced) endpoint identity selected by the
// CIDR policies. Namespaced policy rules only apply to identities of the same
// namespace, so it carries the namespace label.
var memloopCIDRSubject = func() *identity.Identity {
	lbls := labels.NewLabelsFromModel([]string{
		"k8s:app=memloop-cidr-client",
		"k8s:" + k8sConst.PodNamespaceLabel + "=memloop",
	})
	return identity.NewIdentity(identity.NumericIdentity(70000), lbls)
}()

// memloopCIDRBlock returns the /20 block for (wave, policy, block). Blocks are
// unique per wave so that consecutive waves select disjoint prefixes.
func memloopCIDRBlock(wave, pol, blk int) netip.Addr {
	n := (wave*memloopCIDRPoliciesPerWave+pol)*memloopCIDRBlocksPerPolicy + blk
	// n < 4096 * 16 for any reasonable wave count; /20 => 3rd octet step 16
	return netip.AddrFrom4([4]byte{byte(100 + n/4096), byte(n / 16 % 256), byte(n % 16 << 4), 0})
}

// memloopCIDRRules builds the 25 CNP-like rules of a wave, one api.Rules per
// policy resource.
func memloopCIDRRules(wave int) []api.Rules {
	selector := api.NewESFromLabels(
		labels.ParseSelectLabel("k8s:app=memloop-cidr-client"),
		labels.ParseSelectLabel("k8s:"+k8sConst.PodNamespaceLabel+"=memloop"),
	)
	out := make([]api.Rules, 0, memloopCIDRPoliciesPerWave)
	for pol := range memloopCIDRPoliciesPerWave {
		cidrSet := make(api.CIDRRuleSlice, 0, memloopCIDRBlocksPerPolicy)
		for blk := range memloopCIDRBlocksPerPolicy {
			base := memloopCIDRBlock(wave, pol, blk)
			except := make([]api.CIDR, 0, memloopCIDRHolesPerBlock)
			b := base.As4()
			for h := range memloopCIDRHolesPerBlock {
				// 22 holes spread over the 256 /28s of the /20
				idx := h * 11
				hole := netip.AddrFrom4([4]byte{b[0], b[1], b[2] + byte(idx/16), byte(idx%16) << 4})
				except = append(except, api.CIDR(netip.PrefixFrom(hole, 28).String()))
			}
			cidrSet = append(cidrSet, api.CIDRRule{
				Cidr:        api.CIDR(netip.PrefixFrom(base, 20).String()),
				ExceptCIDRs: except,
			})
		}
		name := fmt.Sprintf("cidr-wave-%d-pol-%d", wave, pol)
		rule := &api.Rule{
			EndpointSelector: selector,
			Egress: []api.EgressRule{{
				EgressCommonRule: api.EgressCommonRule{ToCIDRSet: cidrSet},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{{Port: "443", Protocol: api.ProtoTCP}},
				}},
			}},
			Labels: utils.GetPolicyLabels("memloop", name,
				k8stypes.UID(fmt.Sprintf("00000000-0000-0000-%04d-%012d", wave%10000, pol)),
				utils.ResourceTypeCiliumNetworkPolicy),
		}
		rule.Sanitize()
		out = append(out, api.Rules{rule})
	}
	return out
}

func memloopCIDRResource(wave, pol int) ipcachetypes.ResourceID {
	return ipcachetypes.NewResourceID(ipcachetypes.ResourceKindCNP, "memloop",
		fmt.Sprintf("cidr-wave-%d-pol-%d", wave, pol))
}

type memloopCIDRWave struct {
	ids identity.IdentityMap
}

// apply installs all policies of a wave and allocates CIDR identities for the
// referenced prefixes (as the ipcache would), returning the identities.
func memloopCIDRApplyWave(td *testData, wave int) memloopCIDRWave {
	var allPrefixes []netip.Prefix
	for pol, rules := range memloopCIDRRules(wave) {
		entries := policyutils.RulesToPolicyEntries(rules)
		allPrefixes = append(allPrefixes, GetCIDRPrefixes(entries)...)
		td.repo.ReplaceByResource(entries, memloopCIDRResource(wave, pol))
	}
	ids := make(identity.IdentityMap, len(allPrefixes))
	for i, p := range allPrefixes {
		id := identity.IdentityScopeLocal + identity.NumericIdentity(wave*memloopCIDRIDsPerWave+i+1)
		ids[id] = labels.GetCIDRLabels(p)
	}
	wg := &sync.WaitGroup{}
	td.sc.UpdateIdentities(ids, nil, wg)
	wg.Wait()
	return memloopCIDRWave{ids: ids}
}

func memloopCIDRRemoveWave(td *testData, wave int, w memloopCIDRWave) {
	for pol := range memloopCIDRPoliciesPerWave {
		td.repo.ReplaceByResource(nil, memloopCIDRResource(wave, pol))
	}
	wg := &sync.WaitGroup{}
	td.sc.UpdateIdentities(nil, w.ids, wg)
	wg.Wait()
}

// memloopCIDRResolve resolves and distills the policy of the subject
// identity, returning the number of map state entries.
func memloopCIDRResolve(b *testing.B, td *testData, logger *slog.Logger) int {
	sp, err := td.repo.resolvePolicyLocked(memloopCIDRSubject)
	if err != nil {
		b.Fatal(err)
	}
	owner := DummyOwner{logger: logger}
	epPolicy := sp.DistillPolicy(logger, owner, nil)
	epPolicy.Ready()
	n := epPolicy.Len()
	epPolicy.Detach(logger)
	sp.Detach()
	return n
}

func memloopCIDRNewTestData(b *testing.B, logger *slog.Logger) *testData {
	td := newTestData(b, logger)
	td.bootstrapRepo(nil, 0, b)
	td.addIdentity(memloopCIDRSubject)
	return td
}

func memloopCIDRHeapAlloc() uint64 {
	var ms runtime.MemStats
	runtime.GC()
	runtime.GC()
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}

// BenchmarkMemloopScenario_CIDRPolicy runs memloopCIDRWaves waves per
// iteration on a fresh repository: install a wave's 25 policies (2,875
// prefixes), allocate CIDR identities, resolve+distill the endpoint policy,
// then remove the previous wave. "inuse-B/op" is the heap retained by the
// repository/selector cache at the end of an iteration.
func BenchmarkMemloopScenario_CIDRPolicy(b *testing.B) {
	oldEnforcement := GetPolicyEnabled()
	b.Cleanup(func() { SetPolicyEnabled(oldEnforcement) })
	SetPolicyEnabled(option.DefaultEnforcement)

	logger := slog.New(slog.DiscardHandler)
	b.ReportAllocs()

	var inuseTotal int64
	entries := 0
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		before := memloopCIDRHeapAlloc()
		b.StartTimer()

		td := memloopCIDRNewTestData(b, logger)
		var prev memloopCIDRWave
		for wave := range memloopCIDRWaves {
			cur := memloopCIDRApplyWave(td, wave)
			entries += memloopCIDRResolve(b, td, logger)
			if wave > 0 {
				memloopCIDRRemoveWave(td, wave-1, prev)
			}
			prev = cur
		}
		entries += memloopCIDRResolve(b, td, logger)

		b.StopTimer()
		after := memloopCIDRHeapAlloc()
		inuseTotal += int64(after) - int64(before)
		runtime.KeepAlive(td)
		td.stopNotificationHandlers()
		b.StartTimer()
	}
	// Each wave must yield an allow entry per selected /20 identity.
	if entries < b.N*memloopCIDRWaves*memloopCIDRPoliciesPerWave*memloopCIDRBlocksPerPolicy {
		b.Fatalf("too few policy map entries computed: %d", entries)
	}
	b.ReportMetric(float64(inuseTotal)/float64(b.N), "inuse-B/op")
}

// BenchmarkMemloopScenario_CIDRPolicy_Inuse adds one new wave (25 policies,
// 2,875 prefixes + CIDR identities) per iteration to a single long-lived
// repository without removing earlier waves. "inuse-B/op" is the retained
// heap per wave, so retained-heap regressions of rules, selectors and
// selector-cache identity bookkeeping show up directly.
func BenchmarkMemloopScenario_CIDRPolicy_Inuse(b *testing.B) {
	oldEnforcement := GetPolicyEnabled()
	b.Cleanup(func() { SetPolicyEnabled(oldEnforcement) })
	SetPolicyEnabled(option.DefaultEnforcement)

	logger := slog.New(slog.DiscardHandler)
	b.ReportAllocs()

	td := memloopCIDRNewTestData(b, logger)
	waves := make([]memloopCIDRWave, 0, b.N)
	before := memloopCIDRHeapAlloc()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		waves = append(waves, memloopCIDRApplyWave(td, i))
	}
	b.StopTimer()
	after := memloopCIDRHeapAlloc()
	runtime.KeepAlive(td)
	runtime.KeepAlive(waves)
	b.ReportMetric(float64(int64(after)-int64(before))/float64(b.N), "inuse-B/op")
}
