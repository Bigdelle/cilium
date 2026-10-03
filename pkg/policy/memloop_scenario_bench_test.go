// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Memloop scenario: endpoint-scale
//
// Intent: offline, in-process reproduction of the agent-side policy memory
// behaviour while a policy-selected Deployment is scaled 0 -> 60 -> 0 pods.
// No BPF, no endpoint manager: each simulated endpoint goes through the
// policy pipeline the endpoint regeneration uses:
//
//	identity added to SelectorCache (+ subject SelectorCache)
//	-> Repository.ComputeSelectorPolicy (resolvePolicyLocked)
//	-> selectorPolicy.DistillPolicy -> EndpointPolicy.Ready
//	-> incremental MapChanges delivered to already running endpoints and
//	   consumed via EndpointPolicy.ConsumeMapChanges
//
// and on scale-down EndpointPolicy.Detach, selectorPolicy.Detach and
// identity removal from the SelectorCaches. Every benchmark iteration is one
// full 0 -> 60 -> 0 wave; the policy repository (a handful of
// CiliumNetworkPolicies: intra-app ingress, ingress from a monitoring
// namespace, egress to kube-dns and to a backend) and a background population
// of peer identities are built once outside the measured loop.
//
// GKE workload mirrored: memloop "endpoint-scale" (deployment scaling
// 0 -> 60 -> 0 pods with network policies applied).
//
// Hot packages / functions (pkg/policy):
//   - Repository.resolvePolicyLocked / computePolicyEnforcementAndRules
//   - ruleSlice.resolveL4Policy, L4Policy.Attach / detach
//   - selectorPolicy.DistillPolicy, L4DirectionPolicy.toMapState, newMapState
//   - SelectorCache.UpdateIdentities / updateSelections /
//     handleUserNotifications, MapChanges.AccumulateMapChanges /
//     consumeMapChanges
//
// Benchmark: BenchmarkMemloopScenario_EndpointScale. Since every wave tears
// down all endpoint state, inuse-B/op approximates bytes leaked per wave.

package policy

import (
	"log/slog"
	"runtime"
	"strconv"
	"sync"
	"testing"

	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/u8proto"
)

const (
	// memloopEPMaxEndpoints is the peak replica count of the scaled deployment.
	memloopEPMaxEndpoints = 60
	// memloopEPBackgroundIDs is the number of unrelated peer identities.
	memloopEPBackgroundIDs = 300
	// memloopEPMonitoringIDs is the number of identities in the monitoring
	// namespace (allowed to scrape the scaled app).
	memloopEPMonitoringIDs = 20
	// memloopEPBackendIDs is the number of backend identities the app may
	// talk to.
	memloopEPBackendIDs = 10
	// memloopEPFirstID is the first numeric identity used for scaled pods.
	memloopEPFirstID = 40000
)

// memloopEPOwner is a minimal PolicyOwner standing in for an Endpoint.
type memloopEPOwner struct {
	id uint64
}

func (o *memloopEPOwner) GetID() uint64 { return o.id }
func (o *memloopEPOwner) GetIngressNamedPort(string, u8proto.U8proto) uint16 {
	return 0
}
func (o *memloopEPOwner) PolicyDebug(string, ...any)           {}
func (o *memloopEPOwner) IsHost() bool                         { return false }
func (o *memloopEPOwner) PreviousMapStateSizes() MapStateSizes { return MapStateSizes{} }
func (o *memloopEPOwner) RegenerateIfAlive(*regeneration.ExternalRegenerationMetadata) <-chan bool {
	ch := make(chan bool)
	close(ch)
	return ch
}

type memloopEPEndpoint struct {
	owner *memloopEPOwner
	id    *identity.Identity
	sp    SelectorPolicy
	epp   *EndpointPolicy
}

func memloopEPPodLabels(idx int) labels.Labels {
	return labels.NewLabelsFromModel([]string{
		"k8s:app=memloop-ep",
		"k8s:io.kubernetes.pod.namespace=memloop",
		"k8s:io.cilium.k8s.policy.serviceaccount=memloop-ep",
		"k8s:io.cilium.k8s.policy.cluster=default",
		// Unique per replica so that identities scale 0 -> 60 -> 0.
		"k8s:memloop-replica=" + strconv.Itoa(idx),
	})
}

func memloopEPPeerIdentities() identity.IdentityMap {
	ids := identity.IdentityMap{}
	next := identity.NumericIdentity(30000)
	add := func(lbls ...string) {
		ids[next] = labels.NewLabelsFromModel(append(lbls, "k8s:io.cilium.k8s.policy.cluster=default"))
		next++
	}
	add("k8s:k8s-app=kube-dns", "k8s:io.kubernetes.pod.namespace=kube-system")
	for i := range memloopEPMonitoringIDs {
		add("k8s:app=prometheus-"+strconv.Itoa(i), "k8s:io.kubernetes.pod.namespace=monitoring")
	}
	for i := range memloopEPBackendIDs {
		add("k8s:app=memloop-backend", "k8s:io.kubernetes.pod.namespace=memloop", "k8s:shard="+strconv.Itoa(i))
	}
	for i := range memloopEPBackgroundIDs {
		add("k8s:app=bg-"+strconv.Itoa(i), "k8s:io.kubernetes.pod.namespace=bg-"+strconv.Itoa(i%10))
	}
	return ids
}

func memloopEPRules() api.Rules {
	appSel := api.NewESFromLabels(
		labels.ParseSelectLabel("k8s:app=memloop-ep"),
		labels.ParseSelectLabel("k8s:io.kubernetes.pod.namespace=memloop"),
	)
	monitoringSel := api.NewESFromLabels(labels.ParseSelectLabel("k8s:io.kubernetes.pod.namespace=monitoring"))
	dnsSel := api.NewESFromLabels(
		labels.ParseSelectLabel("k8s:k8s-app=kube-dns"),
		labels.ParseSelectLabel("k8s:io.kubernetes.pod.namespace=kube-system"),
	)
	backendSel := api.NewESFromLabels(
		labels.ParseSelectLabel("k8s:app=memloop-backend"),
		labels.ParseSelectLabel("k8s:io.kubernetes.pod.namespace=memloop"),
	)
	tcp := func(port string) []api.PortRule {
		return []api.PortRule{{Ports: []api.PortProtocol{{Port: port, Protocol: api.ProtoTCP}}}}
	}
	uid := k8stypes.UID("6d1f0ae2-6a43-4c3a-9d5e-memloop00001")
	rules := api.Rules{
		{
			EndpointSelector: appSel,
			Ingress: []api.IngressRule{
				{IngressCommonRule: api.IngressCommonRule{FromEndpoints: []api.EndpointSelector{appSel}}, ToPorts: tcp("8080")},
				{IngressCommonRule: api.IngressCommonRule{FromEndpoints: []api.EndpointSelector{monitoringSel}}, ToPorts: tcp("9090")},
			},
			Labels: utils.GetPolicyLabels("memloop", "memloop-ep-ingress", uid, utils.ResourceTypeCiliumNetworkPolicy),
		},
		{
			EndpointSelector: appSel,
			Egress: []api.EgressRule{
				{
					EgressCommonRule: api.EgressCommonRule{ToEndpoints: []api.EndpointSelector{dnsSel}},
					ToPorts: []api.PortRule{{Ports: []api.PortProtocol{
						{Port: "53", Protocol: api.ProtoUDP},
						{Port: "53", Protocol: api.ProtoTCP},
					}}},
				},
				{EgressCommonRule: api.EgressCommonRule{ToEndpoints: []api.EndpointSelector{backendSel}}, ToPorts: tcp("443")},
				{EgressCommonRule: api.EgressCommonRule{ToEndpoints: []api.EndpointSelector{appSel}}, ToPorts: tcp("8080")},
			},
			Labels: utils.GetPolicyLabels("memloop", "memloop-ep-egress", uid, utils.ResourceTypeCiliumNetworkPolicy),
		},
	}
	for _, r := range rules {
		r.Sanitize()
	}
	return rules
}

type memloopEPEnv struct {
	td     *testData
	logger *slog.Logger
	eps    []*memloopEPEndpoint
}

func memloopEPSetup(b *testing.B) *memloopEPEnv {
	b.Helper()
	logger := slog.New(slog.DiscardHandler)
	td := newTestData(b, logger)
	td.bootstrapRepo(nil, 0, b)
	td.withIDs(memloopEPPeerIdentities())
	td.repo.MustAddList(memloopEPRules())
	return &memloopEPEnv{td: td, logger: logger, eps: make([]*memloopEPEndpoint, 0, memloopEPMaxEndpoints)}
}

func (e *memloopEPEnv) updateIdentities(added, deleted identity.IdentityMap) {
	wg := &sync.WaitGroup{}
	e.td.subjectSc.UpdateIdentities(added, deleted, wg)
	e.td.sc.UpdateIdentities(added, deleted, wg)
	wg.Wait()
}

// consumeIncremental drains incremental policy map changes of running
// endpoints, as the endpoint's applyPolicyMapChanges would.
func (e *memloopEPEnv) consumeIncremental() {
	for _, ep := range e.eps {
		closer, _ := ep.epp.ConsumeMapChanges()
		closer()
	}
}

func (e *memloopEPEnv) scaleUp(b *testing.B, idx int) {
	id := identity.NewIdentity(identity.NumericIdentity(memloopEPFirstID+idx), memloopEPPodLabels(idx))
	e.updateIdentities(identity.IdentityMap{id.ID: id.Labels}, nil)
	e.consumeIncremental()

	owner := &memloopEPOwner{id: uint64(1000 + idx)}
	sp, _, err := e.td.repo.ComputeSelectorPolicy(id)
	if err != nil {
		b.Fatalf("ComputeSelectorPolicy(%d): %v", id.ID, err)
	}
	epp := sp.DistillPolicy(e.logger, owner, nil)
	if err := epp.Ready(); err != nil {
		b.Fatalf("Ready(%d): %v", id.ID, err)
	}
	e.eps = append(e.eps, &memloopEPEndpoint{owner: owner, id: id, sp: sp, epp: epp})
}

func (e *memloopEPEnv) scaleDown() {
	ep := e.eps[len(e.eps)-1]
	e.eps[len(e.eps)-1] = nil
	e.eps = e.eps[:len(e.eps)-1]
	ep.epp.Detach(e.logger)
	ep.sp.Detach()
	e.updateIdentities(nil, identity.IdentityMap{ep.id.ID: ep.id.Labels})
	e.consumeIncremental()
}

func (e *memloopEPEnv) wave(b *testing.B) int {
	peak := 0
	for i := range memloopEPMaxEndpoints {
		e.scaleUp(b, i)
	}
	for _, ep := range e.eps {
		peak += ep.epp.Len()
	}
	for len(e.eps) > 0 {
		e.scaleDown()
	}
	return peak
}

func memloopEPHeap() uint64 {
	runtime.GC()
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	return ms.HeapAlloc
}

func BenchmarkMemloopScenario_EndpointScale(b *testing.B) {
	prev := GetPolicyEnabled()
	SetPolicyEnabled(option.DefaultEnforcement)
	b.Cleanup(func() { SetPolicyEnabled(prev) })

	env := memloopEPSetup(b)
	// Warm-up wave: absorbs one-off lazy allocations (selector users,
	// notification handler goroutine, pools).
	peak := env.wave(b)
	if peak == 0 {
		b.Fatal("endpoint policies at peak have no map entries; scenario misconfigured")
	}

	before := memloopEPHeap()
	b.ReportAllocs()
	for b.Loop() {
		peak = env.wave(b)
	}
	b.StopTimer()
	after := memloopEPHeap()
	runtime.KeepAlive(env)
	b.ReportMetric(float64(int64(after)-int64(before))/float64(b.N), "inuse-B/op")
	b.ReportMetric(float64(peak), "peak-mapentries")
}
