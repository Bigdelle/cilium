// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Memloop scenario: k8s-crd
//
// Intent: offline, in-process reproduction of the agent-side allocation
// profile caused by churning Kubernetes resources and Cilium CRDs, so that
// memory optimisations to the CRD/resource conversion paths can be measured
// without a cluster.
//
// GKE workload mirrored: the memloop GKE "k8s-crd" workload, which churns
// pods (25 labels + 15 annotations each), their CiliumEndpoints,
// CiliumNetworkPolicies and Kubernetes NetworkPolicies in waves. Each wave
// replaces half of the pod population (new names/UIDs => CEP delete + create)
// and updates a quarter of the CNPs/KNPs (new resourceVersion => re-parse).
//
// Hot packages / functions exercised:
//   - pkg/k8s: GetPodMetadata (ObjectMeta.DeepCopy, SanitizePodLabels,
//     named ports), AnnotationsEqual, TransformToCiliumEndpoint,
//     ConvertCEPToCoreCEP, ConvertCoreCiliumEndpointToTypesCiliumEndpoint,
//     ParseNetworkPolicy.
//   - pkg/k8s/apis/cilium.io/v2: CiliumNetworkPolicy.DeepCopy / Parse
//     (Validate, Sanitize, ParseRules -> utils.ParseToCiliumRule).
//   - pkg/labels: Map2Labels, Labels.SortedList, Labels.LabelArray.
//   - pkg/labelsfilter: Filter (identity vs information labels).
//
// Benchmarks:
//   - BenchmarkMemloopScenario_K8sCRD: full churn (initial sync + waves),
//     transient allocations per op.
//   - BenchmarkMemloopScenario_K8sCRD_Inuse: same churn, but the resulting
//     agent-side caches (pod identity labels, slim CEPs, core CEPs, parsed
//     CNP rules, parsed KNP entries) are retained and their heap footprint
//     is reported as inuse-B/op.
//
// Everything is deterministic (fixed seed, no network, no BPF, no sleeps).

package k8s

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"runtime"
	"sync"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sTypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/api/v1/models"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_networkingv1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/networking/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/util/intstr"
	k8stypes "github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/labelsfilter"
	"github.com/cilium/cilium/pkg/policy/api"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
)

const (
	memloopK8sCRDSeed          = 0x6b38735f637264 // "k8s_crd"
	memloopK8sCRDNamespaces    = 10
	memloopK8sCRDPods          = 1000 // steady-state pod population
	memloopK8sCRDWaves         = 4
	memloopK8sCRDLabelsPerPod  = 25
	memloopK8sCRDAnnosPerPod   = 15
	memloopK8sCRDCNPs          = 100
	memloopK8sCRDKNPs          = 50
	memloopK8sCRDPolicyRuleSet = 4 // ingress/egress rules per policy
)

var memloopK8sCRDRelevantAnnotations = []string{
	"policy.cilium.io/proxy-visibility",
	"network.cilium.io/ipv4-pod-cidr",
	"io.cilium.no-track-port",
	"memloop.example.com/anno-3",
}

// memloopK8sCRDPodEvent is one informer pod object plus its CiliumEndpoint.
type memloopK8sCRDPodEvent struct {
	key string
	pod *slim_corev1.Pod
	cep *cilium_v2.CiliumEndpoint
}

type memloopK8sCRDFixture struct {
	logger     *slog.Logger
	namespaces map[string]*slim_corev1.Namespace
	// generations[0] is the initial population, generations[w] (w>=1) holds
	// the pods that are created in wave w (replacing half the population).
	generations [][]memloopK8sCRDPodEvent
	cnps        [][]*cilium_v2.CiliumNetworkPolicy // [wave][i]
	knps        [][]*slim_networkingv1.NetworkPolicy
}

// memloopK8sCRDState is the agent-side cache built from the churn.
type memloopK8sCRDState struct {
	podIdentity map[string]labels.LabelArray
	podInfo     map[string]labels.Labels
	podIDKey    map[string][]byte
	podPorts    map[string]int
	slimCEPs    map[string]*k8stypes.CiliumEndpoint
	coreCEPs    map[string]*cilium_v2alpha1.CoreCiliumEndpoint
	cesCEPs     map[string]*k8stypes.CiliumEndpoint
	cnpRules    map[string]api.Rules
	knpEntries  map[string]policytypes.PolicyEntries
	annoChanged int
}

func newMemloopK8sCRDState() *memloopK8sCRDState {
	return &memloopK8sCRDState{
		podIdentity: make(map[string]labels.LabelArray, memloopK8sCRDPods),
		podInfo:     make(map[string]labels.Labels, memloopK8sCRDPods),
		podIDKey:    make(map[string][]byte, memloopK8sCRDPods),
		podPorts:    make(map[string]int, memloopK8sCRDPods),
		slimCEPs:    make(map[string]*k8stypes.CiliumEndpoint, memloopK8sCRDPods),
		coreCEPs:    make(map[string]*cilium_v2alpha1.CoreCiliumEndpoint, memloopK8sCRDPods),
		cesCEPs:     make(map[string]*k8stypes.CiliumEndpoint, memloopK8sCRDPods),
		cnpRules:    make(map[string]api.Rules, memloopK8sCRDCNPs),
		knpEntries:  make(map[string]policytypes.PolicyEntries, memloopK8sCRDKNPs),
	}
}

var (
	memloopK8sCRDOnce    sync.Once
	memloopK8sCRDFixt    *memloopK8sCRDFixture
	memloopK8sCRDInitErr error
)

func memloopK8sCRDGetFixture(b *testing.B) *memloopK8sCRDFixture {
	b.Helper()
	memloopK8sCRDOnce.Do(func() {
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		memloopK8sCRDInitErr = labelsfilter.ParseLabelPrefixCfg(logger, nil, nil, "")
		if memloopK8sCRDInitErr == nil {
			memloopK8sCRDFixt, memloopK8sCRDInitErr = memloopK8sCRDBuildFixture(logger)
		}
	})
	if memloopK8sCRDInitErr != nil {
		b.Fatal(memloopK8sCRDInitErr)
	}
	return memloopK8sCRDFixt
}

func memloopK8sCRDNamespace(i int) string { return fmt.Sprintf("memloop-ns-%02d", i) }

func memloopK8sCRDBuildPod(rng *rand.Rand, gen, idx int) memloopK8sCRDPodEvent {
	ns := memloopK8sCRDNamespace(idx % memloopK8sCRDNamespaces)
	name := fmt.Sprintf("memloop-app-%03d-g%d-%05d", idx%40, gen, idx)
	uid := k8sTypes.UID(fmt.Sprintf("00000000-0000-%04x-%04x-%012x", gen, idx%0xffff, rng.Uint64()&0xffffffffffff))
	app := fmt.Sprintf("app-%03d", idx%40)

	lbls := make(map[string]string, memloopK8sCRDLabelsPerPod)
	lbls["app"] = app
	lbls["app.kubernetes.io/name"] = app
	lbls["app.kubernetes.io/instance"] = fmt.Sprintf("%s-%d", app, idx%3)
	lbls["app.kubernetes.io/version"] = fmt.Sprintf("v1.%d.%d", idx%7, gen)
	lbls["pod-template-hash"] = fmt.Sprintf("%08x", rng.Uint32())
	lbls["controller-revision-hash"] = fmt.Sprintf("%010x", rng.Uint64()&0xffffffffff)
	lbls["tier"] = []string{"frontend", "backend", "db", "cache"}[idx%4]
	for len(lbls) < memloopK8sCRDLabelsPerPod {
		n := len(lbls)
		lbls[fmt.Sprintf("memloop.example.com/label-%02d", n)] = fmt.Sprintf("value-%02d-%d", n, (idx+n)%5)
	}

	annos := make(map[string]string, memloopK8sCRDAnnosPerPod)
	annos["policy.cilium.io/proxy-visibility"] = "<Ingress/80/TCP/HTTP>"
	annos["kubectl.kubernetes.io/last-applied-configuration"] = fmt.Sprintf(
		`{"apiVersion":"v1","kind":"Pod","metadata":{"name":%q,"namespace":%q}}`, name, ns)
	annos["memloop.example.com/anno-3"] = fmt.Sprintf("gen-%d", gen)
	for len(annos) < memloopK8sCRDAnnosPerPod {
		n := len(annos)
		annos[fmt.Sprintf("memloop.example.com/anno-%02d", n)] = fmt.Sprintf("annotation-value-%02d-%08x", n, rng.Uint32())
	}

	ip4 := fmt.Sprintf("10.%d.%d.%d", 64+gen, (idx>>8)&0xff, idx&0xff)
	ip6 := fmt.Sprintf("fd00:%x::%x", gen, idx+1)
	nodeIP := fmt.Sprintf("192.168.0.%d", 1+idx%50)
	sa := fmt.Sprintf("sa-%s", app)

	pod := &slim_corev1.Pod{
		TypeMeta: slim_metav1.TypeMeta{Kind: "Pod", APIVersion: "v1"},
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:            name,
			Namespace:       ns,
			UID:             uid,
			ResourceVersion: fmt.Sprintf("%d", 1000+gen*10000+idx),
			Labels:          lbls,
			Annotations:     annos,
			OwnerReferences: []slim_metav1.OwnerReference{{
				APIVersion: "apps/v1", Kind: "ReplicaSet",
				Name: app + "-rs", UID: k8sTypes.UID(fmt.Sprintf("rs-%s-%d", app, gen)),
			}},
		},
		Spec: slim_corev1.PodSpec{
			ServiceAccountName: sa,
			NodeName:           fmt.Sprintf("node-%02d", idx%50),
			Containers: []slim_corev1.Container{
				{Name: "app", Ports: []slim_corev1.ContainerPort{
					{Name: "http", ContainerPort: 8080, Protocol: slim_corev1.ProtocolTCP},
					{Name: "grpc", ContainerPort: 9090, Protocol: slim_corev1.ProtocolTCP},
					{Name: "metrics", ContainerPort: 9100, Protocol: slim_corev1.ProtocolTCP},
				}},
				{Name: "sidecar", Ports: []slim_corev1.ContainerPort{
					{Name: "dns", ContainerPort: 53, Protocol: slim_corev1.ProtocolUDP},
					{Name: "", ContainerPort: 15000, Protocol: slim_corev1.ProtocolTCP},
				}},
			},
		},
		Status: slim_corev1.PodStatus{
			PodIP:  ip4,
			PodIPs: []slim_corev1.PodIP{{IP: ip4}, {IP: ip6}},
			HostIP: nodeIP,
		},
	}

	idLabels := make([]string, 0, 8)
	for _, k := range []string{"app", "tier", "app.kubernetes.io/name", "app.kubernetes.io/instance"} {
		idLabels = append(idLabels, "k8s:"+k+"="+lbls[k])
	}
	idLabels = append(idLabels, "k8s:io.kubernetes.pod.namespace="+ns,
		"k8s:io.cilium.k8s.policy.serviceaccount="+sa,
		"k8s:io.cilium.k8s.policy.cluster=default")

	cep := &cilium_v2.CiliumEndpoint{
		TypeMeta: metav1.TypeMeta{Kind: "CiliumEndpoint", APIVersion: "cilium.io/v2"},
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       ns,
			UID:             k8sTypes.UID(string(uid) + "-cep"),
			ResourceVersion: fmt.Sprintf("%d", 2000+gen*10000+idx),
			Labels:          lbls,
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "v1", Kind: "Pod", Name: name, UID: uid,
			}},
		},
		Status: cilium_v2.EndpointStatus{
			ID:             int64(1 + idx),
			Identity:       &cilium_v2.EndpointIdentity{ID: int64(10000 + idx%40), Labels: idLabels},
			Networking:     &cilium_v2.EndpointNetworking{Addressing: cilium_v2.AddressPairList{{IPV4: ip4, IPV6: ip6}}, NodeIP: nodeIP},
			Encryption:     cilium_v2.EncryptionSpec{Key: idx % 2},
			State:          "ready",
			ServiceAccount: sa,
			NamedPorts: models.NamedPorts{
				{Name: "http", Port: 8080, Protocol: "TCP"},
				{Name: "grpc", Port: 9090, Protocol: "TCP"},
				{Name: "metrics", Port: 9100, Protocol: "TCP"},
				{Name: "dns", Port: 53, Protocol: "UDP"},
			},
		},
	}
	return memloopK8sCRDPodEvent{key: ns + "/" + name, pod: pod, cep: cep}
}

func memloopK8sCRDBuildCNP(wave, idx int) (*cilium_v2.CiliumNetworkPolicy, error) {
	ns := memloopK8sCRDNamespace(idx % memloopK8sCRDNamespaces)
	app := fmt.Sprintf("app-%03d", idx%40)
	ingress := make([]map[string]any, 0, memloopK8sCRDPolicyRuleSet)
	egress := make([]map[string]any, 0, memloopK8sCRDPolicyRuleSet)
	for r := range memloopK8sCRDPolicyRuleSet {
		peer := fmt.Sprintf("app-%03d", (idx+r+1)%40)
		ingress = append(ingress, map[string]any{
			"fromEndpoints": []any{
				map[string]any{"matchLabels": map[string]string{"app": peer, "tier": "frontend"}},
				map[string]any{"matchExpressions": []any{map[string]any{
					"key": "app.kubernetes.io/version", "operator": "In", "values": []string{"v1.0.0", "v1.1.0", fmt.Sprintf("v1.%d.%d", r, wave)},
				}}},
			},
			"toPorts": []any{map[string]any{"ports": []any{
				map[string]string{"port": fmt.Sprintf("%d", 8080+r), "protocol": "TCP"},
				map[string]string{"port": "http", "protocol": "TCP"},
			}}},
		})
		egress = append(egress, map[string]any{
			"toEndpoints": []any{map[string]any{"matchLabels": map[string]string{
				"app": peer, "k8s:io.kubernetes.pod.namespace": memloopK8sCRDNamespace((idx + r) % memloopK8sCRDNamespaces),
			}}},
			"toPorts": []any{map[string]any{"ports": []any{map[string]string{"port": "9090", "protocol": "TCP"}}}},
		})
	}
	egress = append(egress, map[string]any{
		"toCIDRSet": []any{map[string]any{"cidr": "10.0.0.0/8", "except": []string{"10.96.0.0/12"}}},
	})
	obj := map[string]any{
		"apiVersion": "cilium.io/v2",
		"kind":       "CiliumNetworkPolicy",
		"metadata": map[string]any{
			"name":            fmt.Sprintf("memloop-cnp-%03d", idx),
			"namespace":       ns,
			"uid":             fmt.Sprintf("cnp-uid-%03d", idx),
			"resourceVersion": fmt.Sprintf("%d", 5000+wave*1000+idx),
			"labels":          map[string]string{"memloop": "k8s-crd", "wave": fmt.Sprintf("%d", wave)},
		},
		"spec": map[string]any{
			"endpointSelector": map[string]any{"matchLabels": map[string]string{"app": app}},
			"ingress":          ingress,
			"egress":           egress,
		},
	}
	raw, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	cnp := &cilium_v2.CiliumNetworkPolicy{}
	if err := json.Unmarshal(raw, cnp); err != nil {
		return nil, err
	}
	return cnp, nil
}

func memloopK8sCRDBuildKNP(wave, idx int) *slim_networkingv1.NetworkPolicy {
	ns := memloopK8sCRDNamespace(idx % memloopK8sCRDNamespaces)
	tcp := slim_corev1.ProtocolTCP
	var ingress []slim_networkingv1.NetworkPolicyIngressRule
	var egress []slim_networkingv1.NetworkPolicyEgressRule
	for r := range memloopK8sCRDPolicyRuleSet {
		port := intstr.FromInt(8080 + r)
		named := intstr.FromString("grpc")
		ingress = append(ingress, slim_networkingv1.NetworkPolicyIngressRule{
			Ports: []slim_networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: &port}, {Protocol: &tcp, Port: &named}},
			From: []slim_networkingv1.NetworkPolicyPeer{
				{PodSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": fmt.Sprintf("app-%03d", (idx+r)%40)}}},
				{
					NamespaceSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{"kubernetes.io/metadata.name": memloopK8sCRDNamespace(r)}},
					PodSelector:       &slim_metav1.LabelSelector{MatchLabels: map[string]string{"tier": "frontend"}},
				},
			},
		})
		egress = append(egress, slim_networkingv1.NetworkPolicyEgressRule{
			Ports: []slim_networkingv1.NetworkPolicyPort{{Protocol: &tcp, Port: &port}},
			To: []slim_networkingv1.NetworkPolicyPeer{
				{IPBlock: &slim_networkingv1.IPBlock{CIDR: fmt.Sprintf("172.%d.0.0/16", 16+r), Except: []string{fmt.Sprintf("172.%d.1.0/24", 16+r)}}},
			},
		})
	}
	return &slim_networkingv1.NetworkPolicy{
		TypeMeta: slim_metav1.TypeMeta{Kind: "NetworkPolicy", APIVersion: "networking.k8s.io/v1"},
		ObjectMeta: slim_metav1.ObjectMeta{
			Name:            fmt.Sprintf("memloop-knp-%03d", idx),
			Namespace:       ns,
			UID:             k8sTypes.UID(fmt.Sprintf("knp-uid-%03d", idx)),
			ResourceVersion: fmt.Sprintf("%d", 7000+wave*1000+idx),
		},
		Spec: slim_networkingv1.NetworkPolicySpec{
			PodSelector: slim_metav1.LabelSelector{MatchLabels: map[string]string{"app": fmt.Sprintf("app-%03d", idx%40)}},
			Ingress:     ingress,
			Egress:      egress,
			PolicyTypes: []slim_networkingv1.PolicyType{slim_networkingv1.PolicyTypeIngress, slim_networkingv1.PolicyTypeEgress},
		},
	}
}

func memloopK8sCRDBuildFixture(logger *slog.Logger) (*memloopK8sCRDFixture, error) {
	rng := rand.New(rand.NewPCG(memloopK8sCRDSeed, memloopK8sCRDSeed^0x9e3779b97f4a7c15))
	f := &memloopK8sCRDFixture{
		logger:     logger,
		namespaces: make(map[string]*slim_corev1.Namespace, memloopK8sCRDNamespaces),
	}
	for i := range memloopK8sCRDNamespaces {
		name := memloopK8sCRDNamespace(i)
		f.namespaces[name] = &slim_corev1.Namespace{ObjectMeta: slim_metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"kubernetes.io/metadata.name": name,
				"team":                        fmt.Sprintf("team-%d", i%3),
				"env":                         "memloop",
			},
		}}
	}

	// Initial population plus one replacement half-population per wave.
	f.generations = make([][]memloopK8sCRDPodEvent, memloopK8sCRDWaves+1)
	for gen := range f.generations {
		n := memloopK8sCRDPods
		if gen > 0 {
			n = memloopK8sCRDPods / 2
		}
		f.generations[gen] = make([]memloopK8sCRDPodEvent, n)
		for i := range n {
			f.generations[gen][i] = memloopK8sCRDBuildPod(rng, gen, i)
		}
	}

	// wave 0: all policies; wave w>=1: a quarter of them are updated.
	f.cnps = make([][]*cilium_v2.CiliumNetworkPolicy, memloopK8sCRDWaves+1)
	f.knps = make([][]*slim_networkingv1.NetworkPolicy, memloopK8sCRDWaves+1)
	for w := range memloopK8sCRDWaves + 1 {
		for i := range memloopK8sCRDCNPs {
			if w == 0 || i%4 == (w-1)%4 {
				cnp, err := memloopK8sCRDBuildCNP(w, i)
				if err != nil {
					return nil, err
				}
				f.cnps[w] = append(f.cnps[w], cnp)
			}
		}
		for i := range memloopK8sCRDKNPs {
			if w == 0 || i%4 == (w-1)%4 {
				f.knps[w] = append(f.knps[w], memloopK8sCRDBuildKNP(w, i))
			}
		}
	}
	return f, nil
}

func (s *memloopK8sCRDState) upsertPod(f *memloopK8sCRDFixture, ev memloopK8sCRDPodEvent, old *slim_corev1.Pod) {
	pod := ev.pod
	if old != nil && !AnnotationsEqual(memloopK8sCRDRelevantAnnotations, old.Annotations, pod.Annotations) {
		s.annoChanged++
	}
	namedPorts, lbls := GetPodMetadata(f.logger, cmtypes.DefaultClusterInfo, f.namespaces[pod.Namespace], pod)
	all := labels.Map2Labels(lbls, labels.LabelSourceK8s)
	idLbls, infoLbls := labelsfilter.Filter(all)
	s.podIdentity[ev.key] = idLbls.LabelArray()
	s.podIDKey[ev.key] = idLbls.SortedList()
	s.podInfo[ev.key] = infoLbls
	s.podPorts[ev.key] = len(NamedPortsIdentityLabels(namedPorts))
}

func (s *memloopK8sCRDState) upsertCEP(ev memloopK8sCRDPodEvent) error {
	slim, err := TransformToCiliumEndpoint(ev.cep)
	if err != nil {
		return err
	}
	s.slimCEPs[ev.key] = slim
	core := ConvertCEPToCoreCEP(ev.cep)
	s.coreCEPs[ev.key] = core
	s.cesCEPs[ev.key] = ConvertCoreCiliumEndpointToTypesCiliumEndpoint(core, ev.cep.Namespace)
	return nil
}

func (s *memloopK8sCRDState) deletePod(key string) {
	delete(s.podIdentity, key)
	delete(s.podIDKey, key)
	delete(s.podInfo, key)
	delete(s.podPorts, key)
	delete(s.slimCEPs, key)
	delete(s.coreCEPs, key)
	delete(s.cesCEPs, key)
}

func (s *memloopK8sCRDState) upsertPolicies(f *memloopK8sCRDFixture, wave int) error {
	for _, in := range f.cnps[wave] {
		// The informer hands out shared objects; Parse sanitizes in place,
		// so the agent works on a copy.
		cnp := in.DeepCopy()
		rules, err := cnp.Parse(f.logger, cmtypes.PolicyAnyCluster)
		if err != nil {
			return err
		}
		s.cnpRules[cnp.Namespace+"/"+cnp.Name] = rules
	}
	for _, knp := range f.knps[wave] {
		entries, err := ParseNetworkPolicy(f.logger, cmtypes.PolicyAnyCluster, knp)
		if err != nil {
			return err
		}
		s.knpEntries[knp.Namespace+"/"+knp.Name] = entries
	}
	return nil
}

// memloopK8sCRDRun replays the initial sync followed by all churn waves.
func memloopK8sCRDRun(f *memloopK8sCRDFixture) (*memloopK8sCRDState, error) {
	s := newMemloopK8sCRDState()
	// live[i] is the pod currently occupying population slot i.
	live := make([]memloopK8sCRDPodEvent, memloopK8sCRDPods)
	copy(live, f.generations[0])

	if err := s.upsertPolicies(f, 0); err != nil {
		return nil, err
	}
	for _, ev := range live {
		s.upsertPod(f, ev, nil)
		if err := s.upsertCEP(ev); err != nil {
			return nil, err
		}
	}

	for w := 1; w <= memloopK8sCRDWaves; w++ {
		// Replace one half of the population, alternating halves per wave.
		off := ((w - 1) % 2) * (memloopK8sCRDPods / 2)
		for i, ev := range f.generations[w] {
			slot := off + i
			old := live[slot]
			// Label/annotation update on the old pod before it terminates.
			s.upsertPod(f, old, old.pod)
			s.deletePod(old.key)
			s.upsertPod(f, ev, old.pod)
			if err := s.upsertCEP(ev); err != nil {
				return nil, err
			}
			live[slot] = ev
		}
		if err := s.upsertPolicies(f, w); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func memloopK8sCRDCheck(b *testing.B, s *memloopK8sCRDState) {
	b.Helper()
	if len(s.podIdentity) != memloopK8sCRDPods || len(s.slimCEPs) != memloopK8sCRDPods ||
		len(s.cnpRules) != memloopK8sCRDCNPs || len(s.knpEntries) != memloopK8sCRDKNPs {
		b.Fatalf("unexpected state sizes: pods=%d ceps=%d cnps=%d knps=%d",
			len(s.podIdentity), len(s.slimCEPs), len(s.cnpRules), len(s.knpEntries))
	}
}

// BenchmarkMemloopScenario_K8sCRD measures allocations of a full k8s-crd
// churn run (initial sync + waves of pod/CEP/CNP/KNP churn).
func BenchmarkMemloopScenario_K8sCRD(b *testing.B) {
	f := memloopK8sCRDGetFixture(b)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		s, err := memloopK8sCRDRun(f)
		if err != nil {
			b.Fatal(err)
		}
		memloopK8sCRDCheck(b, s)
	}
}

// BenchmarkMemloopScenario_K8sCRD_Inuse retains the caches produced by each
// churn run and reports their heap footprint as inuse-B/op.
func BenchmarkMemloopScenario_K8sCRD_Inuse(b *testing.B) {
	f := memloopK8sCRDGetFixture(b)
	states := make([]*memloopK8sCRDState, 0, 16)
	var ms runtime.MemStats

	b.ReportAllocs()
	runtime.GC()
	runtime.ReadMemStats(&ms)
	before := ms.HeapAlloc
	b.ResetTimer()
	for b.Loop() {
		s, err := memloopK8sCRDRun(f)
		if err != nil {
			b.Fatal(err)
		}
		states = append(states, s)
	}
	b.StopTimer()
	for _, s := range states {
		memloopK8sCRDCheck(b, s)
	}
	runtime.GC()
	runtime.ReadMemStats(&ms)
	after := ms.HeapAlloc
	var inuseDelta int64
	if after > before {
		inuseDelta = int64(after - before)
	}
	b.ReportMetric(float64(inuseDelta)/float64(len(states)), "inuse-B/op")
	runtime.KeepAlive(states)
	runtime.KeepAlive(f)
}
