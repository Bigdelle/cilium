// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/labels"
)

// hasLabelsScan is the linear scan that hasLabelsRLocked replaced. It is kept
// here so the map lookup can be checked against it directly.
func hasLabelsScan(allEpLabels labels.Labels, l labels.Labels) bool {
	for _, v := range l {
		found := false
		for _, j := range allEpLabels {
			if j.Equals(&v) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func epWithLabels(all labels.Labels) *Endpoint {
	e := &Endpoint{}
	e.labels = labels.OpLabels{
		Custom:                labels.Labels{},
		OrchestrationIdentity: all,
		OrchestrationInfo:     labels.Labels{},
		Disabled:              labels.Labels{},
	}
	return e
}

func TestHasLabelsRLockedMatchesScan(t *testing.T) {
	all := labels.Labels{}
	for _, l := range labels.ParseLabelArray(
		"k8s:app=frontend",
		"k8s:io.kubernetes.pod.namespace=default",
		"any:env=prod",
		"reserved:host",
	) {
		all[l.Key] = l
	}

	for name, filter := range map[string]labels.Labels{
		"empty":               {},
		"nil":                 nil,
		"single present":      labels.Map2Labels(map[string]string{"app": "frontend"}, labels.LabelSourceK8s),
		"single absent key":   labels.Map2Labels(map[string]string{"nope": "x"}, labels.LabelSourceK8s),
		"present key bad val": labels.Map2Labels(map[string]string{"app": "backend"}, labels.LabelSourceK8s),
		"wrong source":        labels.Map2Labels(map[string]string{"app": "frontend"}, labels.LabelSourceCNI),
		"health":              labels.LabelHealth,
		"ingress":             labels.LabelIngress,
	} {
		t.Run(name, func(t *testing.T) {
			e := epWithLabels(all)
			require.Equal(t, hasLabelsScan(all, filter), e.hasLabelsRLocked(filter))
		})
	}
}

var sinkHasLabels bool

func BenchmarkHasLabelsRLocked(b *testing.B) {
	all := labels.Labels{}
	for i := range 32 {
		l := labels.NewLabel(fmt.Sprintf("k8s-label-%02d", i), fmt.Sprintf("value-%02d", i), labels.LabelSourceK8s)
		all[l.Key] = l
	}
	e := epWithLabels(all)

	// labels.LabelHealth is the filter the hot caller in policy.go uses.
	b.ReportAllocs()
	for b.Loop() {
		sinkHasLabels = e.hasLabelsRLocked(labels.LabelHealth)
	}
}

// TestOpLabelsLookupMatchesAllLabels pins OpLabels.Lookup to the merged map
// AllLabels builds, including the override order between the four sources.
func TestOpLabelsLookupMatchesAllLabels(t *testing.T) {
	mk := func(source string, kvs ...string) labels.Labels {
		l := labels.Labels{}
		for i := 0; i < len(kvs); i += 2 {
			lbl := labels.NewLabel(kvs[i], kvs[i+1], source)
			l[lbl.Key] = lbl
		}
		return l
	}

	// "shared" is present in all four maps with a different value in each,
	// so any mistake in the precedence order shows up.
	o := labels.OpLabels{
		Custom:                mk(labels.LabelSourceAny, "shared", "custom", "only-custom", "x"),
		Disabled:              mk(labels.LabelSourceAny, "shared", "disabled", "only-disabled", "x"),
		OrchestrationIdentity: mk(labels.LabelSourceK8s, "shared", "identity", "only-identity", "x"),
		OrchestrationInfo:     mk(labels.LabelSourceK8s, "shared", "info", "only-info", "x"),
	}

	all := o.AllLabels()
	for _, key := range []string{"shared", "only-custom", "only-disabled", "only-identity", "only-info", "absent"} {
		t.Run(key, func(t *testing.T) {
			want, wantOK := all[key]
			got, gotOK := o.Lookup(key)
			require.Equal(t, wantOK, gotOK)
			require.Equal(t, want, got)
		})
	}

	// And with sources missing entirely.
	empty := labels.OpLabels{}
	_, ok := empty.Lookup("anything")
	require.False(t, ok)
}
