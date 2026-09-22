// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metric

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
)

func TestGaugeWithLabels(t *testing.T) {
	o := NewGaugeVecWithLabels(GaugeOpts{
		Namespace: "cilium",
		Subsystem: "subsystem",
		Name:      "test",
	}, Labels{
		{Name: "foo", Values: NewValues("0", "1")},
		{Name: "bar", Values: NewValues("a", "b")},
	})
	r := prometheus.NewRegistry()
	r.MustRegister(o)
	ms, err := dumpMetrics(o)
	assert.NoError(t, err)
	assert.Len(t, ms, 4)
}

func gaugeVecCacheLen(gv *gaugeVec) int {
	n := 0
	gv.cache.Range(func(_, _ any) bool { n++; return true })
	return n
}

// TestGaugeVecCacheIsEvictedOnDelete guards against the wrapper cache growing
// without bound. The cache is keyed by the underlying prometheus.Gauge, so an
// entry that is not evicted when its child is deleted keeps that child alive
// forever -- an unbounded leak for any metric whose label values churn.
func TestGaugeVecCacheIsEvictedOnDelete(t *testing.T) {
	newVec := func() *gaugeVec {
		return NewGaugeVec(GaugeOpts{Namespace: "test", Name: "cache_evict_g"}, []string{"id"})
	}

	t.Run("DeleteLabelValues", func(t *testing.T) {
		gv := newVec()
		for i := range 100 {
			gv.WithLabelValues(strconv.Itoa(i)).Set(1)
		}
		require.Equal(t, 100, gaugeVecCacheLen(gv))
		for i := range 100 {
			require.True(t, gv.DeleteLabelValues(strconv.Itoa(i)))
		}
		require.Zero(t, gaugeVecCacheLen(gv), "cache must not retain wrappers for deleted children")
	})

	t.Run("Delete", func(t *testing.T) {
		gv := newVec()
		gv.WithLabelValues("a").Set(1)
		require.Equal(t, 1, gaugeVecCacheLen(gv))
		require.True(t, gv.Delete(prometheus.Labels{"id": "a"}))
		require.Zero(t, gaugeVecCacheLen(gv))
	})

	t.Run("DeletePartialMatch", func(t *testing.T) {
		gv := newVec()
		gv.WithLabelValues("a").Set(1)
		gv.WithLabelValues("b").Set(1)
		require.Equal(t, 2, gaugeVecCacheLen(gv))
		require.Equal(t, 1, gv.DeletePartialMatch(prometheus.Labels{"id": "a"}))
		require.Zero(t, gaugeVecCacheLen(gv))
	})

	t.Run("Reset", func(t *testing.T) {
		gv := newVec()
		gv.WithLabelValues("a").Set(1)
		gv.Reset()
		require.Zero(t, gaugeVecCacheLen(gv))
	})

	t.Run("churn does not grow the cache unboundedly", func(t *testing.T) {
		gv := newVec()
		for i := range 10000 {
			lv := strconv.Itoa(i)
			gv.WithLabelValues(lv).Set(1)
			gv.DeleteLabelValues(lv)
		}
		require.Zero(t, gaugeVecCacheLen(gv))
	})
}

// TestGaugeVecCacheReturnsSameWrapper documents the property the cache exists
// for: repeated lookups of the same label set return the same wrapper and do
// not allocate.
func TestGaugeVecCacheReturnsSameWrapper(t *testing.T) {
	gv := NewGaugeVec(GaugeOpts{Namespace: "test", Name: "cache_same_g"}, []string{"id"})
	first := gv.WithLabelValues("x")
	for range 100 {
		require.Same(t, first, gv.WithLabelValues("x"))
	}
	require.Zero(t, testing.AllocsPerRun(100, func() { gv.WithLabelValues("x") }),
		"cached WithLabelValues must not allocate")
}
