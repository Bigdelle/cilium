// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metric

import (
	"strconv"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCounterWithLabels(t *testing.T) {
	o := NewCounterVecWithLabels(CounterOpts{
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

func counterVecCacheLen(cv *counterVec) int {
	n := 0
	cv.cache.Range(func(_, _ any) bool { n++; return true })
	return n
}

// TestCounterVecCacheIsEvictedOnDelete guards against the wrapper cache growing
// without bound. See the equivalent gauge test for the rationale.
func TestCounterVecCacheIsEvictedOnDelete(t *testing.T) {
	newVec := func() *counterVec {
		return NewCounterVec(CounterOpts{Namespace: "test", Name: "cache_evict_c"}, []string{"id"})
	}

	t.Run("DeleteLabelValues", func(t *testing.T) {
		cv := newVec()
		for i := range 100 {
			cv.WithLabelValues(strconv.Itoa(i)).Inc()
		}
		require.Equal(t, 100, counterVecCacheLen(cv))
		for i := range 100 {
			require.True(t, cv.DeleteLabelValues(strconv.Itoa(i)))
		}
		require.Zero(t, counterVecCacheLen(cv), "cache must not retain wrappers for deleted children")
	})

	t.Run("Delete", func(t *testing.T) {
		cv := newVec()
		cv.WithLabelValues("a").Inc()
		require.True(t, cv.Delete(prometheus.Labels{"id": "a"}))
		require.Zero(t, counterVecCacheLen(cv))
	})

	t.Run("DeletePartialMatch", func(t *testing.T) {
		cv := newVec()
		cv.WithLabelValues("a").Inc()
		cv.WithLabelValues("b").Inc()
		require.Equal(t, 1, cv.DeletePartialMatch(prometheus.Labels{"id": "a"}))
		require.Zero(t, counterVecCacheLen(cv))
	})

	t.Run("churn does not grow the cache unboundedly", func(t *testing.T) {
		cv := newVec()
		for i := range 10000 {
			lv := strconv.Itoa(i)
			cv.WithLabelValues(lv).Inc()
			cv.DeleteLabelValues(lv)
		}
		require.Zero(t, counterVecCacheLen(cv))
	})
}

// TestCounterVecCacheReturnsSameWrapper documents the property the cache exists for.
func TestCounterVecCacheReturnsSameWrapper(t *testing.T) {
	cv := NewCounterVec(CounterOpts{Namespace: "test", Name: "cache_same_c"}, []string{"id"})
	first := cv.WithLabelValues("x")
	for range 100 {
		require.Same(t, first, cv.WithLabelValues("x"))
	}
	require.Zero(t, testing.AllocsPerRun(100, func() { cv.WithLabelValues("x") }),
		"cached WithLabelValues must not allocate")
}
