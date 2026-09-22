// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metric

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func NewCounter(opts CounterOpts) Counter {
	return &counter{
		Counter: prometheus.NewCounter(opts.toPrometheus()),
		metric: metric{
			enabled: !opts.Disabled,
			opts:    Opts(opts),
		},
	}
}

type Counter interface {
	prometheus.Counter
	WithMetadata

	Get() float64
}

type counter struct {
	prometheus.Counter
	metric
}

func (c *counter) Get() float64 {
	var pm dto.Metric
	err := c.Counter.Write(&pm)
	if err == nil {
		return *pm.Counter.Value
	}
	return 0
}

// NewCounterVec creates a new DeletableVec[Counter] based on the provided CounterOpts and
// partitioned by the given label names.
func NewCounterVec(opts CounterOpts, labelNames []string) *counterVec {
	return &counterVec{
		CounterVec: prometheus.NewCounterVec(opts.toPrometheus(), labelNames),
		metric: metric{
			enabled: !opts.Disabled,
			opts:    Opts(opts),
		},
	}
}

// NewCounterVecWithLabels creates a new DeletableVec[Counter] based on the provided CounterOpts and
// partitioned by the given labels.
// This will also initialize the labels with the provided values so that metrics with known label value
// ranges can be pre-initialized to zero upon init.
//
// This should only be used when all label values are known at init, otherwise use of the
// metric vector with uninitialized labels will result in warnings.
//
// Note: Disabled metrics will not have their label values initialized.
//
// For example:
//
//	NewCounterVecWithLabels(CounterOpts{
//		Namespace: "cilium",
//		Subsystem: "subsystem",
//		Name:      "cilium_test",
//		Disabled:  false,
//	}, Labels{
//		{Name: "foo", Values: NewValues("0", "1")},
//		{Name: "bar", Values: NewValues("a", "b")},
//	})
//
// Will initialize the following metrics to:
//
//	cilium_subsystem_cilium_test{foo="0", bar="a"} 0
//	cilium_subsystem_cilium_test{foo="0", bar="b"} 0
//	cilium_subsystem_cilium_test{foo="1", bar="a"} 0
//	cilium_subsystem_cilium_test{foo="1", bar="b"} 0
func NewCounterVecWithLabels(opts CounterOpts, labels Labels) *counterVec {
	cv := NewCounterVec(opts, labels.labelNames())
	initLabels[Counter](&cv.metric, labels, cv, opts.Disabled)
	return cv
}

type counterVec struct {
	*prometheus.CounterVec
	metric

	// cache memoizes the Counter wrapper for each underlying
	// prometheus.Counter, so that the hot WithLabelValues path does not
	// allocate a wrapper per call.
	//
	// Every method that can remove a metric from the embedded CounterVec must
	// also evict from here, otherwise the entry -- and the dead
	// prometheus.Counter it is keyed by -- stays reachable forever. See Reset,
	// Delete, DeleteLabelValues and DeletePartialMatch below.
	cache sync.Map
}

func (cv *counterVec) wrapCounter(promCounter prometheus.Counter) Counter {
	if v, ok := cv.cache.Load(promCounter); ok {
		return v.(Counter)
	}
	c := &counter{
		Counter: promCounter,
		metric:  cv.metric,
	}
	cv.cache.Store(promCounter, c)
	return c
}

func (cv *counterVec) Reset() {
	cv.cache.Clear()
	cv.CounterVec.Reset()
}

// Delete removes the metric for the given labels and drops the cached wrapper.
//
// The whole cache is cleared rather than the single entry: the wrapper is keyed
// by the prometheus.Counter, which is not recoverable from the labels once the
// child has been deleted. Deletions are rare compared to WithLabelValues, and
// the cache refills lazily.
func (cv *counterVec) Delete(labels prometheus.Labels) bool {
	cv.cache.Clear()
	return cv.CounterVec.Delete(labels)
}

// DeleteLabelValues removes the metric for the given label values and drops the
// cached wrappers. See Delete for why the whole cache is cleared.
func (cv *counterVec) DeleteLabelValues(lvs ...string) bool {
	cv.cache.Clear()
	return cv.CounterVec.DeleteLabelValues(lvs...)
}

// DeletePartialMatch removes all metrics matching the given labels and drops the
// cached wrappers. See Delete for why the whole cache is cleared.
func (cv *counterVec) DeletePartialMatch(labels prometheus.Labels) int {
	cv.cache.Clear()
	return cv.CounterVec.DeletePartialMatch(labels)
}

func (cv *counterVec) CurryWith(labels prometheus.Labels) (Vec[Counter], error) {
	cv.checkLabels(labels)
	vec, err := cv.CounterVec.CurryWith(labels)
	if err == nil {
		return &counterVec{CounterVec: vec, metric: cv.metric}, nil
	}
	return nil, err
}

func (cv *counterVec) GetMetricWith(labels prometheus.Labels) (Counter, error) {
	promCounter, err := cv.CounterVec.GetMetricWith(labels)
	if err == nil {
		return cv.wrapCounter(promCounter), nil
	}
	return nil, err
}

func (cv *counterVec) GetMetricWithLabelValues(lvs ...string) (Counter, error) {
	promCounter, err := cv.CounterVec.GetMetricWithLabelValues(lvs...)
	if err == nil {
		return cv.wrapCounter(promCounter), nil
	}
	return nil, err
}

func (cv *counterVec) With(labels prometheus.Labels) Counter {
	cv.checkLabels(labels)
	promCounter := cv.CounterVec.With(labels)
	return cv.wrapCounter(promCounter)
}

func (cv *counterVec) WithLabelValues(lvs ...string) Counter {
	cv.checkLabelValues(lvs...)
	promCounter := cv.CounterVec.WithLabelValues(lvs...)
	return cv.wrapCounter(promCounter)
}

func (cv *counterVec) SetEnabled(e bool) {
	if !e {
		cv.Reset()
	}

	cv.metric.SetEnabled(e)
}

type CounterOpts Opts

func (co CounterOpts) toPrometheus() prometheus.CounterOpts {
	return prometheus.CounterOpts{
		Name:        co.Name,
		Namespace:   co.Namespace,
		Subsystem:   co.Subsystem,
		Help:        co.Help,
		ConstLabels: co.ConstLabels,
	}
}
