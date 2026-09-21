// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metric

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func NewGauge(opts GaugeOpts) Gauge {
	return &gauge{
		Gauge: prometheus.NewGauge(opts.toPrometheus()),
		metric: metric{
			enabled: !opts.Disabled,
			opts:    Opts(opts),
		},
	}
}

type Gauge interface {
	prometheus.Gauge
	WithMetadata

	Get() float64
}

type gauge struct {
	prometheus.Gauge
	metric
}

func (g *gauge) Get() float64 {
	var pm dto.Metric
	err := g.Gauge.Write(&pm)
	if err == nil {
		return *pm.Gauge.Value
	}
	return 0
}

// NewGaugeVec creates a new DeletableVec[Gauge] based on the provided GaugeOpts and
// partitioned by the given label names.
func NewGaugeVec(opts GaugeOpts, labelNames []string) *gaugeVec {
	gv := &gaugeVec{
		GaugeVec: prometheus.NewGaugeVec(opts.toPrometheus(), labelNames),
		metric: metric{
			enabled: !opts.Disabled,
			opts:    Opts(opts),
		},
	}
	return gv
}

// NewGaugeVecWithLabels creates a new DeletableVec[Gauge] based on the provided CounterOpts and
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
//	NewGaugeVecWithLabels(GaugeOpts{
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
func NewGaugeVecWithLabels(opts GaugeOpts, labels Labels) *gaugeVec {
	gv := NewGaugeVec(opts, labels.labelNames())
	initLabels[Gauge](&gv.metric, labels, gv, opts.Disabled)
	return gv
}

type gaugeVec struct {
	*prometheus.GaugeVec
	metric

	// cache memoizes the Gauge wrapper for each underlying prometheus.Gauge, so
	// that the hot WithLabelValues path does not allocate a wrapper per call.
	//
	// Every method that can remove a metric from the embedded GaugeVec must
	// also evict from here, otherwise the entry -- and the dead
	// prometheus.Gauge it is keyed by -- stays reachable forever. See Reset,
	// Delete, DeleteLabelValues and DeletePartialMatch below.
	cache sync.Map
}

func (gv *gaugeVec) wrapGauge(promGauge prometheus.Gauge) Gauge {
	if v, ok := gv.cache.Load(promGauge); ok {
		return v.(Gauge)
	}
	g := &gauge{
		Gauge:  promGauge,
		metric: gv.metric,
	}
	gv.cache.Store(promGauge, g)
	return g
}

func (gv *gaugeVec) Reset() {
	gv.cache.Clear()
	gv.GaugeVec.Reset()
}

// Delete removes the metric for the given labels and drops the cached wrapper.
//
// The whole cache is cleared rather than the single entry: the wrapper is keyed
// by the prometheus.Gauge, which is not recoverable from the labels once the
// child has been deleted. Deletions are rare compared to WithLabelValues, and
// the cache refills lazily.
func (gv *gaugeVec) Delete(labels prometheus.Labels) bool {
	gv.cache.Clear()
	return gv.GaugeVec.Delete(labels)
}

// DeleteLabelValues removes the metric for the given label values and drops the
// cached wrappers. See Delete for why the whole cache is cleared.
func (gv *gaugeVec) DeleteLabelValues(lvs ...string) bool {
	gv.cache.Clear()
	return gv.GaugeVec.DeleteLabelValues(lvs...)
}

// DeletePartialMatch removes all metrics matching the given labels and drops the
// cached wrappers. See Delete for why the whole cache is cleared.
func (gv *gaugeVec) DeletePartialMatch(labels prometheus.Labels) int {
	gv.cache.Clear()
	return gv.GaugeVec.DeletePartialMatch(labels)
}

func (gv *gaugeVec) CurryWith(labels prometheus.Labels) (Vec[Gauge], error) {
	gv.checkLabels(labels)
	vec, err := gv.GaugeVec.CurryWith(labels)
	if err == nil {
		return &gaugeVec{GaugeVec: vec, metric: gv.metric}, nil
	}
	return nil, err
}

func (gv *gaugeVec) GetMetricWith(labels prometheus.Labels) (Gauge, error) {
	promGauge, err := gv.GaugeVec.GetMetricWith(labels)
	if err == nil {
		return gv.wrapGauge(promGauge), nil
	}
	return nil, err
}

func (gv *gaugeVec) GetMetricWithLabelValues(lvs ...string) (Gauge, error) {
	promGauge, err := gv.GaugeVec.GetMetricWithLabelValues(lvs...)
	if err == nil {
		return gv.wrapGauge(promGauge), nil
	}
	return nil, err
}

func (gv *gaugeVec) With(labels prometheus.Labels) Gauge {
	gv.checkLabels(labels)

	promGauge := gv.GaugeVec.With(labels)
	return gv.wrapGauge(promGauge)
}

func (gv *gaugeVec) WithLabelValues(lvs ...string) Gauge {
	gv.checkLabelValues(lvs...)

	promGauge := gv.GaugeVec.WithLabelValues(lvs...)
	return gv.wrapGauge(promGauge)
}

func (gv *gaugeVec) SetEnabled(e bool) {
	if !e {
		gv.Reset()
	}

	gv.metric.SetEnabled(e)
}

type GaugeFunc interface {
	prometheus.GaugeFunc
	WithMetadata
}

func NewGaugeFunc(opts GaugeOpts, function func() float64) GaugeFunc {
	return &gaugeFunc{
		GaugeFunc: prometheus.NewGaugeFunc(opts.toPrometheus(), function),
		metric: metric{
			enabled: !opts.Disabled,
			opts:    Opts(opts),
		},
	}
}

type gaugeFunc struct {
	prometheus.GaugeFunc
	metric
}

type GaugeOpts Opts

func (o GaugeOpts) toPrometheus() prometheus.GaugeOpts {
	return prometheus.GaugeOpts{
		Namespace:   o.Namespace,
		Subsystem:   o.Subsystem,
		Name:        o.Name,
		Help:        o.Help,
		ConstLabels: o.ConstLabels,
	}
}
