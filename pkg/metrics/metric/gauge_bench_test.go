// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metric

import (
	"fmt"
	"testing"
)

// BenchmarkGaugeVecWithLabelValues measures (*gaugeVec).WithLabelValues plus a
// Set on the returned Gauge, cycling through many distinct label tuples (as
// per-endpoint / per-identity gauges do) so no single cached child dominates.
func BenchmarkGaugeVecWithLabelValues(b *testing.B) {
	for _, n := range []int{16, 1024} {
		b.Run(fmt.Sprintf("series=%d", n), func(b *testing.B) {
			gv := NewGaugeVec(GaugeOpts{
				Namespace: "cilium",
				Subsystem: "bench",
				Name:      "gauge",
				Help:      "benchmark gauge",
			}, []string{"direction", "reason", "endpoint"})
			lvs := make([][]string, n)
			for i := range lvs {
				lvs[i] = []string{
					[]string{"ingress", "egress"}[i%2],
					fmt.Sprintf("reason-%d", i%7),
					fmt.Sprintf("endpoint-%d", i),
				}
				gv.WithLabelValues(lvs[i]...) // pre-create all children
			}
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				gv.WithLabelValues(lvs[i%n]...).Set(float64(i))
				i++
			}
		})
	}
}
