package filters

import (
	"context"

	flowpb "github.com/cilium/cilium/api/v1/flow"
	v1 "github.com/cilium/cilium/pkg/hubble/api/v1"
)

func filterByIpTraceId(ip_trace_ids []uint64) FilterFunc {
	return func(ev *v1.Event) bool {
		flow := ev.GetFlow()
		if flow == nil {
			return false
		}
		iptid := flow.GetIpTraceId()
		for _, id := range ip_trace_ids {
			if id == iptid {
				return true
			}
		}
		return false
	}
}

// IPTraceIDFilter implements filtering based on flow IPTraceIDs.
type IPTraceIDFilter struct{}

// OnBuildFilter builds an IP Trace ID filter.
func (e *IPTraceIDFilter) OnBuildFilter(ctx context.Context, ff *flowpb.FlowFilter) ([]FilterFunc, error) {
	var fs []FilterFunc
	if ids := ff.GetIpTraceId(); len(ids) > 0 {
		fs = append(fs, filterByIpTraceId(ids))
	}

	return fs, nil
}
