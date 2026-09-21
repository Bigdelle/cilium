// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/source"
)

func BenchmarkInjectLabels(b *testing.B) {
	s := setupIPCacheTestSuite(b)
	ipc := s.IPIdentityCache

	addr := netip.MustParseAddr("1.0.0.0")
	lbls := labels.NewLabelsFromSortedList(labels.LabelSourceCIDRGroup + ":foo=bar")

	prefixes := make([]cmtypes.PrefixCluster, 0, b.N)

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; b.Loop(); i++ {
		pfx := cmtypes.NewLocalPrefixCluster(netip.PrefixFrom(addr, 30))
		for range 4 {
			addr = addr.Next()
		}
		prefixes = append(prefixes, ipc.metadata.upsertLocked(pfx, source.Kubernetes, "cidr-policy", lbls)...)
		if i%1000 == 0 {
			b.Log(i)
		}
	}
	b.Logf("%d", len(prefixes))
	b.Log(addr.String())
	_, err := ipc.doInjectLabels(b.Context(), prefixes)
	if err != nil {
		b.Fatal(err)
	}

	b.StopTimer()

	// sanity checks
	require.Len(b, ipc.ipToIdentityCache, len(prefixes))
}

func BenchmarkDoInjectLabels(b *testing.B) {
	s := setupIPCacheTestSuite(b)
	ipc := s.IPIdentityCache

	addr := netip.MustParseAddr("1.0.0.0")
	lbls := labels.NewLabelsFromSortedList(labels.LabelSourceCIDRGroup + ":foo=bar;fqdn:host-001.w1.memloop-dns.internal=")
	prefixes := make([]cmtypes.PrefixCluster, 0, 64)
	for range 64 {
		pfx := cmtypes.NewLocalPrefixCluster(netip.PrefixFrom(addr, 32))
		addr = addr.Next()
		prefixes = append(prefixes, ipc.metadata.upsertLocked(pfx, source.Generated, "dns-policy", lbls)...)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := ipc.doInjectLabels(b.Context(), prefixes); err != nil {
			b.Fatal(err)
		}
	}
}
