// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loadbalancer

import (
	"testing"

	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"
)

func TestLookupFrontendByTuple(t *testing.T) {
	db := statedb.New()
	fes, err := NewFrontendsTable(DefaultConfig, db)
	require.NoError(t, err, "NewFrontendsTable")

	var addr L3n4Addr
	addr.ParseFromString("10.0.0.1:80/TCP")

	wtxn := db.WriteTxn(fes)
	fe := &Frontend{
		FrontendParams: FrontendParams{Address: addr},
	}
	fes.Insert(wtxn, fe)
	txn := wtxn.Commit()

	fe2, found := LookupFrontendByTuple(txn, fes, addr.AddrCluster(), addr.Protocol(), addr.Port(), addr.Scope())
	require.True(t, found)
	require.NotNil(t, fe2)
	require.Equal(t, fe, fe2)

	var addr2 L3n4Addr
	addr2.ParseFromString("10.0.0.2:80/TCP")
	fe2, found = LookupFrontendByTuple(txn, fes, addr2.AddrCluster(), addr2.Protocol(), addr2.Port(), addr2.Scope())
	require.False(t, found)
	require.Nil(t, fe2)
}

func BenchmarkLookupFrontendByTuple(b *testing.B) {
	db := statedb.New()
	fes, err := NewFrontendsTable(DefaultConfig, db)
	require.NoError(b, err)

	var addr L3n4Addr
	addr.ParseFromString("10.0.0.1:80/TCP")
	wtxn := db.WriteTxn(fes)
	fes.Insert(wtxn, &Frontend{FrontendParams: FrontendParams{Address: addr}})
	txn := wtxn.Commit()

	ac := addr.AddrCluster()
	proto := addr.Protocol()
	port := addr.Port()
	scope := addr.Scope()

	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_, found := LookupFrontendByTuple(txn, fes, ac, proto, port, scope)
		if !found {
			b.Fatal("expected found")
		}
	}
}
