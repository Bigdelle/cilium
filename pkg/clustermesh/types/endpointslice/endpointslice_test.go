// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpointslice

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	slim_discovery_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/discovery/v1"
)

func TestClusterEndpointSlice(t *testing.T) {
	eps := ClusterEndpointSlice{
		Cluster:     "default",
		Namespace:   "bar",
		Name:        "foo",
		AddressType: slim_discovery_v1.AddressTypeIPv4,
	}

	b, err := eps.Marshal()
	require.NoError(t, err)
	unmarshal := ClusterEndpointSlice{}
	err = unmarshal.Unmarshal("", b)
	require.NoError(t, err)
	require.Equal(t, eps, unmarshal)

	require.Equal(t, "foo", unmarshal.Name)
	require.Equal(t, "bar", unmarshal.Namespace)
	require.Equal(t, "default/bar/foo", unmarshal.String())
	require.Equal(t, "default/bar/foo", unmarshal.GetKeyName())

	b, err = eps.MarshalJSON()
	require.NoError(t, err)
	unmarshal = ClusterEndpointSlice{}
	err = unmarshal.UnmarshalJSON(b)
	require.NoError(t, err)
	require.Equal(t, eps, unmarshal)

	require.Equal(t, "foo", unmarshal.Name)
	require.Equal(t, "bar", unmarshal.Namespace)
	require.Equal(t, "default/bar/foo", unmarshal.String())
	require.Equal(t, "default/bar/foo", unmarshal.GetKeyName())
}

func TestClusterEndpointSliceValidate(t *testing.T) {
	tests := []struct {
		name   string
		eps    ClusterEndpointSlice
		errstr string
	}{
		{
			name:   "empty",
			eps:    ClusterEndpointSlice{},
			errstr: "cluster is unset",
		},
		{
			name: "minimum information",
			eps: ClusterEndpointSlice{
				Cluster:     "foo",
				Namespace:   "bar",
				Name:        "qux",
				AddressType: slim_discovery_v1.AddressTypeIPv4,
			},
		},
		{
			name: "valid IPv4",
			eps: ClusterEndpointSlice{
				Cluster:     "foo",
				ClusterID:   99,
				Namespace:   "bar",
				Name:        "qux",
				AddressType: slim_discovery_v1.AddressTypeIPv4,
				Endpoints: []slim_discovery_v1.Endpoint{{
					Addresses: []string{"10.1.2.3"},
				}},
			},
		},
		{
			name: "valid IPv6",
			eps: ClusterEndpointSlice{
				Cluster:     "foo",
				ClusterID:   99,
				Namespace:   "bar",
				Name:        "qux",
				AddressType: slim_discovery_v1.AddressTypeIPv6,
				Endpoints: []slim_discovery_v1.Endpoint{{
					Addresses: []string{"2001:db8::1"},
				}},
			},
		},
		{
			name: "invalid IPv4 endpoint address",
			eps: ClusterEndpointSlice{
				Cluster:     "foo",
				Namespace:   "bar",
				Name:        "qux",
				AddressType: slim_discovery_v1.AddressTypeIPv4,
				Endpoints: []slim_discovery_v1.Endpoint{{
					Addresses: []string{"2001:db8::1"},
				}},
			},
			errstr: "invalid IPv4 endpoint address: 2001:db8::1",
		},
		{
			name: "invalid IPv6 endpoint address",
			eps: ClusterEndpointSlice{
				Cluster:     "foo",
				Namespace:   "bar",
				Name:        "qux",
				AddressType: slim_discovery_v1.AddressTypeIPv6,
				Endpoints: []slim_discovery_v1.Endpoint{{
					Addresses: []string{"10.1.2.3"},
				}},
			},
			errstr: "invalid IPv6 endpoint address: 10.1.2.3",
		},
		{
			name: "IPv6 endpoint address with zone",
			eps: ClusterEndpointSlice{
				Cluster:     "foo",
				Namespace:   "bar",
				Name:        "qux",
				AddressType: slim_discovery_v1.AddressTypeIPv6,
				Endpoints: []slim_discovery_v1.Endpoint{{
					Addresses: []string{"fd10::1234%zone"},
				}},
			},
			errstr: "invalid IPv6 endpoint address: fd10::1234%zone",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.eps.validate()
			if tt.errstr != "" {
				require.EqualError(t, err, tt.errstr)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestValidatingClusterEndpointSlice(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		eps       ClusterEndpointSlice
		validator clusterEndpointSliceValidator
		errstr    string
	}{
		{
			name: "valid cluster name",
			eps: ClusterEndpointSlice{
				Cluster: "foo", Namespace: "bar", Name: "qux", AddressType: slim_discovery_v1.AddressTypeIPv4,
			},
			validator: ClusterNameValidator("foo"),
		},
		{
			name: "invalid cluster name",
			eps: ClusterEndpointSlice{
				Cluster: "foo", Namespace: "bar", Name: "qux", AddressType: slim_discovery_v1.AddressTypeIPv4,
			},
			validator: ClusterNameValidator("fred"),
			errstr:    "unexpected cluster name: got foo, expected fred",
		},
		{
			name: "valid namespaced name",
			key:  "bar/qux",
			eps: ClusterEndpointSlice{
				Cluster: "foo", Namespace: "bar", Name: "qux", AddressType: slim_discovery_v1.AddressTypeIPv4,
			},
			validator: NamespacedNameValidator(),
		},
		{
			name: "invalid namespaced name",
			key:  "fred/qux",
			eps: ClusterEndpointSlice{
				Cluster: "foo", Namespace: "bar", Name: "qux", AddressType: slim_discovery_v1.AddressTypeIPv4,
			},
			validator: NamespacedNameValidator(),
			errstr:    "namespaced name does not match key: got bar/qux, expected fred/qux",
		},
		{
			name: "valid cluster ID",
			eps: ClusterEndpointSlice{
				Cluster: "foo", Namespace: "bar", Name: "qux", ClusterID: 10, AddressType: slim_discovery_v1.AddressTypeIPv4,
			},
			validator: ClusterIDValidator(new(uint32(10))),
		},
		{
			name: "invalid cluster ID",
			eps: ClusterEndpointSlice{
				Cluster: "foo", Namespace: "bar", Name: "qux", ClusterID: 10, AddressType: slim_discovery_v1.AddressTypeIPv4,
			},
			validator: ClusterIDValidator(new(uint32(15))),
			errstr:    "unexpected cluster ID: got 10, expected 15",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.eps.Marshal()
			require.NoError(t, err)

			got := KeyCreator(tt.validator)()
			err = got.Unmarshal(tt.key, data)
			if tt.errstr != "" {
				require.EqualError(t, err, tt.errstr)
				return
			}

			require.NoError(t, err)
			gotEPS := got.(*ValidatingClusterEndpointSlice).ClusterEndpointSlice
			require.Equal(t, tt.eps, gotEPS)
		})
	}
}

func makeBenchmarkClusterEndpointSlice(numEndpoints int) ClusterEndpointSlice {
	ready := true
	port := int32(8080)
	portName := "http"
	zone := "us-central1-a"
	endpoints := make([]slim_discovery_v1.Endpoint, numEndpoints)
	for i := range numEndpoints {
		nodeName := fmt.Sprintf("node-%03d", i%16)
		endpoints[i] = slim_discovery_v1.Endpoint{
			Addresses: []string{fmt.Sprintf("10.244.%d.%d", (i/250)+1, (i%250)+1)},
			Conditions: slim_discovery_v1.EndpointConditions{
				Ready:   &ready,
				Serving: &ready,
			},
			NodeName: &nodeName,
			Zone:     &zone,
		}
	}
	return ClusterEndpointSlice{
		Cluster:     "cluster-west-1",
		ClusterID:   42,
		Namespace:   "production",
		Name:        "checkout-svc-abcde",
		AddressType: slim_discovery_v1.AddressTypeIPv4,
		Labels: map[string]string{
			"kubernetes.io/service-name": "checkout-svc",
		},
		Endpoints: endpoints,
		Ports: []slim_discovery_v1.EndpointPort{{
			Name: &portName,
			Port: &port,
		}},
	}
}

func TestClusterEndpointSliceConcurrentMarshalUnmarshal(t *testing.T) {
	small := makeBenchmarkClusterEndpointSlice(50)
	// Also exercise payloads exceeding maxPooledBufferSize (64 KiB) to verify
	// non-pooled fallback paths and absence of buffer aliasing across goroutines.
	large := makeBenchmarkClusterEndpointSlice(1200)

	var wg sync.WaitGroup
	for g := range 8 {
		wg.Go(func() {
			src := small
			if g%2 == 1 {
				src = large
			}
			for range 25 {
				data, err := src.Marshal()
				require.NoError(t, err)
				var dst ClusterEndpointSlice
				require.NoError(t, dst.Unmarshal("", data))
				require.Equal(t, src, dst)
			}
		})
	}
	wg.Wait()
}

func BenchmarkClusterEndpointSliceMarshal(b *testing.B) {
	eps := makeBenchmarkClusterEndpointSlice(50)
	b.ReportAllocs()
	for b.Loop() {
		data, err := eps.Marshal()
		if err != nil || len(data) == 0 {
			b.Fatalf("Marshal failed: %v", err)
		}
	}
}

func BenchmarkClusterEndpointSliceUnmarshal(b *testing.B) {
	eps := makeBenchmarkClusterEndpointSlice(50)
	encoded, err := eps.Marshal()
	require.NoError(b, err)

	b.ReportAllocs()
	for b.Loop() {
		var dst ClusterEndpointSlice
		if err := dst.Unmarshal("", encoded); err != nil {
			b.Fatalf("Unmarshal failed: %v", err)
		}
	}
}
