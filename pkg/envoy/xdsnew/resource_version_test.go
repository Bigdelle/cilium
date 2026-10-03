// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"fmt"
	"testing"

	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_config_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	cache_types "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	envoy_resource "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// inlineRouteListener builds a listener whose HCM (packed with anypb.New, as
// pkg/ciliumenvoyconfig does) carries an inline route configuration with map
// fields. anypb.New marshals non-deterministically, so the Any bytes differ
// between rebuilds whenever such a map has more than one entry.
func inlineRouteListener(t *testing.T, filters int) *envoy_config_listener.Listener {
	tpfc := map[string]*anypb.Any{}
	md := map[string]*structpb.Struct{}
	for i := range filters {
		tpfc[fmt.Sprintf("envoy.filters.http.f%02d", i)] = mustAny(t, wrapperspb.String(fmt.Sprintf("cfg-%d", i)))
		md[fmt.Sprintf("ns%02d", i)] = &structpb.Struct{Fields: map[string]*structpb.Value{"k": structpb.NewStringValue(fmt.Sprintf("v%d", i))}}
	}
	hcm := &envoy_config_http.HttpConnectionManager{
		StatPrefix: "l",
		RouteSpecifier: &envoy_config_http.HttpConnectionManager_RouteConfig{RouteConfig: &envoy_config_route.RouteConfiguration{
			Name: "routes",
			VirtualHosts: []*envoy_config_route.VirtualHost{{
				Name:                 "vh",
				Domains:              []string{"*"},
				TypedPerFilterConfig: tpfc,
				Metadata:             &envoy_config_core.Metadata{FilterMetadata: md},
			}},
		}},
	}
	return &envoy_config_listener.Listener{
		Name: "l",
		FilterChains: []*envoy_config_listener.FilterChain{{
			Filters: []*envoy_config_listener.Filter{{
				Name:       "envoy.filters.network.http_connection_manager",
				ConfigType: &envoy_config_listener.Filter_TypedConfig{TypedConfig: mustAny(t, hcm)},
			}},
		}},
	}
}

func TestResourceVersionDeterministicAcrossAnyPayloadMapOrder(t *testing.T) {
	c := &cacheImpl{}
	versions := map[string]int{}
	for range 100 {
		v, err := c.resourceVersion(envoy_resource.ListenerType,
			map[string]cache_types.Resource{"l": inlineRouteListener(t, 8)})
		require.NoError(t, err)
		versions[v]++
	}
	require.Len(t, versions, 1, "identical content must yield one version, got %v", versions)

	v1, err := c.resourceVersion(envoy_resource.ListenerType, map[string]cache_types.Resource{"l": inlineRouteListener(t, 3)})
	require.NoError(t, err)
	v2, err := c.resourceVersion(envoy_resource.ListenerType, map[string]cache_types.Resource{"l": inlineRouteListener(t, 4)})
	require.NoError(t, err)
	require.NotEqual(t, v1, v2, "a change inside an Any payload must change the version")
}

func TestResourceVersionDelimitsNamesAndContexts(t *testing.T) {
	c := &cacheImpl{}
	v := func(res map[string]cache_types.Resource, ctx ...string) string {
		s, err := c.resourceVersion(envoy_resource.ClusterType, res, ctx...)
		require.NoError(t, err)
		return s
	}
	empty := func() cache_types.Resource { return &envoy_config_cluster.Cluster{} }
	require.NotEqual(t,
		v(map[string]cache_types.Resource{"a": empty(), "b": empty()}),
		v(map[string]cache_types.Resource{"ab": empty()}))
	require.NotEqual(t,
		v(map[string]cache_types.Resource{"x": empty(), "": empty()}),
		v(map[string]cache_types.Resource{"x": empty()}))
	require.NotEqual(t,
		v(map[string]cache_types.Resource{"x": empty()}, "ctx"),
		v(map[string]cache_types.Resource{"x": empty()}, "ct", "x"))
	require.NotEqual(t,
		v(map[string]cache_types.Resource{"x": &envoy_config_cluster.Cluster{Name: "1"}}),
		v(map[string]cache_types.Resource{"x": &envoy_config_cluster.Cluster{Name: "2"}}))
}
