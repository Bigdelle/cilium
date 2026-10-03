// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"fmt"
	"testing"

	cilium "github.com/cilium/proxy/go/cilium/api"
	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_extensions_filters_http_router_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	envoy_config_http "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	cache_types "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	envoy_resource "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func benchAny(b *testing.B, m proto.Message) *anypb.Any {
	a, err := anypb.New(m)
	if err != nil {
		b.Fatal(err)
	}
	return a
}

// benchListener returns a CEC-style listener: an HTTP connection manager
// (packed in an Any) with an inline route configuration that carries a
// per-filter config and metadata map, as produced by
// ciliumenvoyconfig's resource parser.
func benchListener(b *testing.B, i int) *envoy_config_listener.Listener {
	hcm := &envoy_config_http.HttpConnectionManager{
		StatPrefix: fmt.Sprintf("listener-%d", i),
		HttpFilters: []*envoy_config_http.HttpFilter{{
			Name:       "envoy.filters.http.router",
			ConfigType: &envoy_config_http.HttpFilter_TypedConfig{TypedConfig: benchAny(b, &envoy_extensions_filters_http_router_v3.Router{})},
		}},
		RouteSpecifier: &envoy_config_http.HttpConnectionManager_RouteConfig{RouteConfig: &envoy_config_route.RouteConfiguration{
			Name: fmt.Sprintf("routes-%d", i),
			VirtualHosts: []*envoy_config_route.VirtualHost{{
				Name:    fmt.Sprintf("vh-%d", i),
				Domains: []string{fmt.Sprintf("svc-%d.ns.svc.cluster.local", i), "*"},
				Routes: []*envoy_config_route.Route{{
					Match: &envoy_config_route.RouteMatch{PathSpecifier: &envoy_config_route.RouteMatch_Prefix{Prefix: fmt.Sprintf("/api/v%d", i%3)}},
					Action: &envoy_config_route.Route_Route{Route: &envoy_config_route.RouteAction{
						ClusterSpecifier: &envoy_config_route.RouteAction_Cluster{Cluster: fmt.Sprintf("ns/svc-%d:80", i)},
					}},
				}},
				TypedPerFilterConfig: map[string]*anypb.Any{
					"envoy.filters.http.a": benchAny(b, wrapperspb.String(fmt.Sprintf("a-%d", i))),
					"envoy.filters.http.b": benchAny(b, wrapperspb.UInt32(uint32(i))),
				},
				Metadata: &envoy_config_core.Metadata{FilterMetadata: map[string]*structpb.Struct{
					"cilium.io": {Fields: map[string]*structpb.Value{
						"owner":     structpb.NewStringValue(fmt.Sprintf("cec-%d", i)),
						"namespace": structpb.NewStringValue("default"),
					}},
				}},
			}},
		}},
	}
	return &envoy_config_listener.Listener{
		Name: fmt.Sprintf("default/cec-%d/listener", i),
		Address: &envoy_config_core.Address{Address: &envoy_config_core.Address_SocketAddress{SocketAddress: &envoy_config_core.SocketAddress{
			Address: "127.0.0.1", PortSpecifier: &envoy_config_core.SocketAddress_PortValue{PortValue: uint32(10000 + i)},
		}}},
		FilterChains: []*envoy_config_listener.FilterChain{{
			Filters: []*envoy_config_listener.Filter{{
				Name:       "envoy.filters.network.http_connection_manager",
				ConfigType: &envoy_config_listener.Filter_TypedConfig{TypedConfig: benchAny(b, hcm)},
			}},
		}},
	}
}

func benchCluster(i int) *envoy_config_cluster.Cluster {
	return &envoy_config_cluster.Cluster{
		Name:                 fmt.Sprintf("ns/svc-%d:80", i),
		ClusterDiscoveryType: &envoy_config_cluster.Cluster_Type{Type: envoy_config_cluster.Cluster_EDS},
		EdsClusterConfig:     &envoy_config_cluster.Cluster_EdsClusterConfig{ServiceName: fmt.Sprintf("ns/svc-%d:80", i)},
		LbPolicy:             envoy_config_cluster.Cluster_ROUND_ROBIN,
	}
}

func benchEndpoints(i int) *envoy_config_endpoint.ClusterLoadAssignment {
	var lbs []*envoy_config_endpoint.LbEndpoint
	for j := 0; j < 1+i%4; j++ {
		lbs = append(lbs, &envoy_config_endpoint.LbEndpoint{HostIdentifier: &envoy_config_endpoint.LbEndpoint_Endpoint{Endpoint: &envoy_config_endpoint.Endpoint{
			Address: &envoy_config_core.Address{Address: &envoy_config_core.Address_SocketAddress{SocketAddress: &envoy_config_core.SocketAddress{
				Address: fmt.Sprintf("10.%d.%d.%d", i/250, i%250, j+1), PortSpecifier: &envoy_config_core.SocketAddress_PortValue{PortValue: 8080},
			}}},
		}}})
	}
	return &envoy_config_endpoint.ClusterLoadAssignment{
		ClusterName: fmt.Sprintf("ns/svc-%d:80", i),
		Endpoints:   []*envoy_config_endpoint.LocalityLbEndpoints{{LbEndpoints: lbs}},
	}
}

func benchNetworkPolicy(i int) *cilium.NetworkPolicy {
	return &cilium.NetworkPolicy{
		EndpointIps: []string{fmt.Sprintf("10.0.%d.%d", i/250, i%250)},
		EndpointId:  uint64(1000 + i),
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{{
			Port:     uint32(80 + i%5),
			Protocol: envoy_config_core.SocketAddress_TCP,
			Rules: []*cilium.PortNetworkPolicyRule{{
				RemotePolicies: []uint32{uint32(256 + i), uint32(512 + i)},
				L7: &cilium.PortNetworkPolicyRule_HttpRules{HttpRules: &cilium.HttpNetworkPolicyRules{
					HttpRules: []*cilium.HttpNetworkPolicyRule{{
						Headers: []*envoy_config_route.HeaderMatcher{{Name: ":path", HeaderMatchSpecifier: &envoy_config_route.HeaderMatcher_PresentMatch{PresentMatch: true}}},
					}},
				}},
			}},
		}},
	}
}

// benchResourceGroups builds n distinct resources per xDS type, so no two
// iterations' inputs share hashing state and no size-1 cache could help.
func benchResourceGroups(b *testing.B, n int) map[string]map[string]cache_types.Resource {
	g := map[string]map[string]cache_types.Resource{
		envoy_resource.ListenerType: {},
		envoy_resource.ClusterType:  {},
		envoy_resource.EndpointType: {},
		NetworkPolicyTypeURL:        {},
	}
	for i := 0; i < n; i++ {
		l := benchListener(b, i)
		g[envoy_resource.ListenerType][l.Name] = l
		c := benchCluster(i)
		g[envoy_resource.ClusterType][c.Name] = c
		e := benchEndpoints(i)
		g[envoy_resource.EndpointType][e.ClusterName] = e
		g[NetworkPolicyTypeURL][fmt.Sprintf("%d", 1000+i)] = benchNetworkPolicy(i)
	}
	return g
}

// BenchmarkResourceVersion measures (*cacheImpl).resourceVersion over
// realistic resource sets of increasing size (Ingress/Gateway CEC listeners
// with Any-packed HCM configs, EDS clusters, endpoints and network policies).
func BenchmarkResourceVersion(b *testing.B) {
	c := &cacheImpl{}
	for _, n := range []int{10, 100} {
		groups := benchResourceGroups(b, n)
		b.Run(fmt.Sprintf("resources=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				for typeURL, res := range groups {
					if _, err := c.resourceVersion(typeURL, res, "ctx"); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}
