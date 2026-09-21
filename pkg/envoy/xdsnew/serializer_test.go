// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	cilium "github.com/cilium/proxy/go/cilium/api"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_config_listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_config_route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_config_tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	secret "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/cilium/cilium/pkg/envoy/xds"
)

func TestMarshalUnmarshalEmptyResources(t *testing.T) {
	require := require.New(t)

	resources := xds.Resources{
		Endpoints:          map[string]*endpoint.ClusterLoadAssignment{},
		Clusters:           map[string]*cluster.Cluster{},
		Routes:             map[string]*route.RouteConfiguration{},
		Listeners:          map[string]*listener.Listener{},
		Secrets:            map[string]*secret.Secret{},
		NetworkPolicies:    map[string]*cilium.NetworkPolicy{},
		NetworkPolicyHosts: map[string]*cilium.NetworkPolicyHosts{},
	}

	encodedResources, err := Marshal(&resources)
	require.NoError(err)

	decodedResources, err := Unmarshal(encodedResources)
	require.NoError(err)

	require.Equal(resources, decodedResources)
}

func TestMarshalUnmarshalResources(t *testing.T) {
	require := require.New(t)

	resources := xds.Resources{
		Listeners: map[string]*envoy_config_listener.Listener{
			"listener1": {
				Name: "listener1",
				Address: &envoy_config_core_v3.Address{
					Address: &envoy_config_core_v3.Address_SocketAddress{
						SocketAddress: &envoy_config_core_v3.SocketAddress{
							Protocol: envoy_config_core_v3.SocketAddress_TCP,
							Address:  "0.0.0.0",
							PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{
								PortValue: 8080,
							},
						},
					},
				},
			},
		},
		Clusters: map[string]*envoy_config_cluster.Cluster{
			"cluster1": {
				Name: "cluster1",
			},
			"cluster2": {
				Name: "cluster2",
			},
		},
		Secrets: map[string]*envoy_config_tls.Secret{
			"secret1": {
				Name: "secret1",
			},
		},
		Routes: map[string]*envoy_config_route.RouteConfiguration{
			"routeConfig1": {
				Name: "routeConfig1",
			},
		},
		Endpoints:          map[string]*envoy_config_endpoint.ClusterLoadAssignment{},
		NetworkPolicies:    map[string]*cilium.NetworkPolicy{},
		NetworkPolicyHosts: map[string]*cilium.NetworkPolicyHosts{},
	}

	encodedResources, err := Marshal(&resources)
	require.NoError(err)

	decodedResources, err := Unmarshal(encodedResources)
	require.NoError(err)

	require.Equal(resources, decodedResources)
}

// TestMarshalIsDeterministic guards the stability contract documented on
// compactJSONInPlace. protojson.Marshal deliberately emits unstable
// insignificant whitespace (golang/protobuf#1082), and marshal's output is
// hashed into the xDS resource version: if identical content produced different
// bytes, every snapshot generation would look like a change and Envoy would be
// sent a spurious full re-push.
func TestMarshalIsDeterministic(t *testing.T) {
	res := &cilium.NetworkPolicy{
		EndpointId:  42,
		EndpointIps: []string{"10.0.0.1", "f00d::1"},
		IngressPerPortPolicies: []*cilium.PortNetworkPolicy{
			{Port: 80, Protocol: envoy_config_core_v3.SocketAddress_TCP},
			{Port: 443, Protocol: envoy_config_core_v3.SocketAddress_TCP},
		},
	}

	first, err := marshal(res)
	require.NoError(t, err)
	for range 64 {
		got, err := marshal(res)
		require.NoError(t, err)
		require.Equal(t, first, got, "marshal must be byte-stable for identical content")
	}

	// A separate but equal message must serialize identically too.
	clone := proto.Clone(res).(*cilium.NetworkPolicy)
	got, err := marshal(clone)
	require.NoError(t, err)
	require.Equal(t, first, got, "equal messages must serialize identically")

	// And the output must still round-trip.
	var back cilium.NetworkPolicy
	require.NoError(t, unmarshal([]byte(first), &back))
	require.True(t, proto.Equal(res, &back), "marshal output must round-trip through unmarshal")

	// No insignificant whitespace survives.
	require.NotContains(t, first, ": ")
	require.NotContains(t, first, ", ")
	require.NotContains(t, first, "\n")
}

func TestCompactJSONInPlace(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{"no whitespace", `{"a":1}`, `{"a":1}`},
		{"spaces between tokens", `{ "a" : 1 , "b" : [ 1 , 2 ] }`, `{"a":1,"b":[1,2]}`},
		{"newlines and tabs", "{\n\t\"a\": 1\n}", `{"a":1}`},
		{"whitespace inside strings is kept", `{ "a" : "x  y\tz" }`, `{"a":"x  y\tz"}`},
		{"escaped quote does not end the string", `{ "a" : "he said \" ok " }`, `{"a":"he said \" ok "}`},
		{"escaped backslash before quote", `{ "a" : "trailing\\" , "b" : 2 }`, `{"a":"trailing\\","b":2}`},
		{"unicode escapes untouched", `{ "a" : "\u003cx\u003e" }`, `{"a":"\u003cx\u003e"}`},
		{"empty object", `{ }`, `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := string(compactJSONInPlace([]byte(tc.in)))
			require.Equal(t, tc.want, got)
			// The result must still be valid JSON that parses to the same value.
			var a, b any
			require.NoError(t, json.Unmarshal([]byte(tc.in), &a))
			require.NoError(t, json.Unmarshal([]byte(got), &b))
			require.Equal(t, a, b)
		})
	}
}

func TestWriteJSONString(t *testing.T) {
	for _, s := range []string{
		"",
		"listener1",
		"cilium-ingress/default/basic",
		`quote"inside`,
		`back\slash`,
		"tab\there",
		"bell\a",
		"vertical\vtab",
		"newline\nhere",
		"nul\x00byte",
		"unicode-ünïcödé",
		"emoji-\U0001F600",
		"<script>&</script>",
	} {
		t.Run(s, func(t *testing.T) {
			var sb strings.Builder
			require.NoError(t, writeJSONString(&sb, s))

			// The output must be valid JSON that round-trips exactly.
			// strconv.AppendQuote would emit \a, \v, \x00 and \U0001F600
			// here, none of which encoding/json accepts.
			var got string
			require.NoError(t, json.Unmarshal([]byte(sb.String()), &got))
			require.Equal(t, s, got)
		})
	}
}

func TestMarshalUnmarshalResourceNameNeedingEscapes(t *testing.T) {
	// Resource names reach Marshal straight from the Envoy config, so they
	// are not guaranteed to be plain ASCII. Whatever they contain, the
	// encoding has to survive a Marshal/Unmarshal round trip.
	name := "listener-\"quoted\"\t\a\v-ünïcödé-\U0001F600"
	resources := xds.Resources{
		Listeners: map[string]*envoy_config_listener.Listener{
			name: {Name: name},
		},
	}

	encoded, err := Marshal(&resources)
	require.NoError(t, err)

	decoded, err := Unmarshal(encoded)
	require.NoError(t, err)
	require.Len(t, decoded.Listeners, 1)
	require.True(t, proto.Equal(resources.Listeners[name], decoded.Listeners[name]))
}

// benchResources builds a resource set roughly the shape and size of what a
// busy agent pushes: a few hundred clusters and matching endpoints.
func benchResources(n int) *xds.Resources {
	res := xds.Resources{
		Clusters:  make(map[string]*envoy_config_cluster.Cluster, n),
		Endpoints: make(map[string]*envoy_config_endpoint.ClusterLoadAssignment, n),
	}
	for i := range n {
		name := fmt.Sprintf("cilium-ingress/namespace-%03d/service-%03d:8080", i, i)
		res.Clusters[name] = &envoy_config_cluster.Cluster{
			Name:           name,
			ConnectTimeout: &durationpb.Duration{Seconds: 5},
		}
		res.Endpoints[name] = &envoy_config_endpoint.ClusterLoadAssignment{
			ClusterName: name,
			Endpoints: []*envoy_config_endpoint.LocalityLbEndpoints{{
				LbEndpoints: []*envoy_config_endpoint.LbEndpoint{{
					HostIdentifier: &envoy_config_endpoint.LbEndpoint_Endpoint{
						Endpoint: &envoy_config_endpoint.Endpoint{
							Address: &envoy_config_core_v3.Address{
								Address: &envoy_config_core_v3.Address_SocketAddress{
									SocketAddress: &envoy_config_core_v3.SocketAddress{
										Address:       fmt.Sprintf("10.0.%d.%d", i/256, i%256),
										PortSpecifier: &envoy_config_core_v3.SocketAddress_PortValue{PortValue: 8080},
									},
								},
							},
						},
					},
				}},
			}},
		}
	}
	return &res
}

var sinkEncoded map[string]string

func BenchmarkMarshal(b *testing.B) {
	res := benchResources(256)
	b.ReportAllocs()
	for b.Loop() {
		encoded, err := Marshal(res)
		if err != nil {
			b.Fatal(err)
		}
		sinkEncoded = encoded
	}
}
