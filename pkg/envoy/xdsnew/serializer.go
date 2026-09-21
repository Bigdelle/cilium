// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	cilium "github.com/cilium/proxy/go/cilium/api"
	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	endpoint "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	secret "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_resource "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/pkg/envoy/xds"
)

type Resource interface {
	proto.Message
}

// compactJSONInPlace removes insignificant whitespace from a JSON document,
// writing the result back over src and returning the truncated slice. src is
// modified. Whitespace inside string literals is preserved.
//
// This exists because protojson.Marshal deliberately does not produce stable
// output: protobuf-go randomizes insignificant whitespace so that callers
// cannot depend on the exact bytes.
// See https://github.com/golang/protobuf/issues/1082
//
// Removing all insignificant whitespace is sufficient to make the output
// deterministic, and unlike the json.Marshal(json.RawMessage(data)) round trip
// it previously used, it needs neither a full re-parse nor a second buffer.
func compactJSONInPlace(src []byte) []byte {
	dst := src[:0]
	inString := false
	escaped := false
	for _, b := range src {
		if inString {
			dst = append(dst, b)
			switch {
			case escaped:
				escaped = false
			case b == '\\':
				escaped = true
			case b == '"':
				inString = false
			}
			continue
		}
		switch b {
		case ' ', '\t', '\n', '\r':
			continue
		case '"':
			inString = true
		}
		dst = append(dst, b)
	}
	return dst
}

func marshal(res Resource) (string, error) {
	opts := protojson.MarshalOptions{UseProtoNames: true, Indent: ""}
	data, err := opts.Marshal(res)
	if err != nil {
		return "", err
	}

	// Since protojson.Marshal does not produce stable output,
	// this is a workaround to produce stable json output.
	// See https://github.com/golang/protobuf/issues/1082
	return string(compactJSONInPlace(data)), nil
}

type serializedResource struct {
	Name     string          `json:"name"`
	Resource json.RawMessage `json:"resource"`
}

// writeJSONString writes s to sb as a JSON string literal.
//
// strconv.AppendQuote must not be used for this: it produces a Go string
// literal, which for non-printable or non-ASCII input can contain \x, \a, \v
// and \U escapes. None of those are valid JSON, and the result would fail to
// parse back into []serializedResource in unmarshalEach.
//
// Resource names are almost always plain printable ASCII, which needs no
// escaping at all, so that case is handled without allocating. Anything else
// falls back to encoding/json.
func writeJSONString(sb *strings.Builder, s string) error {
	if isPlainJSONString(s) {
		sb.WriteByte('"')
		sb.WriteString(s)
		sb.WriteByte('"')
		return nil
	}
	quoted, err := json.Marshal(s)
	if err != nil {
		return err
	}
	sb.Write(quoted)
	return nil
}

// isPlainJSONString reports whether s can be emitted between quotes verbatim.
func isPlainJSONString(s string) bool {
	for i := range len(s) {
		switch c := s[i]; {
		case c < 0x20, c > 0x7e, c == '"', c == '\\':
			return false
		}
	}
	return true
}

func resourceKeys[T any](resources map[string]T) []string {
	keys := make([]string, 0, len(resources))
	for k := range resources {
		keys = append(keys, k)
	}
	return keys
}

func Marshal(resources *xds.Resources) (map[string]string, error) {
	encodedResources := map[string]string{}

	// marshalSorted serializes all resources of a given type in sorted key order
	// to produce a deterministic, complete encoding for versioning.
	marshalSorted := func(typeURL string, keys []string, marshalByKey func(key string) (string, error)) error {
		if len(keys) == 0 {
			return nil
		}

		slices.SortFunc(keys, cmp.Compare)
		marshaledValues := make([]string, len(keys))
		totalLen := 2 + len(keys)*24
		for i, k := range keys {
			marshaledResource, err := marshalByKey(k)
			if err != nil {
				return err
			}
			marshaledValues[i] = marshaledResource
			totalLen += len(k) + len(marshaledResource)
		}

		var sb strings.Builder
		sb.Grow(totalLen)
		sb.WriteByte('[')
		for i, k := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(`{"name":`)
			if err := writeJSONString(&sb, k); err != nil {
				return err
			}
			sb.WriteString(`,"resource":`)
			sb.WriteString(marshaledValues[i])
			sb.WriteByte('}')
		}
		sb.WriteByte(']')
		encodedResources[typeURL] = sb.String()
		return nil
	}

	if err := marshalSorted(envoy_resource.EndpointType, resourceKeys(resources.Endpoints), func(k string) (string, error) {
		return marshal(resources.Endpoints[k])
	}); err != nil {
		return nil, err
	}

	if err := marshalSorted(envoy_resource.ClusterType, resourceKeys(resources.Clusters), func(k string) (string, error) {
		return marshal(resources.Clusters[k])
	}); err != nil {
		return nil, err
	}

	if err := marshalSorted(envoy_resource.RouteType, resourceKeys(resources.Routes), func(k string) (string, error) {
		return marshal(resources.Routes[k])
	}); err != nil {
		return nil, err
	}

	if err := marshalSorted(envoy_resource.ListenerType, resourceKeys(resources.Listeners), func(k string) (string, error) {
		return marshal(resources.Listeners[k])
	}); err != nil {
		return nil, err
	}

	if err := marshalSorted(envoy_resource.SecretType, resourceKeys(resources.Secrets), func(k string) (string, error) {
		return marshal(resources.Secrets[k])
	}); err != nil {
		return nil, err
	}

	if err := marshalSorted(NetworkPolicyTypeURL, resourceKeys(resources.NetworkPolicies), func(k string) (string, error) {
		return marshal(resources.NetworkPolicies[k])
	}); err != nil {
		return nil, err
	}

	if err := marshalSorted(NetworkPolicyHostsTypeURL, resourceKeys(resources.NetworkPolicyHosts), func(k string) (string, error) {
		return marshal(resources.NetworkPolicyHosts[k])
	}); err != nil {
		return nil, err
	}

	return encodedResources, nil
}

func Unmarshal(encodedResources map[string]string) (xds.Resources, error) {
	resources := xds.Resources{
		Endpoints:          map[string]*endpoint.ClusterLoadAssignment{},
		Clusters:           map[string]*cluster.Cluster{},
		Routes:             map[string]*route.RouteConfiguration{},
		Listeners:          map[string]*listener.Listener{},
		Secrets:            map[string]*secret.Secret{},
		NetworkPolicies:    map[string]*cilium.NetworkPolicy{},
		NetworkPolicyHosts: map[string]*cilium.NetworkPolicyHosts{},
		// PortAllocationCallbacks: nil,
	}
	for resourceType, resourceList := range encodedResources {
		switch resourceType {
		case envoy_resource.EndpointType:
			err := unmarshalEach(resourceList, func(name string, resource json.RawMessage) error {
				unmarshalledEndpoint := &endpoint.ClusterLoadAssignment{}
				if err := unmarshal(resource, unmarshalledEndpoint); err != nil {
					return err
				}
				resources.Endpoints[name] = unmarshalledEndpoint
				return nil
			})
			if err != nil {
				return xds.Resources{}, err
			}
		case envoy_resource.ClusterType:
			err := unmarshalEach(resourceList, func(name string, resource json.RawMessage) error {
				unmarshalledCluster := &cluster.Cluster{}
				if err := unmarshal(resource, unmarshalledCluster); err != nil {
					return err
				}
				resources.Clusters[name] = unmarshalledCluster
				return nil
			})
			if err != nil {
				return xds.Resources{}, err
			}
		case envoy_resource.RouteType:
			err := unmarshalEach(resourceList, func(name string, resource json.RawMessage) error {
				unmarshalledRoute := &route.RouteConfiguration{}
				if err := unmarshal(resource, unmarshalledRoute); err != nil {
					return err
				}
				resources.Routes[name] = unmarshalledRoute
				return nil
			})
			if err != nil {
				return xds.Resources{}, err
			}
		case envoy_resource.ListenerType:
			err := unmarshalEach(resourceList, func(name string, resource json.RawMessage) error {
				unmarshalledListener := &listener.Listener{}
				if err := unmarshal(resource, unmarshalledListener); err != nil {
					return err
				}
				resources.Listeners[name] = unmarshalledListener
				return nil
			})
			if err != nil {
				return xds.Resources{}, err
			}
		case envoy_resource.SecretType:
			err := unmarshalEach(resourceList, func(name string, resource json.RawMessage) error {
				unmarshalledSecret := &secret.Secret{}
				if err := unmarshal(resource, unmarshalledSecret); err != nil {
					return err
				}
				resources.Secrets[name] = unmarshalledSecret
				return nil
			})
			if err != nil {
				return xds.Resources{}, err
			}
		case NetworkPolicyTypeURL:
			err := unmarshalEach(resourceList, func(name string, resource json.RawMessage) error {
				unmarshalledNetworkPolicy := &cilium.NetworkPolicy{}
				if err := unmarshal(resource, unmarshalledNetworkPolicy); err != nil {
					return err
				}
				resources.NetworkPolicies[name] = unmarshalledNetworkPolicy
				return nil
			})
			if err != nil {
				return xds.Resources{}, err
			}
		case NetworkPolicyHostsTypeURL:
			err := unmarshalEach(resourceList, func(name string, resource json.RawMessage) error {
				unmarshalledNetworkPolicyHosts := &cilium.NetworkPolicyHosts{}
				if err := unmarshal(resource, unmarshalledNetworkPolicyHosts); err != nil {
					return err
				}
				resources.NetworkPolicyHosts[name] = unmarshalledNetworkPolicyHosts
				return nil
			})
			if err != nil {
				return xds.Resources{}, err
			}
		}
	}
	return resources, nil
}

func unmarshalEach(str string, decode func(name string, resource json.RawMessage) error) error {
	var serializedResources []serializedResource
	if err := json.Unmarshal([]byte(str), &serializedResources); err != nil {
		return fmt.Errorf("error deserializing resources: %w", err)
	}

	for _, serializedResource := range serializedResources {
		if len(serializedResource.Resource) == 0 {
			return fmt.Errorf("resource %q cannot be empty", serializedResource.Name)
		}
		if err := decode(serializedResource.Name, serializedResource.Resource); err != nil {
			return err
		}
	}
	return nil
}

func unmarshal(data []byte, res Resource) error {
	if res == nil {
		return fmt.Errorf("resource cannot be nil")
	}

	err := protojson.Unmarshal(data, res)
	if err != nil {
		return fmt.Errorf("error deserializing resource: %w", err)
	}
	return nil
}
