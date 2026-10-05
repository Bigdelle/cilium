// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package xdsnew

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"sync"

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

// marshal serializes an Envoy resource to a stable JSON string.
func marshal(res Resource) (string, error) {
	var sb strings.Builder
	if err := marshalTo(&sb, res); err != nil {
		return "", err
	}
	return sb.String(), nil
}

// bufPool provides reusable bytes.Buffer instances for zero-allocation JSON compaction and escaping.
var bufPool = sync.Pool{
	New: func() any {
		return new(bytes.Buffer)
	},
}

// marshalTo serializes an Envoy resource to stable JSON directly into a strings.Builder,
// bypassing intermediate string allocations and deep copy reflection overhead.
func marshalTo(w interface{ Write([]byte) (int, error) }, res Resource) error {
	opts := protojson.MarshalOptions{UseProtoNames: true, Indent: ""}

	bPtr := protoBytesPool.Get().(*[]byte)
	b := (*bPtr)[:0]

	data, err := opts.MarshalAppend(b, res)
	if err != nil {
		if cap(b) <= 4096 {
			protoBytesPool.Put(bPtr)
		}
		return err
	}

	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()

	// json.Compact safely strips protojson's randomized whitespace natively.
	if err := json.Compact(buf, data); err != nil {
		if cap(data) <= 4096 {
			*bPtr = data
			protoBytesPool.Put(bPtr)
		}
		if buf.Cap() <= 4096 {
			bufPool.Put(buf)
		}
		return err
	}

	buf2 := bufPool.Get().(*bytes.Buffer)
	buf2.Reset()

	// json.HTMLEscape strictly replicates the HTML-escaping behavior of json.Marshal
	// to guarantee byte-for-byte stability for version hashing.
	json.HTMLEscape(buf2, buf.Bytes())

	w.Write(buf2.Bytes())

	if cap(data) <= 4096 {
		*bPtr = data
		protoBytesPool.Put(bPtr)
	}
	if buf.Cap() <= 4096 {
		bufPool.Put(buf)
	}
	if buf2.Cap() <= 4096 {
		bufPool.Put(buf2)
	}
	return nil
}

type serializedResource struct {
	Name     string          `json:"name"`
	Resource json.RawMessage `json:"resource"`
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
	marshalSorted := func(typeURL string, keys []string, getResource func(key string) Resource) error {
		if len(keys) == 0 {
			return nil
		}

		slices.SortFunc(keys, cmp.Compare)
		var sb strings.Builder
		sb.WriteByte('[')
		for i, k := range keys {
			if i > 0 {
				sb.WriteByte(',')
			}
			sb.WriteString(`{"name":`)

			// json.Marshal securely quotes and escapes the string key.
			enc, _ := json.Marshal(k)
			sb.Write(enc)

			sb.WriteString(`,"resource":`)
			if err := marshalTo(&sb, getResource(k)); err != nil {
				return err
			}
			sb.WriteByte('}')
		}
		sb.WriteByte(']')

		encodedResources[typeURL] = sb.String()
		return nil
	}

	if err := marshalSorted(envoy_resource.EndpointType, resourceKeys(resources.Endpoints), func(k string) Resource {
		return resources.Endpoints[k]
	}); err != nil {
		return nil, err
	}

	if err := marshalSorted(envoy_resource.ClusterType, resourceKeys(resources.Clusters), func(k string) Resource {
		return resources.Clusters[k]
	}); err != nil {
		return nil, err
	}

	if err := marshalSorted(envoy_resource.RouteType, resourceKeys(resources.Routes), func(k string) Resource {
		return resources.Routes[k]
	}); err != nil {
		return nil, err
	}

	if err := marshalSorted(envoy_resource.ListenerType, resourceKeys(resources.Listeners), func(k string) Resource {
		return resources.Listeners[k]
	}); err != nil {
		return nil, err
	}

	if err := marshalSorted(envoy_resource.SecretType, resourceKeys(resources.Secrets), func(k string) Resource {
		return resources.Secrets[k]
	}); err != nil {
		return nil, err
	}

	if err := marshalSorted(NetworkPolicyTypeURL, resourceKeys(resources.NetworkPolicies), func(k string) Resource {
		return resources.NetworkPolicies[k]
	}); err != nil {
		return nil, err
	}

	if err := marshalSorted(NetworkPolicyHostsTypeURL, resourceKeys(resources.NetworkPolicyHosts), func(k string) Resource {
		return resources.NetworkPolicyHosts[k]
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

var protoBytesPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 4096)
		return &b
	},
}
