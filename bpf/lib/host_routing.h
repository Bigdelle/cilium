/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "common.h"
#include "map_defs.h"

struct host_routing_v4_key {
	struct bpf_lpm_trie_key lpm_key;
	__u32 ip4;
} __packed;

struct host_routing_v6_key {
	struct bpf_lpm_trie_key lpm_key;
	union v6addr ip6;
} __packed;

#ifdef ENABLE_IPV4
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct host_routing_v4_key);
	__type(value, __u8);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 16384);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG_COND);
} cilium_host_routing_v4 __section_maps_btf;
#endif

#ifdef ENABLE_IPV6
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct host_routing_v6_key);
	__type(value, __u8);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 16384);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG_COND);
} cilium_host_routing_v6 __section_maps_btf;
#endif

static __always_inline bool
host_routing_lookup_v4(__be32 ip4)
{
#ifdef ENABLE_IPV4
	struct host_routing_v4_key key = {
		.lpm_key = {
			.prefixlen = 32,
		},
		.ip4 = ip4,
	};
	if (map_lookup_elem(&cilium_host_routing_v4, &key))
		return true;
#endif
	return false;
}

static __always_inline bool
host_routing_lookup_v6(const union v6addr *ip6)
{
#ifdef ENABLE_IPV6
	struct host_routing_v6_key key = {
		.lpm_key = {
			.prefixlen = 128,
		},
		.ip6 = *ip6,
	};
	if (map_lookup_elem(&cilium_host_routing_v6, &key))
		return true;
#endif
	return false;
}

static __always_inline bool
host_routing_enabled_v4(__be32 saddr, __be32 daddr)
{
	if (host_routing_lookup_v4(saddr) || host_routing_lookup_v4(daddr))
		return true;

	return false;
}

static __always_inline bool
host_routing_enabled_v6(const union v6addr *saddr, const union v6addr *daddr)
{
	if (host_routing_lookup_v6(saddr) || host_routing_lookup_v6(daddr))
		return true;

	return false;
}
