#ifndef TRACE_ID_UTIL_H
#define TRACE_ID_UTIL_H

#include <bpf/ctx/ctx.h>
#include <bpf/api.h>
#include "common.h"
#include "ip_options.h"

// Define the trace ID map with __u64 trace_id
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32); // only one key here
    __type(value, __u64); // trace_id type
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} trace_id_map __section_maps_btf;

/* Macro to set trace_id in the map */
#define bpf_trace_id_set(trace_id)                        \
    ({                                                    \
        __u32 __z = 0;                                    \
        __u64 *__cache = map_lookup_elem(&trace_id_map, &__z); \
        if (always_succeeds(__cache))                     \
            *__cache = trace_id;                          \
        trace_id;                                         \
    })

/* Macro to get trace_id from the map */
#define bpf_trace_id_get()                                \
    ({                                                    \
        __u32 __z = 0;                                    \
        __u64 *__cache = map_lookup_elem(&trace_id_map, &__z); \
        __u64 trace_id = 0;                               \
        if (always_succeeds(__cache))                     \
            trace_id = *__cache;                          \
        trace_id;                                         \
    })

static __always_inline __u64 load_trace_id() {
    return bpf_trace_id_get();
}

// Function to check trace ID and store it if valid
static __always_inline void check_and_store_trace_id(struct __ctx_buff *ctx, __u8 ip_opt_type_value) {
    __s16 trace_id; // will have to change this to be 64 bits, also change ip_options tracing to return 64 bits.
    trace_id = trace_id_from_ctx(ctx, ip_opt_type_value);

    // Check if the trace ID is valid
    if (trace_id > 0) {
        bpf_trace_id_set(trace_id);
    } else {
        bpf_trace_id_set(0);
    }
}

#endif // TRACE_ID_UTIL_H
