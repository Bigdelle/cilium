#include "common.h"
#include <bpf/ctx/skb.h>
#include "pktgen.h"
#include "node_config.h"


#define DEBUG
#define ENABLE_PACKET_IP_TRACING

#include <lib/trace_helpers.h>


// Used to define IP options for packet generation.
struct ip4opthdr {
	// type field of the IP option.
	__u8 type;
	// len field of the IP option. Usually equal to total length of the IP
	// option, including type and len. Can be specified different from data
	// length for testing purposes. If zero, it will not be written to the
	// packet, so that tests can specify single-byte options.
	__u8 len;
	// Arbitrary data for the payload of the IP option.
	__u8 *data;
	// Length of the data field in bytes. Must match exactly.
	__u8 data_len;
};
// Injects a packet into the ctx with the IPv4 options specified. See comments
// on the struct for more details on how to specify options. The total byte
// content of the options must align on 4-byte boundaries so that the IHL can be
// accurate.
//
// opts_len:   the number of options in opts.
// opts_bytes: the total number of bytes in options.
static __always_inline __maybe_unused int
gen_packet_with_options(struct __sk_buff *ctx, struct ip4opthdr *opts, __u8 opts_len, __u8 opts_bytes)
{
	struct pktgen builder;
	struct iphdr *l3;
	__u8 *new_opt;
	int i, j, new_opt_len;
	if (opts_bytes % 4 != 0)
		// Options must be aligned on 4-byte boundaries.
		return TEST_ERROR;
	pktgen__init(&builder, ctx);
	if (!pktgen__push_ethhdr(&builder))
		return TEST_ERROR;
	l3 = pktgen__push_default_iphdr_with_options(&builder, opts_bytes / 4);
	if (!l3)
		return TEST_ERROR;
	// opts start just after the l3 header.
	new_opt = (__u8*) &l3[1];
	for (i = 0; i < opts_len; i++) {
		new_opt_len = 0;
		new_opt[0] = opts[i].type;
		new_opt_len++;
		if (opts[i].len != 0) {
			new_opt[new_opt_len] = opts[i].len;
			new_opt_len++;
		}
		for (j = 0; j < opts[i].data_len; j++) {
			new_opt[new_opt_len] = opts[i].data[j];
			new_opt_len++;
		}
		new_opt += new_opt_len;
	}
	if (!pktgen__push_data(&builder, default_data, sizeof(default_data)))
		return TEST_ERROR;
	pktgen__finish(&builder);
	return TEST_PASS;
}

/* SECTION 1: Following section has tests for ntohll function for 8 bytes of data
*/

/* General test for non-mixed. 
*/
CHECK("tc", "test_ntohll_function")
int check_test_ntohll_function()
{
    test_init();

    __u64 input = 0x0102030405060708;
    __u64 expected_output = 0x0807060504030201;
    __u64 output = ntohll(input);

    if (output != expected_output) {
        test_fatal("ntohll(0x%016llx) = 0x%016llx; want 0x%016llx\n", input, output, expected_output);
    }
    // Finish the test.
    test_finish();
}
/* Test positive values which would be negative on conversion
*/
CHECK("tc", "test_ntohll_max_positive")
int check_test_ntohll_max_positive() {
    test_init();

    __u64 input = 0xFFFFFFFFFFFFFF80;
    __u64 expected_output = 0x80FFFFFFFFFFFFFF;
    __u64 output = ntohll(input);

    if (output != expected_output) {
        test_fatal("ntohll(0x%016llx) = 0x%016llx; want 0x%016llx\n", input, output, expected_output);
    } 
    test_finish();
}
/* Test max negative values
*/
CHECK("tc", "test_ntohll_min_negative")
int check_test_ntohll_min_negative() {
    test_init();

    __u64 input = 0x8000000000000000;
    __u64 expected_output = 0x0000000000000080;
    __u64 output = ntohll(input);

    if (output != expected_output) {
        test_fatal("ntohll(0x%016llx) = 0x%016llx; want 0x%016llx\n", input, output, expected_output);
    }

    test_finish();
}
/* Test for mixed_endian
*/
CHECK("tc", "test_ntohll_mixed_endian")
int check_test_ntohll_mixed_endian() {
    test_init();

    __u64 input = 0x12345678ABCDEF01;
    __u64 expected_output = 0x01EFCDAB78563412;
    __u64 output = ntohll(input);

    if (output != expected_output) {
        test_fatal("ntohll(0x%016llx) = 0x%016llx; want 0x%016llx\n", input, output, expected_output);
    }

    test_finish();
}

/* SECTION 2: Following section has tests for trace ID feature for packet validation and preprocessing
*/

/* Test packet with no l3 header should return TRACE_ID_ERROR.
 */
PKTGEN("tc", "extract_trace_id_with_no_l3_header_error")
int test_extract_trace_id_with_no_l3_header_error_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	pktgen__init(&builder, ctx);
	if (!pktgen__push_ethhdr(&builder))
		return TEST_ERROR;
	// Missing L3 header.
	if (!pktgen__push_data(&builder, default_data, sizeof(default_data)))
		return TEST_ERROR;
	pktgen__finish(&builder);
	return TEST_PASS;
}
CHECK("tc", "extract_trace_id_with_no_l3_header_error")
int test_extract_trace_id_with_no_l3_header_error_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = TRACE_ID_ERROR;
	__s64 trace_id = trace_id_from_ctx(ctx, 136);
	if (trace_id != want) {
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	}
	test_finish();
}
/* Test packet with no eth header should return TRACE_ID_NO_FAMILY.
 */
PKTGEN("tc", "extract_trace_id_with_no_eth_header_no_family")
int test_extract_trace_id_with_no_eth_header_no_family_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	pktgen__init(&builder, ctx);
	// Missing eth and l3 headers.
	if (!pktgen__push_data(&builder, default_data, sizeof(default_data)))
		return TEST_ERROR;
	pktgen__finish(&builder);
	return TEST_PASS;
}
CHECK("tc", "extract_trace_id_with_no_eth_header_no_family")
int test_extract_trace_id_with_no_eth_header_no_family_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = TRACE_ID_NO_FAMILY;
	__s64 trace_id = trace_id_from_ctx(ctx, 136);
	if (trace_id != want) {
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	}
	test_finish();
}
/* Test packet with IPv6 header should return TRACE_ID_SKIP_IPV6.
 */
PKTGEN("tc", "extract_trace_id_with_ipv6_header_skip")
int test_extract_trace_id_with_ipv6_header_skip_pktgen(struct __ctx_buff *ctx)
{
	struct pktgen builder;
	pktgen__init(&builder, ctx);
	if (!pktgen__push_ethhdr(&builder))
		return TEST_ERROR;
	if (!pktgen__push_default_ipv6hdr(&builder))
		return TEST_ERROR;
	if (!pktgen__push_data(&builder, default_data, sizeof(default_data)))
		return TEST_ERROR;
	pktgen__finish(&builder);
	return TEST_PASS;
}
CHECK("tc", "extract_trace_id_with_ipv6_header_skip")
int test_extract_trace_id_with_ipv6_header_skip_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = TRACE_ID_SKIP_IPV6;
	__s64 trace_id = trace_id_from_ctx(ctx, 136);
	if (trace_id != want) {
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	}
	test_finish();
}
/* Test trace ID after END should return TRACE_ID_NOT_FOUND.
 */
PKTGEN("tc", "extract_trace_id_after_ipopt_end_not_found")
int test_extract_trace_id_after_ipopt_end_not_found_pktgen(struct __ctx_buff *ctx)
{
	struct ip4opthdr opts[] = {
		{
			.type = IPOPT_END,
			.len = 0, // Single byte option.
			.data_len = 0,
		},
		{
			.type = 136,
			.len = 4,
			.data = (__u8*)"\x00\x01",
			.data_len = 2,
		},
		// Add padding to align on 4-byte boundary.
		{
			.type = IPOPT_NOOP,
			.len = 0, // Single byte option.
			.data_len = 0,
		},
		{
			.type = IPOPT_NOOP,
			.len = 0, // Single byte option.
			.data_len = 0,
		},
		{
			.type = IPOPT_NOOP,
			.len = 0, // Single byte option.
			.data_len = 0,
		},
	};
	return gen_packet_with_options(ctx, opts, 5, 8);
}
CHECK("tc", "extract_trace_id_after_ipopt_end_not_found")
int test_extract_trace_id_after_ipopt_end_not_found_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = TRACE_ID_NOT_FOUND;
	__s64 trace_id = trace_id_from_ctx(ctx, 136);
	if (trace_id != want) {
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	}
	test_finish();
}
/* Test trace ID comes after loop limit should return TRACE_ID_NOT_FOUND.
 */
PKTGEN("tc", "extract_trace_id_after_loop_limit_not_found")
int test_extract_trace_id_after_loop_limit_not_found_pktgen(struct __ctx_buff *ctx)
{
	struct ip4opthdr opts[] = {
		{
			.type = IPOPT_NOOP,
			.len = 0, // Single byte option.
			.data_len = 0,
		},
		{
			.type = IPOPT_NOOP,
			.len = 0, // Single byte option.
			.data_len = 0,
		},
		{
			.type = IPOPT_NOOP,
			.len = 0, // Single byte option.
			.data_len = 0,
		},
		// The loop limit is 3 so the following options are ignored.
		{
			.type = 136,
			.len = 4,
			.data = (__u8*)"\x00\x01",
			.data_len = 2,
		},
		{
			.type = IPOPT_NOOP,
			.len = 0, // Single byte option.
			.data_len = 0,
		},
	};
	return gen_packet_with_options(ctx, opts, 5, 8);
}
CHECK("tc", "extract_trace_id_after_loop_limit_not_found")
int test_extract_trace_id_after_loop_limit_not_found_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = TRACE_ID_NOT_FOUND;
	__s64 trace_id = trace_id_from_ctx(ctx, 136);
	if (trace_id != want) {
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	}
	test_finish();
}

/* SECTION 3: Following section has tests for parsing of 2, 4, and 8-byte trace IDs. 
*/

/* Test a single option specifying the trace ID with no special cases.
 */
PKTGEN("tc", "extract_trace_id_solo")
int test_extract_trace_id_solo_pktgen(struct __ctx_buff *ctx)
{
	struct ip4opthdr opts[] = {
		{
			.type = 136,
			.len = 4,
			.data = (__u8*)"\x00\x01",
			.data_len = 2,
		},
	};
	return gen_packet_with_options(ctx, opts, 1, 4);
}
CHECK("tc", "extract_trace_id_solo")
int test_extract_trace_id_solo_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = 1;
	__s64 trace_id = trace_id_from_ctx(ctx, 136);
	if (trace_id != want) {
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	}
	test_finish();
}
/* Test three options with the trace ID option being first.
 */
PKTGEN("tc", "extract_trace_id_first_of_three")
int test_extract_trace_id_first_of_three_pktgen(struct __ctx_buff *ctx)
{
	struct ip4opthdr opts[] = {
		{
			.type = 136,
			.len = 4,
			.data = (__u8*)"\x00\x01",
			.data_len = 2,
		},
		{
			.type = 10,
			.len = 4,
			.data = (__u8*)"\x10\x10",
			.data_len = 2,
		},
		{
			.type = 11,
			.len = 4,
			.data = (__u8*)"\x11\x11",
			.data_len = 2,
		},
	};
	return gen_packet_with_options(ctx, opts, 3, 12);
}
CHECK("tc", "extract_trace_id_first_of_three")
int test_extract_trace_id_first_of_three_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = 1;
	__s64 trace_id = trace_id_from_ctx(ctx, 136);
	if (trace_id != want) {
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	}
	test_finish();
}
/* Test three options with the trace ID option being between the other two.
 */
PKTGEN("tc", "extract_trace_id_middle_of_three")
int test_extract_trace_id_middle_of_three_pktgen(struct __ctx_buff *ctx)
{
	struct ip4opthdr opts[] = {
		{
			.type = 10,
			.len = 4,
			.data = (__u8*)"\x10\x10",
			.data_len = 2,
		},
		{
			.type = 136,
			.len = 4,
			.data = (__u8*)"\x00\x01",
			.data_len = 2,
		},
		{
			.type = 11,
			.len = 4,
			.data = (__u8*)"\x11\x11",
			.data_len = 2,
		},
	};
	return gen_packet_with_options(ctx, opts, 3, 12);
}
CHECK("tc", "extract_trace_id_middle_of_three")
int test_extract_trace_id_middle_of_three_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = 1;
	__s64 trace_id = trace_id_from_ctx(ctx, 136);
	if (trace_id != want) {
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	}
	test_finish();
}
/* Test three options with the trace ID option being last of the three.
 */
PKTGEN("tc", "extract_trace_id_last_of_three")
int test_extract_trace_id_last_of_three_pktgen(struct __ctx_buff *ctx)
{
	struct ip4opthdr opts[] = {
		{
			.type = 10,
			.len = 4,
			.data = (__u8*)"\x10\x10",
			.data_len = 2,
		},
		{
			.type = 11,
			.len = 4,
			.data = (__u8*)"\x11\x11",
			.data_len = 2,
		},
		{
			.type = 136,
			.len = 4,
			.data = (__u8*)"\x00\x01",
			.data_len = 2,
		},
	};
	return gen_packet_with_options(ctx, opts, 3, 12);
}
CHECK("tc", "extract_trace_id_last_of_three")
int test_extract_trace_id_last_of_three_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = 1;
	__s64 trace_id = trace_id_from_ctx(ctx, 136);
	if (trace_id != want) {
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	}
	test_finish();
}
/* Test two options with the trace ID coming after an unusually sized option.
 */
PKTGEN("tc", "extract_trace_id_after_other_option_with_diff_len")
int test_extract_trace_id_after_other_option_with_diff_len_pktgen(struct __ctx_buff *ctx)
{
	struct ip4opthdr opts[] = {
		{
			.type = 11,
			.len = 12, // large option
			.data = (__u8*)"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
			.data_len = 10,
		},
		{
			.type = 136,
			.len = 4,
			.data = (__u8*)"\x00\x01",
			.data_len = 2,
		},
	};
	return gen_packet_with_options(ctx, opts, 2, 16);
}
CHECK("tc", "extract_trace_id_after_other_option_with_diff_len")
int test_extract_trace_id_after_other_option_with_diff_len_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = 1;
	__s64 trace_id = trace_id_from_ctx(ctx, 136);
	if (trace_id != want) {
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	}
	test_finish();
}
/* Test multiple options with the trace ID coming after a NOOP option.
 */
PKTGEN("tc", "extract_trace_id_after_ipopt_noop")
int test_extract_trace_id_after_ipopt_noop_pktgen(struct __ctx_buff *ctx)
{
	struct ip4opthdr opts[] = {
		{
			.type = IPOPT_NOOP,
			.len = 0, // Single byte option.
			.data_len = 0,
		},
		{
			.type = IPOPT_NOOP,
			.len = 0, // Single byte option.
			.data_len = 0,
		},
		{
			.type = 136,
			.len = 4,
			.data = (__u8*)"\x00\x01",
			.data_len = 2,
		},
		{
			.type = IPOPT_NOOP,
			.len = 0, // Single byte option.
			.data_len = 0,
		},
		{
			.type = IPOPT_NOOP,
			.len = 0, // Single byte option.
			.data_len = 0,
		},
	};
	return gen_packet_with_options(ctx, opts, 5, 8);
}
CHECK("tc", "extract_trace_id_after_ipopt_noop")
int test_extract_trace_id_after_ipopt_noop_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = 1;
	__s64 trace_id = trace_id_from_ctx(ctx, 136);
	if (trace_id != want) {
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	}
	test_finish();
}
/* Test multiple options with the trace ID not present should return TRACE_ID_NOT_FOUND.
 */
PKTGEN("tc", "extract_trace_id_not_found_with_other_options")
int test_extract_trace_id__not_found_with_other_options_pktgen(struct __ctx_buff *ctx)
{
	struct ip4opthdr opts[] = {
		{
			.type = 10,
			.len = 4,
			.data = (__u8*)"\x10\x10",
			.data_len = 2,
		},
		{
			.type = 11,
			.len = 4,
			.data = (__u8*)"\x11\x11",
			.data_len = 2,
		},
	};
	return gen_packet_with_options(ctx, opts, 2, 8);
}
CHECK("tc", "extract_trace_id_not_found_with_other_options")
int test_extract_trace_id_not_found_with_other_options_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = TRACE_ID_NOT_FOUND;
	__s64 trace_id = trace_id_from_ctx(ctx, 136);
	if (trace_id != want) {
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	}
	test_finish();
}
/* Test no options present should return TRACE_ID_NOT_FOUND.
 */
PKTGEN("tc", "extract_trace_id_not_found_with_no_options")
int test_extract_trace_id_not_found_with_no_options_pktgen(struct __ctx_buff *ctx)
{
	struct ip4opthdr opts[] = {};
	return gen_packet_with_options(ctx, opts, 0, 0);
}
CHECK("tc", "extract_trace_id_not_found_with_no_options")
int test_extract_trace_id_not_found_with_no_options_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = TRACE_ID_NOT_FOUND;
	__s64 trace_id = trace_id_from_ctx(ctx, 136);
	if (trace_id != want) {
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	}
	test_finish();
}
/* Test trace ID with negative value should return TRACE_ID_INVALID.
 */
PKTGEN("tc", "extract_trace_id_negative_invalid")
int test_extract_trace_id_negative_invalid_pktgen(struct __ctx_buff *ctx)
{
	struct ip4opthdr opts[] = {
		{
			.type = 136,
			.len = 4,
			.data = (__u8*)"\x80\x01", // First bit makes it negative.
			.data_len = 2,
		},
	};
	return gen_packet_with_options(ctx, opts, 1, 4);
}
CHECK("tc", "extract_trace_id_negative_invalid")
int test_extract_trace_id_negative_invalid_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = TRACE_ID_INVALID;
	__s64 trace_id = trace_id_from_ctx(ctx, 136);
	if (trace_id != want) {
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	}
	test_finish();
}
/* Test trace ID with incorrect length field should return INVALID.
 */
PKTGEN("tc", "extract_trace_id_wrong_len_invalid")
int test_extract_trace_id_wrong_len_invalid_pktgen(struct __ctx_buff *ctx)
{
	struct ip4opthdr opts[] = {
		{
			.type = 136,
			.len = 3, // Should be 4.
			.data = (__u8*)"\x00\x01",
			.data_len = 2,
		},
	};
	return gen_packet_with_options(ctx, opts, 1, 4);
}
CHECK("tc", "extract_trace_id_wrong_len_invalid")
int test_extract_trace_id_wrong_len_invalid_check(struct __ctx_buff *ctx)
{
	test_init();
	__s64 want = TRACE_ID_INVALID;
	__s64 trace_id = trace_id_from_ctx(ctx, 136);
	if (trace_id != want) {
		test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
	}
	test_finish();
}
/* Store and read trace ID to different option than stream ID with 2 bytes of data. */
PKTGEN("tc", "extract_trace_id_different_option_type")
int test_extract_trace_id_different_option_type_pktgen(struct __ctx_buff *ctx)
{
    struct ip4opthdr opts[] = {
        {
            .type = 137,
            .len = 4,
            .data = (__u8*)"\x00\x02",
            .data_len = 2,
        },
    };
    return gen_packet_with_options(ctx, opts, 1, 4);
}
CHECK("tc", "extract_trace_id_different_option_type")
int test_extract_trace_id_different_option_type_check(struct __ctx_buff *ctx)
{
    test_init();
    __s64 want = 2; 
    __s64 trace_id = trace_id_from_ctx(ctx, 137);
    if (trace_id != want) {
        test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
    }
    test_finish();
}
/* Read trace ID from wrong IP option. */
PKTGEN("tc", "extract_read_trace_id_wrong_option_type")
int test_extract_read_trace_id_wrong_option_type_pktgen(struct __ctx_buff *ctx)
{
    struct ip4opthdr opts[] = {
        {
            .type = 137,
            .len = 4,
            .data = (__u8*)"\x00\x02",
            .data_len = 2,
        },
    };
    return gen_packet_with_options(ctx, opts, 1, 4);
}
CHECK("tc", "extract_read_trace_id_wrong_option_type")
int test_extract_read_trace_id_wrong_option_type_check(struct __ctx_buff *ctx)
{
    test_init();
    __s64 want = TRACE_ID_NOT_FOUND; 
    __s64 trace_id = trace_id_from_ctx(ctx, 136);
    if (trace_id != want) {
        test_fatal("trace_id_from_ctx(ctx) = %d; want %d\n", trace_id, want);
    }
    test_finish();
}
/* Test a valid 4-byte trace ID. 
*/
PKTGEN("tc", "extract_trace_id_4_bytes_valid")
int test_extract_trace_id_4_bytes_valid_pktgen(struct __ctx_buff *ctx)
{
    struct ip4opthdr opts[] = {
        {
            .type = 136,
            .len = 6,
            .data = (__u8*)"\x00\x01\x23\x45",
            .data_len = 4,
        },
    };
    return gen_packet_with_options(ctx, opts, 1, 8);
}
CHECK("tc", "extract_trace_id_4_bytes_valid")
int test_extract_trace_id_4_bytes_valid_check(struct __ctx_buff *ctx)
{
    test_init();
    __s64 want = 0x00012345;
    __s64 trace_id = trace_id_from_ctx(ctx, 136);
    if (trace_id != want) {
        test_fatal("trace_id_from_ctx(ctx) = %lld; want %lld\n", trace_id, want);
    }
    test_finish();
}
/* Test negative trace id should return TRACE_ID_INVALID.
*/
PKTGEN("tc", "extract_trace_id_negative_4_bytes")
int test_extract_trace_id_negative_4_bytes_pktgen(struct __ctx_buff *ctx)
{
    struct ip4opthdr opts[] = {
        {
            .type = 136,
            .len = 6,
            .data = (__u8*)"\x80\x01\x23\x45", // First bit makes it negative.
            .data_len = 4,
        },
    };
    return gen_packet_with_options(ctx, opts, 1, 8);
}
CHECK("tc", "extract_trace_id_negative_4_bytes")
int test_extract_trace_id_negative_4_bytes_check(struct __ctx_buff *ctx)
{
    test_init();
    __s64 want = TRACE_ID_INVALID;
    __s64 trace_id = trace_id_from_ctx(ctx, 136);
    if (trace_id != want) {
        test_fatal("trace_id_from_ctx(ctx) = %lld; want %lld\n", trace_id, want);
    }
    test_finish();
}
/* Test a 4-byte trace ID with incorrect length. 
*/
PKTGEN("tc", "extract_trace_id_4_bytes_wrong_length")
int test_extract_trace_id_4_bytes_wrong_length_pktgen(struct __ctx_buff *ctx)
{
    struct ip4opthdr opts[] = {
        {
            .type = 136,
            .len = 5, // Incorrect length
            .data = (__u8*)"\x01\x23\x45\x67",
            .data_len = 4,
        },
    };
    return gen_packet_with_options(ctx, opts, 1, 8);
}
CHECK("tc", "extract_trace_id_4_bytes_wrong_length")
int test_extract_trace_id_4_bytes_wrong_length_check(struct __ctx_buff *ctx)
{
    test_init();
    __s64 want = TRACE_ID_INVALID;
    __s64 trace_id = trace_id_from_ctx(ctx, 136);
    if (trace_id != want) {
        test_fatal("trace_id_from_ctx(ctx) = %lld; want %lld\n", trace_id, want);
    }
    test_finish();
}
/* Test a 4-byte trace ID before the end of option list. 
*/
PKTGEN("tc", "extract_trace_id_4_bytes_before_end")
int test_extract_trace_id_4_bytes_before_end_pktgen(struct __ctx_buff *ctx)
{
    struct ip4opthdr opts[] = {
        {
            .type = 136,
            .len = 6,
            .data = (__u8*)"\x00\x01\x23\x45",
            .data_len = 4,
        },
        {
            .type = IPOPT_END,
            .len = 0,
            .data_len = 0,
        },
    };
    return gen_packet_with_options(ctx, opts, 2, 8);
}
CHECK("tc", "extract_trace_id_4_bytes_before_end")
int test_extract_trace_id_4_bytes_before_end_check(struct __ctx_buff *ctx)
{
    test_init();
    __s64 want = 0x12345;
    __s64 trace_id = trace_id_from_ctx(ctx, 136);
    if (trace_id != want) {
        test_fatal("trace_id_from_ctx(ctx) = %lld; want %lld\n", trace_id, want);
    }
    test_finish();
}
/* Test a valid 8-byte trace ID. 
*/
PKTGEN("tc", "extract_trace_id_8_bytes_valid")
int test_extract_trace_id_8_bytes_valid_pktgen(struct __ctx_buff *ctx)
{
    struct ip4opthdr opts[] = {
        {
            .type = 136,
            .len = 10, // Total length including type and len fields
            .data = (__u8*)"\x12\x34\x56\x78\x9A\xBC\xDE\xF0",
            .data_len = 8,
        },
    };
    return gen_packet_with_options(ctx, opts, 1, 12);
}
CHECK("tc", "extract_trace_id_8_bytes_valid")
int test_extract_trace_id_8_bytes_valid_check(struct __ctx_buff *ctx)
{
    test_init();
    __s64 want = 0x123456789ABCDEF0; // Expected 8-byte trace ID
    __s64 trace_id = trace_id_from_ctx(ctx, 136);
    if (trace_id != want) {
        test_fatal("trace_id_from_ctx(ctx) = %lld; want %lld\n", trace_id, want);
    }
    test_finish();
}
/* Test an 8-byte trace ID followed by padding. 
*/
PKTGEN("tc", "extract_trace_id_8_bytes_with_padding")
int test_extract_trace_id_8_bytes_with_padding_pktgen(struct __ctx_buff *ctx)
{
    struct ip4opthdr opts[] = {
        {
            .type = 136,
            .len = 10, // Total length including type and len fields
            .data = (__u8*)"\x01\x02\x03\x04\x00\x00\x00\x00",
            .data_len = 8,
        },
        {
            .type = IPOPT_NOOP,
            .len = 0, // Padding
            .data_len = 0,
        },
    };
    return gen_packet_with_options(ctx, opts, 2, 12);
}
CHECK("tc", "extract_trace_id_8_bytes_with_padding")
int test_extract_trace_id_8_bytes_with_padding_check(struct __ctx_buff *ctx)
{
    test_init();
    __s64 want = 0x0102030400000000; // Expected valid trace ID
    __s64 trace_id = trace_id_from_ctx(ctx, 136);
    if (trace_id != want) {
        test_fatal("trace_id_from_ctx(ctx) = %lld; want %lld\n", trace_id, want);
    }
    test_finish();
}
/* Test an 8-byte trace ID that represents a negative value. 
*/
PKTGEN("tc", "extract_trace_id_8_bytes_negative")
int test_extract_trace_id_8_bytes_negative_pktgen(struct __ctx_buff *ctx)
{
    struct ip4opthdr opts[] = {
        {
            .type = 136,
            .len = 10, // Total length including type and len fields
            .data = (__u8*)"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFA", // Negative value in 2's complement
            .data_len = 8,
        },
    };
    return gen_packet_with_options(ctx, opts, 1, 12);
}
CHECK("tc", "extract_trace_id_8_bytes_negative")
int test_extract_trace_id_8_bytes_negative_check(struct __ctx_buff *ctx)
{
    test_init();
    __s64 want = TRACE_ID_INVALID; // Expected invalid trace ID
    __s64 trace_id = trace_id_from_ctx(ctx, 136);
    if (trace_id != want) {
        test_fatal("trace_id_from_ctx(ctx) = %lld; want %lld\n", trace_id, want);
    }
    test_finish();
}
/* Test an 8-byte trace ID with an invalid option length. 
*/
PKTGEN("tc", "extract_trace_id_8_bytes_invalid_length")
int test_extract_trace_id_8_bytes_invalid_length_pktgen(struct __ctx_buff *ctx)
{
    struct ip4opthdr opts[] = {
        {
            .type = 136,
            .len = 9, // Invalid length, should be 10
            .data = (__u8*)"\x01\x02\x03\x04\x05\x06\x07\x08",
            .data_len = 8,
        },
    };
    return gen_packet_with_options(ctx, opts, 1, 12);
}
CHECK("tc", "extract_trace_id_8_bytes_invalid_length")
int test_extract_trace_id_8_bytes_invalid_length_check(struct __ctx_buff *ctx)
{
    test_init();
    __s64 want = TRACE_ID_INVALID; // Expected invalid trace ID
    __s64 trace_id = trace_id_from_ctx(ctx, 136);
    if (trace_id != want) {
        test_fatal("trace_id_from_ctx(ctx) = %lld; want %lld\n", trace_id, want);
    }
    test_finish();
}

/* SECTION 4: Following section has tests for trace_helpers features
*/

/* Test setting and getting a valid 2-byte trace ID. 
*/
PKTGEN("tc", "set_and_get_valid_2_byte_trace_id")
int test_set_and_get_valid_2_byte_trace_id_pktgen(struct __ctx_buff *ctx)
{
    struct ip4opthdr opts[] = {
        {
            .type = 136,
            .len = 4,
            .data = (__u8*)"\x12\x34",
            .data_len = 2,
        },
    };
    return gen_packet_with_options(ctx, opts, 1, 4);
}
CHECK("tc", "set_and_get_valid_2_byte_trace_id")
int test_set_and_get_valid_2_byte_trace_id_check(struct __ctx_buff *ctx)
{
    test_init();

    check_and_store_ip_trace_id(ctx, 136);
    __u64 trace_id = load_ip_trace_id();
    __u64 want = 0x1234;

    if (trace_id != want) {
        test_fatal("load_ip_trace_id() = %llu; want %llu\n", trace_id, want);
    } 
    test_finish();
}
/* Test clearing the trace ID with no IP options. 
*/
PKTGEN("tc", "clear_trace_id_no_ip_options")
int test_clear_trace_id_no_ip_options_pktgen(struct __ctx_buff *ctx)
{
    struct ip4opthdr opts[] = {};
    return gen_packet_with_options(ctx, opts, 0, 0);
}
CHECK("tc", "clear_trace_id_no_ip_options")
int test_clear_trace_id_no_ip_options_check(struct __ctx_buff *ctx)
{
    test_init();

    check_and_store_ip_trace_id(ctx, 136);
    __u64 trace_id = load_ip_trace_id();
    __u64 want = 0;

    if (trace_id != want) {
        test_fatal("load_ip_trace_id() = %llu; want %llu\n", trace_id, want);
    }
    test_finish();
}
/* Test setting and getting an invalid trace ID. 
*/
PKTGEN("tc", "set_and_get_invalid_trace_id")
int test_set_and_get_invalid_trace_id_pktgen(struct __ctx_buff *ctx)
{
    struct ip4opthdr opts[] = {
        {
            .type = 136,
            .len = 4,
            .data = (__u8*)"\x80\x01", // First bit makes it negative.
            .data_len = 2,
        },
    };
    return gen_packet_with_options(ctx, opts, 1, 4);
}
CHECK("tc", "set_and_get_invalid_trace_id")
int test_set_and_get_invalid_trace_id_check(struct __ctx_buff *ctx)
{
    test_init();

    check_and_store_ip_trace_id(ctx, 136);
    __u64 trace_id = load_ip_trace_id();
    __u64 want = 0;

    if (trace_id != want) {
        test_fatal("load_ip_trace_id() = %llu; want %llu\n", trace_id, want);
    }
    test_finish();
}
/* Test sending two packets: one with IP options and one without, ensuring the trace ID is cleared. 
*/
PKTGEN("tc", "two_packets_with_and_without_ip_options")
int test_two_packets_with_and_without_ip_options_pktgen(struct __ctx_buff *ctx)
{
    struct ip4opthdr opts1[] = {
        {
            .type = 136,
            .len = 4,
            .data = (__u8*)"\x12\x34",
            .data_len = 2,
        },
    };

    // Generate first packet with IP options
    if (gen_packet_with_options(ctx, opts1, 1, 4) != TEST_PASS) {
        return TEST_ERROR;
    }

    // Simulate sending the first packet
    check_and_store_ip_trace_id(ctx, 136);

    struct ip4opthdr opts2[] = {};
    // Generate second packet without IP options
    return gen_packet_with_options(ctx, opts2, 0, 0);
}
CHECK("tc", "two_packets_with_and_without_ip_options")
int test_two_packets_with_and_without_ip_options_check(struct __ctx_buff *ctx)
{
    test_init();

    // Process the second packet to clear the trace ID in the map
    check_and_store_ip_trace_id(ctx, 136);
    __u64 trace_id = load_ip_trace_id();
    __u64 want = 0;

    if (trace_id != want) {
        test_fatal("load_ip_trace_id() = %llu; want %llu\n", trace_id, want);
    }

    test_finish();
    return 0;
}

