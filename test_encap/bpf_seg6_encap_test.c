/* 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#define KBUILD_MODNAME "BPF SEG6_ENCAP_TEST"
#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>
#include "bpf_endian.h"
#include "bpf_helpers.h"

/* Only use this for debug output. Notice output from bpf_trace_printk()
 *  * end-up in /sys/kernel/debug/tracing/trace_pipe
 *   */
#define bpf_debug(fmt, ...)						\
			({							\
			char ____fmt[] = fmt;				\
			bpf_trace_printk(____fmt, sizeof(____fmt),	\
			##__VA_ARGS__);			\
			})

#define htonll(x) ((bpf_htonl(1)) == 1 ? (x) : ((uint64_t)bpf_htonl((x) & \
				0xFFFFFFFF) << 32) | bpf_htonl((x) >> 32))
#define ntohll(x) ((bpf_ntohl(1)) == 1 ? (x) : ((uint64_t)bpf_ntohl((x) & \
				0xFFFFFFFF) << 32) | bpf_ntohl((x) >> 32))

struct ip6_addr_t {
	unsigned long long hi;
	unsigned long long lo;
} __attribute__((packed));

struct ip6_srh_t {
	unsigned char nexthdr;
	unsigned char hdrlen;
	unsigned char type;
	unsigned char segments_left;
	unsigned char first_segment;
	unsigned char flags;
	unsigned short tag;

	struct ip6_addr_t segments[0];
} __attribute__((packed));

SEC("encap_srh")
int __encap_srh(struct __sk_buff *skb)
{
	struct ip6_addr_t s1 = { .hi = 0xfc00000200000003, .lo = 0x1 };
	struct ip6_addr_t s2 = { .hi = 0xfc00000200000002, .lo = 0x1 };
	struct ip6_addr_t s3 = { .hi = 0xfc00000200000005, .lo = 0x1 };
	struct ip6_addr_t s4 = { .hi = 0xfc00000200000004, .lo = 0x1 };
	struct ip6_addr_t *segs[] = { &s4, &s3, &s2, &s1 };

	struct ip6_srh_t *srh;
	char srh_buf[72]; // room for 4 segments
	int err;

	if (skb->mark != 42)
		return TC_ACT_OK;

	srh = (struct ip6_srh_t *)srh_buf;
	srh->nexthdr = 0;
	srh->hdrlen = 8;
	srh->type = 4;
	srh->segments_left = 3;
	srh->first_segment = 3;
	srh->flags = 0;
	srh->tag = 0;

	#pragma clang loop unroll(full)
	for (unsigned int i = 0; i < 4; i++) {
		struct ip6_addr_t *cur_seg = (struct ip6_addr_t *)((char *)srh + sizeof(*srh) + i*sizeof(struct ip6_addr_t));

		cur_seg->lo = htonll(segs[i]->lo);
		cur_seg->hi = htonll(segs[i]->hi);
	}

	err = bpf_skb_push_seg6_encap(skb, (void *)srh, sizeof(srh_buf));
	if (err)
		return TC_ACT_SHOT;

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
