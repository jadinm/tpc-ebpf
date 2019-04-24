/* 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#define KBUILD_MODNAME "EBPF SOCKS HHF"
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"

#define IPPROTO_TCP 6
#define AF_INET6 10
#define SOL_IPV6 41
#define IPV6_RTHDR 57

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

SEC("sockops")
int handle_sockop(struct bpf_sock_ops *skops)
{
	struct ip6_addr_t s1 = { .hi = 0xfc11000000000000, .lo = 0x2 };
	struct ip6_addr_t s2 = { .hi = 0xfc11000000000000, .lo = 0x2 };
	struct ip6_addr_t s3 = { .hi = 0xfc11000000000000, .lo = 0x2 };
	struct ip6_addr_t s4 = { .hi = 0xfc11000000000000, .lo = 0x2 };
	struct ip6_addr_t *segs[] = { &s4, &s3, &s2, &s1 };
	struct ip6_srh_t *srh;
	char srh_buf[72]; // room for 4 segments

	int op;
	int rv = 0;
	int bufsize = 150000;

	op = (int) skops->op;


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

	bpf_debug("BPF command: %d\n", op);
	bpf_debug("before switch");
	switch (op) {
		case BPF_SOCK_OPS_TCP_XMIT:
		case BPF_SOCK_OPS_UDP_XMIT:
			if (skops->family == AF_INET6) {
				bpf_debug("SOCK_OPS_XMIT: setsockopt before");
				rv = bpf_setsockopt(skops, SOL_IPV6, IPV6_RTHDR,
					srh, sizeof(srh_buf));
				bpf_debug("SOCK_OPS_XMIT: setsockopt done");
			}

	}
	skops->reply = rv;

	return 1;
}

char _license[] SEC("license") = "GPL";
