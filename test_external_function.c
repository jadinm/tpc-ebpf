/* 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#define KBUILD_MODNAME "EBPF SOCKS HHF"
#include <asm/byteorder.h>
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "kernel.h"
#include "floating_point.h"
#include "floating_point_test.h"

#define AF_INET6 		10 /* IPv6 HDR */

SEC("sockops")
int handle_sockop(struct bpf_sock_ops *skops)
{
	int op;
	int rv = 0;
	__u32 key = 0;
	__u64 cur_time;
	__u32 ecount;
	struct dst_infos *dst_infos;
	struct flow_infos *flow_info;
	struct flow_tuple flow_id;

	cur_time = bpf_ktime_get_ns();
	op = (int) skops->op;

	/* Only execute the prog for scp */
	if (skops->family != AF_INET6) {
		skops->reply = -1;
		return 0;
	}
    bpf_debug("Function called\n");

	get_flow_id_from_sock(&flow_id, skops);
    dst_infos = (void *)bpf_map_lookup_elem(&dest_map, flow_id.remote_addr);
    if (dst_infos) {
        bpf_debug("Function intermediate\n");
	    floating_test_all();
    }
    //bpf_debug("Function end\n");

	skops->reply = rv;

	return 0;
}

char _license[] SEC("license") = "GPL";
