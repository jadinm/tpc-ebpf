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
#include "utils.h"

#define htonll(x) ((bpf_htonl(1)) == 1 ? (x) : ((uint64_t)bpf_htonl((x) & \
				0xFFFFFFFF) << 32) | bpf_htonl((x) >> 32))
#define ntohll(x) ((bpf_ntohl(1)) == 1 ? (x) : ((uint64_t)bpf_ntohl((x) & \
				0xFFFFFFFF) << 32) | bpf_ntohl((x) >> 32))

SEC("sockops")
int handle_sockop(struct bpf_sock_ops *skops)
{
	struct ip6_srh_t *srh;
	//struct bpf_sock_tuple tuple;
	struct fab_test_key macle;
	struct flow_infos *flow_info;
	char srh_buf[72]; // room for 4 segment

	int op;
	int rv = 0;
	int key = 0;

	op = (int) skops->op;
	
	/* Only execute the prog for scp */
	if (skops->family != AF_INET6 || bpf_ntohl(skops->remote_port) != 22) {
		skops->reply = -1;
		return 0;
	}
	macle.family = skops->family;
	macle.local_addr[0] = skops->local_ip6[0];
	macle.local_addr[1] = bpf_ntohl(skops->local_ip6[1]);
	macle.local_addr[2] = bpf_ntohl(skops->local_ip6[2]);
	macle.local_addr[3] = bpf_ntohl(skops->local_ip6[3]);
	macle.remote_addr[0] = skops->remote_ip6[0];
	macle.remote_addr[1] = bpf_ntohl(skops->remote_ip6[1]);
	macle.remote_addr[2] = bpf_ntohl(skops->remote_ip6[2]);
	macle.remote_addr[3] = bpf_ntohl(skops->remote_ip6[3]);
	macle.local_port =  skops->local_port;
	macle.remote_port = bpf_ntohl(skops->remote_port);
	flow_info = (void *)bpf_map_lookup_elem(&conn_map, &macle);


	if (!flow_info) {
		bpf_debug("flow not found, adding it\n");
		struct flow_infos new_flow;
		new_flow.srh_id = 1;
		new_flow.last_retransmit = 2345;
		new_flow.curr_threshold = 6789;
		bpf_map_update_elem(&conn_map, &macle, &new_flow, BPF_ANY);
	}

	switch (op) {
		case BPF_SOCK_OPS_TCP_XMIT:
		case BPF_SOCK_OPS_UDP_XMIT:
			break;
		case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
			srh = (void *)bpf_map_lookup_elem(&srh_map, &key);
			if (srh)
				rv = bpf_setsockopt(skops, SOL_IPV6, IPV6_RTHDR,
						srh, sizeof(srh_buf)); 
			break;
		case BPF_SOCK_OPS_RETRANS_CB:
			key = ((key+1)%2);
			srh = (void *)bpf_map_lookup_elem(&srh_map, &key); 
			/*bpf_map_update_elem(&map, &key, srh, BPF_ANY); */
			if (srh)
				rv = bpf_setsockopt(skops, SOL_IPV6, IPV6_RTHDR,
						srh, sizeof(srh_buf)); 
			break;

	}
	skops->reply = rv;

	return 1;
}

char _license[] SEC("license") = "GPL";
