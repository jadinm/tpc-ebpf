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
#define TCP_CLOSE 7
SEC("sockops")
int handle_sockop(struct bpf_sock_ops *skops)
{
	struct ip6_srh_t *srh;
	struct flow_infos *flow_info;
	struct flow_tuple flow_id;
	char srh_buf[72]; // room for 4 segment

	int op;
	int rv = 0;
	int key = 0;
	int tempkey = 0;
	uint64_t tempval = 300;
//	__u64 cur_time;

//	cur_time = bpf_ktime_get_ns();
	op = (int) skops->op;
	
	/* Only execute the prog for scp */
	if (skops->family != AF_INET6 || bpf_ntohl(skops->remote_port) != 22) {
		skops->reply = -1;
		return 0;
	}

	bpf_map_update_elem(&bw_map, &tempkey, &tempval, BPF_ANY);
	tempkey++;
	tempval = 100;
	bpf_map_update_elem(&bw_map, &tempkey, &tempval, BPF_ANY);
	tempkey++;
	tempval = 200;
	bpf_map_update_elem(&bw_map, &tempkey, &tempval, BPF_ANY);

	get_flow_id_from_sock(&flow_id, skops);
	flow_info = (void *)bpf_map_lookup_elem(&conn_map, &flow_id);

	if (!flow_info) {
		int ret;

		bpf_debug("flow not found, adding it\n");
		struct flow_infos new_flow;
		new_flow.srh_id = get_best_path(&bw_map);
		bpf_debug("Select path ID : %lu\n", new_flow.srh_id);
		new_flow.last_reported_bw = 0;
		new_flow.sample_start_time = 0;
		new_flow.current_bytes = 0;
		ret = bpf_map_update_elem(&conn_map, &flow_id, &new_flow, BPF_ANY);
		if (ret) 
			return 1;
	}

	//bpf_debug("segs_out: %lu packets: %lu interval: %lu\n", skops->segs_out, skops->rate_delivered, skops->rate_interval_us);
	//bpf_debug("snd_una: %lu rate : %lu interval: %lu\n", skops->snd_una, skops->rate_delivered, skops->rate_interval_us);
	switch (op) {
		case BPF_SOCK_OPS_STATE_CB:
			if (skops->args[1] == BPF_TCP_CLOSE) {
				bpf_map_delete_elem(&conn_map, &flow_id);
			}
			break;
		case BPF_SOCK_OPS_RWND_INIT:
		case BPF_SOCK_OPS_TIMEOUT_INIT:
			return 0;
		case BPF_SOCK_OPS_TCP_XMIT:
		case BPF_SOCK_OPS_UDP_XMIT:
			break;
		case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
			break;
		case BPF_SOCK_OPS_TCP_CONNECT_CB:
			bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);
			srh = (void *)bpf_map_lookup_elem(&srh_map, &key);
			if (srh)
				rv = bpf_setsockopt(skops, SOL_IPV6, IPV6_RTHDR,
						srh, sizeof(srh_buf)); 
			break;
		case BPF_SOCK_OPS_RETRANS_CB:
			bpf_debug("Restrans called\n");
			flow_info = (void *)bpf_map_lookup_elem(&conn_map, &flow_id);
			if (flow_info) {
				flow_info->srh_id = ((flow_info->srh_id+1)%2);
				bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
				srh = (void *)bpf_map_lookup_elem(&srh_map, &flow_info->srh_id); 
				if (srh) 
					rv = bpf_setsockopt(skops, SOL_IPV6, IPV6_RTHDR,
							srh, sizeof(srh_buf)); 
			}
			break;

	}
	skops->reply = rv;

	return 0;
}

char _license[] SEC("license") = "GPL";
