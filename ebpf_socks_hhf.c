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
#include "utils_hhf.h"

#define htonll(x) ((bpf_htonl(1)) == 1 ? (x) : ((uint64_t)bpf_htonl((x) & \
				0xFFFFFFFF) << 32) | bpf_htonl((x) >> 32))
#define ntohll(x) ((bpf_ntohl(1)) == 1 ? (x) : ((uint64_t)bpf_ntohl((x) & \
				0xFFFFFFFF) << 32) | bpf_ntohl((x) >> 32))
SEC("sockops")
int handle_sockop(struct bpf_sock_ops *skops)
{
	struct ip6_srh_t *srh;
	struct srh_record_t *srh_record;
	struct flow_infos *flow_info;
	struct flow_tuple flow_id;
	char srh_buf[72]; // room for 4 segment

	int op;
	int rv = 0;
	int key = 0;
	int elephant_key = 1;
	__u64 cur_time;

	cur_time = bpf_ktime_get_ns();
	op = (int) skops->op;
	
	/* Only execute the prog for scp */
	if (skops->family != AF_INET6 || (skops->local_port != 8080 && bpf_ntohl(skops->remote_port) != 5201 && bpf_ntohl(skops->remote_port) != 8000)) {
		skops->reply = -1;
		return 0;
	}
	get_flow_id_from_sock(&flow_id, skops);
	flow_info = (void *)bpf_map_lookup_elem(&conn_map, &flow_id);

	if (!flow_info) {
		int ret;
		struct flow_infos new_flow;

		new_flow.srh_id = 0;
		new_flow.sample_start_time = cur_time;
		new_flow.sample_start_bytes = skops->snd_una;
		new_flow.is_elephant = 0;
		ret = bpf_map_update_elem(&conn_map, &flow_id, &new_flow, BPF_ANY);
		if (ret) 
			return 1;
		flow_info = (void *)bpf_map_lookup_elem(&conn_map, &flow_id);
		if (!flow_info)
			return 1;
	}

	//bpf_debug("segs_out: %lu packets: %lu interval: %lu\n", skops->segs_out, skops->rate_delivered, skops->rate_interval_us);
	//bpf_debug("snd_una: %lu rate : %lu interval: %lu\n", skops->snd_una, skops->rate_delivered, skops->rate_interval_us);
	switch (op) {
		case BPF_SOCK_OPS_STATE_CB: /* Change in the state of the TCP CONNECTION */
			/* This flow is closed, cleanup the maps */
			if (skops->args[1] == BPF_TCP_CLOSE) {
				/* Delete the flow from the flows map */
				bpf_map_delete_elem(&conn_map, &flow_id);
			}
			break;
		case BPF_SOCK_OPS_RWND_INIT:
		case BPF_SOCK_OPS_TIMEOUT_INIT:
			return 0;
		case BPF_SOCK_OPS_TCP_XMIT:
			if (flow_info->is_elephant)
				break;
			/* More than 1 second has passed, let's check */
			if ((cur_time - flow_info->sample_start_time) >= 1000000000) {
				uint32_t bytes_sent = skops->snd_una - flow_info->sample_start_bytes;
				if (bytes_sent >= 1000000) {
					srh_record = (void *)bpf_map_lookup_elem(&srh_map, &elephant_key);
					if (srh_record) {
						rv = bpf_setsockopt(skops, SOL_IPV6, IPV6_RTHDR,
								&srh_record->srh, sizeof(srh_buf));
						if (!rv) {
							/* Update flow informations */
							flow_info->srh_id = elephant_key;
							flow_info->is_elephant = 1;
							bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
						}
					}
				} else {
					flow_info->sample_start_time = cur_time;
					flow_info->sample_start_bytes = skops->snd_una;
					bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
				}
			}
			break;
		case BPF_SOCK_OPS_UDP_XMIT:
			break;
		case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
			//bpf_debug("Una initial: %lu\n", skops->snd_una);
			flow_info->sample_start_time = cur_time;
			flow_info->sample_start_bytes = skops->snd_una;
			bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
			bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);
			//bpf_sock_ops_cb_flags_set(skops, (BPF_SOCK_OPS_RETRANS_CB_FLAG|BPF_SOCK_OPS_RTO_CB_FLAG));
			srh_record = (void *)bpf_map_lookup_elem(&srh_map, &flow_info->srh_id);
			if (srh_record) {
				rv = bpf_setsockopt(skops, SOL_IPV6, IPV6_RTHDR,
						&srh_record->srh, sizeof(srh_buf)); 
			}
			break;

		case BPF_SOCK_OPS_TCP_CONNECT_CB:
			bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);
			//bpf_sock_ops_cb_flags_set(skops, (BPF_SOCK_OPS_RETRANS_CB_FLAG|BPF_SOCK_OPS_RTO_CB_FLAG));
			srh_record = (void *)bpf_map_lookup_elem(&srh_map, &flow_info->srh_id);
			if (srh_record) {
				rv = bpf_setsockopt(skops, SOL_IPV6, IPV6_RTHDR,
						&srh_record->srh, sizeof(srh_buf)); 
			}
			break;

		case BPF_SOCK_OPS_ECN_CE:
			break;
		case BPF_SOCK_OPS_NEEDS_ECN:
			bpf_debug("Need ECN called\n");
			return 1;
		case BPF_SOCK_OPS_RETRANS_CB:
			break;

	}
	skops->reply = rv;

	return 0;
}

char _license[] SEC("license") = "GPL";
