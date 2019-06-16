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
	struct srh_record_t *srh_record;
	struct flow_infos *flow_info;
	struct flow_tuple flow_id;
	char srh_buf[72]; // room for 4 segment

	int op;
	int rv = 0;
	int key = 0;
	__u64 cur_time;

	cur_time = bpf_ktime_get_ns();
	op = (int) skops->op;
	
	/* Only execute the prog for scp */
	if (skops->family != AF_INET6 || bpf_ntohl(skops->remote_port) != 22) {
		skops->reply = -1;
		return 0;
	}
	get_flow_id_from_sock(&flow_id, skops);
	flow_info = (void *)bpf_map_lookup_elem(&conn_map, &flow_id);

	if (!flow_info) {
		int ret;
		struct flow_infos new_flow;

		bpf_debug("flow not found, adding it\n");
		new_flow.srh_id = get_best_path(&srh_map);
		bpf_debug("Select path ID : %lu\n", new_flow.srh_id);
		new_flow.last_reported_bw = 0;
		new_flow.sample_start_time = cur_time;
		new_flow.sample_start_bytes = skops->snd_una;
		new_flow.last_move_time = cur_time;
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
				/* Remove the bw this flow occupied */
				srh_record = (void *)bpf_map_lookup_elem(&srh_map, &flow_info->srh_id);
				if (srh_record) {
					srh_record->curr_bw = srh_record->curr_bw - flow_info->last_reported_bw;
					bpf_map_update_elem(&srh_map, &flow_info->srh_id, srh_record, BPF_ANY);
				}
				/* Delete the flow from the flows map */
				bpf_map_delete_elem(&conn_map, &flow_id);
			}
			break;
		case BPF_SOCK_OPS_RWND_INIT:
		case BPF_SOCK_OPS_TIMEOUT_INIT:
			return 0;
		case BPF_SOCK_OPS_TCP_XMIT:
			//bpf_debug("currtime: %llu start time : %llu\n", cur_time, flow_info->sample_start_time);
			//bpf_debug("una: %lu, start: %lu, bytes envoyes : %lu\n",skops->snd_una, flow_info->sample_start_bytes, skops->snd_una - flow_info->sample_start_bytes);
			/* More than 1/10 second has passed, let's check */
			if ((cur_time - flow_info->sample_start_time) >= 100000000) {
			//	uint64_t factor = (cur_time - flow_info->sample_start_time)/100000000;
				uint64_t factor = ((/*10000**/(cur_time - flow_info->sample_start_time)) + 100000000/2)/100000000;
				uint32_t bytes_sent = skops->snd_una - flow_info->sample_start_bytes;
				uint32_t bw = (((bytes_sent/**10000*/)/factor)/*/10000*/);
			/*	bpf_debug("start: %llu curr: %llu factor: %lu\n",flow_info->sample_start_time, cur_time, factor);*/
				bpf_debug("Estimated bw: %lu (bytes sent: %lu)\n", bw, bytes_sent);
				srh_record = (void *)bpf_map_lookup_elem(&srh_map, &flow_info->srh_id);
				if (srh_record) {
					srh_record->curr_bw = srh_record->curr_bw - flow_info->last_reported_bw;
					srh_record->curr_bw = srh_record->curr_bw + bw;
					flow_info->sample_start_time = cur_time;
					flow_info->sample_start_bytes = skops->snd_una;
					flow_info->last_reported_bw = bw;
					bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
					bpf_map_update_elem(&srh_map, &flow_info->srh_id, srh_record, BPF_ANY);
				}
			}
			break;
		case BPF_SOCK_OPS_UDP_XMIT:
			break;
		case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
			bpf_debug("Una initial: %lu\n", skops->snd_una);
			flow_info->sample_start_time = cur_time;
			flow_info->sample_start_bytes = skops->snd_una;
			bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
			break;

		case BPF_SOCK_OPS_TCP_CONNECT_CB:
			bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG);
			srh_record = (void *)bpf_map_lookup_elem(&srh_map, &flow_info->srh_id);
			if (srh_record) {
				rv = bpf_setsockopt(skops, SOL_IPV6, IPV6_RTHDR,
						&srh_record->srh, sizeof(srh_buf)); 
			}
			break;
		case BPF_SOCK_OPS_RETRANS_CB:
			bpf_debug("Restrans called\n");
			key = get_better_path(&srh_map, flow_info, 1);

			/* We already moved less than 3 seconds ago... do nothing */
			if ((cur_time - flow_info->last_move_time) < 3000000000)
				break;

			/* If we already are on the best path, nothing to do */
			if (key == flow_info->srh_id)
				break;

			/* First, remove our info from the previous path */
			srh_record = (void *)bpf_map_lookup_elem(&srh_map, &flow_info->srh_id); 
			if (srh_record) {
				srh_record->curr_bw = srh_record->curr_bw - flow_info->last_reported_bw;
				bpf_map_update_elem(&srh_map, &flow_info->srh_id, srh_record, BPF_ANY);
			}

			/* Then move to the next path */
			srh_record = (void *)bpf_map_lookup_elem(&srh_map, &key);
			if (srh_record) { 
				rv = bpf_setsockopt(skops, SOL_IPV6, IPV6_RTHDR,
						&srh_record->srh, sizeof(srh_buf));
				if (!rv) {
					/* Update flow informations */
					flow_info->srh_id = key;
					flow_info->last_move_time = cur_time;
					bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);

					/* Update the new path bw */
					srh_record->curr_bw = srh_record->curr_bw + flow_info->last_reported_bw;
					bpf_map_update_elem(&srh_map, &flow_info->srh_id, srh_record, BPF_ANY);
				}
			}
			break;

	}
	skops->reply = rv;

	return 0;
}

char _license[] SEC("license") = "GPL";
