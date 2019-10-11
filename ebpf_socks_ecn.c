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
	struct dst_infos *dst_infos;
	struct flow_infos *flow_info;
	struct flow_tuple flow_id;
	struct params_better_path args_bp;
	char srh_buf[72]; // room for 4 segment
	char dest_addr_buf[255];

	int op;
	int rv = 0;
	uint32_t key = 0;
	__u64 cur_time;

	cur_time = bpf_ktime_get_ns();
	op = (int) skops->op;
	
	/* Only execute the prog for scp */
	if (skops->family != AF_INET6) {
		skops->reply = -1;
		return 0;
	}
	get_flow_id_from_sock(&flow_id, skops);
	flow_info = (void *)bpf_map_lookup_elem(&conn_map, &flow_id);

	if (!flow_info) {  // TODO Problem if listening connections => no destination defined !!!
		int ret;
		struct flow_infos new_flow;

		bpf_debug("flow not found, adding it\n");
		new_flow.srh_id = get_best_dest_path(&dest_map, (struct ip6_addr_t *) flow_id.remote_addr);
		bpf_debug("Select path ID : %lu\n", new_flow.srh_id);
		new_flow.last_reported_bw = 0;
		new_flow.sample_start_time = cur_time;
		new_flow.sample_start_bytes = skops->snd_una;
		new_flow.last_move_time = cur_time;
		new_flow.first_loss_time = 0;
		new_flow.number_of_loss = 0;
		ret = bpf_map_update_elem(&conn_map, &flow_id, &new_flow, BPF_ANY);
		if (ret) 
			return 1;
		flow_info = (void *)bpf_map_lookup_elem(&conn_map, &flow_id);
		if (!flow_info)
			return 1;
		bpf_debug("Flow path is correctly entered !\n");
	}

	//bpf_debug("segs_out: %lu packets: %lu interval: %lu\n", skops->segs_out, skops->rate_delivered, skops->rate_interval_us);
	//bpf_debug("snd_una: %lu rate : %lu interval: %lu\n", skops->snd_una, skops->rate_delivered, skops->rate_interval_us);
	switch (op) {
		case BPF_SOCK_OPS_STATE_CB: // Change in the state of the TCP CONNECTION
			// This flow is closed, cleanup the maps
			if (skops->args[1] == BPF_TCP_CLOSE) {
				// Remove the bw this flow occupied
				dst_infos = (void *)bpf_map_lookup_elem(&dest_map, flow_id.remote_addr);
				if (dst_infos && flow_info->srh_id >= 0 && flow_info->srh_id < MAX_SRH_BY_DEST) {
					srh_record = &dst_infos->srhs[flow_info->srh_id];
					//srh_record->curr_bw = srh_record->curr_bw - flow_info->last_reported_bw;  // TODO Problem if no more bandwidth and we took that out of despair
					bpf_map_update_elem(&dest_map, flow_id.remote_addr, dst_infos, BPF_ANY);
				}
				// Delete the flow from the flows map
				bpf_map_delete_elem(&conn_map, &flow_id);
			}
			break;
		case BPF_SOCK_OPS_RWND_INIT:
		case BPF_SOCK_OPS_TIMEOUT_INIT:
			return 0;
		case BPF_SOCK_OPS_TCP_XMIT:
			//bpf_debug("currtime: %llu start time : %llu\n", cur_time, flow_info->sample_start_time);
			//bpf_debug("una: %lu, start: %lu, bytes envoyes : %lu\n",skops->snd_una, flow_info->sample_start_bytes, skops->snd_una - flow_info->sample_start_bytes);
			// More than 1/10 second has passed, let's check
			//if ((cur_time - flow_info->sample_start_time) >= 100000000) {
			//	uint64_t factor = (cur_time - flow_info->sample_start_time)/100000000;
			//	uint64_t factor = (((cur_time - flow_info->sample_start_time)) + 100000000/2)/100000000;
			//	uint32_t bytes_sent = skops->snd_una - flow_info->sample_start_bytes;
				//uint32_t bw = (((bytes_sent)/factor));
				//bpf_debug("start: %llu curr: %llu factor: %lu\n",flow_info->sample_start_time, cur_time, factor);
				//bpf_debug("Estimated bw: %lu (bytes sent: %lu)\n", bw, bytes_sent);
				//dst_infos = (void *) bpf_map_lookup_elem(&dest_map, flow_id.remote_addr);
				//if (dst_infos && flow_info->srh_id >= 0 && flow_info->srh_id < MAX_SRH_BY_DEST) {
					// srh_record = &dst_infos->srhs[flow_info->srh_id];
					//srh_record->curr_bw = srh_record->curr_bw - flow_info->last_reported_bw; // TODO Problem if no more bandwidth and we took that out of despair
					//srh_record->curr_bw = srh_record->curr_bw + bw; // TODO Problem if no more bandwidth and we took that out of despair
			//		flow_info->sample_start_time = cur_time;
			//		flow_info->sample_start_bytes = skops->snd_una;
			//		flow_info->last_reported_bw = bw;
			//		bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
					// bpf_map_update_elem(&dest_map, flow_id.remote_addr, dst_infos, BPF_ANY);
				//}
			//}
			break;
		case BPF_SOCK_OPS_UDP_XMIT:
			break;
		case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
			bpf_debug("Active established !!!\n");
		case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
			//bpf_debug("Una initial: %lu\n", skops->snd_una);
			bpf_debug("Passive or active established !!!\n");
			flow_info->sample_start_time = cur_time;
			flow_info->sample_start_bytes = skops->snd_una;
			bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
			break;

		case BPF_SOCK_OPS_TCP_CONNECT_CB:
			bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG); // TCP State change
			//bpf_sock_ops_cb_flags_set(skops, (BPF_SOCK_OPS_RETRANS_CB_FLAG|BPF_SOCK_OPS_RTO_CB_FLAG));
			dst_infos = (void *)bpf_map_lookup_elem(&dest_map, flow_id.remote_addr);
			if (dst_infos && flow_info->srh_id >= 0 && flow_info->srh_id < MAX_SRH_BY_DEST) {
				srh_record = &dst_infos->srhs[flow_info->srh_id];
				rv = bpf_setsockopt(skops, SOL_IPV6, IPV6_RTHDR,
						&srh_record->srh, sizeof(srh_buf));
				//bpf_debug("CONNECT - setsockopt return value %d\n", rv);
			}
			break;

		case BPF_SOCK_OPS_ECN_CE:
			bpf_debug("Congestion experienced\n");

			// We already moved less than 3 seconds ago... do nothing
			if ((cur_time - flow_info->last_move_time) < 3000000000)
				break;

			bpf_debug("Congestion experienced - Try to change from %u\n", flow_info->srh_id);
			key = get_better_dest_path(&dest_map, flow_info, 0, flow_id.remote_addr);
			bpf_debug("Congestion experienced 2 - Try to change from %u to %u\n", flow_info->srh_id, key);

			// This can't be helped
			if (key == flow_info->srh_id)
				break;
			bpf_debug("Congestion experienced 3 - Changing in progress\n");

			// Get the infos for the current path and remove our bw
			dst_infos = (void *)bpf_map_lookup_elem(&dest_map, flow_id.remote_addr);
			if (dst_infos) {
				bpf_debug("Congestion experienced 4 - dst_infos found!\n");
				// Check needed to avoid verifier complaining about unbounded access
				if(flow_info->srh_id >= 0 && flow_info->srh_id < MAX_SRH_BY_DEST) {
					srh_record = &dst_infos->srhs[flow_info->srh_id];
					//srh_record->curr_bw = srh_record->curr_bw - flow_info->last_reported_bw; // TODO Problem if no more bandwidth and we took that out of despair
					bpf_map_update_elem(&dest_map, flow_id.remote_addr, dst_infos, BPF_ANY);
				}

				// Then move to the next path
				// Check needed to avoid verifier complaining about unbounded access
				if (key >= 0 && key < MAX_SRH_BY_DEST) {
					srh_record = &dst_infos->srhs[key];
					size_t srh_buf_len = sizeof(srh_record->srh);
					if (srh_buf_len >= 0 && srh_buf_len <= 72) {
						rv = bpf_setsockopt(skops, SOL_IPV6, IPV6_RTHDR,
								&srh_record->srh, srh_buf_len);
					}
					if (!rv) {
						// Update flow informations
						flow_info->srh_id = key;
						flow_info->last_move_time = cur_time;
						flow_info->first_loss_time = 0;
						flow_info->number_of_loss = 0;
						bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);

						// Update the new path bw
						//srh_record->curr_bw = srh_record->curr_bw + flow_info->last_reported_bw; // TODO Problem if no more bandwidth and we took that out of despair
						bpf_map_update_elem(&dest_map, flow_id.remote_addr, dst_infos, BPF_ANY);
						bpf_debug("Congestion experienced 7 - after updating flow info\n");
					}
					bpf_debug("Congestion experienced 8 - Change finished !\n");
				}
			}
			break;
		case BPF_SOCK_OPS_NEEDS_ECN:
			bpf_debug("Need ECN called\n");
			return 1;

		case BPF_SOCK_OPS_RETRANS_CB:
			bpf_debug("Restrans called\n");

			// We already moved less than 3 seconds ago... do nothing
			if ((cur_time - flow_info->last_move_time) < 3000000000)
				break;
			
			// If this is the first time we experience a loss for this sample
			if (flow_info->first_loss_time == 0) {
				flow_info->first_loss_time = cur_time;
				flow_info->number_of_loss = 1;
				bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
				break;
			}

			flow_info->number_of_loss++;	

			// If we experienced more than 3 losses in 1 second
			if ((cur_time - flow_info->first_loss_time) > 1000000000) {
				flow_info->first_loss_time = cur_time;
				flow_info->number_of_loss = 1;
				bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
				break;
			} else {
				// It's been lesst than 1 second
				if (flow_info->number_of_loss < 4) {
					bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
					break;	
				}
			}

			args_bp.self_allowed = 1;
			args_bp.dst_addr = (struct ip6_addr_t *) &flow_id.remote_addr;
			key = get_better_dest_path(&dest_map, flow_info, &args_bp);

			// If we already are on the best path
			if (key == flow_info->srh_id) {
				// If this pith isn't THAT bad, let's stay
				if (flow_info->number_of_loss < 10)
					break;

				// Try a different path
				args_bp.self_allowed = 0;
				args_bp.dst_addr = (struct ip6_addr_t *) flow_id.remote_addr;
				key = get_better_dest_path(&dest_map, flow_info, &args_bp);

				// Couldn't get a best path, too bad, nothing we can do
				if (key == flow_info->srh_id)
					break;
			}

			// First, remove our info from the previous path
			dst_infos = (void *)bpf_map_lookup_elem(&dest_map, flow_id.remote_addr);
			if (dst_infos) {
				if (flow_info->srh_id >= 0 && flow_info->srh_id < MAX_SRH_BY_DEST) {
					srh_record = &dst_infos->srhs[flow_info->srh_id];
					//srh_record->curr_bw = srh_record->curr_bw - flow_info->last_reported_bw; // TODO Problem if no more bandwidth and we took that out of despair
					bpf_map_update_elem(&dest_map, flow_id.remote_addr, dst_infos, BPF_ANY);
				}

				// Then move to the next path
				if (key >= 0 && key < MAX_SRH_BY_DEST) {
					srh_record = &dst_infos->srhs[key];
					rv = bpf_setsockopt(skops, SOL_IPV6, IPV6_RTHDR,
							&srh_record->srh, sizeof(srh_buf));
					if (!rv) {
						// Update flow informations
						flow_info->srh_id = key;
						flow_info->last_move_time = cur_time;
						flow_info->first_loss_time = 0;
						flow_info->number_of_loss = 0;
						bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);

						// Update the new path bw
						//srh_record->curr_bw = srh_record->curr_bw + flow_info->last_reported_bw; // TODO Problem if no more bandwidth and we took that out of despair
						bpf_map_update_elem(&dest_map, flow_id.remote_addr, dst_infos, BPF_ANY);
					}
				}
			}
			break;

	}
	skops->reply = rv;

	return 0;
}

char _license[] SEC("license") = "GPL";
