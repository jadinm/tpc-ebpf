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

static int move_path(struct dst_infos *dst_infos, __u32 key, struct bpf_sock_ops *skops)
{
	int rv = 1;
	char cc[20];
	struct ip6_srh_t *srh = NULL;
	__u32 bw = 0;
	// Check needed to avoid verifier complaining about unbounded access
	// The check needs to be placed very near the actual line
	if (key >= 0 && key < MAX_SRH_BY_DEST) {
		srh = &(dst_infos->srhs[key].srh);
		bw = dst_infos->srhs[key].curr_bw * (1000 / 8) * 1000 * 9 / 10; // max 0.9 the bw
		rv = bpf_setsockopt(skops, SOL_IPV6, IPV6_RTHDR, srh, sizeof(*srh));
		/*if (!rv) {
			rv = bpf_setsockopt(skops, SOL_SOCKET,
					    SO_MAX_PACING_RATE, &bw, sizeof(int));
			//bpf_debug("Try to set max pacing rate to %u returned %d\n", bw, rv);
		}*/
	}

	if (!rv) {
		rv = bpf_getsockopt(skops, SOL_TCP, TCP_CONGESTION, cc, sizeof(cc));
		bpf_debug("CC got ? %d\n", rv);
		if (!rv) {
			rv = bpf_setsockopt(skops, SOL_TCP, TCP_CONGESTION, cc, sizeof(cc));
			bpf_debug("CC reset ? %d\n", rv);
		}
	}
	return !!rv;
}

static __always_inline void update_flow_timers(struct flow_infos *flow_info, struct dst_infos *dst_infos)
{
	// Timers
	__u64 ecn_time = 0;
	ecn_time = ((__u64) bpf_get_prandom_u32()) * 1000;
	if (ecn_time >= 0 && ecn_time <= __UINT64_MAX__ - 1 && flow_info->wait_backoff_max >= 0 && flow_info->wait_backoff_max <= __UINT64_MAX__ - 1) {
		ecn_time = (ecn_time % flow_info->wait_backoff_max) + 1;
	} else {
		ecn_time = flow_info->wait_backoff_max; // max
	}

	flow_info->wait_backoff_max = flow_info->wait_backoff_max * 2; // Exponentially increase the maximum backoff time

	//bpf_debug("RANDOM = %lu\n", ecn_time);
	flow_info->wait_before_move = ecn_time;
}

static int create_new_flow_infos(struct bpf_elf_map *dt_map, struct bpf_elf_map *c_map, struct flow_tuple *flow_id, __u64 cur_time, struct bpf_sock_ops *skops) {
	struct flow_infos *flow_info;
	struct flow_infos new_flow;
	int rv = 0;
	memset(&new_flow, 0, sizeof(struct flow_infos));

	//bpf_debug("flow not found, adding it\n");
	new_flow.exp3_last_number_actions = 1;
	new_flow.exp3_start_snd_nxt = skops->snd_nxt;
	// Timers
	new_flow.wait_backoff_max = WAIT_BEFORE_INITIAL_MOVE;
	struct dst_infos *dst_infos = (void *) bpf_map_lookup_elem(dt_map, flow_id->remote_addr);
	if (!dst_infos)
		return 1; // Listening connections

	// Inititialize to 1 EXP3 weight and probabilities
	new_flow.exp3_last_probability.mantissa = LARGEST_BIT;
	new_flow.exp3_last_probability.exponent = BIAS;
	floating tmp;
	int i;
	for (i = 0; i <= MAX_SRH_BY_DEST - 1; i++) {
		bpf_to_floating(1, 0, 1, &tmp, sizeof(floating));
		exp3_weight_set(&new_flow, i, tmp);
	}

	// Insert flow to map
	return bpf_map_update_elem(c_map, flow_id, &new_flow, BPF_ANY);
}

SEC("sockops")
int handle_sockop(struct bpf_sock_ops *skops)
{
	struct dst_infos *dst_infos;
	struct flow_infos *flow_info;
	struct flow_tuple flow_id;

	int op;
	int rv = 0;
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
		if (create_new_flow_infos(&dest_map, &conn_map, &flow_id, cur_time, skops)) {
			return 1;
		}
		flow_info = (void *) bpf_map_lookup_elem(&conn_map, &flow_id);
		if (flow_info) {
			dst_infos = (void *) bpf_map_lookup_elem(&dest_map, flow_id.remote_addr);
			if (dst_infos) {
				// Call EXP3
				flow_info->srh_id = exp3_next_path(&dest_map, flow_info, flow_id.remote_addr, 0);
				move_path(dst_infos, flow_info->srh_id, skops);
				flow_info->exp3_start_snd_nxt = skops->snd_nxt;
				update_flow_timers(flow_info, dst_infos);

				if (flow_info->srh_id >= 0 && flow_info->srh_id <= MAX_SRH_BY_DEST - 1)
					flow_info->exp3_curr_reward = dst_infos->srhs[flow_info->srh_id].curr_bw;

				rv = bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
				if (rv)
					return 1;

				take_snapshot(&stat_map, flow_info, &flow_id);

				bpf_sock_ops_cb_flags_set(skops, (BPF_SOCK_OPS_RETRANS_CB_FLAG|BPF_SOCK_OPS_RTO_CB_FLAG|BPF_SOCK_OPS_RTT_CB_FLAG));
				skops->reply = rv;
				return 0;
			}
		}
		return 1;
	}

	//bpf_debug("segs_out: %lu packets: %lu interval: %lu\n", skops->segs_out, skops->rate_delivered, skops->rate_interval_us);
	//bpf_debug("snd_una: %lu rate : %lu interval: %lu\n", skops->snd_una, skops->rate_delivered, skops->rate_interval_us);
	switch (op) {
		case BPF_SOCK_OPS_STATE_CB: // Change in the state of the TCP CONNECTION
			// This flow is closed, cleanup the maps
			if (skops->args[1] == BPF_TCP_CLOSE) {
				// Remove the bw this flow occupied
				/*dst_infos = (void *)bpf_map_lookup_elem(&dest_map, flow_id.remote_addr);
				if (dst_infos && flow_info->srh_id >= 0 && flow_info->srh_id < MAX_SRH_BY_DEST) {
					srh_record = &dst_infos->srhs[flow_info->srh_id];
					//srh_record->curr_bw = srh_record->curr_bw - flow_info->last_reported_bw;  // TODO Problem if no more bandwidth and we took that out of despair
					bpf_map_update_elem(&dest_map, flow_id.remote_addr, dst_infos, BPF_ANY);
				}*/
				// Delete the flow from the flows map
				take_snapshot(&stat_map, flow_info, &flow_id);
				bpf_map_delete_elem(&conn_map, &flow_id);
			}
			break;
		/*case BPF_SOCK_OPS_RWND_INIT:
		case BPF_SOCK_OPS_TIMEOUT_INIT:
			return 0;*/
		/*case BPF_SOCK_OPS_TCP_XMIT:
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
			break;*/
		/*case BPF_SOCK_OPS_UDP_XMIT:
			break;*/
		/*case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
			//bpf_debug("Active established !!!\n");*/
		/*case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
			//bpf_debug("Una initial: %lu\n", skops->snd_una);
			//bpf_debug("Passive or active established !!!\n");
			flow_info->sample_start_time = cur_time;
			flow_info->sample_start_bytes = skops->snd_una;
			bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
			break;*/
		case BPF_SOCK_OPS_TCP_CONNECT_CB:
			//bpf_sock_ops_cb_flags_set(skops, BPF_SOCK_OPS_STATE_CB_FLAG); // TCP State change
			//bpf_sock_ops_cb_flags_set(skops, (BPF_SOCK_OPS_RETRANS_CB_FLAG|BPF_SOCK_OPS_RTO_CB_FLAG|BPF_SOCK_OPS_RTT_CB_FLAG));
			/*dst_infos = (void *)bpf_map_lookup_elem(&dest_map, flow_id.remote_addr);
			if (dst_infos && flow_info->srh_id >= 0 && flow_info->srh_id < MAX_SRH_BY_DEST) {
				srh_record = &dst_infos->srhs[flow_info->srh_id];
				rv = bpf_setsockopt(skops, SOL_IPV6, IPV6_RTHDR,
						&srh_record->srh, sizeof(srh_buf));
				//bpf_debug("CONNECT - setsockopt return value %d\n", rv);
			}*/
			break;
		case BPF_SOCK_OPS_RTT_CB:
			// This RTT count is useful to determine the congestion level
			flow_info->rtt_count += 1;
			rv = bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
			if (rv)
				return 1;
			break;
		/*case BPF_SOCK_OPS_ECN_ECE:
			//bpf_debug("ECN received\n");
			break;*/
		case BPF_SOCK_OPS_ECN_CE:
			//bpf_debug("Congestion experienced %lu %lu\n", flow_info->rtt_count, flow_info->last_ecn_rtt);
			if (flow_info->rtt_count > flow_info->last_ecn_rtt + 100) {
				flow_info->ecn_count = 0;
			} else {
				//bpf_debug("Consecutive congestion experienced\n");
			}
			flow_info->last_ecn_rtt = flow_info->rtt_count;

			__u32 ecount = flow_info->ecn_count;
			flow_info->ecn_count = ecount + 1;

			// We already moved less than X seconds ago... do nothing
			if (flow_info->ecn_count < 3 || (cur_time - flow_info->last_move_time) < flow_info->wait_before_move) {
				rv = bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
				if (rv)
					return 1;
				break;
			}
			flow_info->ecn_count = 0;

			flow_info->exp3_curr_reward = (skops->snd_nxt - flow_info->exp3_start_snd_nxt) / 1000000; // MB
			// It should be at least 1 otherwise, it raises issues
			flow_info->exp3_curr_reward = (flow_info->exp3_curr_reward / ((__u32) ((cur_time - flow_info->last_move_time) / 1000000000L))) + 1; // MB/s
			//bpf_debug("time diff %u in ms\n", ((__u32) ((cur_time - flow_info->last_move_time) / 1000000L)));
			__u32 key = exp3_next_path(&dest_map, flow_info, flow_id.remote_addr, USE_EXP3); // XXX Uniform EXP3 with 0 because it means that reward never computed
			take_snapshot(&stat_map, flow_info, &flow_id); // Even if it doesn't change, we want to know

			// This can't be helped
			if (key == flow_info->srh_id)
				break;
			//bpf_debug("Congestion experienced 3 - Changing in progress\n");

			// Get the infos for the current path and remove our bw
			dst_infos = (void *)bpf_map_lookup_elem(&dest_map, flow_id.remote_addr);
			if (dst_infos) {
				//bpf_debug("Congestion experienced 4 - dst_infos found!\n");

				// Then move to the next path
				rv = move_path(dst_infos, key, skops);
				if (!rv) {
					// Update flow informations
					flow_info->srh_id = key;
					flow_info->last_move_time = cur_time;
					bpf_debug("%u - %u\n", (skops->snd_nxt - flow_info->exp3_start_snd_nxt) / 1000000, ((__u32) ((cur_time - flow_info->last_move_time) / 1000000000L)));
					flow_info->exp3_start_snd_nxt = skops->snd_nxt;

					update_flow_timers(flow_info, dst_infos);
					bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
					//bpf_debug("Congestion experienced 6 - src %u.%u - Changing to %u\n",
					//          flow_id.local_addr[0], flow_id.local_addr[1], key);
					//bpf_debug("Congestion experienced 7 - after updating flow info\n");
				}
				//bpf_debug("Congestion experienced 8 - Change finished !\n");
			}
			break;
		/*case BPF_SOCK_OPS_NEEDS_ECN:
			//bpf_debug("Need ECN called\n");
			return 1;*/

		/*case BPF_SOCK_OPS_RTO_CB:
			bpf_debug("Restrans called\n");

			ecount = flow_info->ecn_count;
			if (ecount < 3)
				flow_info->ecn_count = ecount + 1;

			// We already moved less than X seconds ago... do nothing
			if (flow_info->ecn_count < 3 || (cur_time - flow_info->last_move_time) < flow_info->wait_before_move)
			// TODO Remove if ((cur_time - flow_info->last_move_time) < 3000000000)
				break;

			//bpf_debug("Congestion experienced - Try to change from %u\n", flow_info->srh_id);
			key = get_better_dest_path(&dest_map, flow_info, 0, flow_id.remote_addr);

			// This can't be helped
			if (key == flow_info->srh_id)
				break;
			//bpf_debug("Congestion experienced 3 - Changing in progress\n");

			// Get the infos for the current path and remove our bw
			dst_infos = (void *)bpf_map_lookup_elem(&dest_map, flow_id.remote_addr);
			if (dst_infos) {
				//bpf_debug("Congestion experienced 4 - dst_infos found!\n");

				// Then move to the next path
				rv = move_path(dst_infos, key, skops);
				if (!rv) {
					// Update flow informations
					flow_info->srh_id = key;
					flow_info->last_move_time = cur_time;
					flow_info->first_loss_time = 0;
					flow_info->number_of_loss = 0;

					update_flow_timers(flow_info, dst_infos);
					bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
					bpf_debug("Congestion experienced RTO - src %u.%u - Changing to %u\n",
					          flow_id.local_addr[0], flow_id.local_addr[1], key);
					//bpf_debug("Congestion experienced 7 - after updating flow info\n");
				}
				//bpf_debug("Congestion experienced 8 - Change finished !\n");
			}
			break;*/
	}
	skops->reply = rv;

	return 0;
}

char _license[] SEC("license") = "GPL";
