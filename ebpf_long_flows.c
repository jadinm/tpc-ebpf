/* 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#define KBUILD_MODNAME "EBPF LONG FLOWS"
#include <asm/byteorder.h>
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "kernel.h"
#include "ebpf_long_flows.h"


static int move_path(struct bpf_elf_map *dst_map, void *id, __u32 key, struct bpf_sock_ops *skops)
{
	int rv = 1;
	char cc[20];
	struct dst_infos *dst_infos = (void *) bpf_map_lookup_elem(dst_map, id);
	if (dst_infos) {
		struct ip6_srh_t *srh = NULL;
		// Check needed to avoid verifier complaining about unbounded access
		// The check needs to be placed very near the actual line
		if (key >= 0 && key < MAX_SRH_BY_DEST) {
			srh = &(dst_infos->srhs[key].srh);
			rv = bpf_setsockopt(skops, SOL_IPV6, IPV6_RTHDR, srh, sizeof(*srh));
		}

		if (!rv) {
			// Reset congestion control
			rv = bpf_getsockopt(skops, SOL_TCP, TCP_CONGESTION, cc, sizeof(cc));
			if (!rv) {
				rv = bpf_setsockopt(skops, SOL_TCP, TCP_CONGESTION, cc, sizeof(cc));
			}
		}
	}
	return !!rv;
}

static int create_new_flow_infos(struct bpf_elf_map *dt_map, struct bpf_elf_map *c_map, struct flow_tuple *flow_id, __u64 cur_time, struct bpf_sock_ops *skops) {
	struct flow_infos *flow_info;
	struct flow_infos new_flow;
	int rv = 0;
	memset(&new_flow, 0, sizeof(struct flow_infos));

	//bpf_debug("flow not found, adding it\n");
	new_flow.exp3_last_number_actions = 1;
	// Timers
	new_flow.last_move_time = cur_time;
	struct dst_infos *dst_infos = (void *) bpf_map_lookup_elem(dt_map, flow_id->remote_addr);
	if (!dst_infos)
		return 1; // Listening connections

	// Inititialize to 1 EXP3 weight and probabilities
	int i;
	floating tmp;
	bpf_to_floating(1, 0, 1, &tmp, sizeof(floating));
	for (i = 0; i <= MAX_SRH_BY_DEST - 1; i++) {
		exp3_weight_set(&new_flow, i, tmp);
	}
	new_flow.exp3_last_probability.mantissa = tmp.mantissa;
	new_flow.exp3_last_probability.exponent = tmp.exponent;

	// Insert flow to map
	return bpf_map_update_elem(c_map, flow_id, &new_flow, BPF_ANY);
}

static int is_compliant(struct bpf_sock_ops *skops, struct flow_infos *flow_info)
{
	__u32 pacing_bw = 0;
	int rv = bpf_getsockopt(skops, SOL_SOCKET, SO_MAX_PACING_RATE, &pacing_bw, sizeof(__u32));
	pacing_bw = (__u32) ((((__u64) pacing_bw) * ((__u64) 8)) / ((__u64) 1000000)); // Mbps
	// Rate computation from tcp_compute_delivery_rate() because skops->rate_delivered is in [pkts / sample interval in seconds]
	// We don't multiply by 10**6 because the time frame is in µs and there are 10**6 µs in one second
	flow_info->exp3_curr_reward = (__u32) (((__u64) skops->rate_delivered) * ((__u64) skops->mss_cache) * ((__u64) 8)) / ((__u64) skops->rate_interval_us); // Mbps
	// bpf_debug("%u (curr_bw Mbps) - %u (pacing_rate Mbps)\n", flow_info->exp3_curr_reward, pacing_bw);
	return flow_info->exp3_curr_reward * 9 / 8 >= pacing_bw;
}

SEC("sockops")
int handle_sockop(struct bpf_sock_ops *skops)
{
	struct flow_infos *flow_info;
	struct flow_tuple flow_id;

	int rv = 0;
	__u64 cur_time;

	cur_time = bpf_ktime_get_ns();

	/* Only execute the prog for scp */
	if (skops->family != AF_INET6) {
		skops->reply = -1;
		return 0;
	}
	get_flow_id_from_sock(&flow_id, skops);
	flow_info = (void *)bpf_map_lookup_elem(&conn_map, &flow_id);
	if (!flow_info) {
		// TODO Problem if listening connections => no destination defined !!!
		// TODO Also does not work on SYN+ACK request socks
		if (create_new_flow_infos(&dest_map, &conn_map, &flow_id, cur_time, skops)) {
			return 1;
		}
		flow_info = (void *) bpf_map_lookup_elem(&conn_map, &flow_id);
		if (flow_info) {
			// Call EXP3
			flow_info->srh_id = exp3_next_path(&dest_map, flow_info, flow_id.remote_addr, 0);
			move_path(&dest_map, flow_id.remote_addr, flow_info->srh_id, skops);
			rv = bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
			if (rv)
				return 1;

			take_snapshot(&stat_map, flow_info, &flow_id);

			bpf_sock_ops_cb_flags_set(skops, (BPF_SOCK_OPS_RETRANS_CB_FLAG|BPF_SOCK_OPS_RTO_CB_FLAG|BPF_SOCK_OPS_RTT_CB_FLAG|BPF_SOCK_OPS_STATE_CB_FLAG));
			skops->reply = rv;
			return 0;
		}
		return 1;
	}

	switch ((int) skops->op) {
		case BPF_SOCK_OPS_STATE_CB: // Change in the state of the TCP CONNECTION
			// This flow is closed, cleanup the maps
			if (skops->args[1] == BPF_TCP_CLOSE) {
				// Delete the flow from the flows map
				// take_snapshot(&stat_map, flow_info, &flow_id);
				bpf_map_delete_elem(&conn_map, &flow_id);
			}
			break;
		case BPF_SOCK_OPS_TCP_CONNECT_CB:
			break;
		case BPF_SOCK_OPS_RTT_CB:
			// This RTT count is useful to determine the congestion level
			flow_info->rtt_count += 1;

			/* Check flow requirement (pacing rate vs actual rate) */
			if (is_compliant(skops, flow_info)) {
				// Flow respecting requirement
				flow_info->unstable = 0;
				flow_info->last_unstable_rtt = flow_info->rtt_count;
				rv = bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
				break;
			}

			if (flow_info->last_move_time + WAIT_BEFORE_INITIAL_MOVE > cur_time) {
				// Still warming up on this path
				rv = bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
				break;
			}
			if (!flow_info->unstable) {
				// Mark as unstable
				bpf_debug("Mark unstable\n");
				flow_info->unstable = 1;
				flow_info->last_unstable_rtt = flow_info->rtt_count;
				rv = bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
				break;
			}
			if (flow_info->last_unstable_rtt + WAIT_UNSTABLE_RTT > flow_info->rtt_count) {
				// Not unstable for long enough
				bpf_debug("Not unstable long enough\n");
				rv = bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
				break;
			}
			// Acting on instability
			bpf_debug("Sufficient unstability\n");
			flow_info->unstable = 0;

			__u32 key = exp3_next_path(&dest_map, flow_info, flow_id.remote_addr, USE_EXP3); // XXX Uniform EXP3 with 0 because it means that reward never computed
			take_snapshot(&stat_map, flow_info, &flow_id); // Even if it doesn't change, we want to know

			if (key == flow_info->srh_id) {
				// This can't be helped
				rv = bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
				break;
			}

			// Move to the next path
			rv = move_path(&dest_map, flow_id.remote_addr, key, skops);
			if (!rv) {
				// Update flow informations
				flow_info->srh_id = key;
				flow_info->last_move_time = cur_time;
			}
			rv = bpf_map_update_elem(&conn_map, &flow_id, flow_info, BPF_ANY);
			break;
	}
	skops->reply = rv;

	return 0;
}

char _license[] SEC("license") = "GPL";
