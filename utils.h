#ifndef EBPF_UTILS_H
#define EBPF_UTILS_H

#include "bpf_helpers.h"
#include "floating_point.h"

/* Defining constant values */

#define IPPROTO_TCP 	6 /* TCP protocol in HDR */
#define AF_INET6 		10 /* IPv6 HDR */
#define SOL_IPV6 		41 /* IPv6 Sockopt */
#define SOL_SOCKET		1 /* Socket Sockopt */
#define SO_MAX_PACING_RATE	47 /* Max pacing rate for setsockopt */
#define IPV6_RTHDR 		57 /* SRv6 Option for sockopt */
#define ETH_HLEN 		14 /* Ethernet hdr length */
// #define DEBUG 			1
#define PIN_NONE		0
#define PIN_GLOBAL_NS	2
#define MAX_SRH			50
#define MAX_FLOWS		1024
#define MAX_SRH_BY_DEST 4
#define MAX_SEGS_NBR	4

#define WAIT_BEFORE_INITIAL_MOVE 1000000000 // 1 sec
#define WAIT_BACKOFF 2 // Multiply by two the waiting time whenever a path change is made

// Exp3 GAMMA
#define GAMMA(x) bpf_to_floating(0, 5, 1, &x, sizeof(floating)) // 0.5
#define GAMMA_REV(x) bpf_to_floating(2, 0, 1, &x, sizeof(floating)) // 1/0.5 = 2
#define ONE_MINUS_GAMMA(x) bpf_to_floating(0, 5, 1, &x, sizeof(floating)) // 1 - 0.5 = 0.5

// Stats
#define MAX_SNAPSHOTS 100 // The max number fo snapshot to keep

/* eBPF definitions */
#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif

#ifndef __inline
# define __inline                         \
   inline __attribute__((always_inline))
#endif

#define SEC(NAME) __attribute__((section(NAME), used))

#define DEBUG
#ifdef  DEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 *  * end-up in /sys/kernel/debug/tracing/trace_pipe
 *   */
#define bpf_debug(fmt, ...)						\
			({						\
			char ____fmt[] = fmt;				\
			bpf_trace_printk(____fmt, sizeof(____fmt),	\
			##__VA_ARGS__);					\
			})
#else
#define bpf_debug(fmt, ...) { } while (0);
#endif

#define htonll(x) ((bpf_htonl(1)) == 1 ? (x) : ((uint64_t)bpf_htonl((x) & \
				0xFFFFFFFF) << 32) | bpf_htonl((x) >> 32))
#define ntohll(x) ((bpf_ntohl(1)) == 1 ? (x) : ((uint64_t)bpf_ntohl((x) & \
				0xFFFFFFFF) << 32) | bpf_ntohl((x) >> 32))

/* IPv6 address */
struct ip6_addr_t {
	unsigned long long hi;
	unsigned long long lo;
} __attribute__((packed));

/* SRH definition */
struct ip6_srh_t {
	unsigned char nexthdr;
	unsigned char hdrlen;
	unsigned char type;
	unsigned char segments_left;
	unsigned char first_segment;
	unsigned char flags;
	unsigned short tag;

	struct ip6_addr_t segments[MAX_SEGS_NBR];
} __attribute__((packed));

struct srh_record_t {
	__u32 srh_id;
	__u32 is_valid;
	__u64 curr_bw; // Mbps
	__u64 delay; // ms
	struct ip6_srh_t srh;
} __attribute__((packed));

struct flow_tuple {
	__u32 family;
	__u32 local_addr[4];
	__u32 remote_addr[4];
	__u32 local_port;
	__u32 remote_port;	
} __attribute__((packed));

struct flow_infos {
	__u32 srh_id;
	__u32 last_reported_bw;
	__u64 sample_start_time;
	__u32 sample_start_bytes;
	__u64 last_move_time;
	__u64 wait_backoff_max; // current max wating time
	__u64 wait_before_move; // current waiting time
	__u64 first_loss_time;
	__u32 number_of_loss;
	__u64 rtt_count; // Count the number of RTT in the connection, this is useful to know if congestion signals are consecutive or not
	__u32 ecn_count; // Count the number of consecutive CWR sent (either from ECN or other causes)
	__u64 last_ecn_rtt; // The index of the last RTT were we sent an CWR
	__u32 exp3_last_number_actions;
	__u32 exp3_curr_reward;
	floating exp3_last_probability;
	floating exp3_weight_0; // Current weight for each path
	floating exp3_weight_1; // Current weight for each path
	floating exp3_weight_2; // Current weight for each path
	floating exp3_weight_3; // Current weight for each path
} __attribute__((packed));

struct flow_snapshot {
	__u32 sequence; // 0 if never used -> we change the lowest sequence id
	__u64 time;
	struct flow_tuple flow_id;
	struct flow_infos flow;
} __attribute__((packed));

#define exp3_weight_set(flow_infos, idx, value) \
	if (idx == 0) {\
		(flow_infos)->exp3_weight_0.mantissa = (value).mantissa; \
		(flow_infos)->exp3_weight_0.exponent = (value).exponent; \
	} else if (idx == 1) { \
		(flow_infos)->exp3_weight_1.mantissa = (value).mantissa; \
		(flow_infos)->exp3_weight_1.exponent = (value).exponent; \
	} else if (idx == 2) { \
		(flow_infos)->exp3_weight_2.mantissa = (value).mantissa; \
		(flow_infos)->exp3_weight_2.exponent = (value).exponent; \
	} else { \
		(flow_infos)->exp3_weight_3.mantissa = (value).mantissa; \
		(flow_infos)->exp3_weight_3.exponent = (value).exponent; \
	}

#define exp3_weight_get(flow_infos, idx, value) \
	if (idx == 0) { \
		(value).mantissa = (flow_infos)->exp3_weight_0.mantissa; \
		(value).exponent = (flow_infos)->exp3_weight_0.exponent; \
	} else if (idx == 1) { \
		(value).mantissa = (flow_infos)->exp3_weight_1.mantissa; \
		(value).exponent = (flow_infos)->exp3_weight_1.exponent; \
	} else if (idx == 2) { \
		(value).mantissa = (flow_infos)->exp3_weight_2.mantissa; \
		(value).exponent = (flow_infos)->exp3_weight_2.exponent; \
	} else { \
		(value).mantissa = (flow_infos)->exp3_weight_3.mantissa; \
		(value).exponent = (flow_infos)->exp3_weight_3.exponent; \
	}

struct dst_infos {
	struct ip6_addr_t dest;
	__u32 max_reward;
	struct srh_record_t srhs[MAX_SRH_BY_DEST];
} __attribute__((packed));

struct bpf_elf_map {
	__u32 type;
	__u32 size_key;
	__u32 size_value;
	__u32 max_elem;
	__u32 flags;
	__u32 id;
	__u32 pinning;
} __attribute__((packed));

static void get_flow_id_from_sock(struct flow_tuple *flow_id, struct bpf_sock_ops *skops)
{
	flow_id->family = skops->family;
	flow_id->local_addr[0] = skops->local_ip6[0];
	flow_id->local_addr[1] = skops->local_ip6[1];
	flow_id->local_addr[2] = skops->local_ip6[2];
	flow_id->local_addr[3] = skops->local_ip6[3];
	flow_id->remote_addr[0] = skops->remote_ip6[0];
	flow_id->remote_addr[1] = skops->remote_ip6[1];
	flow_id->remote_addr[2] = skops->remote_ip6[2];
	flow_id->remote_addr[3] = skops->remote_ip6[3];
	flow_id->local_port =  skops->local_port;
	flow_id->remote_port = bpf_ntohl(skops->remote_port);
}

struct snapshot_arg {
	struct flow_snapshot *new_snapshot;
	__u64 oldest_seq;
	__u32 best_idx;
	__u32 max_seq;
	__u32 setup;
};

static void take_snapshot(struct bpf_elf_map *st_map, struct flow_infos *flow_info, struct flow_tuple *flow_id)
{
	struct flow_snapshot *curr_snapshot = NULL;
	struct snapshot_arg arg = {
		.new_snapshot = NULL,
		.oldest_seq = 0,
		.best_idx = 0,
		.max_seq = 0
	};

	curr_snapshot = (void *) bpf_map_lookup_elem(st_map, &arg.best_idx);
	if (curr_snapshot) {
		arg.new_snapshot = curr_snapshot;
		arg.oldest_seq = curr_snapshot->sequence;
		arg.max_seq = curr_snapshot->sequence;
	}

	//#pragma clang loop unroll(full)
	for (int i = 0; i <= MAX_SNAPSHOTS - 1; i++) {
		int xxx = i;
		curr_snapshot = (void *) bpf_map_lookup_elem(st_map, &xxx);
		if (curr_snapshot) {
			if (arg.max_seq < curr_snapshot->sequence) {
				arg.max_seq = curr_snapshot->sequence;
			}
			if (arg.oldest_seq > curr_snapshot->sequence) {
				arg.oldest_seq = curr_snapshot->sequence;
				arg.new_snapshot = curr_snapshot;
				arg.best_idx = xxx;
			}
		}
	}
	if (arg.new_snapshot) {
		memcpy(&arg.new_snapshot->flow, flow_info, sizeof(struct flow_infos));
		memcpy(&arg.new_snapshot->flow_id, flow_id, sizeof(struct flow_tuple));
		arg.new_snapshot->sequence = arg.max_seq + 1;
		arg.new_snapshot->time = bpf_ktime_get_ns();
		bpf_map_update_elem(st_map, &arg.best_idx, arg.new_snapshot, BPF_ANY);
	}
}

static __always_inline void exp3_reward_path(struct flow_infos *flow_info, struct dst_infos *dst_infos)
{
	/*
	theReward = reward(choice, t)
	weights[choice] *= math.exp(theReward / (probabilityDistribution[choice] * gamma_rev * numActions)) # important that we use estimated reward here!
	*/
	floating gamma_rev;
	floating reward;
	floating scaled_reward; // should be in [0, 1]
	floating exponent_den_factor;
	floating exponent_den;
	floating nbr_actions;
	floating exponent;
	floating weight_factor;
	floating float_tmp, float_tmp2;
	floating operands[2];

	floating max_reward;
	bpf_to_floating(dst_infos->max_reward + 1, 0, 1, &max_reward, sizeof(floating));

	GAMMA_REV(gamma_rev);

	// TODO Compute new reward !!!!
	bpf_to_floating(flow_info->exp3_curr_reward, 0, 1, &reward, sizeof(floating));
	bpf_to_floating(flow_info->exp3_last_number_actions, 1, 0, &nbr_actions, sizeof(floating));

	set_floating(operands[0], flow_info->exp3_last_probability);
	set_floating(operands[1], gamma_rev);
	bpf_floating_multiply(operands, sizeof(floating) * 2, &exponent_den_factor, sizeof(floating));

	set_floating(operands[0], exponent_den_factor);
	set_floating(operands[1], nbr_actions);
	bpf_floating_multiply(operands, sizeof(floating) * 2, &exponent_den, sizeof(floating));

	set_floating(operands[0], reward);
	set_floating(operands[1], max_reward);
	bpf_floating_divide(operands, sizeof(floating) * 2, &scaled_reward, sizeof(floating));

	set_floating(operands[0], scaled_reward);
	set_floating(operands[1], exponent_den);
	bpf_floating_divide(operands, sizeof(floating) * 2, &exponent, sizeof(floating));

	bpf_floating_e_power_a(&exponent, sizeof(floating), &weight_factor, sizeof(floating));
	//bpf_debug("OK AFTER EXP %d\n", (weight_factor.mantissa & LARGEST_BIT) != 0);
	// TODO Remove
	//flow_info->exp3_weight_mantissa_1 = weight_factor.mantissa;
	//flow_info->exp3_weight_exponent_1 = weight_factor.exponent;
	//weight_factor.mantissa = exponent.mantissa;
	//weight_factor.exponent = exponent.exponent;
	// TODO Remove

	__u32 idx = flow_info->srh_id;
	if (idx >= 0 && idx <= MAX_SRH_BY_DEST - 1) { // Always true but this is for eBPF loader
		exp3_weight_get(flow_info, idx, float_tmp);
		//bpf_debug("OK END 1 %d\n", (float_tmp.mantissa & LARGEST_BIT) != 0);
		set_floating(operands[0], float_tmp);
		set_floating(operands[1], weight_factor);
		bpf_floating_multiply(operands, sizeof(floating) * 2, &float_tmp2, sizeof(floating));
		exp3_weight_set(flow_info, idx, float_tmp2);
	}
}

static __u32 exp3_next_path(struct bpf_elf_map *dt_map, struct flow_infos *flow_info, __u32 *dst_addr, int reward_compute)
{
	/*
	def distr(weights, gamma=0.0):
		theSum = float(sum(weights))
		return tuple((1.0 - gamma) * (w / theSum) + (gamma / len(weights)) for w in weights)

	def exp3(numActions, reward, gamma):
		weights = [1.0] * numActions

		t = 0
		while True:
			probabilityDistribution = distr(weights, gamma)
			choice = draw(probabilityDistribution)
			theReward = reward(choice, t)

			estimatedReward = theReward / probabilityDistribution[choice]
			weights[choice] *= math.exp(estimatedReward * gamma / numActions) # important that we use estimated reward here!

			yield choice, theReward, estimatedReward, weights
			t = t + 1
	*/
	floating operands[2];
	floating gamma;
	GAMMA(gamma);

	__u32 chosen_id = 0, current_delay = 0;
	struct srh_record_t *srh_record = NULL;
	struct dst_infos *dst_infos = NULL;

	dst_infos = (void *) bpf_map_lookup_elem(dt_map, dst_addr);
	if (!dst_infos) {
		//bpf_debug("Cannot find the destination entry => Cannot find another SRH\n");
		return chosen_id;
	}

	// Compute the reward of the previous path
	if (reward_compute) {
		exp3_reward_path(flow_info, dst_infos);
	}

	// Compute the sum of weights
	floating sum;
	bpf_to_floating(0, 0, 1, &sum, sizeof(floating));
	__u32 nbr_valid_paths = 0;
	#pragma clang loop unroll(full)
	for (__u32 i = 0; i <= MAX_SRH_BY_DEST - 1; i++) {
		int xxx = i; // Compiler cannot unroll otherwise
		srh_record = &dst_infos->srhs[i];

		// Wrong SRH ID -> might be inconsistent state, so skip
		// Not a valid SRH for the destination
		// Same SRH
		if (!srh_record || !srh_record->srh.type) {  // 1
			//bpf_debug("Cannot find the SRH entry indexed at %d at a dest entry\n", i);
			continue;
		}

		if (!srh_record->is_valid) {  // 1
			//bpf_debug("SRH entry indexed at %d by the dest entry is invalid\n", i);
			continue; // Not a valid SRH for the destination
		}

		/* XXX Check with Schapira
		if (!flow_info || srh_record->srh_id == flow_info->srh_id) {  // 1
			continue;
		}*/

		set_floating(operands[0], sum);
		exp3_weight_get(flow_info, xxx, operands[1]);
		bpf_floating_add(operands, sizeof(floating) * 2, &sum, sizeof(floating));
		nbr_valid_paths += 1;
	}

	// Compute the probabilities
	floating probability;
	floating one_minus_gamma;
	ONE_MINUS_GAMMA(one_minus_gamma);
	floating weight_times_gama;
	floating term1;
	floating valid_paths;
	bpf_to_floating(nbr_valid_paths, 0, 1, &valid_paths, sizeof(floating));
	floating term2;

	set_floating(operands[0], gamma);
	set_floating(operands[1], valid_paths);
	bpf_floating_divide(operands, sizeof(floating) * 2, &term2, sizeof(floating));

	__u64 pick = ((__u64) bpf_get_prandom_u32()) % FLOAT_MULT; // No problem if FLOAT_MULT < UIN32T_MAX
	__u64 accumulator = 0;
	__u32 decimal[2];
	decimal[0] = 0;
	decimal[1] = 0;

	#pragma clang loop unroll(full)
	for (__u32 i = 0; i <= MAX_SRH_BY_DEST - 1; i++) {
		int yyy = i; // Compiler cannot unroll otherwise
		srh_record = &dst_infos->srhs[i];

		// Wrong SRH ID -> might be inconsistent state, so skip
		// Not a valid SRH for the destination
		// Same SRH
		if (!srh_record || !srh_record->srh.type) {  // 2
			//bpf_debug("Cannot find the SRH entry indexed at %d at a dest entry\n", i);
			continue;
		}

		if (!srh_record->is_valid) {  // 2
			//bpf_debug("SRH entry indexed at %d by the dest entry is invalid\n", i);
			continue; // Not a valid SRH for the destination
		}

		/* XXX Check with Schapira
		if (!flow_info || srh_record->srh_id == flow_info->srh_id) {  // 2
			continue;
		}
		*/

		// prob[i] = (1.0 - gamma) * (w[i] / theSum) + (gamma / len(weights))
		set_floating(operands[0], one_minus_gamma);
		exp3_weight_get(flow_info, yyy, operands[1]);
		bpf_floating_multiply(operands, sizeof(floating) * 2, &weight_times_gama, sizeof(floating));

		set_floating(operands[0], weight_times_gama);
		set_floating(operands[1], sum);
		bpf_floating_divide(operands, sizeof(floating) * 2, &term1, sizeof(floating));

		set_floating(operands[0], term1);
		set_floating(operands[1], term2);
		bpf_floating_add(operands, sizeof(floating) * 2, &probability, sizeof(floating));

		bpf_floating_to_u32s(&probability, sizeof(floating), (__u64 *) decimal, sizeof(decimal));
		accumulator += decimal[1]; // No need to take the integer part since these are numbers in [0, 1[
		if (pick < accumulator) {
			// We found the chosen one
			chosen_id = i;
			set_floating(flow_info->exp3_last_probability, probability);
			//bpf_debug("prob mantissa %llu - exp %u\n", probability.mantissa, probability.exponent);
			bpf_debug("%u - %u\n", pick, decimal[1]);
			break;
		}
	}

	//exp3_weight_get(flow_info, 0, operands[0]); // TODO Remove
	//exp3_weight_get(flow_info, 1, operands[1]); // TODO Remove
	//bpf_debug("%llu - %u\n", operands[0].mantissa, operands[0].exponent); // TODO Remove
	//bpf_debug("%llu - %u\n", operands[1].mantissa, operands[1].exponent); // TODO Remove

	flow_info->exp3_last_number_actions = nbr_valid_paths;
	return chosen_id;
}

struct bpf_elf_map SEC("maps") conn_map = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct flow_tuple),
	.size_value	= sizeof(struct flow_infos),
	.pinning	= PIN_NONE,
	.max_elem	= MAX_FLOWS,
};

struct bpf_elf_map SEC("maps") dest_map = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(unsigned long long),  // XXX Only looks at the most significant 64 bits of the address
	.size_value	= sizeof(struct dst_infos),
	.pinning	= PIN_NONE,
	.max_elem	= MAX_FLOWS,
};

struct bpf_elf_map SEC("maps") stat_map = {
	.type		= BPF_MAP_TYPE_ARRAY,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(struct flow_snapshot),
	.pinning	= PIN_NONE,
	.max_elem	= MAX_SNAPSHOTS,
};

#endif
