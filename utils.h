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

// Float constant multiplier to make float operations work with integer
#define FLOAT_MULT 1000000000

// Exp3 GAMMA
#define GAMMA(x) to_floating(0, 5, 1, &x) // 0.5
#define GAMMA_REV(x) to_floating(2, 0, 1, &x) // 2

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
	__u64 curr_bw; 
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
	__u64 exp3_weigth_mantissa_0; // Current weight for each path
	__u32 exp3_weigth_exponent_0;
	__u64 exp3_weigth_mantissa_1; // Current weight for each path
	__u32 exp3_weigth_exponent_1;
	__u64 exp3_weigth_mantissa_2; // Current weight for each path
	__u32 exp3_weigth_exponent_2;
	__u64 exp3_weigth_mantissa_3; // Current weight for each path
	__u32 exp3_weigth_exponent_3;
} __attribute__((packed));

#define exp3_weigth_mantissa_set(flow_infos, idx, value) \
	if (idx == 0) \
		flow_infos->exp3_weigth_mantissa_0 = value; \
	else if (idx == 1) \
		flow_infos->exp3_weigth_mantissa_1 = value; \
	else if (idx == 2) \
		flow_infos->exp3_weigth_mantissa_2 = value; \
	else \
		flow_infos->exp3_weigth_mantissa_3 = value;

#define exp3_weigth_exponent_set(flow_infos, idx, value) \
	if (idx == 0) \
		flow_infos->exp3_weigth_exponent_0 = value; \
	else if (idx == 1) \
		flow_infos->exp3_weigth_exponent_1 = value; \
	else if (idx == 2) \
		flow_infos->exp3_weigth_exponent_2 = value; \
	else \
		flow_infos->exp3_weigth_exponent_3 = value;

#define exp3_weigth_mantissa_get(flow_infos, idx, value) \
	if (idx == 0) \
		value = flow_infos->exp3_weigth_mantissa_0; \
	else if (idx == 1) \
		value = flow_infos->exp3_weigth_mantissa_1; \
	else if (idx == 2) \
		value = flow_infos->exp3_weigth_mantissa_2; \
	else \
		value = flow_infos->exp3_weigth_mantissa_3;

#define exp3_weigth_exponent_get(flow_infos, idx, value) \
	if (idx == 0) \
		value = flow_infos->exp3_weigth_exponent_0; \
	else if (idx == 1) \
		value = flow_infos->exp3_weigth_exponent_1; \
	else if (idx == 2) \
		value = flow_infos->exp3_weigth_exponent_2; \
	else \
		value = flow_infos->exp3_weigth_exponent_3;

struct dst_infos {
	struct ip6_addr_t dest;
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

static void get_flow_id_from_sock(struct flow_tuple *flow_id, struct bpf_sock_ops *skops) {
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

/*static __always_inline uint32_t get_best_dest_path(struct bpf_elf_map *dt_map, struct ip6_addr_t *dst_addr) {
	uint64_t lowest_delay = 0;
	uint32_t lowest_id = 0, current_delay = 0;
	struct srh_record_t *srh_record = NULL;
	unsigned int firsti = 1;
	struct dst_infos *dst_infos = NULL;


	dst_infos = (void *) bpf_map_lookup_elem(dt_map, dst_addr);
	if (!dst_infos) {
		//bpf_debug("Cannot find the destination entry => Cannot find another SRH\n");
		return lowest_id;
	}

	if (lowest_id >=0 && lowest_id < MAX_SRH_BY_DEST) {
		srh_record = &dst_infos->srhs[lowest_id];
		if (!srh_record) {
			//bpf_debug("Cannot find the SRH entry\n");
		} else {
			lowest_delay = srh_record->delay;
		}
	}

	//#pragma clang loop unroll(full)
	for (unsigned int i = firsti; i <= MAX_SRH_BY_DEST - 1; i++) {
		int j = i; // Compiler cannot unroll otherwise
		srh_record = &dst_infos->srhs[i];

		// Wrong SRH ID -> might be inconsistent state, so skip
		if (!srh_record || !srh_record->srh.type) {
			//bpf_debug("Cannot find the SRH entry indexed at %d at a dest entry\n", i);
			continue;
		}

		if (!srh_record->is_valid) {
			//bpf_debug("SRH entry indexed at %d by the dest entry is invalid\n", i);
			continue; // Not a valid SRH for the destination
		}

		current_delay = srh_record->delay;
		bpf_debug("current delay: %lu\n", current_delay);
		if (current_delay < lowest_delay) {
			lowest_delay = current_delay;
			lowest_id = i;
		}

	}
	return lowest_id;
}*/

/*static uint32_t get_better_dest_path(struct bpf_elf_map *dt_map, struct flow_infos *flow_info, int self_allowed, __u32 *dst_addr) {
	uint64_t lowest_delay = 0;
	uint32_t lowest_id = flow_info->srh_id, current_delay = 0;
	struct srh_record_t *srh_record = NULL;
	unsigned int firsti = 0;
	struct dst_infos *dst_infos = NULL;

	dst_infos = (void *) bpf_map_lookup_elem(dt_map, dst_addr);
	if (!dst_infos) {
		//bpf_debug("Cannot find the destination entry => Cannot find another SRH\n");
		return lowest_id;
	}

	if (lowest_id >=0 && lowest_id < MAX_SRH_BY_DEST) {
		srh_record = &dst_infos->srhs[lowest_id];
		if (!srh_record) {
			//bpf_debug("Cannot find the SRH entry\n");
		} else {
			lowest_delay = srh_record->delay;
		}
	}

	#pragma clang loop unroll(full)
	for (unsigned int i = firsti; i < MAX_SRH_BY_DEST; i++) {
		int j = i; // Compiler cannot unroll otherwise
		srh_record = &dst_infos->srhs[i];

		// Wrong SRH ID -> might be inconsistent state, so skip
		if (!srh_record || !srh_record->srh.type) {
			//bpf_debug("Cannot find the SRH entry indexed at %d at a dest entry\n", i);
			continue;
		}

		if (!srh_record->is_valid) {
			//bpf_debug("SRH entry indexed at %d by the dest entry is invalid\n", i);
			continue; // Not a valid SRH for the destination
		}

		if (!self_allowed && srh_record->srh_id == flow_info->srh_id)
			continue;

		current_delay = srh_record->delay;
		bpf_debug("current delay: %lu\n", current_delay);
		if (current_delay < lowest_delay || (!self_allowed && lowest_id == flow_info->srh_id)) {
			lowest_delay = current_delay;
			lowest_id = i;
		}

	}
	return lowest_id;
}*/

static __always_inline void exp3_reward_path(struct flow_infos *flow_info) {
	/*
	theReward = reward(choice, t)
	weights[choice] *= math.exp(theReward / (probabilityDistribution[choice] * gamma_rev * numActions)) # important that we use estimated reward here!
	*/
	floating gamma_rev;
	floating reward;
	floating exponent_den_factor;
	floating exponent_den;
	floating nbr_actions;
	floating exponent;
	floating weight_factor;
	floating float_tmp, float_tmp2;

	GAMMA_REV(gamma_rev);

	to_floating(flow_info->exp3_curr_reward, 0, 1, &reward); // TODO Compute reward
	to_floating(flow_info->exp3_last_number_actions, 1, 0, &nbr_actions);
	floating_multiply(flow_info->exp3_last_probability, gamma_rev, &exponent_den_factor);
	floating_multiply(exponent_den_factor, nbr_actions, &exponent_den);
	floating_divide(reward, exponent_den, &exponent);
	float_e_power_a(exponent, &weight_factor);
	// TODO Remove
	flow_info->exp3_weigth_mantissa_1 = weight_factor.mantissa;
	flow_info->exp3_weigth_exponent_1 = weight_factor.exponent;
	//weight_factor.mantissa = exponent.mantissa;
	//weight_factor.exponent = exponent.exponent;
	// TODO Remove

	__u32 idx = flow_info->srh_id;
	if (idx >= 0 && idx <= MAX_SRH_BY_DEST - 1) { // Always true but this is for eBPF loader
		exp3_weigth_mantissa_get(flow_info, idx, float_tmp.mantissa);
		exp3_weigth_exponent_get(flow_info, idx, float_tmp.exponent);
		floating_multiply(float_tmp, weight_factor, &float_tmp2);
		exp3_weigth_mantissa_set(flow_info, idx, float_tmp2.mantissa);
		exp3_weigth_exponent_set(flow_info, idx, float_tmp2.exponent);
	}
}

static __always_inline __u32 exp3_next_path(struct bpf_elf_map *dt_map, struct flow_infos *flow_info, __u32 *dst_addr) {
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
	floating gamma;
	GAMMA(gamma);

	__u32 chosen_id = 1, current_delay = 0;
	struct srh_record_t *srh_record = NULL;
	struct dst_infos *dst_infos = NULL;

	dst_infos = (void *) bpf_map_lookup_elem(dt_map, dst_addr);
	if (!dst_infos) {
		//bpf_debug("Cannot find the destination entry => Cannot find another SRH\n");
		return chosen_id;
	}

	// Compute the reward of the previous path
	exp3_reward_path(flow_info);

	// Compute the sum of weights
	/*floating sum;
	to_floating(0, 0, 1, &sum);
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

		if (!flow_info || srh_record->srh_id == flow_info->srh_id) {  // 1
			continue;
		}

		floating_add(sum, flow_info->exp3_weigths[xxx], &sum);
		nbr_valid_paths += 1;
	}*/

	// TODO Compute the probabilities
	/*floating probability;
	floating one;
	to_floating(1, 0, 1, &one);
	floating one_minus_gamma;
	floating_add(one, gamma, &one_minus_gamma);
	floating weight_times_gama;
	floating term1;
	floating valid_paths;
	to_floating(nbr_valid_paths, 0, 1, &valid_paths);
	floating term2;
	floating_divide(gamma, valid_paths, &term2);

	__u64 pick = ((__u64) bpf_get_prandom_u32()) % FLOAT_MULT; // No problem if FLOAT_MULT < UIN32T_MAX
	__u64 accumulator = 0;
	__u32 integer_part;
	__u32 decimal_part;

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

		if (!flow_info || srh_record->srh_id == flow_info->srh_id) {  // 2
			continue;
		}

		// prob[i] = (1.0 - gamma) * (w[i] / theSum) + (gamma / len(weights))
		floating_multiply(one_minus_gamma, flow_info->exp3_weigths[yyy], &term1); // TODO , &weight_times_gama);
		//floating_divide(weight_times_gama, sum, &term1); // TODO Instructions that makes everything overflow
		floating_add(term1, term2, &probability);
*/
		/*floating_to_u32s(probability, &integer_part, &decimal_part);
		accumulator += decimal_part; // No need to take the integer part since these are numbers in [0, 1[
		if (pick < accumulator) {
			// We found the chosen one
			chosen_id = i;
			flow_info->exp3_last_probability.mantissa = probability.mantissa;
			flow_info->exp3_last_probability.exponent = probability.exponent;
			break;
		}*/
	/*}

	flow_info->exp3_last_number_actions = nbr_valid_paths;*/
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

#endif
