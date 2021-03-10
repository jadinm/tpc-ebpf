#ifndef EBPF_LONG_FLOWS_H
#define EBPF_LONG_FLOWS_H

#include "utils.h"

#define MIN_WEIGHT(x) bpf_to_floating(0, 25, 2, x, sizeof(floating))
#define MIN_WEIGHT_EXP BIAS - 2 // 0.25
#define MAX_WEIGHT(x) bpf_to_floating(64, 0, 1, x, sizeof(floating))
#define MAX_WEIGHT_EXP BIAS + 6 // 64

#define MIN_DOUBLE_EXP BIAS - 200 // 64
#define MIN_DOUBLE(x) x.mantissa = LARGEST_BIT; \
					  x.exponent = MIN_DOUBLE_EXP;

struct flow_infos {
	__u32 srh_id;
	__u64 rtt_count; // Count the number of RTT in the connection, this is useful to know if congestion signals are consecutive or not
	__u32 ecn_count; // Count the number of consecutive CWR sent (either from ECN or other causes)
	__u64 last_ecn_rtt; // The index of the last RTT were we sent an CWR
	__u8 negative_loss;
	__u32 exp4_curr_loss;
	__u64 established_timestamp;
	__u64 rtt_timestamp;
	floating exp4_last_probability; // Probability of the current action
	__u32 same_path_selected;
	floating exp4_last_expectation_stability; // Expectation value of the current action for expert always advising not changing
	floating exp4_last_expectation_change; // Expectation value of the current action for expert always advising changing paths
} __attribute__((packed));

struct dst_infos {
	struct ip6_addr_t dest;
	__u32 max_reward;
	struct srh_record_t srhs[MAX_SRH_BY_DEST];
	floating exp4_weight[MAX_EXPERTS];
	__u32 last_srh_id;
} __attribute__((packed));

struct flow_snapshot {
	__u32 sequence; // 0 if never used -> we change the lowest sequence id
	__u64 time;
	__u32 srh_id;
	__s32 reward;
	struct ip6_addr_t dest;
	floating exp4_weight[MAX_EXPERTS];
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

struct snapshot_arg {
	struct flow_snapshot *new_snapshot;
	__u64 oldest_seq;
	__u32 best_idx;
	__u32 max_seq;
	__u32 setup;
};

static void take_snapshot(struct bpf_elf_map *st_map, struct dst_infos *dst_info, struct flow_infos *flow_info)
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
		memcpy(&arg.new_snapshot->dest, &dst_info->dest, sizeof(struct ip6_addr_t));
		memcpy(arg.new_snapshot->exp4_weight, dst_info->exp4_weight, sizeof(dst_info->exp4_weight));
		arg.new_snapshot->sequence = arg.max_seq + 1;
		arg.new_snapshot->time = bpf_ktime_get_ns();
		arg.new_snapshot->srh_id = flow_info->srh_id;
		if (flow_info->negative_loss)
			arg.new_snapshot->reward = (__s32) flow_info->exp4_curr_loss;
		else
			arg.new_snapshot->reward = -1 * ((__s32) flow_info->exp4_curr_loss);

		bpf_debug("HERE-SNAPSHOT-DEST (size %d) 0x%llx exp 0x%x\n", sizeof(dst_info->exp4_weight), dst_info->exp4_weight[MAX_SRH_BY_DEST].mantissa, dst_info->exp4_weight[MAX_SRH_BY_DEST].exponent); // TODO Remove
		bpf_debug("HERE-SNAPSHOT (size %d) 0x%llx exp 0x%x\n", sizeof(floating) * MAX_EXPERTS, arg.new_snapshot->exp4_weight[MAX_SRH_BY_DEST].mantissa, arg.new_snapshot->exp4_weight[MAX_SRH_BY_DEST].exponent); // TODO Remove
		bpf_map_update_elem(st_map, &arg.best_idx, arg.new_snapshot, BPF_ANY);
	} else {
		bpf_debug("HERE STAT FAIL\n");
	}
}

static inline void update_weight(struct flow_infos *flow_info, struct dst_infos *dst_infos, floating factor, __u32 idx)
{
	floating operands[2];
	floating one;
	floating float_tmp;
	__u32 decimal[2];
	ONE(one);

	// Invert factor_path_expert if loss is positive because negative exponent == invert the result
	if (!flow_info->negative_loss) {
		bpf_debug("HERE POSITIVE LOSS\n"); // TODO Remove
		set_floating(operands[0], one);
		set_floating(operands[1], factor);
		bpf_floating_divide(operands, sizeof(floating) * 2, &float_tmp, sizeof(floating)); // loss should not explode
		set_floating(factor, float_tmp);
	}
	bpf_floating_to_u32s(&factor, sizeof(floating), (__u64 *) decimal, sizeof(decimal)); // TODO Remove
	bpf_debug("HERE-factor 1bis %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove
	bpf_debug("HERE-factor-x 1bis 0x%llx exp 0x%x\n", factor.mantissa, factor.exponent); // TODO Remove

	if (idx >= 0 && idx <= MAX_EXPERTS - 1) { // Always true but this is for eBPF loader
		exp4_weight_get(dst_infos, idx, float_tmp);
		bpf_floating_to_u32s(&float_tmp, sizeof(floating), (__u64 *) decimal, sizeof(decimal)); // TODO Remove
		bpf_debug("HERE-old-weight %u %llu.%llu\n", idx, decimal[0], decimal[1]); // TODO Remove
		bpf_debug("HERE-old-weight-x %u 0x%llx exp 0x%x\n", idx, float_tmp.mantissa, float_tmp.exponent); // TODO Remove
		set_floating(operands[0], float_tmp);
		set_floating(operands[1], factor);
		bpf_floating_multiply(operands, sizeof(floating) * 2, &float_tmp, sizeof(floating));
		bpf_debug("HERE-new-weight %u %llu %u\n", idx, float_tmp.mantissa, float_tmp.exponent); // TODO Remove
		bpf_floating_to_u32s(&float_tmp, sizeof(floating), (__u64 *) decimal, sizeof(decimal)); // TODO Remove
		bpf_debug("HERE-new-weight %u %llu.%llu\n", idx, decimal[0], decimal[1]); // TODO Remove
		bpf_debug("HERE-new-weight-x %u 0x%llx exp 0x%x\n", idx, float_tmp.mantissa, float_tmp.exponent); // TODO Remove

		// We bound the weight between [0.25, 64] to prevent explosion
		/*if (float_tmp.exponent < MIN_WEIGHT_EXP) {
			MIN_WEIGHT(&float_tmp);
		} else if (float_tmp.exponent >= MAX_WEIGHT_EXP) {
			MAX_WEIGHT(&float_tmp);
		}*/
		bpf_floating_to_u32s(&float_tmp, sizeof(floating), (__u64 *) decimal, sizeof(decimal)); // TODO Remove
		bpf_debug("HERE-new-weight (after bounds) %u %llu.%llu\n", idx, decimal[0], decimal[1]); // TODO Remove
		bpf_debug("HERE-new-weight-x (after bounds) %u 0x%llx exp 0x%x\n", idx, float_tmp.mantissa, float_tmp.exponent); // TODO Remove

		exp4_weight_set(dst_infos, idx, float_tmp);
	}
}

static void exp4_loss_path(struct flow_infos *flow_info, struct dst_infos *dst_infos, struct bpf_sock_ops *skops)
{
	/*
		For the path that was chosen:
		g_t,i(path) = expert_opinion_t,i(path) * loss(path) / last_probability
		for each i in experts:
			w_t+1,i = w_t,i * exp(-ETA * g_t,i)
	*/
	floating operands[2];
	floating float_tmp;
	__u32 decimal[2];

	floating loss;
	floating max_loss;
	floating factor_path_expert;
	//floating factor_random_expert;
	floating factor_stability_expert;
	floating factor_unstability_expert;

	// loss(path)

	// Completion time
	// flow_info->exp4_curr_loss = (__u32) ((flow_info->rtt_timestamp - flow_info->established_timestamp) / ((__u64) 1000000));

	// RTT (in ms)
	#define MIN_RTT 35
	flow_info->negative_loss = ((skops->srtt_us >> 3) / 1000) < MIN_RTT;
	if (!flow_info->negative_loss)
		flow_info->exp4_curr_loss = ((skops->srtt_us >> 3) / 1000) - MIN_RTT;
	else
		flow_info->exp4_curr_loss = MIN_RTT - ((skops->srtt_us >> 3) / 1000);

	// We bound the max loss/reward between [-0.5, 0.5] to prevent weight explosion
	if (flow_info->exp4_curr_loss > MIN_RTT / 2) {
		flow_info->exp4_curr_loss = MIN_RTT / 2;
	}

	bpf_debug("HERE 0 loss %u (negative ? %d) for path %u\n", flow_info->exp4_curr_loss, flow_info->negative_loss, flow_info->srh_id); // TODO Remove
	bpf_to_floating((__u32) flow_info->exp4_curr_loss, 0, 1, &loss, sizeof(floating));
	bpf_to_floating(MIN_RTT, 0, 1, &max_loss, sizeof(floating));

	set_floating(operands[0], loss);
	set_floating(operands[1], max_loss);
	bpf_floating_divide(operands, sizeof(floating) * 2, &loss, sizeof(floating)); // loss should not explode

	// loss(path) / last_probability (== directly the exponent for this path expert that has a 100% chance of choosing this path)
	bpf_floating_to_u32s(&flow_info->exp4_last_probability, sizeof(floating), (__u64 *) decimal, sizeof(decimal)); // TODO Remove
	bpf_debug("HERE 0bis last_probability %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove
	bpf_debug("HERE 0bis last_probability-x mant 0x%llx exp 0x%x\n", flow_info->exp4_last_probability.mantissa, flow_info->exp4_last_probability.exponent); // TODO Remove

	set_floating(operands[0], loss);
	set_floating(operands[1], flow_info->exp4_last_probability);
	bpf_floating_divide(operands, sizeof(floating) * 2, &loss, sizeof(floating)); // loss should not explode

	// Compute and set path expert weight
	bpf_floating_to_u32s(&loss, sizeof(floating), (__u64 *) decimal, sizeof(decimal)); // TODO Remove
	bpf_debug("HERE 0bis loss %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove
	bpf_debug("HERE 0bis loss-x mant 0x%llx exp 0x%x\n", loss.mantissa, loss.exponent); // TODO Remove
	bpf_floating_e_power_a(&loss, sizeof(floating), &factor_path_expert, sizeof(floating));

	update_weight(flow_info, dst_infos, factor_path_expert, flow_info->srh_id);

	// Compute and set random expert weight

	/*set_floating(operands[0], loss);
	exp4_weight_get(dst_infos, MAX_SRH_BY_DEST, operands[1]);
	bpf_floating_multiply(operands, sizeof(floating) * 2, &float_tmp, sizeof(floating));
	bpf_floating_e_power_a(&float_tmp, sizeof(floating), &factor_random_expert, sizeof(floating));

	update_weight(flow_info, dst_infos, factor_random_expert, MAX_SRH_BY_DEST);*/

	// Compute and set stability expert weight

	if (flow_info->same_path_selected) {
		set_floating(operands[0], loss);
		exp4_weight_get(dst_infos, MAX_SRH_BY_DEST, operands[1]);
		bpf_floating_multiply(operands, sizeof(floating) * 2, &float_tmp, sizeof(floating));
		bpf_floating_e_power_a(&float_tmp, sizeof(floating), &factor_stability_expert, sizeof(floating));

		update_weight(flow_info, dst_infos, factor_stability_expert, MAX_SRH_BY_DEST);
	} else {
		// Compute and set unstability expert weight

		set_floating(operands[0], loss);
		exp4_weight_get(dst_infos, MAX_SRH_BY_DEST + 1, operands[1]);
		bpf_floating_multiply(operands, sizeof(floating) * 2, &float_tmp, sizeof(floating));
		bpf_floating_e_power_a(&float_tmp, sizeof(floating), &factor_unstability_expert, sizeof(floating));

		update_weight(flow_info, dst_infos, factor_unstability_expert, MAX_SRH_BY_DEST + 1);
	}

	// Divide all weights by a big constant value
	struct srh_record_t *srh_record = NULL;
	MIN_DOUBLE(operands[0]);
	for (__u32 i = 0; i <= MAX_EXPERTS - 1; i++) {
		int xxx = i; // Compiler cannot unroll otherwise
		if (i <= MAX_SRH_BY_DEST - 1) {
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
		} // else an expert not depending on a particular path

		exp4_weight_get(dst_infos, xxx, operands[1]);
		//bpf_debug("HERE %llu %u\n", operands[1].mantissa, operands[1].exponent); // TODO Remove
		//bpf_floating_to_u32s(&operands[1], sizeof(floating), (__u64 *) decimal, sizeof(decimal)); // TODO Remove
		//bpf_debug("HERE-2 %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove
		bpf_floating_multiply(operands, sizeof(floating) * 2, &float_tmp, sizeof(floating));
		exp4_weight_set(dst_infos, xxx, float_tmp);
	}
}

static __u32 exp4_next_path(struct bpf_elf_map *dt_map, struct flow_infos *flow_info, __u32 *dst_addr)
{
	/*
		theSum = float(sum(weights))
		distrib = {}
		for path in paths:
			distrib[path] = 0.0
			for i, expert in enumerate(experts):
				distrib[path] += (weights[i] / theSum) * expectation(expert, path)
			distrib[path] = (1 - gamma) * distrib[path] + gamma / nbr_paths

		return weighted_random_choice(distrib)
	*/
	floating operands[2];
	floating gamma;
	GAMMA(gamma);
	floating one_minus_gamma;
	ONE_MINUS_GAMMA(one_minus_gamma);

	__u32 decimal[2];
	decimal[0] = 0;
	decimal[1] = 0;

	__u32 chosen_id = 0, current_delay = 0;
	struct srh_record_t *srh_record = NULL;
	struct dst_infos *dst_infos = NULL;

	dst_infos = (void *) bpf_map_lookup_elem(dt_map, dst_addr);
	if (!dst_infos) {
		//bpf_debug("Cannot find the destination entry => Cannot find another SRH\n");
		return chosen_id;
	}

	// Compute the sum of weights
	floating sum;
	bpf_to_floating(0, 0, 1, &sum, sizeof(floating));
	__u32 nbr_valid_paths = 0;
	#pragma clang loop unroll(full)
	for (__u32 i = 0; i <= MAX_EXPERTS - 1; i++) {
		int xxx = i; // Compiler cannot unroll otherwise
		if (i <= MAX_SRH_BY_DEST - 1) {
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
			nbr_valid_paths += 1;
		} // else an expert not depending on a particular path

		set_floating(operands[0], sum);
		exp4_weight_get(dst_infos, xxx, operands[1]);
		//bpf_debug("HERE %llu %u\n", operands[1].mantissa, operands[1].exponent); // TODO Remove
		//bpf_floating_to_u32s(&operands[1], sizeof(floating), (__u64 *) decimal, sizeof(decimal)); // TODO Remove
		//bpf_debug("HERE-2 %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove
		bpf_floating_add(operands, sizeof(floating) * 2, &sum, sizeof(floating));
	}
	bpf_debug("Valid paths %u\n", nbr_valid_paths); // TODO Remove
	bpf_debug("HERE-sum sum-x mant 0x%llx exp 0x%x\n", sum.mantissa, sum.exponent); // TODO Remove

	// Compute the probabilities

	floating valid_paths;
	bpf_to_floating(nbr_valid_paths, 0, 1, &valid_paths, sizeof(floating));
	floating valid_paths_minus_one;
	bpf_to_floating(nbr_valid_paths - 1, 0, 1, &valid_paths_minus_one, sizeof(floating));

	// Produce gamma exploration probability
	floating exploration_probability;
	set_floating(operands[0], gamma);
	set_floating(operands[1], valid_paths);
	bpf_floating_divide(operands, sizeof(floating) * 2, &exploration_probability, sizeof(floating));
	bpf_floating_to_u32s(&exploration_probability, sizeof(floating), (__u64 *) decimal, sizeof(decimal));
	bpf_debug("HERE-exploration_probability %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove

	// Produce stable probability (to be applied if same path)
	floating stable_probability;
	exp4_weight_get(dst_infos, MAX_SRH_BY_DEST, stable_probability);

	// Produce unstable probability (to be applied if not the same path)
	floating unstable_probability;
	exp4_weight_get(dst_infos, MAX_SRH_BY_DEST + 1, operands[0]);
	set_floating(operands[1], valid_paths_minus_one);
	bpf_floating_divide(operands, sizeof(floating) * 2, &unstable_probability, sizeof(floating));

	__u64 pick = ((__u64) bpf_get_prandom_u32()) % FLOAT_MULT; // No problem if FLOAT_MULT < UIN32T_MAX
	__u64 accumulator = 0;

	floating probability;
	__u8 found = 0;
	bpf_debug("HERE-pick %llu\n", pick); // TODO Remove
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
			continue; // Not a valid SRH for the destination
		}
		// Take the expert always suggesting this path at 100%
		exp4_weight_get(dst_infos, yyy, probability);

		// and add the random expert
		/*set_floating(operands[1], random_probability);
		bpf_floating_add(operands, sizeof(floating) * 2, &probability, sizeof(floating));
		bpf_debug("HERE-probability 0 last_probability-x mant 0x%llx exp 0x%x\n", probability.mantissa, probability.exponent); // TODO Remove
		*/

		if (yyy != (int) dst_infos->last_srh_id) { // Add the unstable expert probability 
			set_floating(operands[0], probability);
			set_floating(operands[1], unstable_probability);
			bpf_floating_add(operands, sizeof(floating) * 2, &probability, sizeof(floating));
			bpf_debug("HERE-probability 1 last_probability-x mant 0x%llx exp 0x%x\n", probability.mantissa, probability.exponent); // TODO Remove
			bpf_floating_to_u32s(&probability, sizeof(floating), (__u64 *) decimal, sizeof(decimal));
			bpf_debug("HERE-probability 1 %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove
		} else { // Add the stable expert probability
			set_floating(operands[0], probability);
			set_floating(operands[1], stable_probability);
			bpf_floating_add(operands, sizeof(floating) * 2, &probability, sizeof(floating));
			bpf_debug("HERE-probability 2 last_probability-x mant 0x%llx exp 0x%x\n", probability.mantissa, probability.exponent); // TODO Remove
			bpf_floating_to_u32s(&probability, sizeof(floating), (__u64 *) decimal, sizeof(decimal));
			bpf_debug("HERE-probability 2 %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove
		}

		// Divide by the sum of weights
		set_floating(operands[0], probability);
		set_floating(operands[1], sum);
		bpf_floating_divide(operands, sizeof(floating) * 2, &probability, sizeof(floating));
		bpf_debug("HERE-probability 3 last_probability-x mant 0x%llx exp 0x%x\n", probability.mantissa, probability.exponent); // TODO Remove
		bpf_floating_to_u32s(&probability, sizeof(floating), (__u64 *) decimal, sizeof(decimal));
		bpf_debug("HERE-probability 3 %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove

		// Multiply by 1-gamma
		set_floating(operands[0], probability);
		set_floating(operands[1], one_minus_gamma);
		bpf_floating_multiply(operands, sizeof(floating) * 2, &probability, sizeof(floating));
		bpf_debug("HERE-probability 4 last_probability-x mant 0x%llx exp 0x%x\n", probability.mantissa, probability.exponent); // TODO Remove
		bpf_floating_to_u32s(&probability, sizeof(floating), (__u64 *) decimal, sizeof(decimal));
		bpf_debug("HERE-probability 4 %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove

		// Add gamma exploration
		set_floating(operands[0], probability);
		set_floating(operands[1], exploration_probability);
		bpf_floating_add(operands, sizeof(floating) * 2, &probability, sizeof(floating));
		bpf_debug("HERE-probability 5 last_probability-x mant 0x%llx exp 0x%x\n", probability.mantissa, probability.exponent); // TODO Remove
		bpf_floating_to_u32s(&probability, sizeof(floating), (__u64 *) decimal, sizeof(decimal));
		bpf_debug("HERE-probability 5 %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove

		// Pick the path or continue
		bpf_floating_to_u32s(&probability, sizeof(floating), (__u64 *) decimal, sizeof(decimal));
		accumulator += decimal[1]; // No need to take the integer part since these are numbers in [0, 1[
		bpf_debug("HERE-probability %u last_probability-x mant 0x%llx exp 0x%x\n", i, flow_info->exp4_last_probability.mantissa, flow_info->exp4_last_probability.exponent); // TODO Remove
		bpf_debug("HERE-probability %u acc %llu vs %llu\n", i, accumulator, decimal[1]); // TODO Remove
		if (pick < accumulator) {
			// We found the chosen one
			chosen_id = i;
			found = 1;
			set_floating(flow_info->exp4_last_probability, probability);
			bpf_debug("HERE-probability %llu.%llu\n", decimal[0], decimal[1]); // TODO Remove
			bpf_debug("HERE-probability last_probability-x mant 0x%llx exp 0x%x\n", flow_info->exp4_last_probability.mantissa, flow_info->exp4_last_probability.exponent); // TODO Remove
			break;
		}
	}
	if (!found) {
		bpf_debug("NOOOOOOOOOOOOOOOOT FOUNNNNNDDDDDD\n"); // TODO Remove
	}

	if (chosen_id == dst_infos->last_srh_id)
		flow_info->same_path_selected = 1;

	return chosen_id;
}

struct bpf_elf_map SEC("maps") short_conn_map = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(struct flow_tuple),
	.size_value	= sizeof(struct flow_infos),
	.pinning	= PIN_NONE,
	.max_elem	= MAX_FLOWS,
};

struct bpf_elf_map SEC("maps") short_dest_map = {
	.type		= BPF_MAP_TYPE_HASH,
	.size_key	= sizeof(unsigned long long),  // XXX Only looks at the most significant 64 bits of the address
	.size_value	= sizeof(struct dst_infos),
	.pinning	= PIN_NONE,
	.max_elem	= MAX_FLOWS,
};

struct bpf_elf_map SEC("maps") short_stat_map = {
	.type		= BPF_MAP_TYPE_ARRAY,
	.size_key	= sizeof(__u32),
	.size_value	= sizeof(struct flow_snapshot),
	.pinning	= PIN_NONE,
	.max_elem	= MAX_SNAPSHOTS,
};

#endif
