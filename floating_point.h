#ifndef FIXED_POINT_H
#define FIXED_POINT_H

#include <linux/swab.h>
#include "bpf_helpers.h"


struct floating_type {
	__u64 mantissa; // We use the full mantissa
	__u32 exponent; // We only use 11 bits for the exponent (as in a double)
} __attribute__((packed));

typedef struct floating_type floating;

#define BIAS 1024 /* == 2**10 - Above means positive exponent and below means negative one */
#define LARGEST_BIT ((__u64) 1U) << 63U
#define CONV_SCALE 1000000000 // For the division by two
#define EXP_LIMIT 3


/* At most power to 64 */
static __always_inline __u64 floating_u64_pow(__u64 base, __u32 exponent) {
	__u32 i;
	__u64 pow = 1;
	#pragma clang loop unroll(full)
	for (i = 1; i <= 64; i++) { // -1024 is the maximum for an exponent in double
        int xxx = i;
		if (xxx <= exponent)
			pow *= base;
	}
	return pow;
}

static __always_inline __u32 floating_decimal_to_binary(__u32 decimal, __u32 digits) {
	// Encode the decimal as a sum of negative powers of 2
	__u32 i = 1;
	__u64 shift = 0;
	__u64 scale = floating_u64_pow(10, digits);
	__u32 sol = 0;
	#pragma clang loop unroll(full)
	for (i = 1; i <= 32; i++) { // -1024 is the maximum for an exponent in double
        int j = i;
		sol = sol << 1U;
		shift = ((__u64) decimal) << 1U;
		decimal = decimal << 1U;
		if (scale <= shift) {
			sol = sol | 1U;
			decimal -= scale;
		}
	}
	return sol;
}

static __always_inline void floating_normalize(floating *number) {
	// Get the position of the first 1 in the binary of the mantissa
	// and change the exponent

	if (!number->mantissa) {
		number->exponent = BIAS;
		return;
	}

	__u32 i = 0;
    __u32 found = 0;
	#pragma clang loop unroll(full)
	for (i = 0; i <= 63; i++) { // XXX Does not unroll
        int xxx = i;
        if (!found && (number->mantissa & LARGEST_BIT) != 0) {
            found = 1;
        } else if (!found) {
            number->exponent = number->exponent - 1;
            number->mantissa = number->mantissa << 1U;
        }
	}
}

/**
 * Create a floating
 *
 * @param integer The integer part of the floating
 * @param decimal The decimal part of the floating
 * @param digits The number of digits before the comma
 *               (e.g., for 1.0005, you would give )
 * @return a new floating
 */
static __always_inline void to_floating(__u32 integer, __u32 decimal, __u32 digits, floating *result) {
    result->mantissa = (((__u64) integer) << 32U) | ((__u64) floating_decimal_to_binary(decimal, digits));
    result->exponent = BIAS + 31;
	// The first bit must be 1
	floating_normalize(result);
}

/**
 * Reverse of decimal_to_binary
 */
static __always_inline __u32 floating_binary_to_decimal(__u32 decimal) {
	__u32 i = 0;
	__u32 sol = 0;
	__u32 curr_bit = 0;
	#pragma clang loop unroll(full)
	for (i = 0; i <= 31; i++) { // XXX Does not unroll
        int j = i;
		curr_bit = (decimal & (1U << i)) >> i;
		decimal = decimal & ~(1U << i); // Clear the bit
		sol = sol + curr_bit * ((__u32) CONV_SCALE);
		sol /= 2;
	}
	return sol;
}

static __always_inline __u32 floating_to_u32s(floating number, __u32 *integer, __u32 *decimal) {
	*integer = 0;
	__u32 shift = 0;
	__u32 decimal_shift = 0;

	if (number.exponent >= BIAS) { // There is an integer part
		shift = number.exponent + 1 - BIAS;
	} else {
		decimal_shift = BIAS - number.exponent - 1;
	}
	if (shift) { // Shifting mantissa more than 63 times would perform a wrapping
		*integer = (__u32) (number.mantissa >> (64 - shift));
	}
	//bpf_printk("integer %u - mantissa %llx - shift %u\n", *integer, number.mantissa, shift);

	*decimal = (__u32) ((number.mantissa << shift) >> (decimal_shift + 32U));
	*decimal = floating_binary_to_decimal(*decimal);
	return 9;
}

static void floating_add(floating a, floating b, floating *result) {

	floating first;
	floating second;
	if (a.exponent > b.exponent) {
		first.mantissa = a.mantissa;
		first.exponent = a.exponent;
		second.mantissa = b.mantissa;
		second.exponent = b.exponent;
	} else {
		first.mantissa = b.mantissa;
		first.exponent = b.exponent;
		second.mantissa = a.mantissa;
		second.exponent = a.exponent;
	}

	if (first.exponent - second.exponent + 1 < 64)
		second.mantissa = second.mantissa >> (first.exponent - second.exponent + 1);
	else
		second.mantissa = 0;
	first.mantissa = first.mantissa >> 1U; // Just in case of overflow

	result->exponent = first.exponent + 1;
	result->mantissa = first.mantissa + second.mantissa;
	floating_normalize(result);
}

static void floating_multiply(floating a, floating b, floating *result) {
	result->mantissa = (a.mantissa >> 32U) * (b.mantissa >> 32U);
	result->exponent = a.exponent + b.exponent - BIAS + 1;
}

struct euclidian_arg {
	__u32 i;
	__u64 numerator;
	__u64 denominator;
	__u64 remainder[2];
	__u32 first_one;
};

static __u64 euclidian_division_inner(struct euclidian_arg *arg) {
	__u64 sol = 0;
	__u64 carry = 0;

	// R := R << 1
	arg->remainder[1] = arg->remainder[1] << 1U;
	if (arg->remainder[0] & LARGEST_BIT) {
		arg->remainder[1] += 1;
	}
	arg->remainder[0] = arg->remainder[0] << 1U;

	// R(0) := N(i)
	if (arg->i - 1 >= 64) {
		// numerator is limited to 64bits => no need to change remainder[1]
		arg->remainder[0] |= (arg->numerator & (((__u64) 1) << (arg->i - 1 - 64))) >> (arg->i - 1 - 64);
	}


	// if R ≥ D then
	// R := R − D
	if (arg->remainder[1]) {
		arg->remainder[1] -= 1;
		carry = ((~((__u64) 0)) - arg->denominator) + 1;
		arg->remainder[0] = arg->remainder[0] + carry;

		// Q(i) := 1
		if (!arg->first_one)
			arg->first_one = arg->i;
		sol |= (((__u64) 1) << ((63 + arg->i) - arg->first_one));
	} else if (arg->remainder[0] >= arg->denominator) {
		arg->remainder[0] = arg->remainder[0] - arg->denominator;

		// Q(i) := 1
		if (!arg->first_one)
			arg->first_one = arg->i;
		sol |= (((__u64) 1) << ((63 + arg->i) - arg->first_one));
	}

	return sol;
}

static __u64 euclidian_division(__u64 numerator, __u64 denominator) {
	/*
	if D = 0 then error(DivisionByZeroException) end
	Q := 0                  -- Initialize quotient and remainder to zero
	R := 0
	for i := n − 1 .. 0 do  -- Where n is number of bits in N
	  R := R << 1           -- Left-shift R by 1 bit
	  R(0) := N(i)          -- Set the least-significant bit of R equal to bit i of the numerator
	  if R ≥ D then
	    R := R − D
	    Q(i) := 1
	  end
	end
	 */

	__u64 sol = 0;
    __u32 iterator;
	struct euclidian_arg arg;
	arg.numerator = numerator;
	arg.denominator = denominator;
	arg.remainder[0] = 0;
	arg.remainder[1] = 0;
	arg.first_one = 0;
	//#pragma clang loop unroll(full)
	for (iterator = 0; iterator <= 127; iterator++) { // XXX Does not unroll
        int j = iterator;
        arg.i = 128 - j;
		if (!(arg.first_one && arg.first_one - arg.i - 1 >= 63)) {
			euclidian_division_inner(&arg);
		}
	}
	return sol;
}

static void floating_divide(floating numerator, floating denominator, floating *result) {
	if (numerator.mantissa != 0 && denominator.mantissa != 0) {
		result->mantissa = euclidian_division(numerator.mantissa, denominator.mantissa);
		result->exponent = (BIAS + numerator.exponent) - denominator.exponent - 1;
		if (numerator.mantissa > denominator.mantissa)
			result->exponent += 1;
		//bpf_printk("mantissa 0x%llx - num 0x%llx - den 0x%llx\n", result.mantissa, numerator.mantissa, denominator.mantissa);
		//bpf_printk("exponent %u - num %u - den %u\n", result.exponent, numerator.exponent, denominator.exponent);
		return;
	}
	result->mantissa = 0;
    result->exponent = BIAS;
}

//static __u64 euclidian_division_unroll(__u64 numerator, __u64 denominator) {
	/*
	if D = 0 then error(DivisionByZeroException) end
	Q := 0                  -- Initialize quotient and remainder to zero
	R := 0
	for i := n − 1 .. 0 do  -- Where n is number of bits in N
	  R := R << 1           -- Left-shift R by 1 bit
	  R(0) := N(i)          -- Set the least-significant bit of R equal to bit i of the numerator
	  if R ≥ D then
	    R := R − D
	    Q(i) := 1
	  end
	end
	 */

/*	__u64 sol = 0;
    __u32 iterator;
	struct euclidian_arg arg;
	arg.numerator = numerator;
	arg.denominator = denominator;
	arg.remainder[0] = 0;
	arg.remainder[1] = 0;
	arg.first_one = 0;
	#pragma clang loop unroll(full)
	for (iterator = 0; iterator <= 127; iterator++) { // XXX Does not unroll
        int j = iterator;
        arg.i = 128 - j;
		if (!(arg.first_one && arg.first_one - arg.i - 1 >= 63)) {
			euclidian_division_inner(&arg);
		}
	}
	return sol;
}

static void floating_divide_unroll(floating numerator, floating denominator, floating *result) {
	if (numerator.mantissa != 0 && denominator.mantissa != 0) {
		result->mantissa = euclidian_division_unroll(numerator.mantissa, denominator.mantissa);
		result->exponent = (BIAS + numerator.exponent) - denominator.exponent - 1;
		if (numerator.mantissa > denominator.mantissa)
			result->exponent += 1;
		//bpf_printk("mantissa 0x%llx - num 0x%llx - den 0x%llx\n", result.mantissa, numerator.mantissa, denominator.mantissa);
		//bpf_printk("exponent %u - num %u - den %u\n", result.exponent, numerator.exponent, denominator.exponent);
		return;
	}
	result->mantissa = 0;
    result->exponent = BIAS;
}*/

struct exp_args {
	__u32 i;
	floating a;
	floating sum_taylor;
	floating one;
};

static void float_e_power_a_inner(struct exp_args *arg) {
	floating it;
	floating div_result;
	floating prod_result;
	to_floating(arg->i, 0, 1, &it);
	floating_divide(arg->sum_taylor, it, &div_result);
	floating_multiply(div_result, arg->a, &prod_result);
	floating_add(prod_result, arg->one, &arg->sum_taylor);
}

static void float_e_power_a(floating a, floating *result) {
	/*
		uint64_t sum = 1.0;
		for (int i = MAX_ITERATIONS - 1; i > 0; --i)
		    sum = (1 + a * sum / i);

		return sum;
	 */
    __u32 tmp_i = 0;
	struct exp_args arg;
    to_floating(1, 0, 1, &arg.one);
	arg.a.mantissa = a.mantissa;
	arg.a.exponent = a.exponent;
	arg.sum_taylor.exponent = arg.one.exponent;
	arg.sum_taylor.mantissa = arg.one.mantissa;

	// TODO
	arg.i = 2;
	float_e_power_a_inner(&arg);
	arg.i = 1;
	float_e_power_a_inner(&arg);

	result->mantissa = arg.sum_taylor.mantissa;
	result->exponent = arg.sum_taylor.exponent;
}

/* Tests */
/*
static void floating_test_decimal_to_binary() {
	bpf_printk("[subconv] 0.1 == %u =?= 0x19999999\n", floating_decimal_to_binary(1, 1)); // 0x%08x outside eBPF
	bpf_printk("[subconv] 0.5 == %u =?= 0x80000000\n", floating_decimal_to_binary(5, 1));
	bpf_printk("[subconv] 0.7 == %u =?= 0xb3333333\n", floating_decimal_to_binary(7, 1));
	bpf_printk("[subconv] 0.05 == %u =?= 0x0ccccccc\n", floating_decimal_to_binary(5, 2));

	bpf_printk("[subconv] 0.1 == 0.%u\n", floating_binary_to_decimal(floating_decimal_to_binary(1, 1))); // 0.%09u outside eBPF
	bpf_printk("[subconv] 0.5 == 0.%u\n", floating_binary_to_decimal(floating_decimal_to_binary(5, 1)));
	bpf_printk("[subconv] 0.7 == 0.%u\n", floating_binary_to_decimal(floating_decimal_to_binary(7, 1)));
	bpf_printk("[subconv] 0.05 == 0.%u\n", floating_binary_to_decimal(floating_decimal_to_binary(5, 2)));
}

static void floating_test_to_floating() {
	floating float_1;
    to_floating(0, 1, 1, &float_1);
	bpf_printk("[conv] 0.1 == mantisse %llu - exponent %d\n", float_1.mantissa, float_1.exponent - BIAS); // 0x%llx outside eBPF
	__u32 integer_1 = 0;
	__u32 decimal_1 = 0;
	floating_to_u32s(float_1, &integer_1, &decimal_1);
	bpf_printk("[conv] 0.1 == %u.0*%u\n", integer_1, decimal_1);

	floating float_5;
    to_floating(5, 0, 1, &float_5);
	bpf_printk("[conv] 5 == mantisse %llu - exponent %d\n", float_5.mantissa, float_5.exponent - BIAS);
	__u32 integer_5 = 0;
	__u32 decimal_5 = 0;
	floating_to_u32s(float_5, &integer_5, &decimal_5);
	bpf_printk("[conv] 5 == %u.0*%u\n", integer_5, decimal_5);

	floating float_05;
    to_floating(0, 5, 1, &float_05);
	bpf_printk("[conv] 0.5 == mantisse %llu - exponent %d\n", float_05.mantissa, float_05.exponent - BIAS);
	__u32 integer_05 = 0;
	__u32 decimal_05 = 0;
	floating_to_u32s(float_05, &integer_05, &decimal_05);
	bpf_printk("[conv] 0.5 == %u.0*%u\n", integer_05, decimal_05);

	floating float_55;
    to_floating(5, 5, 1, &float_55);
	bpf_printk("[conv] 5.5 == mantisse %llu - exponent %d\n", float_55.mantissa, float_55.exponent - BIAS);
	__u32 integer_55 = 0;
	__u32 decimal_55 = 0;
	floating_to_u32s(float_55, &integer_55, &decimal_55);
	bpf_printk("[conv] 5.5 == %u.0*%u\n", integer_55, decimal_55);

	floating float_005;
    to_floating(0, 5, 2, &float_005);
	bpf_printk("[conv] 0.05 == mantisse %llu - exponent %d\n", float_005.mantissa, float_005.exponent - BIAS);
	__u32 integer_005 = 0;
	__u32 decimal_005 = 0;
	floating_to_u32s(float_005, &integer_005, &decimal_005);
	bpf_printk("[conv] 0.05 == %u.0*%u\n", integer_005, decimal_005);

	floating float_10;
    to_floating(10, 0, 1, &float_10);
	bpf_printk("[conv] 10.0 == mantisse %llu - exponent %d\n", float_10.mantissa, float_10.exponent - BIAS);
	__u32 integer_10 = 0;
	__u32 decimal_10 = 0;
	floating_to_u32s(float_10, &integer_10, &decimal_10);
	bpf_printk("[conv] 10.0 == %u.0*%u\n", integer_10, decimal_10);
}

static void floating_test_divide() {
	floating float_5;
    to_floating(5, 0, 1, &float_5);
	//bpf_printk("[div] 5 == mantisse 0x%llx - exponent %d\n", float_5.mantissa, float_5.exponent - BIAS);

	floating float_05;
    to_floating(0, 5, 1, &float_05);
	//bpf_printk("[div] 0.5 == mantisse 0x%llx - exponent %d\n", float_05.mantissa, float_05.exponent - BIAS);

	__u32 integer_div = 0;
	__u32 decimal_div = 0;
	floating div;

	floating_divide(float_05, float_5, &div);
	floating_to_u32s(div, &integer_div, &decimal_div);
	bpf_printk("[div] 0.5 / 5 == 0.1 == %u.%u\n", integer_div, decimal_div);

	floating_divide(float_5, float_05, &div);
	floating_to_u32s(div, &integer_div, &decimal_div);
	bpf_printk("[div] 5 / 0.5 == 10 == %u.%u\n", integer_div, decimal_div);
}

static void floating_test_multiply() {
	__u32 integer_mult = 0;
	__u32 decimal_mult = 0;

	floating float_5;
    to_floating(5, 0, 1, &float_5);
	//bpf_printk("[mult] 5 == mantisse 0x%llx - exponent %d\n", float_5.mantissa, float_5.exponent - BIAS);

	floating float_05;
    to_floating(0, 5, 1, &float_05);
	//bpf_printk("[mult] 0.5 == mantisse 0x%llx - exponent %d\n", float_05.mantissa, float_05.exponent - BIAS);

	floating mult;
    floating_multiply(float_5, float_05, &mult);
	floating_to_u32s(mult, &integer_mult, &decimal_mult);
	bpf_printk("[mult] 5 * 0.5 == 2.5 == %u.%u\n", integer_mult, decimal_mult);
}

static void floating_test_add() {
	__u32 integer_add = 0;
	__u32 decimal_add = 0;

	floating float_5;
    to_floating(5, 0, 1, &float_5);
	//bpf_printk("[add] 5 == mantisse 0x%llx - exponent %d\n", float_5.mantissa, float_5.exponent - BIAS);

	floating float_05;
    to_floating(0, 5, 1, &float_05);
	//bpf_printk("[add] 0.5 == mantisse 0x%llx - exponent %d\n", float_05.mantissa, float_05.exponent - BIAS);

	floating add;
	floating_add(float_5, float_05, &add);
	floating_to_u32s(add, &integer_add, &decimal_add);
	bpf_printk("[add] 5 + 0.5 == 5.5 == %u.%u\n", integer_add, decimal_add);

	floating_add(float_05, float_5, &add);
	floating_to_u32s(add, &integer_add, &decimal_add);
	bpf_printk("[add] 0.5 + 5 == 5.5 == %u.%u\n", integer_add, decimal_add);
}

static void floating_test_exp() {
	floating result;
	__u32 integer_exp = 0;
	__u32 decimal_exp = 0;

	floating float_5;
    to_floating(5, 0, 1, &float_5);
	//bpf_printk("[exp] 5 == mantisse 0x%llx - exponent %d\n", float_5.mantissa, float_5.exponent - BIAS);

	floating float_05;
    to_floating(0, 5, 1, &float_05);
	//bpf_printk("[exp] 0.5 == mantisse 0x%llx - exponent %d\n", float_05.mantissa, float_05.exponent - BIAS);

	float_e_power_a(float_5, &result);
	floating_to_u32s(result, &integer_exp, &decimal_exp);
	bpf_printk("[exp] e^5 == 148.413159102 == %u.%u\n", integer_exp, decimal_exp);

	float_e_power_a(float_05, &result);
	floating_to_u32s(result, &integer_exp, &decimal_exp);
	bpf_printk("[exp] e^0.5 == 1.648721270 == %u.%u\n", integer_exp, decimal_exp);
}

static int floating_test_all() {
    bpf_printk("[main] Before decimal to binary\n");
	floating_test_decimal_to_binary();
    bpf_printk("[main] Before to floating\n");
	floating_test_to_floating();
    bpf_printk("[main] Before divide\n");
	floating_test_divide();
    bpf_printk("[main] Before multiply\n");
	floating_test_multiply();
    bpf_printk("[main] Before add\n");
	floating_test_add();
    bpf_printk("[main] Before exp\n");
	floating_test_exp();
    bpf_printk("[main] All tests performed\n");
	return 0;
}

*/
#endif