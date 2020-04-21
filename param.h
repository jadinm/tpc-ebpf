#ifndef BPF_PARAM_H
#define BPF_PARAM_H

/* For parameter parsing in the evaluation script, please don't use block comments */

// Exp3 GAMMA
// GAMMA 0.1
#define GAMMA(x) bpf_to_floating(0, 1, 1, &x, sizeof(floating)) // 0.1
#define GAMMA_REV(x) bpf_to_floating(10, 0, 1, &x, sizeof(floating)) // 1/0.1 = 10
#define ONE_MINUS_GAMMA(x) bpf_to_floating(0, 9, 1, &x, sizeof(floating)) // 1 - 0.1 = 0.9

// GAMMA 0.5
//#define GAMMA(x) bpf_to_floating(0, 5, 1, &x, sizeof(floating)) // 0.5
//#define GAMMA_REV(x) bpf_to_floating(2, 0, 1, &x, sizeof(floating)) // 1/0.5 = 2
//#define ONE_MINUS_GAMMA(x) bpf_to_floating(0, 5, 1, &x, sizeof(floating)) // 1 - 0.5 = 0.5

// GAMMA 0.9
//#define GAMMA(x) bpf_to_floating(0, 9, 1, &x, sizeof(floating)) // 0.9
//#define GAMMA_REV(x) bpf_to_floating(1, 111111, 6, &x, sizeof(floating)) // 1/0.9 = 1.11...
//#define ONE_MINUS_GAMMA(x) bpf_to_floating(0, 1, 1, &x, sizeof(floating)) // 1 - 0.9 = 0.1

#define USE_EXP3 1

//#define MAX_REWARD_FACTOR 1
#define MAX_REWARD_FACTOR 10
//#define MAX_REWARD_FACTOR 100

// 10 msec
#define WAIT_BEFORE_INITIAL_MOVE 10000000
// 100 msec
//#define WAIT_BEFORE_INITIAL_MOVE 100000000
// 1 sec
//#define WAIT_BEFORE_INITIAL_MOVE 1000000000


#endif