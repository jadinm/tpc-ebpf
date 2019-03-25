/* 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#define KBUILD_MODNAME "EBPF HHF"
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

#define IPPROTO_TCP 6
#define AF_INET6 10

/* Only use this for debug output. Notice output from bpf_trace_printk()
 *  * end-up in /sys/kernel/debug/tracing/trace_pipe
 *   */
#define bpf_debug(fmt, ...)						\
			({							\
			char ____fmt[] = fmt;				\
			bpf_trace_printk(____fmt, sizeof(____fmt),	\
			##__VA_ARGS__);			\
			})

SEC("cgroup/sock")
int handle_egress(struct __sk_buff *skb)
{
	char fmt[] = "socket: family %d type %d protocol %d\n";
	struct bpf_sock *sk;

	sk = skb->sk;
	if (!sk)
		return 1;

	sk = bpf_sk_fullsock(sk);
	if (!sk)
		return 1;

	if (sk->family != AF_INET6 || sk->protocol != IPPROTO_TCP)
		return 1;

	bpf_debug("egress skb spotted\n");
	bpf_trace_printk(fmt, sizeof(fmt), sk->family, sk->type, sk->protocol);

	return 0;
}

char _license[] SEC("license") = "GPL";
