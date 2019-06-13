/* 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#define KBUILD_MODNAME "EBPF HHF"
#include <asm/byteorder.h>
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "kernel.h"
#include "utils.h"

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

	bpf_debug("egress skb spotted dest: %x:%x\n",bpf_ntohl(skb->remote_ip6[0]), bpf_ntohl(skb->remote_ip6[3]));
	bpf_trace_printk(fmt, sizeof(fmt), sk->family, sk->type, sk->protocol);

	return 1;
}

char _license[] SEC("license") = "GPL";
