/* 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */

#define KBUILD_MODNAME "EBPF SOCKS HHF"
#include <uapi/linux/bpf.h>
#include "bpf_helpers.h"

#define IPPROTO_TCP 6
#define AF_INET6 10
#define SOL_SOCKET 1
#define SO_SNDBUF 7

/* Only use this for debug output. Notice output from bpf_trace_printk()
 *  * end-up in /sys/kernel/debug/tracing/trace_pipe
 *   */
#define bpf_debug(fmt, ...)						\
			({							\
			char ____fmt[] = fmt;				\
			bpf_trace_printk(____fmt, sizeof(____fmt),	\
			##__VA_ARGS__);			\
			})

SEC("sockops")
int handle_sockop(struct bpf_sock_ops *skops)
{
	int op;
	int rv = 0;
	int bufsize = 150000;

	op = (int) skops->op;

	switch (op) {
		case BPF_SOCK_OPS_TCP_XMIT:
		case BPF_SOCK_OPS_UDP_XMIT:
			if (skops->family == AF_INET6) {
				bpf_debug("SOCK_OPS_XMIT: call received");
				rv = bpf_setsockopt(skops, SOL_SOCKET, SO_SNDBUF,
					&bufsize, sizeof(bufsize));
			}

	}
	skops->reply = rv;

	return 1;
}

char _license[] SEC("license") = "GPL";
