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


SEC("sockops")
int handle_sockop(struct bpf_sock_ops *skops)
{
	struct ip6_srh_t *srh;
	char srh_buf[72]; // room for 3 segment

	int op;
	int rv = 0;
	int bufsize = 150000;
	int key = 0;

	op = (int) skops->op;
	

	/* Only execute the prog for scp */
	if (skops->family != AF_INET6 || bpf_ntohl(skops->remote_port) != 22) {
		skops->reply = -1;
		return 0;
	}

	switch (op) {
		case BPF_SOCK_OPS_TCP_XMIT:
		case BPF_SOCK_OPS_UDP_XMIT:
			break;
		case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
			srh = (void *)bpf_map_lookup_elem(&srh_map, &key);
			if (srh)
				rv = bpf_setsockopt(skops, SOL_IPV6, IPV6_RTHDR,
						srh, sizeof(srh_buf)); 
			break;
		case BPF_SOCK_OPS_RETRANS_CB:
			key = ((key+1)%2);
			srh = (void *)bpf_map_lookup_elem(&srh_map, &key); 
			/*bpf_map_update_elem(&map, &key, srh, BPF_ANY); */
			if (srh)
				rv = bpf_setsockopt(skops, SOL_IPV6, IPV6_RTHDR,
						srh, sizeof(srh_buf)); 
			break;

	}
	skops->reply = rv;

	return 1;
}

char _license[] SEC("license") = "GPL";
