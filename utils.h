/* Defining constant values */

#define IPPROTO_TCP 6 /* TCP protocol in HDR */
#define AF_INET6 10 /* IPv6 HDR */
#define SOL_IPV6 41 /* IPv6 Sockopt */
#define IPV6_RTHDR 57 /* SRv6 Option for sockopt */
#define ETH_HLEN 14 /* Ethernet hdr length */
#define DEBUG 1
#define PIN_NONE		0
#define PIN_GLOBAL_NS		2


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

/* Only use this for debug output. Notice output from bpf_trace_printk()
 *  * end-up in /sys/kernel/debug/tracing/trace_pipe
 *   */
#define bpf_debug(fmt, ...)						\
			({						\
			char ____fmt[] = fmt;				\
			bpf_trace_printk(____fmt, sizeof(____fmt),	\
			##__VA_ARGS__);					\
			})

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

	struct ip6_addr_t segments[0];
} __attribute__((packed));
/*
struct fab_flow_tuple {
	__u32 family;
	__be32 local_addr[4];
	__be32 remote_addr[4];
	__be16 local_port;
	__be16 remote_port;	
};*/

struct fab_test_key {
	__u32 family;
	__u32 local_addr[4];
	__u32 remote_addr[4];
	__u32 local_port;
	__u32 remote_port;	
	/*__u32 a;
	__be32 b;
	__be16 c;
	__be16 d;
	__be32 e[4];
	__be32 f[4];*/
};
struct flow_infos {
	__u32 srh_id;
	__u32 last_retransmit;
	__u32 curr_threshold;
};

struct bpf_elf_map {
	__u32 type;
	__u32 size_key;
	__u32 size_value;
	__u32 max_elem;
	__u32 flags;
	__u32 id;
	__u32 pinning;
};

struct bpf_elf_map SEC("maps") srh_map = {
	.type		= BPF_MAP_TYPE_ARRAY,
	.size_key	= sizeof(uint32_t),
	.size_value	= 72,
	.pinning	= PIN_NONE,
	.max_elem	= 3,
};

struct bpf_elf_map SEC("maps") conn_map = {
	.type		= BPF_MAP_TYPE_HASH,
	/*.size_key	= sizeof(struct bpf_sock_tuple),*/
	.size_key	= sizeof(struct fab_test_key),
	.size_value	= sizeof(struct flow_infos),
	.pinning	= PIN_NONE,
	.max_elem	= 3,
};
