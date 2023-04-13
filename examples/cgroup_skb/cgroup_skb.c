//go:build ignore

#include "common.h"
#include <asm-generic/types.h>
#include <asm/bitsperlong.h>
#include <linux/bpf.h>
#include <linux/types.h>

// #include <errno.h>
// #include <gnu/stubs-32.h>
// #include <linux/in.h>
// #include <linux/types.h>
// #include <stdbool.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") pkt_count = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 1,
};

struct dest_info {
	u32 dest_ip;
	u32 dest_port;
};

struct bpf_map_def SEC("maps") port_mapping = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(struct dest_info),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") vaccant_ports = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u32),
	.max_entries = 50,
};

// [5002 , ... , 5001]

u64 PID      = 73161;
u16 NEW_PORT = 8080; // Choose the desired port number
u32 NEW_IP   = 0;    // 192.168.1.23 in hexadecimal forma

SEC("cgroup_skb/egress")
int count_egress_packets(struct __sk_buff *skb) {
	u32 key      = 0;
	u64 init_val = 1;

	u64 *count = bpf_map_lookup_elem(&pkt_count, &key);
	if (!count) {
		bpf_map_update_elem(&pkt_count, &key, &init_val, BPF_ANY);
		return 1;
	}
	__sync_fetch_and_add(count, 1);

	return 1;
}

SEC("cgroup/connect4")
int k_connect4(struct bpf_sock_addr *ctx) {
	u64 id  = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;

	if (pid != PID) {
		return 1;
	}
	bpf_printk("connect4 called [PID:%lu]\n", pid);

	volatile u32 protocol = ctx->protocol;

	if (protocol != 6) {
		return 1;
	}

	// destination ip
	u32 dst_ip = ctx->user_ip4;
	// destination port
	u32 dst_port = ctx->user_port;

	u32 index  = 0;
	u32 *value = bpf_map_lookup_elem(&vaccant_ports, &index);
	if (value) {
		bpf_printk("vaccant proxy at port:%u\n", *value);
	}

	// (*value)++;
	// source ip of the client
	// u32 client_ip = ctx->msg_src_ip4;
	u32 client_ip = 1;

	// bpf_printk("client_ip in connect4 %lu\n", client_ip);

	struct dest_info dest = {
		.dest_ip   = dst_ip,
		.dest_port = dst_port,
	};

	struct dest_info *pdest = bpf_map_lookup_elem(&port_mapping, &client_ip);
	bpf_printk("key address in port_access map:%p\n", &client_ip);
	if (pdest) {
		// Entry exists, update it
		bpf_printk("Entry exists in the port_access map, hence getting the [dest_ip:%lu] and [dest_port:%lu]\n", pdest->dest_ip, pdest->dest_port);
		*pdest = dest;
	} else {
		// Entry does not exist, insert it
		bpf_printk("Entry doesn't exist in the port_access map, hence setting the [dest_ip:%lu]and [dest_port:%lu]\n", dest.dest_ip, dest.dest_port);
		bpf_map_update_elem(&port_mapping, &client_ip, &dest, BPF_ANY);
	}

	// bpf_map_pop_elem(&vaccant_ports, value);
	// 	u32 *value2 = bpf_map_lookup_elem(&vaccant_ports, &index);
	// 	bpf_printk("vaccant proxy at port:%u\n", *value2);
	// }
	// redirecting to proxy.
	ctx->user_ip4  = NEW_IP;
	ctx->user_port = 5000;
	bpf_printk("destination IP: %u | destination Port: %u", ctx->user_ip4, ctx->user_port);
	return 1;
}

SEC("cgroup/getpeername4")
int k_getpeername4(struct bpf_sock_addr *ctx) {
	u64 pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("getpeername4 called [PID:%llu]\n", pid);
	return 1;
}