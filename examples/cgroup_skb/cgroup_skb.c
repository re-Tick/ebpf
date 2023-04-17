//go:build ignore

#include "common.h"
#include <asm-generic/types.h>
#include <asm/bitsperlong.h>
// #include <byteswap.h>
// #include <arpa/inet.h>
#include "bpf_endian.h"
#include "bpf_helpers.h"

#include "bpf_tracing.h"
#include <linux/bpf.h>
#include <linux/types.h>
#include <stdbool.h>

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

// u32 nr_cpus = BPF_CORE_READ(NR_CPUS);

// struct bpf_spin_lock;
struct bpf_spin_lock {
	__u32 val;
};
struct vaccant_port {
	u32 port;
	// bool occupied;
	struct bpf_spin_lock lock;
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
	.type       = BPF_MAP_TYPE_ARRAY,
	.key_size   = sizeof(u32),
	.value_size = sizeof(struct vaccant_port),
	// .value_size  = sizeof(u32),
	.max_entries = 50,
};

// int fd;
// union bpf_attr attr = {
// 	.map_type    = BPF_MAP_TYPE_ARRAY, /* mandatory */
// 	.key_size    = sizeof(__u32),      /* mandatory */
// 	.value_size  = sizeof(__u32),      /* mandatory */
// 	.max_entries = 256,                /* mandatory */
// 	// .map_flags = BPF_F_MMAPABLE;
// 	.map_name = "vaccant_Queue",
// };

// int fd = bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
// int fd = 9;

// struct bpf_map_def SEC("maps") vaccant_Queue = {
// 	// __uint(type, BPF_MAP_TYPE_QUEUE);
// 	// __type(value, __u32);
// 	// __uint(max_entries, 10);
// 	.type = BPF_MAP_TYPE_QUEUE,
// 	// .type = BPF_MAP_TYPE_PERCPU_ARRAY,

// 	.key_size    = sizeof(u32),
// 	.value_size  = sizeof(u64),
// 	.max_entries = 50,
// };

// [5002 , ... , 5001]

u64 PID      = 272706;
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
	// u32 dst_port = ctx->user_port;
	u16 dst_port_u = (u16)ctx->user_port;
	// u16 dst_port   = __bswap_16(dst_port_u);
	u16 dst_port = bpf_ntohs(dst_port_u);

	const u32 index            = (u32)0;
	struct vaccant_port *value = bpf_map_lookup_elem(&vaccant_ports, &index);
	// u32 *value = bpf_map_lookup_elem(&vaccant_ports, &index);

	if (value) {
		// bpf_printk("vaccant proxy at port:%p, sizeof(vaccantPorts): %d\n", (void *)value, sizeof(struct vaccant_port));
		// bpf_printk("vaccant proxy at port:%u\n", *value);
		// __sync_fetch_and_sub(value, *value);

		// 	int ret = bpf_map_delete_elem(&vaccant_ports, &index);
		// if (ret) {
		// 	// Handle the error...
		// 	bpf_printk("error deleting the front from the vaccant_ports:%d\n", ret);
		// }
		// index       = 0;
		// u32 *value2 = bpf_map_lookup_elem(&vaccant_ports, &index);
		// if (value2) {
		// 	bpf_printk("vaccant proxy at port after pop:%u\n", *value2);
		// }
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
	ctx->user_port = (__u32)bpf_ntohs(5000);
	bpf_printk("destination IP: %u | destination Port: %u", ctx->user_ip4, ctx->user_port);
	return 1;
}

SEC("cgroup/getpeername4")
int k_getpeername4(struct bpf_sock_addr *ctx) {
	u64 pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("getpeername4 called [PID:%llu]\n", pid);
	return 1;
}