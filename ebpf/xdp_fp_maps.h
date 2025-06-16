#ifndef __XDP_MAPS_H__
#define __XDP_MAPS_H__

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <bpf/bpf_helpers.h>

#define MAX_MODULES     6
#define MAX_CPUS        6

struct ip6_route_info {
	struct in6_addr ip6;
	__u32 route_id;
};

struct xdp_fp_modules {
	__uint(type,BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size,sizeof(u32));
	__uint(value_size,sizeof(u32));
	__uint(pinning,LIBBPF_PIN_BY_NAME);
	__uint(max_entries,MAX_MODULES);
};

struct xdp_fp_globals {
	__uint(type,BPF_MAP_TYPE_ARRAY);
	__uint(key_size,sizeof(int));
	__uint(value_size,sizeof(int));
	__uint(pinning,LIBBPF_PIN_BY_NAME);
	__uint(max_entries,GLOB_MAX);
};

/* packets forwarding statistics map */
struct xdp_fp_stats {
	__uint(type,BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size,sizeof(int));
	__uint(value_size,sizeof(struct stats_entry));
	__uint(pinning,LIBBPF_PIN_BY_NAME);
	__uint(max_entries,MAX_CPUS);
};

struct xdp_fp_ipv4 {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size,sizeof(struct ipv4_flow));
	__uint(value_size,sizeof(struct ipv4_info));
	__uint(pinning,LIBBPF_PIN_BY_NAME);
	__uint(max_entries,MAX_IPV4_ENTRIES);
};

struct xdp_fp_ipv6 {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size,sizeof(struct ipv6_flow));
	__uint(value_size,sizeof(struct ipv6_info));
	__uint(pinning,LIBBPF_PIN_BY_NAME);
	__uint(max_entries,MAX_IPV6_ENTRIES);
};

struct xdp_fp_mac_to_port {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, ETH_ALEN);
	__uint(value_size, sizeof(int));
	__uint(pinning,LIBBPF_PIN_BY_NAME);
	__uint(max_entries, MAX_MAC_ADDR);
};

struct xdp_fp_tx_ports {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(pinning,LIBBPF_PIN_BY_NAME);
	__uint(max_entries, MAX_PORT);
};

struct xdp_fp_route {
	__uint(type,BPF_MAP_TYPE_ARRAY);
	__uint(key_size,sizeof(int));
	__uint(value_size,sizeof(struct route));
	__uint(pinning,LIBBPF_PIN_BY_NAME);
	__uint(max_entries,MAX_FP_ROUTES);
};

struct xdp_nat64_ip6_ip4_src_map {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct in6_addr);
	__type(value, __be32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
};

struct xdp_nat64_ip4_ip6_src_route_map {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __be32);
	__type(value, struct ip6_route_info);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
};

struct xdp_nat64_dst_ip_route_map {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __be32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
};
extern struct xdp_fp_modules fp_modules;
extern struct xdp_fp_globals fp_globals;
extern struct xdp_fp_stats fp_stats;
extern struct xdp_fp_ipv4 fp_ipv4;
extern struct xdp_fp_ipv6 fp_ipv6;
extern struct xdp_fp_mac_to_port fp_mac_to_port;
extern struct xdp_fp_tx_ports fp_tx_ports;
extern struct xdp_fp_route fp_route;
extern struct xdp_nat64_ip6_ip4_src_map nat64_ip6_ip4_src_map;
extern struct xdp_nat64_ip4_ip6_src_route_map nat64_ip4_ip6_src_route_map;
extern struct xdp_nat64_dst_ip_route_map nat64_dst_ip_route_map;

#endif // __XDP_MAPS_H__

