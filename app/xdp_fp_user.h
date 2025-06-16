/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright 2025 NXP
 */
#ifndef _XDP_FP_USER_H
#define _XDP_FP_USER_H

#include <stdio.h>

#include <linux/bpf.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "xdp_fp_common.h"

#define PINNED_STATS   "/sys/fs/bpf/fp_stats"
#define PINNED_GLOBALS "/sys/fs/bpf/fp_globals"

#define MAX_IF_NAME_LEN 10
#define ETH_ALEN    6

#define PINNED_MAPS "/sys/fs/bpf"
#define PINNED_IPV4 "/sys/fs/bpf/fp_ipv4"
#define PINNED_IPV6 "/sys/fs/bpf/fp_ipv6"
#define PINNED_ROUTE "/sys/fs/bpf/fp_route"
#define PINNED_MAC_PORT "/sys/fs/bpf/fp_mac_to_port"
#define PINNED_PORT "/sys/fs/bpf/fp_tx_ports"
#define PINNED_NAT64_IP6_IP4 "/sys/fs/bpf/nat64_ip6_ip4_src_map"
#define PINNED_NAT64_IP4_IP6 "/sys/fs/bpf/nat64_ip4_ip6_src_route_map"
#define PINNED_NAT64_DST_ROUTE "/sys/fs/bpf/nat64_dst_ip_route_map"

struct vlan_info {
	u16 vlan_id;
	int if_index;
};

void print_stats(struct stats_entry *stats_value, unsigned int nr_cpus);
void print_ip(__u32 ip);
void dump_ipv4_flows(void);
void dump_ipv6_flows(void);
void dump_fp_routes(void);
void dump_nat64_ip6_ip4_src_map();
void dump_nat64_ip4_ip6_src_route_map();
void dump_nat64_dst_ip_route_map();
int route_add(int route_fd, int if_index, unsigned char *smac,
	      unsigned char *dmac, struct vlan_info *vinfo);
int update_ipv4_entries(int map_fd);
int get_device_info(char *device, unsigned char *dev_addr, int *if_index);
void set_flow_rate_limit(void);
int
load_config_and_populate_maps(void);

#endif
