// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2017-18 David Ahern <dsahern@gmail.com>
 * Copyright 2025 NXP
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */

#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/limits.h>
#include <net/if.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>
#include <arpa/inet.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "xdp_fp_common.h"

#define PINNED_STATS   "/sys/fs/bpf/fp_stats"
#define PINNED_GLOBALS "/sys/fs/bpf/fp_globals"

#define MAX_IF_NAME_LEN 10

#define PINNED_MAPS "/sys/fs/bpf"
#define PINNED_IPV4 "/sys/fs/bpf/fp_ipv4"
#define PINNED_IPV6 "/sys/fs/bpf/fp_ipv6"
#define PINNED_ROUTE "/sys/fs/bpf/fp_route"
#define PINNED_MAC_PORT "/sys/fs/bpf/fp_mac_to_port"
#define PINNED_PORT "/sys/fs/bpf/fp_tx_ports"

#define ETH_ALEN    6
#define PROTO_VLAN 0x8100
#define PROTO_IPV4 0x0800
#define PROTO_IPV6 0x86DD

#define IPV4_INPUT_FILE "input.txt"
#define LINE_LEN 128
#define VLAN_ID 42

/* Default MAC addresses */
static unsigned char if1_mac_addr[ETH_ALEN] =
                { 0x00, 0x04, 0x9F, 0x05, 0xC8, 0x39 };
static unsigned char dst_mac_addr1[ETH_ALEN] =
                { 0x02, 0xFF, 0xFF, 0xFF, 0x01, 0x02 };

struct vlan_info {
        u16 vlan_id;
        int if_index;
};

static __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;

static void print_usage(const char *prg)
{
	fprintf(stderr, "\nUsage: %s [options]\n", prg);
	fprintf(stderr, "options:\n");
	fprintf(stderr, " -h    help \n");
	fprintf(stderr, " -d    detach program\n");
	fprintf(stderr, " -S    use skb-mode\n");
	fprintf(stderr,	" -F    force loading prog\n");
	fprintf(stderr,	" -a    attach program (list of ethernet devices)\n");
	fprintf(stderr,	" -b    run program in bridge mode\n");
	fprintf(stderr, " -e    enable Fast Forward (enabled by default)\n");
        fprintf(stderr, " -r    disable Fast Forward \n");
	fprintf(stderr, " -z    reinitilialize statistics counters \n");
	fprintf(stderr, " -g    show global Fast Forward status \n");
	fprintf(stderr, " -s    display statistics counters \n");
	fprintf(stderr, " -D    dump XDP flows \n");
	fprintf(stderr, " -l    set rate limit of a flow \n");
	fprintf(stderr, " -u    load user given rules from input.txt, Applicable with -a option only. \n");
	fprintf(stderr, "\n");
}

static void print_stats(struct stats_entry *stats_value, unsigned int nr_cpus)
{
	unsigned int i, mode;
	u64 all_bytes_fp[GLOB_FP_MAX] = {0}, all_packets_fp[GLOB_FP_MAX] = {0};
	u64 all_bytes_sp[GLOB_FP_MAX] = {0}, all_packets_sp[GLOB_FP_MAX] = {0};

	for (mode = 0u; mode < GLOB_FP_MAX; mode++) {
		printf("--------------------------------------------------------------\n");
		printf("-----------------%s-------------------------\n",
			(mode == GLOB_IP_MODE) ? " IP Forwarding Mode " : "--- Bridge Mode ----");
		printf("--------------------------------------------------------------\n");
		for (i = 0u; i < nr_cpus; i++) {
			all_bytes_fp[mode]   += stats_value[i].bytes_fp[mode];
			all_packets_fp[mode] += stats_value[i].packets_fp[mode];
			if (stats_value[i].bytes_fp[mode]) {
				printf("CPU%u   FP Bytes:%16lu   FP Packets:%16lu\n", i,
					stats_value[i].bytes_fp[mode],
					stats_value[i].packets_fp[mode]);
			}
			all_bytes_sp[mode]   += stats_value[i].bytes_sp[mode];
			all_packets_sp[mode] += stats_value[i].packets_sp[mode];
			if (stats_value[i].bytes_sp[mode]) {
				printf("CPU%u   SP Bytes:%16lu   SP Packets:%16lu\n", i,
					stats_value[i].bytes_sp[mode],
					stats_value[i].packets_sp[mode]);
			}
			if (mode == GLOB_BRIDGE_MODE) {
				if (stats_value[i].m_pkts_fp[mode]) {
					printf("CPU%u   FP Matched Packets:%35lu\n", i,
						stats_value[i].m_pkts_fp[mode]);
				}
				if (stats_value[i].nm_pkts_fp[mode]) {
					printf("CPU%u   FP Unmatched Packets:%34lu\n", i,
						stats_value[i].nm_pkts_fp[mode]);
				}
			}

		}
		printf("**************************************************************\n");
		printf("Total: FP Bytes:%16lu   FP Packets:%16lu\n",
			all_bytes_fp[mode], all_packets_fp[mode]);
		printf("Total: SP Bytes:%16lu   SP Packets:%16lu\n",
			all_bytes_sp[mode], all_packets_sp[mode]);
		printf("--------------------------------------------------------------\n");
	}
}

static int do_attach(int idx, int prog_fd, const char *name)
{
	int err;

	err = bpf_xdp_attach(idx, prog_fd, xdp_flags, NULL);
	if (err < 0) {
		printf("ERROR: failed to attach program to %s\n", name);
		return err;
	}


	return err;
}

static int do_detach(int ifindex, const char *ifname, const char *app_name)
{
	LIBBPF_OPTS(bpf_xdp_attach_opts, opts);
	struct bpf_prog_info prog_info = {};
	char prog_name[BPF_OBJ_NAME_LEN];
	__u32 info_len, curr_prog_id;
	int prog_fd;
	int err = 1;

	if (bpf_xdp_query_id(ifindex, xdp_flags, &curr_prog_id)) {
		printf("ERROR: bpf_xdp_query_id failed (%s)\n",
		       strerror(errno));
		return err;
	}

	if (!curr_prog_id) {
		printf("ERROR: flags(0x%x) xdp prog is not attached to %s\n",
		       xdp_flags, ifname);
		return err;
	}

	info_len = sizeof(prog_info);
	prog_fd = bpf_prog_get_fd_by_id(curr_prog_id);
	if (prog_fd < 0) {
		printf("ERROR: bpf_prog_get_fd_by_id failed (%s)\n",
		       strerror(errno));
		return prog_fd;
	}

	err = bpf_prog_get_info_by_fd(prog_fd, &prog_info, &info_len);
	if (err) {
		printf("ERROR: bpf_prog_get_info_by_fd failed (%s)\n",
		       strerror(errno));
		goto close_out;
	}
	snprintf(prog_name, sizeof(prog_name), "%s_prog", app_name);
	prog_name[BPF_OBJ_NAME_LEN - 1] = '\0';

	if (strcmp(prog_info.name, prog_name)) {
		printf("ERROR: %s isn't attached to %s\n", app_name, ifname);
		err = 1;
		goto close_out;
	}

	opts.old_prog_fd = prog_fd;
	err = bpf_xdp_detach(ifindex, xdp_flags, &opts);
	if (err < 0)
		printf("ERROR: failed to detach program from %s (%s)\n",
				ifname, strerror(errno));
close_out:
	close(prog_fd);
	return err;
}

static int route_add(int route_fd, int if_index, unsigned char *smac,
		unsigned char *dmac, struct vlan_info *vinfo)
{
	struct route route = {};
	int key = if_index;

	route.flags = 0;
	route.mtu = 1500;

	route.l2_hdr_size = 2*ETH_ALEN;
	memcpy(route.l2_hdr, dmac, ETH_ALEN);
	memcpy(route.l2_hdr + ETH_ALEN, smac, ETH_ALEN);

	if (vinfo) {
		route.redir_ifindex = vinfo->if_index;
		u16 *vlan_tpid = (u16 *)&route.l2_hdr[2*ETH_ALEN];
		u16 *vlan_tci = vlan_tpid + 1;
		*vlan_tpid = htons(PROTO_VLAN);
		*vlan_tci = htons(vinfo->vlan_id);
		route.l2_hdr_size += 2*sizeof(u16);
	} else
		route.redir_ifindex = if_index;
	 route.redir_if_type = ARPHRD_ETHER;

	return bpf_map_update_elem(route_fd, &key, &route, BPF_ANY);
}

static void set_ipv4_checksum_correction(struct ipv4_flow *ipv4f,
		struct ipv4_info *ipv4i)
{
	unsigned int saddr_corr = 0;
	unsigned int daddr_corr = 0;
	unsigned int sport_corr = 0;
	unsigned int dport_corr = 0;
	unsigned int corr;

	if (ipv4f->saddr != ipv4i->nat_saddr
			|| ipv4f->daddr != ipv4i->nat_daddr
			|| ipv4f->sport != ipv4i->nat_sport
			|| ipv4f->dport != ipv4i->nat_dport)
		ipv4i->flags |= FP_INFO_FLAG_NAT;

	ipv4i->ip_csum_corr = 0x0001;

	/* Calculate checksum correction */
	saddr_corr = (ipv4f->saddr & 0xffff) + (ipv4f->saddr >> 16)
		+ ((ipv4i->nat_saddr & 0xffff) ^ 0xffff)
		+ ((ipv4i->nat_saddr >> 16) ^ 0xffff);
	daddr_corr = (ipv4f->daddr & 0xffff) + (ipv4f->daddr >> 16)
		+ ((ipv4i->nat_daddr & 0xffff) ^ 0xffff)
		+ ((ipv4i->nat_daddr >> 16) ^ 0xffff);
	sport_corr = ipv4f->sport + (ipv4i->nat_sport ^ 0xffff);
	dport_corr = ipv4f->dport + (ipv4i->nat_dport ^ 0xffff);

	/* IP checksum */
	/* NAT correction */
	corr = saddr_corr + daddr_corr;
	while (corr >> 16)
		corr = (corr & 0xffff) + (corr >> 16);

	if (corr == 0xffff)
		corr = 0;

	/* TTL correction */
	corr += 0x0001;
	if (corr + 1 >= 0x10000)
		corr++;

	ipv4i->ip_csum_corr = corr;

	/* UDP/TCP checksum */
	corr = saddr_corr + daddr_corr + dport_corr + sport_corr;

	while (corr >> 16)
		corr = (corr & 0xffff) + (corr >> 16);

	if (corr == 0xffff)
		corr = 0;

	ipv4i->trans_csum_corr = corr;
}

static int update_ipv4_entries(int map_fd)
{
	struct ipv4_flow ipv4_key = {};
	struct ipv4_info ipv4_value = {};

	FILE *file = fopen(IPV4_INPUT_FILE, "r");
	if (!file) {
		perror("fopen");
		return -1;
	}
	char interface_name[64] = {};
	bool entry_started = false;
	char line[256];
	int entry_count =0;
	int ret = 0;
	while (fgets(line, sizeof(line), file)) {
		// Trim leading whitespace
		char *trimmed = line;
		while (*trimmed == ' ' || *trimmed == '\t' || *trimmed == '\r')
			trimmed++;
		// Entry boundary
		if (*trimmed == '\n' || *trimmed == '\0') {
			if (!entry_started)
				continue;
			// Process complete entry
			if (interface_name[0] != '\0') {
				ipv4_value.route_ifindex = if_nametoindex(interface_name);
				if (ipv4_value.route_ifindex == 0) {
					printf("Invalid interface name: %s\n", interface_name);
				}
			}
			ipv4_value.flags = FP_INFO_FLAG_FAST_PATH;
			set_ipv4_checksum_correction(&ipv4_key, &ipv4_value);
			ret = bpf_map_update_elem(map_fd, &ipv4_key, &ipv4_value, BPF_ANY);
			if (ret) {
				perror("bpf_map_update_elem");
				break;
			}
		}
		// Parse key-value pair
		char key[64], val[64];
		if (sscanf(trimmed, "%[^=]=%s", key, val) != 2)
			continue;
		entry_started = true;
		if (strcmp(key, "saddr") == 0)
			inet_pton(AF_INET, val, &ipv4_key.saddr);
		else if (strcmp(key, "daddr") == 0)
			inet_pton(AF_INET, val, &ipv4_key.daddr);
		else if (strcmp(key, "sport") == 0)
			ipv4_key.sport = htons(atoi(val));
		else if (strcmp(key, "dport") == 0)
			ipv4_key.dport = htons(atoi(val));
		else if (strcmp(key, "protocol") == 0)
			ipv4_key.protocol = atoi(val);
		else if (strcmp(key, "nat_saddr") == 0)
			inet_pton(AF_INET, val, &ipv4_value.nat_saddr);
		else if (strcmp(key, "nat_daddr") == 0)
			inet_pton(AF_INET, val, &ipv4_value.nat_daddr);
		else if (strcmp(key, "nat_sport") == 0)
			ipv4_value.nat_sport = htons(atoi(val));
		else if (strcmp(key, "nat_dport") == 0)
			ipv4_value.nat_dport = htons(atoi(val));
		else if (strcmp(key, "mtu") == 0)
			ipv4_value.mtu = atoi(val);
		else if (strcmp(key, "rate_limit") == 0)
			ipv4_value.rate_limit = atoi(val);
		else if (strcmp(key, "interface") == 0)
			strncpy(interface_name, val, sizeof(interface_name));
	}
	// Handle last entry if file end with a newline
	if (entry_started) {
		if (interface_name[0] != '\0') {
			ipv4_value.route_ifindex = if_nametoindex(interface_name);
			if (ipv4_value.route_ifindex == 0) {
				fprintf(stderr, "Invalid interface name: %s\n", interface_name);
			}
		}
		ipv4_value.flags = FP_INFO_FLAG_FAST_PATH;
		set_ipv4_checksum_correction(&ipv4_key, &ipv4_value);
		++entry_count;
		ret = bpf_map_update_elem(map_fd, &ipv4_key, &ipv4_value, BPF_ANY);
		if (ret){
			printf("bpf_map_update_elem (last entry)");
		}
	}
	fclose(file);
	return ret;
}

static void convert_mac_address(const char *addr_str, unsigned char *mac_addr)
{
	unsigned int input[ETH_ALEN];

	sscanf(addr_str, "%x:%x:%x:%x:%x:%x", &input[0], &input[1], &input[2],
			&input[3], &input[4], &input[5]);


	mac_addr[0] = input[0];
	mac_addr[1] = input[1];
	mac_addr[2] = input[2];
	mac_addr[3] = input[3];
	mac_addr[4] = input[4];
	mac_addr[5] = input[5];
}

static int get_device_info(char *device, unsigned char *dev_addr, int *if_index)
{
	char device_info_path[256];
	FILE *fp;
	char mac_addr_str[3*ETH_ALEN];

	/* MAC address */
	if (dev_addr) {
		sprintf(device_info_path, "/sys/class/net/%s/address", device);
		fp = fopen(device_info_path, "r");
		if (!fp)
			return -1;
		if (fgets(mac_addr_str, 3*ETH_ALEN, fp) == NULL) {
			fprintf(stderr, "Mac address get fails for device %s\n", device);
			return -1;
		}

		convert_mac_address(mac_addr_str, dev_addr);
		fclose(fp);
	}

	/* Interface index */
	if (if_index) {
		sprintf(device_info_path, "/sys/class/net/%s/ifindex", device);
		fp = fopen(device_info_path, "r");
		if (!fp)
			return -1;
		*if_index = atoi(fgets((char *)if_index, 4, fp));
		fclose(fp);
	}

	return 0;
}

void print_ip(__u32 ip)
{
	struct in_addr addr = { .s_addr = ip };

	printf("%s", inet_ntoa(addr));
}

void dump_ipv4_flows(int ipv4_fd)
{
	struct ipv4_flow key = {}, next_key;
	struct ipv4_info value;

	FILE *f = fopen("ipv4_flows.txt", "w");
	if (!f) {
		perror("Failed to open output file");
		return;
	}

	fprintf(f, "IPv4 Flow Table:\n");
	fprintf(f, "-------------------------------------------------------------------------------------------------------------------------------------------\n");
	fprintf(f, "%-15s %-10s %-15s %-10s %-7s %-15s %-15s %-13s %-13s %-7s %-12s\n",
			"Src IP", "Src Port", "Dst IP", "Dst Port", "Proto",
			"Out Src IP", "Out Dst IP", "Out Src Port", "Out Dst Port", "Active", "Rate Limit");

	while (bpf_map_get_next_key(ipv4_fd, &key, &next_key) == 0) {
		if (bpf_map_lookup_elem(ipv4_fd, &next_key, &value) == 0) {
			char saddr[INET_ADDRSTRLEN], daddr[INET_ADDRSTRLEN];
			char nsaddr[INET_ADDRSTRLEN], ndaddr[INET_ADDRSTRLEN];

			inet_ntop(AF_INET, &next_key.saddr, saddr, sizeof(saddr));
			inet_ntop(AF_INET, &next_key.daddr, daddr, sizeof(daddr));
			inet_ntop(AF_INET, &value.nat_saddr, nsaddr, sizeof(nsaddr));
			inet_ntop(AF_INET, &value.nat_daddr, ndaddr, sizeof(ndaddr));

			fprintf(f, "%-15s %-10u %-15s %-10u %-7u %-15s %-15s %-13u %-13u %-7u %-12lu\n",
					saddr, ntohs(next_key.sport),
					daddr, ntohs(next_key.dport),
					next_key.protocol,
					nsaddr, ndaddr,
					ntohs(value.nat_sport), ntohs(value.nat_dport),
					value.active, value.rate_limit);
		}
		key = next_key;
	}
	printf("Run Command to see IPv4 Flows: cat ./ipv4_flows.txt\n");
	fclose(f);
}

void dump_ipv6_flows(int ipv6_fd)
{
	struct ipv6_flow key = {}, next_key;
	struct ipv6_info value;

	FILE *f = fopen("ipv6_flows.txt", "w");
	if (!f) {
		perror("Failed to open output file");
		return;
	}

	fprintf(f, "IPv6 Flow Table:\n");
	fprintf(f, "-------------------------------------------------------------------------------------------------------------------------------------------");
	fprintf(f, "----------------------------------------------------------------------------------------------------\n");
	fprintf(f, "%-40s %-10s %-40s %-10s %-7s %-40s %-40s %-13s %-13s %-7s %-12s\n",
		"Src IP", "Src Port", "Dst IP", "Dst Port", "Proto",
		"Out Src IP", "Out Dst IP", "Out Src Port", "Out Dst Port", "Active", "Rate Limit");

	while (bpf_map_get_next_key(ipv6_fd, &key, &next_key) == 0) {
		if (bpf_map_lookup_elem(ipv6_fd, &next_key, &value) == 0) {
			char saddr[INET6_ADDRSTRLEN], daddr[INET6_ADDRSTRLEN];
			char nsaddr[INET6_ADDRSTRLEN], ndaddr[INET6_ADDRSTRLEN];

			inet_ntop(AF_INET6, next_key.saddr, saddr, sizeof(saddr));
			inet_ntop(AF_INET6, next_key.daddr, daddr, sizeof(daddr));
			inet_ntop(AF_INET6, value.nat_saddr, nsaddr, sizeof(nsaddr));
			inet_ntop(AF_INET6, value.nat_daddr, ndaddr, sizeof(ndaddr));


			fprintf(f, "%-40s %-10u %-40s %-10u %-7u %-40s %-40s %-13u %-13u %-7u %-12lu\n",
				saddr, ntohs(next_key.sport),
				daddr, ntohs(next_key.dport),
				next_key.protocol,
				nsaddr, ndaddr,
				ntohs(value.nat_sport), ntohs(value.nat_dport),
				value.active, value.rate_limit);
		}
		key = next_key;
	}
	fclose(f);
	printf("Run command to see IPv6 Flows: cat ./ipv6_flows.txt\n");
}

void set_flow_rate_limit(void)
{
	int version;
	char saddr_str[INET6_ADDRSTRLEN], daddr_str[INET6_ADDRSTRLEN];
	int sport, dport, proto;
	__u64 rate_limit;
	int map_fd;

	printf("Select IP version (4 or 6): ");
	if (scanf("%d", &version) != 1 || (version != 4 && version != 6)) {
		fprintf(stderr, "Invalid IP version selected.\n");
		return;
	}


	printf("Enter source IP: ");
	if (scanf("%45s", saddr_str) != 1) {
		fprintf(stderr, "Invalid input for source IP\n");
		return;
	}

	printf("Enter destination IP: ");
	if (scanf("%45s", daddr_str) != 1) {
		fprintf(stderr, "Invalid input for destination IP\n");
		return;
	}

	printf("Enter source port: ");
	if (scanf("%d", &sport) != 1) {
		fprintf(stderr, "Invalid input for source port\n");
		return;
	}

	printf("Enter destination port: ");
	if (scanf("%d", &dport) != 1) {
		fprintf(stderr, "Invalid input for destination port\n");
		return;
	}

	printf("Enter protocol (e.g., 6 for TCP, 17 for UDP): ");
	if (scanf("%d", &proto) != 1) {
		fprintf(stderr, "Invalid input for protocol\n");
		return;
	}

	printf("Enter rate limit (bytes/sec): ");
	if (scanf("%llu", &rate_limit) != 1) {
		fprintf(stderr, "Invalid input for rate limit\n");
		return;
	}

	if (version == 4) {
		struct ipv4_flow flow = {};
		struct ipv4_info info = {};

		map_fd = bpf_obj_get(PINNED_IPV4);
		if (map_fd < 0) {
			fprintf(stderr, "bpf_obj_get(%s): %s(%d)\n", PINNED_IPV4, strerror(errno), errno);
			return;
		}

		inet_pton(AF_INET, saddr_str, &flow.saddr);
		inet_pton(AF_INET, daddr_str, &flow.daddr);
		flow.sport = htons(sport);
		flow.dport = htons(dport);
		flow.protocol = proto;

		if (bpf_map_lookup_elem(map_fd, &flow, &info) != 0) {
			fprintf(stderr, "Flow not found, dumping all IPv4 flows:\n");
			dump_ipv4_flows(map_fd);
			close(map_fd);
			return;
		}

		info.rate_limit = rate_limit;
		info.bytes_count = 0;
		info.last_time_ns = 0;

		if (bpf_map_update_elem(map_fd, &flow, &info, BPF_ANY) != 0) {
			perror("Failed to update IPv4 flow info");
		} else {
			printf("Rate limit set to %llu bytes/sec for IPv4 flow\n", rate_limit);
		}
	} else {
		struct ipv6_flow flow = {};
		struct ipv6_info info = {};

		map_fd = bpf_obj_get(PINNED_IPV6);
		if (map_fd < 0) {
			fprintf(stderr, "bpf_obj_get(%s): %s(%d)\n", PINNED_IPV6, strerror(errno), errno);
			return;
		}

		inet_pton(AF_INET6, saddr_str, flow.saddr);
		inet_pton(AF_INET6, daddr_str, flow.daddr);
		flow.sport = htons(sport);
		flow.dport = htons(dport);
		flow.protocol = proto;

		if (bpf_map_lookup_elem(map_fd, &flow, &info) != 0) {
			fprintf(stderr, "Flow not found, dumping all IPv6 flows:\n");
			dump_ipv6_flows(map_fd);
			close(map_fd);
			return;
		}

		info.rate_limit = rate_limit;
		info.bytes_count = 0;
		info.last_time_ns = 0;

		if (bpf_map_update_elem(map_fd, &flow, &info, BPF_ANY) != 0) {
			perror("Failed to update IPv6 flow info");
		} else {
			printf("Rate limit set to %llu bytes/sec for IPv6 flow\n", rate_limit);
		}
    }

    close(map_fd);
}

int main(int argc, char **argv)
{
	const char *prog_name = "xdp_fp";
	struct bpf_program *prog = NULL;
	struct bpf_program *pos;
	const char *sec_name;
	int prog_fd = -1;
	char filename[PATH_MAX];
	struct bpf_object *obj;
	int opt, i, idx, err, icount = 0;
	int attach = 1;
	int ret = -1;
	__u32 port_key = -1, port_value = -1;

	int ipv4_fd = -1, ipv6_fd = -1, route_fd = -1, port_fd = -1;
	char fif[MAX_IF_NAME_LEN];

	int reset_stat = 0, print_stat = 0, ff_disabled = 0, ff_status, show_globals = 0,
	    user_rules = 0;
	int ff_update = 1;
	int fd_stats, fd_globals;
	struct stats_entry *stats_value;
	int stats_key = GLOB_STAT;
	int globals_key;
	unsigned int nr_cpus = sysconf(_SC_NPROCESSORS_CONF);

	while ((opt = getopt(argc, argv, "dauSFzserghblD")) != -1) {
		switch (opt) {
			case 'd':
				attach = 0;
				break;
			case 'S':
				xdp_flags |= XDP_FLAGS_SKB_MODE;
				break;
			case 'F':
				xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
				break;
			case 'a':
				prog_name = "xdp_fp";
				break;
			case 'z':
				reset_stat = 1;
				goto stats;
				break;
			case 's':
				print_stat = 1;
				goto stats;
				break;
			case 'e':
				ff_update = 1;
				ff_disabled = 0;
				goto stats;
				break;
			case 'r':
				ff_update = 1;
				ff_disabled = 1;
				goto stats;
				break;
			case 'g':
				show_globals = 1;
				goto stats;
				break;
			case 'u':
				user_rules = 1;
				break;
			case 'b':
				prog_name = "xdp_fp_bridge";
				break;
			case 'h':
				print_usage(basename(argv[0]));
				return 1;
			case 'D':
				ipv4_fd = bpf_obj_get(PINNED_IPV4);
				if (ipv4_fd < 0) {
					fprintf(stderr, "bpf_obj_get(%s): %s(%d)\n",
						PINNED_IPV4, strerror(errno), errno);
					return 1;
				}
				dump_ipv4_flows(ipv4_fd);
				close(ipv4_fd);
				ipv6_fd = bpf_obj_get(PINNED_IPV6);
				if (ipv6_fd < 0) {
					fprintf(stderr, "bpf_obj_get(%s): %s(%d)\n",
						PINNED_IPV6, strerror(errno), errno);
					return 1;
				}
				dump_ipv6_flows(ipv6_fd);
				close(ipv4_fd);
				return 1;
			case 'l':
				set_flow_rate_limit();
				return 1;
			default:
				print_usage(basename(argv[0]));
				return 1;
		}
	}

	if (!(xdp_flags & XDP_FLAGS_SKB_MODE))
		xdp_flags |= XDP_FLAGS_DRV_MODE;

	if (optind == argc) {
		print_usage(basename(argv[0]));
		return 1;
	}

	if (argv[0][0]== '.' && argv[0][1]=='/')
		snprintf(filename, sizeof(filename), "%s_kern.o", &argv[0][2]);
	else
		snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	if (access(filename, O_RDONLY) < 0) {
		printf("error accessing file %s: %s\n",
			filename, strerror(errno));
		return 1;
	}
	printf("Program Name %s\n", prog_name);

	if (attach) {
		obj = bpf_object__open_file(filename, NULL);
		if (libbpf_get_error(obj))
			return 1;

		bpf_object__for_each_program(pos, obj) {
			bpf_program__set_type(pos, BPF_PROG_TYPE_XDP);
		}

		err = bpf_object__load(obj);
		if (err) {
			printf("Does kernel support devmap lookup?\n");
			/* If not, the error message will be:
			 *  "cannot pass map_type 14 into func bpf_map_lookup_elem#1"
			 */
			return 1;
		}

		bpf_object__for_each_program(pos, obj) {
			sec_name = bpf_program__section_name(pos);
			if (sec_name && !strcmp(sec_name, prog_name)) {
				prog = pos;
				break;
			}
		}
		prog_fd = bpf_program__fd(prog);
		if (prog_fd < 0) {
			printf("program not found: %s\n", strerror(prog_fd));
			return 1;
		}

		// Get port map FD
		port_fd = bpf_object__find_map_fd_by_name(obj, "fp_tx_ports");
		if (port_fd < 0) {
			printf("bpf_object__find_map_fd_by_name failed for fp_tx_ports");
			goto out;
		}

		ipv4_fd = bpf_object__find_map_fd_by_name(obj, "fp_ipv4");
		if (ipv4_fd < 0) {
			fprintf(stderr, "bpf_obj_get(%s): %s(%d)\n",
					PINNED_IPV4, strerror(errno), errno);
			goto out;
		}

		route_fd = bpf_object__find_map_fd_by_name(obj, "fp_route");
		if (route_fd < 0) {
			fprintf(stderr, "bpf_obj_get(%s): %s(%d)\n",
					PINNED_ROUTE, strerror(errno), errno);
			goto out;
		}

	}

	for (i = optind; i < argc; ++i) {
		idx = if_nametoindex(argv[i]);
		if (!idx)
			idx = strtoul(argv[i], NULL, 0);

		if (!idx) {
			fprintf(stderr, "Invalid arg\n");
			return 1;
		}
		sprintf(fif, "%s", argv[i]);

		if (!attach) {
			err = do_detach(idx, argv[i], prog_name);
			if (err)
				ret = err;
		} else {
			if (icount++ > MAX_PORT) {
				fprintf(stderr, "No more ports allowed\n");
				break;
			}
			err = do_attach(idx, prog_fd, argv[i]);
			if (err) {
				fprintf(stderr, "Port = %d program attach error\n", idx);
				ret = err;
			}

			/* populate fp_tx_port table */
			port_key = idx;
			port_value = idx;
			err = bpf_map_update_elem(port_fd, &port_key, &port_value, BPF_ANY);
			if (err) {
				fprintf(stderr, "Update fp_tx_port failsf or idx = %d\n", idx);
			} else {
				printf("Added ifindex %d (%s) to fp_tx_ports map\n", idx, argv[i]);
			}
			if (user_rules) {
				/* Update the ebpf maps*/
				ret = get_device_info(fif, if1_mac_addr, NULL);
				if (ret) {
					fprintf(stderr, "unknown linterface = %s\n", fif);
					goto out;
				}
				ret = route_add(route_fd, idx, if1_mac_addr, dst_mac_addr1, NULL);
				if (ret) {
					fprintf(stderr, "BPF update route: %d", idx);
					goto out;
				}
			}
		}
	}

	if (user_rules) {
		ret = update_ipv4_entries(ipv4_fd);
		if (ret) {
			perror("BPF update IPv4 entries");
			goto out;
		}
	}
stats:
	/* Getting stats part Init fd entries */
	fd_stats = bpf_obj_get(PINNED_STATS);
	if (fd_stats < 0) {
		fprintf(stderr, "bpf_obj_get(%s): %s(%d)\n",
				PINNED_STATS, strerror(errno), errno);
		exit(EXIT_FAILURE);
	}

	fd_globals = bpf_obj_get(PINNED_GLOBALS);
	if (fd_globals < 0) {
		fprintf(stderr, "bpf_obj_get(%s): %s(%d)\n",
				PINNED_GLOBALS, strerror(errno), errno);
		exit(EXIT_FAILURE);
	}
	ipv4_fd = bpf_obj_get(PINNED_IPV4);
	if (ipv4_fd < 0) {
		fprintf(stderr, "bpf_obj_get(%s): %s(%d)\n",
				PINNED_IPV4, strerror(errno), errno);
		exit(EXIT_FAILURE);
	}

	/* Allocate memory for PERCPU statistics entries */
	stats_value = calloc(nr_cpus, sizeof(struct stats_entry));
	if (stats_value == NULL) {
		fprintf(stderr, "Memory allocation failure for statistics (CPU#%u)\n",
				nr_cpus);
		exit(EXIT_FAILURE);
	}

	if (1 == ff_update) {
		globals_key = GLOB_FF_DISABLE;
		bpf_map_lookup_elem(fd_globals, &globals_key, &ff_status);

		if (ff_status != ff_disabled) {
			printf("Updating Fast Forward => %s\n",
					(ff_disabled == 1) ? "disabling" : "enabling");
			bpf_map_update_elem(fd_globals, &globals_key, &ff_disabled, BPF_ANY);
		}
	}

	if (1 == reset_stat) {
		printf("Reseting stats\n");
		memset(stats_value, 0, sizeof(struct stats_entry));
		bpf_map_update_elem(fd_stats, &stats_key, stats_value, BPF_ANY);
		print_stats(stats_value, nr_cpus);
	}

	if (1 == print_stat) {
		printf("Printing stats\n");
		bpf_map_lookup_elem(fd_stats, &stats_key, stats_value);
		print_stats(stats_value, nr_cpus);
	}

	if (1 == show_globals) {
		int global_value;

		globals_key = GLOB_FF_DISABLE;
		bpf_map_lookup_elem(fd_globals, &globals_key, &global_value);
		printf("Global Fast Forward disabled: %d\n", global_value);
	}

	free(stats_value);
	if (!attach) {
		obj = bpf_object__open_file(filename, NULL);
		if (libbpf_get_error(obj))
			return 1;

		bpf_object__unpin_maps(obj, PINNED_MAPS);
		bpf_object__close(obj);
	}

	return ret;

out:
        if (port_fd != -1)
                close(port_fd);
        if (route_fd != -1)
                close(route_fd);
        if (ipv4_fd != -1)
                close(ipv4_fd);
        if (ipv6_fd != -1)
                close(ipv6_fd);

	if (!attach) {
		obj = bpf_object__open_file(filename, NULL);
		if (libbpf_get_error(obj))
			return 1;

		bpf_object__unpin_maps(obj, PINNED_MAPS);
		bpf_object__close(obj);
	}

	return ret;
}
