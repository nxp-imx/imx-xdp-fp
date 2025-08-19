/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright 2025 NXP
 */
#include "xdp_fp_user.h"

void print_stats(struct stats_entry *stats_value, unsigned int nr_cpus)
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

void print_ip(__u32 ip)
{
	struct in_addr addr = { .s_addr = ip };

	printf("%s", inet_ntoa(addr));
}

void dump_ipv4_flows()
{
	struct ipv4_flow key = {}, next_key;
	struct ipv4_info value;
	int ipv4_fd;

	FILE *f = fopen("ipv4_flows.txt", "w");
	if (!f) {
		perror("Failed to open output file");
		return;
	}

	ipv4_fd = bpf_obj_get(PINNED_IPV4);
	if (ipv4_fd < 0) {
		fprintf(stderr, "bpf_obj_get(%s): %s(%d)\n",
			PINNED_IPV4, strerror(errno), errno);
		fclose(f);
		return;
	}
	fprintf(f, "IPv4 Flow Table:\n");
	fprintf(f, "------------------------------------------------------------------------------------------------------------------------------------------------------\n");
	fprintf(f, "%-15s %-10s %-15s %-10s %-7s %-15s %-15s %-13s %-13s %-7s %-12s %-10s\n",
		"Src IP", "Src Port", "Dst IP", "Dst Port", "Proto",
		"Out Src IP", "Out Dst IP", "Out Src Port", "Out Dst Port", "Active", "Rate Limit", "Route Key");

	while (bpf_map_get_next_key(ipv4_fd, &key, &next_key) == 0) {
		if (bpf_map_lookup_elem(ipv4_fd, &next_key, &value) == 0) {
			char saddr[INET_ADDRSTRLEN], daddr[INET_ADDRSTRLEN];
			char nsaddr[INET_ADDRSTRLEN], ndaddr[INET_ADDRSTRLEN];

			inet_ntop(AF_INET, &next_key.saddr, saddr, sizeof(saddr));
			inet_ntop(AF_INET, &next_key.daddr, daddr, sizeof(daddr));
			inet_ntop(AF_INET, &value.nat_saddr, nsaddr, sizeof(nsaddr));
			inet_ntop(AF_INET, &value.nat_daddr, ndaddr, sizeof(ndaddr));

		fprintf(f, "%-15s %-10u %-15s %-10u %-7u %-15s %-15s %-13u %-13u %-7u %-12lu %-10d\n",
				saddr, ntohs(next_key.sport),
				daddr, ntohs(next_key.dport),
				next_key.protocol,
				nsaddr, ndaddr,
				ntohs(value.nat_sport), ntohs(value.nat_dport),
				value.active, value.rate_limit,
				value.route_ifindex);
		}
		key = next_key;
	}

	printf("Run command to see IPv4 Flows: cat ipv4_flows.txt\n");
	close(ipv4_fd);
	fclose(f);
}

void dump_ipv6_flows()
{
	struct ipv6_flow key = {}, next_key;
	struct ipv6_info value;
	int ipv6_fd;

	FILE *f = fopen("ipv6_flows.txt", "w");
	if (!f) {
		perror("Failed to open output file");
		return;
	}

	ipv6_fd = bpf_obj_get(PINNED_IPV6);
	if (ipv6_fd < 0) {
		fprintf(stderr, "bpf_obj_get(%s): %s(%d)\n",
			PINNED_IPV6, strerror(errno), errno);
		fclose(f);
		return;
	}
	fprintf(f, "IPv6 Flow Table:\n");
	fprintf(f, "-------------------------------------------------------------------------------------------------------------------------------------------");
	fprintf(f, "----------------------------------------------------------------------------------------------------\n");
	fprintf(f, "%-40s %-10s %-40s %-10s %-7s %-40s %-40s %-13s %-13s %-7s %-12s %-10s\n",
			"Src IP", "Src Port", "Dst IP", "Dst Port", "Proto",
			"Out Src IP", "Out Dst IP", "Out Src Port", "Out Dst Port", "Active", "Rate Limit", "Route Key");

	while (bpf_map_get_next_key(ipv6_fd, &key, &next_key) == 0) {
		if (bpf_map_lookup_elem(ipv6_fd, &next_key, &value) == 0) {
			char saddr[INET6_ADDRSTRLEN], daddr[INET6_ADDRSTRLEN];
			char nsaddr[INET6_ADDRSTRLEN], ndaddr[INET6_ADDRSTRLEN];

			inet_ntop(AF_INET6, next_key.saddr, saddr, sizeof(saddr));
			inet_ntop(AF_INET6, next_key.daddr, daddr, sizeof(daddr));
			inet_ntop(AF_INET6, value.nat_saddr, nsaddr, sizeof(nsaddr));
			inet_ntop(AF_INET6, value.nat_daddr, ndaddr, sizeof(ndaddr));

			fprintf(f, "%-40s %-10u %-40s %-10u %-7u %-40s %-40s %-13u %-13u %-7u %-12lu %-10d\n",
				saddr, ntohs(next_key.sport),
				daddr, ntohs(next_key.dport),
				next_key.protocol,
				nsaddr, ndaddr,
				ntohs(value.nat_sport), ntohs(value.nat_dport),
				value.active, value.rate_limit,
				value.route_ifindex);
		}
		key = next_key;
	}

	close(ipv6_fd);
	fclose(f);
	printf("Run command to see IPv6 Flows: cat ipv6_flows.txt\n");
}

void dump_fp_routes()
{
	int key = 0, fp_route_fd;
	struct route value;

	FILE *f = fopen("fp_routes.txt", "w");
	if (!f) {
		perror("Failed to open output file");
		return;
	}

	fp_route_fd = bpf_obj_get(PINNED_ROUTE);
	if (fp_route_fd < 0) {
		fprintf(stderr, "bpf_obj_get(%s): %s(%d)\n",
			PINNED_ROUTE, strerror(errno), errno);
		fclose(f);
		return;
	}
	fprintf(f, "Fast Path Route Table:\n");
	fprintf(f, "-------------------------------------------------------------------------------------------------------------\n");
	fprintf(f, "%-10s %-15s %-10s %-6s %-6s %-20s\n",
			"Key", "Flags", "IfIndex", "MTU", "Type", "L2 Header (DEST_MAC SRC_MAC)");

	for (key = 0; key < MAX_FP_ROUTES; key++) {
		if (bpf_map_lookup_elem(fp_route_fd, &key, &value) == 0) {
			if (value.redir_ifindex == 0 && value.l2_hdr_size == 0)
				continue;

			fprintf(f, "%-10d 0x%-13x %-10d %-6u %-6u ",
					key, value.flags, value.redir_ifindex,
					value.mtu, value.redir_if_type);

			for (int i = 0; i < 6 && i < MAX_L2_HEADER_SIZE; i++) {
				fprintf(f, "%02x", value.l2_hdr[i]);
				if (i < 5 && i < value.l2_hdr_size - 1)
					fprintf(f, ":");
			}
			fprintf(f, " ");
			for (int i = 6; i < 12 && i < MAX_L2_HEADER_SIZE; i++) {
				fprintf(f, "%02x", value.l2_hdr[i]);
				if (i < 11 && i < value.l2_hdr_size - 1)
					fprintf(f, ":");
			}
			fprintf(f, "\n");
		}
	}
	close(fp_route_fd);
	fclose(f);
	printf("Run Command to see Fast Path Routes: cat fp_routes.txt\n");
}

void dump_nat64_ip6_ip4_src_map()
{
	int map_fd = bpf_obj_get(PINNED_NAT64_IP6_IP4);
	if (map_fd < 0) {
		perror("Failed to open nat64_ip6_ip4_src_map");
		return;
	}

	FILE *f = fopen("nat64_ip6_ip4_src_map.txt", "w");
	if (!f) {
		perror("Failed to open output file");
		return;
	}

	struct in6_addr key = {}, next_key;
	__be32 value;
	char ip6_str[INET6_ADDRSTRLEN], ip4_str[INET_ADDRSTRLEN];

	fprintf(f, "NAT64 IPv6 to IPv4 Source Map:\n");
	fprintf(f, "-------------------------------------------------------------\n");
	fprintf(f, "%-40s %-15s\n", "IPv6 Address", "IPv4 Address");

	while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
		if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
			inet_ntop(AF_INET6, &next_key, ip6_str, sizeof(ip6_str));
			inet_ntop(AF_INET, &value, ip4_str, sizeof(ip4_str));
			fprintf(f, "%-40s %-15s\n", ip6_str, ip4_str);
		}
		key = next_key;
	}
	fclose(f);
	printf("Run command to view NAT64 source IPs pool: cat nat64_ip6_ip4_src_map.txt\n");
}

void dump_nat64_ip4_ip6_src_route_map()
{
	int map_fd = bpf_obj_get(PINNED_NAT64_IP4_IP6);
	if (map_fd < 0) {
		perror("Failed to open nat64_ip4_ip6_src_route_map");
		return;
	}

	FILE *f = fopen("nat64_ip4_ip6_src_route_map.txt", "w");
	if (!f) {
		perror("Failed to open output file");
		return;
	}

	__be32 key = 0, next_key;
	struct {
		struct in6_addr ip6;
		__u32 route_id;
	} value;
	char ip4_str[INET_ADDRSTRLEN], ip6_str[INET6_ADDRSTRLEN];

	fprintf(f, "NAT64 IPv4 to IPv6 + Route Map:\n");
	fprintf(f, "----------------------------------------------------------------------------------\n");
	fprintf(f, "%-15s %-40s %-10s\n", "IPv4 Address", "IPv6 Address", "Route ID");

	while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
		if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
			inet_ntop(AF_INET, &next_key, ip4_str, sizeof(ip4_str));
			inet_ntop(AF_INET6, &value.ip6, ip6_str, sizeof(ip6_str));
			fprintf(f, "%-15s %-40s %-10u\n", ip4_str, ip6_str, value.route_id);
		}
		key = next_key;
	}

	fclose(f);
	printf("Run command to view NAT46 mapping and Route ID: cat nat64_ip4_ip6_src_route_map.txt\n");
}

void dump_nat64_dst_ip_route_map()
{
	int map_fd = bpf_obj_get(PINNED_NAT64_DST_ROUTE);
	if (map_fd < 0) {
		perror("Failed to open nat64_dst_ip_route_map");
		return;
	}

	FILE *f = fopen("nat64_dst_ip_route_map.txt", "w");
	if (!f) {
		perror("Failed to open output file");
		return;
	}

	__be32 key = 0, next_key;
	__u32 value;
	char ip4_str[INET_ADDRSTRLEN];

	fprintf(f, "NAT64 Destination IP to Route Map:\n");
	fprintf(f, "---------------------------------------------\n");
	fprintf(f, "%-15s %-10s\n", "IPv4 Address", "Route ID");

	while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
		if (bpf_map_lookup_elem(map_fd, &next_key, &value) == 0) {
			inet_ntop(AF_INET, &next_key, ip4_str, sizeof(ip4_str));
			fprintf(f, "%-15s %-10u\n", ip4_str, value);
		}
		key = next_key;
	}

	fclose(f);
	printf("Run command to view NAT64 Routes: cat nat64_dst_ip_route_map.txt\n");
}
