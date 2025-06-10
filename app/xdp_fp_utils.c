/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright 2025 NXP
 */

#include "xdp_fp_user.h"
#include <net/if.h>

#define PROTO_VLAN 0x8100

#define IPV4_INPUT_FILE "input.txt"
#define NAT64_INPUT_FILE "nat64.txt"
#define MAX_ENTRIES 1000

struct ip6_route_info {
	struct in6_addr ip6;
	__u32 route_id;
};

struct ip6_ip4_pair {
	struct in6_addr ip6;
	__be32 ip4;
};

struct ip4_route {
	__be32 ip4;
	__u32 route_id;
};

int route_add(int route_fd, int if_index, unsigned char *smac,
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

int update_ipv4_entries(int map_fd)
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

int get_device_info(char *device, unsigned char *dev_addr, int *if_index)
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
			dump_ipv4_flows();
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
			dump_ipv6_flows();
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

int
load_config_and_populate_maps(void)
{
	const char *filename = NAT64_INPUT_FILE;
	char line[256], section[32] = "";
	struct ip6_ip4_pair ip6_ip4_list[MAX_ENTRIES];
	struct ip4_route ip4_route_list[MAX_ENTRIES];
	int ip6_ip4_count = 0, ip4_route_count = 0;
	int map_fd_ip6_ip4, map_fd_ip4_ip6_route,  map_fd_dst_ip_route, map_fd_route_map;

	FILE *file = fopen(filename, "r");
	if (!file) {
		perror("Failed to open config file");
		return 1;
	}

	map_fd_ip6_ip4 = bpf_obj_get(PINNED_NAT64_IP6_IP4);
	if (map_fd_ip6_ip4 < 0) {
		fprintf(stderr, "bpf_obj_get(%s): %s(%d)\n",
			PINNED_NAT64_IP6_IP4, strerror(errno), errno);
		return 1;
	}
	map_fd_ip4_ip6_route = bpf_obj_get(PINNED_NAT64_IP4_IP6);
	if (map_fd_ip4_ip6_route < 0) {
		fprintf(stderr, "bpf_obj_get(%s): %s(%d)\n",
			PINNED_NAT64_IP4_IP6, strerror(errno), errno);
		close(map_fd_ip6_ip4);
		return 1;
	}
	map_fd_dst_ip_route = bpf_obj_get(PINNED_NAT64_DST_ROUTE);
	if (map_fd_dst_ip_route < 0) {
		fprintf(stderr, "bpf_obj_get(%s): %s(%d)\n",
			PINNED_NAT64_DST_ROUTE, strerror(errno), errno);
		close(map_fd_ip6_ip4);
		close(map_fd_ip4_ip6_route);
		return 1;
	}
	map_fd_route_map = bpf_obj_get(PINNED_ROUTE);
	if (map_fd_route_map < 0) {
		fprintf(stderr, "bpf_obj_get(%s): %s(%d)\n",
			PINNED_ROUTE, strerror(errno), errno);
		close(map_fd_ip6_ip4);
		close(map_fd_ip4_ip6_route);
		close(map_fd_dst_ip_route);
		return 1;
	}

	while (fgets(line, sizeof(line), file)) {
		if (line[0] == '#') continue;
		if (strstr(line, "SRC_IP6-IP4:")) { strcpy(section, "SRC_IP6-IP4"); continue; }
		if (strstr(line, "SRC_IP_ROUTE:")) { strcpy(section, "SRC_IP_ROUTE"); continue; }
		if (strstr(line, "DST_IP_ROUTE:")) { strcpy(section, "DST_IP_ROUTE"); continue; }
		if (strstr(line, "ROUTE_MAP:")) { strcpy(section, "ROUTE_MAP"); continue; }

		if (strlen(line) < 3) continue;

		if (strcmp(section, "SRC_IP6-IP4") == 0) {
			char ip6_str[64], ip4_str[32];

			sscanf(line, "%s %s", ip6_str, ip4_str);
			inet_pton(AF_INET6, ip6_str, &ip6_ip4_list[ip6_ip4_count].ip6);
			inet_pton(AF_INET, ip4_str, &ip6_ip4_list[ip6_ip4_count].ip4);
			bpf_map_update_elem(map_fd_ip6_ip4, &ip6_ip4_list[ip6_ip4_count].ip6, &ip6_ip4_list[ip6_ip4_count].ip4, BPF_ANY);
			ip6_ip4_count++;
		} else if (strcmp(section, "SRC_IP_ROUTE") == 0) {
			char ip4_str[32];
			__u32 route_id;

			sscanf(line, "%s %u", ip4_str, &route_id);
			inet_pton(AF_INET, ip4_str, &ip4_route_list[ip4_route_count].ip4);
			ip4_route_list[ip4_route_count].route_id = route_id;
			ip4_route_count++;
		} else if (strcmp(section, "DST_IP_ROUTE") == 0) {
			char ip4_str[32];
			__u32 route_id;
			__be32 ip4;

			sscanf(line, "%s %u", ip4_str, &route_id);
			inet_pton(AF_INET, ip4_str, &ip4);
			bpf_map_update_elem(map_fd_dst_ip_route, &ip4, &route_id, BPF_ANY);
		} else if (strcmp(section, "ROUTE_MAP") == 0) {
			__u32 route_id;
			char ifname[IF_NAMESIZE];
			__u16 mtu;
			struct route route_entry;
			int ifindex, ret;
			char dst_mac_str[18];
			unsigned char src_mac_str[18];

			sscanf(line, "%u %s %hu %17s", &route_id, ifname, &mtu, dst_mac_str);
			ret = get_device_info(ifname, src_mac_str, &ifindex);
			if (ret) {
				perror("Failed to get device info\n");
				return ret;
			}

			route_entry.l2_hdr_size = 2*ETH_ALEN;
			unsigned int mac[6];
			if (sscanf(dst_mac_str, "%x:%x:%x:%x:%x:%x",
						&mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
				fprintf(stderr, "Invalid MAC address format: %s\n", dst_mac_str);
				continue;
			}

			for (int i = 0; i < ETH_ALEN; i++) {
				route_entry.l2_hdr[i] = (uint8_t)mac[i];
			}

			memcpy(route_entry.l2_hdr + ETH_ALEN, src_mac_str, ETH_ALEN);

			route_entry.flags = 0;
			route_entry.redir_ifindex = ifindex;
			route_entry.mtu = mtu;
			route_entry.redir_if_type = 1;

			bpf_map_update_elem(map_fd_route_map, &route_id, &route_entry, BPF_ANY);
		}
	}

	// Populate reverse map
	for (int i = 0; i < ip6_ip4_count; i++) {
		for (int j = 0; j < ip4_route_count; j++) {
			if (ip6_ip4_list[i].ip4 == ip4_route_list[j].ip4) {
				struct ip6_route_info value = {
					.ip6 = ip6_ip4_list[i].ip6,
					.route_id = ip4_route_list[j].route_id
				};
				bpf_map_update_elem(map_fd_ip4_ip6_route, &ip6_ip4_list[i].ip4, &value, BPF_ANY);
			}
		}
	}

	close(map_fd_ip6_ip4);
	close(map_fd_ip4_ip6_route);
	close(map_fd_dst_ip_route);
	close(map_fd_route_map);
	fclose(file);
	return 0;
}
