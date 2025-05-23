// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2017-18 David Ahern <dsahern@gmail.com>
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

#define PINNED_IPV4 "/sys/fs/bpf/fp_ipv4"
#define PINNED_IPV6 "/sys/fs/bpf/fp_ipv6"
#define PINNED_ROUTE "/sys/fs/bpf/fp_route"

#define ETH_ALEN    6
#define PROTO_VLAN 0x8100
#define PROTO_IPV4 0x0800
#define PROTO_IPV6 0x86DD
//#define IPPROTO_UDP 17
//#define IPPROTO_TCP 6

#define IPV4_INPUT_FILE "input.txt"
#define LINE_LEN 128

#define VLAN_ID 42

static unsigned char if1_mac_addr[ETH_ALEN] =
                { 0x00, 0x04, 0x9F, 0x05, 0xC8, 0x39 };
static unsigned char if2_mac_addr[ETH_ALEN] =
                { 0x6C, 0xB3, 0x11, 0x1B, 0x62, 0xB1 };
static unsigned char dst_mac_addr1[ETH_ALEN] =
                { 0x02, 0xFF, 0xFF, 0xFF, 0x01, 0x02 };
static unsigned char dst_mac_addr2[ETH_ALEN] =
                { 0x02, 0xFF, 0xFF, 0xFF, 0x02, 0x02 };

static int lan_if;
static int wan_if;
//static int vlan_if;

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
	fprintf(stderr,	" -D    direct table lookups (skip fib rules)\n");
	fprintf(stderr, " -z    reinitilialize statistics counters \n");
	fprintf(stderr, " -g    show global map \n");
	fprintf(stderr, " -s    display statistics counters \n");
	fprintf(stderr, "\n");
}

static void print_stats(struct stats_entry *stats_value, unsigned int nr_cpus)
{
	unsigned int i, iftype;
	u64 all_bytes_fp[GLOB_IFTYPE_MAX] = {0}, all_packets_fp[GLOB_IFTYPE_MAX] = {0};
	u64 all_bytes_sp[GLOB_IFTYPE_MAX] = {0}, all_packets_sp[GLOB_IFTYPE_MAX] = {0};

	for (iftype = 0u; iftype < GLOB_IFTYPE_MAX; iftype++) {
		printf("--------------------------------------------------------------\n");
		printf("-----------------FROM %s IFACE-----------------------------\n",
			(iftype == GLOB_ETHERNET_TYPE) ? "ETHER" : "RAWIP");
		printf("--------------------------------------------------------------\n");
		for (i = 0u; i < nr_cpus; i++) {
			all_bytes_fp[iftype]   += stats_value[i].bytes_fp[iftype];
			all_packets_fp[iftype] += stats_value[i].packets_fp[iftype];
			printf("CPU%u   FP Bytes:%16lu   FP Packets:%16lu\n", i,
				stats_value[i].bytes_fp[iftype],
				stats_value[i].packets_fp[iftype]);
			all_bytes_sp[iftype]   += stats_value[i].bytes_sp[iftype];
			all_packets_sp[iftype] += stats_value[i].packets_sp[iftype];
			printf("CPU%u   SP Bytes:%16lu   SP Packets:%16lu\n", i,
				stats_value[i].bytes_sp[iftype],
				stats_value[i].packets_sp[iftype]);

		}
		printf("--------------------------------------------------------------\n");
		printf("Total: FP Bytes:%16lu   FP Packets:%16lu\n",
			all_bytes_fp[iftype], all_packets_fp[iftype]);
		printf("Total: SP Bytes:%16lu   SP Packets:%16lu\n",
			all_bytes_sp[iftype], all_packets_sp[iftype]);
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
	/* TODO: Remember to cleanup map, when adding use of shared map
	 *  bpf_map_delete_elem((map_fd, &idx);
	 */
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
		else if (strcmp(key, "interface") == 0)
			strncpy(interface_name, val, sizeof(interface_name) - 1);
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
		fgets(mac_addr_str, 3*ETH_ALEN, fp);
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

int main(int argc, char **argv)
{
	const char *prog_name = "xdp_fp";
	struct bpf_program *prog = NULL;
	struct bpf_program *pos;
	const char *sec_name;
	int prog_fd = -1;
	char filename[PATH_MAX];
	struct bpf_object *obj;
	int opt, i, idx, err;
	int attach = 1;
	int ret = -1;

	int ipv4_fd = -1, ipv6_fd = -1, route_fd = -1;
	char lif[MAX_IF_NAME_LEN], wif[MAX_IF_NAME_LEN];

	int reset_stat = 0, print_stat = 0, ff_disabled = 0, ff_status, show_globals = 0;
	int ff_update = 1;
	int fd_stats, fd_globals;
	struct stats_entry *stats_value;
	int stats_key = GLOB_STAT;
	int globals_key;
	unsigned int nr_cpus = sysconf(_SC_NPROCESSORS_CONF);

	while ((opt = getopt(argc, argv, "dDSFzsergh")) != -1) {
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
			case 'D':
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
			case 'h':
				print_usage(basename(argv[0]));
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

	if (attach) {
		if (argv[0][0]== '.' && argv[0][1]=='/')
			snprintf(filename, sizeof(filename), "%s_kern.o", &argv[0][2]);
		else
			snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

		if (access(filename, O_RDONLY) < 0) {
			printf("error accessing file %s: %s\n",
				filename, strerror(errno));
			return 1;
		}

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
	}

	for (i = optind; i < argc; ++i) {
		idx = if_nametoindex(argv[i]);
		if (!idx)
			idx = strtoul(argv[i], NULL, 0);

		if (!idx) {
			fprintf(stderr, "Invalid arg\n");
			return 1;
		}
		if (!attach) {
			err = do_detach(idx, argv[i], prog_name);
			if (err)
				ret = err;
		} else {
			err = do_attach(idx, prog_fd, argv[i]);
			if (err)
				ret = err;
		}
	}
	snprintf(lif, sizeof(lif), "%s", argv[2]);
	snprintf(wif, sizeof(wif), "%s", argv[3]);

	/* Update the ebpf maps*/
	ret = get_device_info(lif, if1_mac_addr, &lan_if);
	if (ret)
		goto out;
	ret = get_device_info(wif, if2_mac_addr, &wan_if);
	if (ret)
		goto out;

	ipv4_fd = bpf_obj_get(PINNED_IPV4);
	if (ipv4_fd < 0) {
		fprintf(stderr, "bpf_obj_get(%s): %s(%d)\n",
				PINNED_IPV4, strerror(errno), errno);
		goto out;
	}

	route_fd = bpf_obj_get(PINNED_ROUTE);
	if (route_fd < 0) {
		fprintf(stderr, "bpf_obj_get(%s): %s(%d)\n",
				PINNED_ROUTE, strerror(errno), errno);
		goto out;
	}

	ret = route_add(route_fd, lan_if, if1_mac_addr, dst_mac_addr1, NULL);
	if (ret) {
		fprintf(stderr, "BPF update route: %d", lan_if);
		goto out;
	}

	ret = route_add(route_fd, wan_if, if2_mac_addr, dst_mac_addr2, NULL);
	if (ret) {
		fprintf(stderr, "BPF update route: %d", wan_if);
		goto out;
	}

	ret = update_ipv4_entries(ipv4_fd);
	if (ret) {
		perror("BPF update IPv4 entries");
		goto out;
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
		printf("glob_ff_disabled: %d\n", global_value);
	}

	free(stats_value);

	return ret;

out:
        if (route_fd != -1)
                close(route_fd);
        if (ipv4_fd != -1)
                close(ipv4_fd);
        if (ipv6_fd != -1)
                close(ipv6_fd);

	return ret;

}
