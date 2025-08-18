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

#include <linux/if_link.h>
#include <linux/limits.h>
#include <libgen.h>

#include "xdp_fp_user.h"

/* Default MAC addresses */
unsigned char if1_mac_addr[ETH_ALEN] =
		{ 0x00, 0x04, 0x9F, 0x05, 0xC8, 0x39 };
unsigned char dst_mac_addr1[ETH_ALEN] =
		{ 0x02, 0xFF, 0xFF, 0xFF, 0x01, 0x02 };

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
	fprintf(stderr, " -P    Populate NAT64 configuration \n");
	fprintf(stderr, " -l    set rate limit of a flow \n");
	fprintf(stderr, " -u    load user given rules from input.txt, Applicable with -a option only. \n");
	fprintf(stderr, "\n");
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

int main(int argc, char **argv)
{
	const char *prog_name = "xdp_fp";
	char filename[PATH_MAX];
	const char *sec_name;
	struct bpf_program *pos;
	struct bpf_object *obj;
	int prog_fd = -1, nat64_fd = -1, nat46_fd = -1;
	int opt, i, idx, err, icount = 0;
	int ret = -1;
	int attach = 1;
	__u32 port_key = -1, port_value = -1;
	int modules_key;

	int ipv4_fd = -1, ipv6_fd = -1, route_fd = -1, port_fd = -1, modules_fd = -1;
	char fif[MAX_IF_NAME_LEN];

	int reset_stat = 0, print_stat = 0, ff_disabled = 0, ff_status, show_globals = 0,
	    user_rules = 0;
	int ff_update = 1;
	int fd_stats, fd_globals;
	struct stats_entry *stats_value;
	int stats_key = GLOB_STAT;
	int globals_key;
	unsigned int nr_cpus = sysconf(_SC_NPROCESSORS_CONF);

	while ((opt = getopt(argc, argv, "dauSFzserghblDP")) != -1) {
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
				ff_update = 0;
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
				dump_ipv4_flows();
				dump_ipv6_flows();
				dump_fp_routes();
#ifdef NAT64_SIIT
    				dump_nat64_ip6_ip4_src_map();
				dump_nat64_ip4_ip6_src_route_map();
				dump_nat64_dst_ip_route_map();
#endif
				return 1;
			case 'P':
				load_config_and_populate_maps();
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

		modules_fd = bpf_object__find_map_fd_by_name(obj, "fp_modules");
		if (modules_fd < 0) {
			printf("bpf_object__find_map_fd_by_name failed for fp_modules");
			goto out;
		}
	
		bpf_object__for_each_program(pos, obj) {
			sec_name = bpf_program__section_name(pos);
			if (sec_name && !strcmp(sec_name, prog_name)) {
				prog_fd = bpf_program__fd(pos);
				if (prog_fd < 0) {
					printf("program not found: %s\n", strerror(prog_fd));
					goto out;
				}
			}
			if (sec_name && !strcmp(sec_name, "nat64_siit")) {
				nat64_fd = bpf_program__fd(pos);
				if (nat64_fd < 0) {
					printf("program not found: %s\n", strerror(nat64_fd));
					goto out;
				}
				modules_key =  XDP_NAT64_SIIT;
				err = bpf_map_update_elem(modules_fd, &modules_key, &nat64_fd, BPF_ANY);
				if (err) {
					fprintf(stderr, "Update modules_fd fails\n");
					goto out;
				}
			}
			if (sec_name && !strcmp(sec_name, "nat46_siit")) {
				nat46_fd = bpf_program__fd(pos);
				if (nat46_fd < 0) {
					printf("program not found: %s\n", strerror(nat46_fd));
					goto out;
				}
				modules_key =  XDP_NAT46_SIIT;
				err = bpf_map_update_elem(modules_fd, &modules_key, &nat46_fd, BPF_ANY);
				if (err) {
					fprintf(stderr, "Update modules_fd fails\n");
					goto out;
				}
			}
		}

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
		snprintf(fif, sizeof(fif), "%s", argv[i]);

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
        if (nat64_fd != -1)
                close(nat64_fd);
        if (nat46_fd != -1)
                close(nat46_fd);
        if (modules_fd != -1)
                close(modules_fd);

	if (!attach) {
		obj = bpf_object__open_file(filename, NULL);
		if (libbpf_get_error(obj))
			return 1;

		bpf_object__unpin_maps(obj, PINNED_MAPS);
		bpf_object__close(obj);
	}

	return ret;
}
