/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright 2025 NXP
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ipv6.h>

#include <bpf/bpf_helpers.h>

#include <stdbool.h>
#include "xdp_fp.h"
#include "xdp_fp_common.h"
#include "ipv4.h"
#include "transport.h"

struct vlan_hdr {
        __be16  h_vlan_TCI;
        __be16  h_vlan_encapsulated_proto;
};

struct vlan_ethhdr {
	unsigned char   h_dest[ETH_ALEN];
	unsigned char   h_source[ETH_ALEN];
	__be16      h_vlan_proto;
	__be16      h_vlan_TCI;
	__be16      h_vlan_encapsulated_proto;
};

#define MAX_MODULES     6
#define MAX_CPUS        6
#define PIN_GLOBAL_NS   2
#define ETHER_ADDR_LEN 6

#define ETHERTYPE_IPV4                  0x0800
#define ETHERTYPE_IPV6                  0x86DD
#define ETHERTYPE_VLAN                  0x8100
#define ETHERTYPE_VLAN_STAG		0x88a8

#define NEXTHDR_UDP     17
#define NEXTHDR_TCP     6
#define NEXTHDR_ROUTING 43
#define NEXTHDR_HOP     0
#define NEXTHDR_DEST    60
#define MAX_EXT_HEADERS 16U
#define IPV6_VERSION    6U
#define IPV6_HEADER_LENGTH 40U

struct {
	__uint(type,BPF_MAP_TYPE_ARRAY);
	__uint(key_size,sizeof(u32));
	__uint(value_size,sizeof(u32));
	__uint(pinning,LIBBPF_PIN_BY_NAME);
	__uint(max_entries,MAX_MODULES);
} fp_modules SEC(".maps");

struct {
	__uint(type,BPF_MAP_TYPE_ARRAY);
	__uint(key_size,sizeof(int));
	__uint(value_size,sizeof(int));
	__uint(pinning,LIBBPF_PIN_BY_NAME);
	__uint(max_entries,GLOB_MAX);
} fp_globals SEC(".maps");

/* packets forwarding statistics map */
struct {
	__uint(type,BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size,sizeof(int));
	__uint(value_size,sizeof(struct stats_entry));
	__uint(pinning,LIBBPF_PIN_BY_NAME);
	__uint(max_entries,MAX_CPUS);
} fp_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size,sizeof(struct ipv4_flow));
	__uint(value_size,sizeof(struct ipv4_info));
	__uint(pinning,LIBBPF_PIN_BY_NAME);
	__uint(max_entries,MAX_IPV4_ENTRIES);
} fp_ipv4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size,sizeof(struct ipv6_flow));
	__uint(value_size,sizeof(struct ipv6_info));
	__uint(pinning,LIBBPF_PIN_BY_NAME);
	__uint(max_entries,MAX_IPV6_ENTRIES);
} fp_ipv6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, ETH_ALEN);
	__uint(value_size, sizeof(int));
	__uint(pinning,LIBBPF_PIN_BY_NAME);
	__uint(max_entries, MAX_MAC_ADDR);
} fp_mac_to_port SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
	__uint(pinning,LIBBPF_PIN_BY_NAME);
	__uint(max_entries, MAX_PORT);
} fp_tx_ports SEC(".maps");

static void __always_inline ipv6_copy(u32 *a, u32 *b)
{
        a[0] = b[0];
	a[1] = b[1];
	a[2] = b[2];
	a[3] = b[3];
}

struct {
	__uint(type,BPF_MAP_TYPE_ARRAY);
	__uint(key_size,sizeof(int));
	__uint(value_size,sizeof(struct route));
	__uint(pinning,LIBBPF_PIN_BY_NAME);
	__uint(max_entries,MAX_FP_ROUTES);
} fp_route SEC(".maps");

static __always_inline int prepare_transmit(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth;
	struct route *route;
	u64 nh_off = sizeof(struct ethhdr);
	u16 h_proto;
	int ifindex, index_key, index_key_stat = GLOB_STAT;
	struct stats_entry *stats;
#ifdef DEBUG
	const char module[] = "TX";
#endif

	stats = bpf_map_lookup_elem(&fp_stats, &index_key_stat);
	if (!stats) {
		bpf_debug("%s: No stats enabled\n", module);
		goto pass;
	}

	if (data + sizeof(int) > data_end) {
		bpf_debug("%s: Invalid data(%p) + sizeof(int) > data_end(%p) => XDP_PASS\n",
				module, data, data_end);
		goto pass;
	}

	/* Retrieve ifindex as metadata from the buffer head */
	ifindex = *((int *)(data));

	/* Skip metadata & adjust head */
	if (bpf_xdp_adjust_head(ctx, (int)sizeof(int))) {
		bpf_debug("%s: bpf_xdp_adjust_head(%d) failure\n", module, (int)sizeof(int));
		goto pass;
	}

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	eth = (struct ethhdr *)(data);

	if ((void *)(eth + 1) > data_end) {
		bpf_debug("%s: Invalid eth(%p) + 1 > data_end(%p) => XDP_PASS\n",
				module, (void *)eth, data_end);
		goto pass;
	}

	h_proto = eth->h_proto;

	if (h_proto == htons(ETHERTYPE_VLAN) ||
			h_proto == htons(ETHERTYPE_VLAN_STAG)) {
		nh_off += sizeof(struct vlan_hdr);
	}

	index_key = ifindex;
	route = bpf_map_lookup_elem(&fp_route, &index_key);
	if (!route) {
		bpf_debug("%s: Non existing route(%d) => XDP_PASS\n", module, index_key);
		goto pass;
	}

	if (route->redir_if_type == ARPHRD_ETHER) {
		/* CMM doesn't count ether_type (2 bytes) in l2_hdr_size */
		if (bpf_xdp_adjust_head(ctx, (int)nh_off - 2 - (int)route->l2_hdr_size)) {
			bpf_debug("%s: bpf_xdp_adjust_head(%d) failure => XDP_PASS\n",
					module, (int)nh_off - 2 - (int)route->l2_hdr_size);
			goto pass;
		}

		data = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;

		if (data + MAX_L2_HEADER_SIZE > data_end) {
			bpf_debug("%s: Invalid data(%p) + MAX_L2_HEADER_SIZE > data_end(%p)\n",
					module, data, data_end);
			goto pass;
		}

		/* Copy full ethernet header (without the 2 bytes ether_type) */
		__builtin_memcpy(data, route->l2_hdr, (unsigned int)(2 * ETHER_ADDR_LEN));
		/* Copy VLAN info in Ethernet header if present */
		if (route->l2_hdr_size > (u16)(2 * ETHER_ADDR_LEN)) {
			__builtin_memcpy(data + 2 * ETHER_ADDR_LEN,
					&route->l2_hdr[2 * ETHER_ADDR_LEN], sizeof(struct vlan_hdr));
			/* Keep 2 bytes ether_type as per original ethernet data received */
			bpf_debug("%s: VLAN TPID(%x) VLAN TCI(%u)\n",
					module,
					htons(*(u16 *)(data + 2 * ETHER_ADDR_LEN)),
					htons(*((u16 *)(data + 2 * ETHER_ADDR_LEN) + 1)));
		}
	}
	else if (route->redir_if_type == ARPHRD_RAWIP) {
		/* Redirect IP packet to RAWIP interface, strip ethernet header */
		if (bpf_xdp_adjust_head(ctx, (int)nh_off)) {
			bpf_debug("%s: bpf_xdp_adjust_head(%d) failure => XDP_PASS\n",
					module, (int)nh_off);
			goto pass;
		}

		data = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;
	}
	else {
		bpf_debug("%s: Invalid redir_if_type(%d) => XDP_PASS\n",
				module, route->redir_if_type);
		goto pass;
	}

	bpf_debug("TX: Redirect packet:%llu (%llu) to interface:%d\n",
			stats->packets_fp[GLOB_IP_MODE], (u64)ctx->data_end - (u64)ctx->data, route->redir_ifindex);
	if (stats) {
		stats->packets_fp[GLOB_IP_MODE]++;
		stats->bytes_fp[GLOB_IP_MODE] += (u64)ctx->data_end - (u64)ctx->data;
	}

	return bpf_redirect(route->redir_ifindex, 0);

	/* Fallthrough */
	bpf_debug("%s: Fallthrough(%llu) => XDP_PASS\n",
			module, (u64)ctx->data_end - (u64)ctx->data);

pass:
	bpf_debug("%s: => XDP_PASS(%llu)\n", module, (u64)ctx->data_end - (u64)ctx->data);
	if (stats) {
		stats->packets_sp[GLOB_IP_MODE]++;
		stats->bytes_sp[GLOB_IP_MODE] += (u64)ctx->data_end - (u64)ctx->data;
	}

	return XDP_PASS;
}

static __always_inline int parse_ipv6(struct xdp_md *ctx)
{
	u8 *next_hdr, protocol;
	bool loop_cont = true;
	unsigned int hdr_len = 0UL;
	struct ipv6_flow ipv6_key = {};
	struct ipv6_info *info = NULL;
	unsigned int i, check;
	struct udp_hdr *udph;
	struct tcp_hdr *tcph;
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ipv6hdr *iph;
	struct ethhdr *eth = (struct ethhdr *)data;
	u16 h_proto;
	u64 nh_off = sizeof(struct ethhdr);
	int *ifindex, index_key_stat = GLOB_STAT;
	struct stats_entry *stats;
#ifdef DEBUG
	const char module[] = "IPV6";
#endif

	stats = bpf_map_lookup_elem(&fp_stats, &index_key_stat);
	if (!stats) {
		bpf_debug("%s: No stats enabled\n", module);
		goto pass;
	}

	if (data + nh_off > data_end) {
		bpf_debug("%s: Invalid data(%p) + nh_off > data_end(%p) => XDP_PASS\n", module, data, data_end);
		goto pass;
	}

	h_proto = eth->h_proto;

	if (h_proto == htons(ETHERTYPE_VLAN) ||
			h_proto == htons(ETHERTYPE_VLAN_STAG)) {
		nh_off += sizeof(struct vlan_hdr);
		if (data + nh_off > data_end) {
			bpf_debug("%s/VLAN: Invalid data(%p) + nh_off > data_end(%p) => XDP_PASS\n",
					module, data, data_end);
			goto pass;
		}
	}

	iph = (struct ipv6hdr *)(data + nh_off);

	if ((void *)(iph + 1) > data_end) {
		bpf_debug("%s: Invalid IP header length => XDP_PASS\n", module);
		goto pass;
	}

	if (iph->version != 6U || iph->hop_limit <= 1U) {
		bpf_debug("%s: Invalid IP header (%u %u) => XDP_PASS\n",
				module, (unsigned int)(iph->version), (unsigned int)(iph->hop_limit));
		goto pass;
	}

	next_hdr = (u8 *)(iph + 1);
	if ((void *)(next_hdr + 2) > data_end) {
		bpf_debug("%s: Invalid next_hdr(%p) + 2 > data_end(%p) => XDP_PASS\n",
				module, (void *)next_hdr, data_end);
		goto pass;
	}

	protocol = iph->nexthdr;

	if (protocol == NEXTHDR_UDP || protocol == NEXTHDR_TCP)
		loop_cont = false;

#pragma clang loop unroll(full)
	for (i = 0; loop_cont && i < MAX_EXT_HEADERS; i++) {
		if (protocol == NEXTHDR_ROUTING || protocol == NEXTHDR_HOP
				|| protocol == NEXTHDR_DEST) {
			protocol = next_hdr[0];
			hdr_len = ((unsigned int)next_hdr[1] + 1U) << 3;
			next_hdr += hdr_len;
			if ((void *)(next_hdr + 2) > data_end) {
				bpf_debug("%s: Invalid next_hdr(%p) + 2 > data_end(%p) => XDP_PASS\n",
						module, (void *)next_hdr, data_end);
				goto pass;
			}
		} else {
			loop_cont = false;
		}
	}

	if (loop_cont) {
		bpf_debug("%s/TCP: loop_cont:%u => XDP_PASS\n", module, (unsigned int)loop_cont);
		goto pass;
	}

	switch (protocol) {
		case IPPROTOCOL_UDP:
			udph = (struct udp_hdr *)next_hdr;

			if ((void *)(udph + 1) > data_end) {
				bpf_debug("%s/UDP: Invalid udph(%p) + 1 > data_end(%p) => XDP_PASS\n",
						module, (void *)udph, data_end);
				return XDP_PASS;
			}

			ipv6_copy(ipv6_key.saddr, (u32 *)&iph->saddr);
			ipv6_copy(ipv6_key.daddr, (u32 *)&iph->daddr);
			ipv6_key.sport = udph->source_port;
			ipv6_key.dport = udph->dest_port;
			ipv6_key.protocol = protocol;

			info = bpf_map_lookup_elem(&fp_ipv6, &ipv6_key);
			if (!info) {
				bpf_debug("%s/UDP: No element found  => XDP_PASS\n", module);
				goto pass;
			}

			/* Check for route validity */
			if (info->route_ifindex < 0) {
				bpf_debug("%s/UDP: Invalid route => XDP_PASS\n", module);
				goto pass;
			}

			/* Check for IP datagram length validity */
			if ((htons(iph->payload_len) + IPV6_HEADER_LENGTH > info->mtu) ||
					(((u64)data_end - (u64)data - (u64)nh_off) > (u64)info->mtu)) {
				bpf_debug("%s/UDP: Invalid IP size (%u) > MTU (%u) => XDP_PASS\n",
						module, (unsigned int)(htons(iph->payload_len) + IPV6_HEADER_LENGTH), (unsigned int)(info->mtu));
				goto pass;
			}

			info->active = 1U;

			/* WARNING!!! packet may be modified by xdp program after this point
			 * Linux networking stack may be lost handling the PASS packets */
			if (info->flags & FP_INFO_FLAG_NAT) {
				/* Update addresses and ports */
				ipv6_copy((u32 *)&iph->saddr, info->nat_saddr);
				ipv6_copy((u32 *)&iph->daddr, info->nat_daddr);
				udph->source_port = info->nat_sport;
				udph->dest_port = info->nat_dport;
				if (udph->checksum) {
					check = udph->checksum + info->trans_csum_corr;
					if (check + 1U >= 0x10000U)
						check++;
					udph->checksum = (u16)check;
				}
			}
			break;
		case IPPROTOCOL_TCP:
			tcph = (struct tcp_hdr *)next_hdr;

			if ((void *)(tcph + 1) > data_end) {
				bpf_debug("%s/TCP: Invalid tcph(%p) + 1 > data_end(%p) => XDP_PASS\n",
						module, (void *)tcph, data_end);
				goto pass;
			}

			/* Make sure all SYN/ACK (iow all SYN) packets are sent the Host even
			 * when the connection is already established. For some specific needs
			 * Host application may want to monitor _all_ syn/ack to modify MSS
			 * value */
			if (tcph->rst || tcph->fin || tcph->syn) {
				bpf_debug("IPV6/TCP: rst(%u)/fin(%u)/syn(%u) => XDP_PASS\n",
						(unsigned int)(tcph->rst), (unsigned int)(tcph->fin), (unsigned int)(tcph->syn));
				goto pass;
			}

			ipv6_copy(ipv6_key.saddr, (u32 *)&iph->saddr);
			ipv6_copy(ipv6_key.daddr, (u32 *)&iph->daddr);
			ipv6_key.sport = tcph->source_port;
			ipv6_key.dport = tcph->dest_port;
			ipv6_key.protocol = protocol;

			info = bpf_map_lookup_elem(&fp_ipv6, &ipv6_key);
			if (!info) {
				bpf_debug("%s/TCP: No element found => XDP_PASS\n", module);
				goto pass;
			}

			/* Check for route validity */
			if (info->route_ifindex < 0) {
				bpf_debug("%s/TCP: Invalid route => XDP_PASS\n", module);
				goto pass;
			}
			/* Check for IP datagram length validity */
			if ((htons(iph->payload_len) + IPV6_HEADER_LENGTH > info->mtu) ||
					(((u64)data_end - (u64)data - (u64)nh_off) > (u64)info->mtu)) {
				bpf_debug("%s/TCP: Invalid IP size (%u) > MTU (%u) => XDP_PASS\n",
						module, (unsigned int)(htons(iph->payload_len) + IPV6_HEADER_LENGTH), (unsigned int)(info->mtu));
				goto pass;
			}
			info->active = 1U;

			/* WARNING!!! packet may be modified by xdp program after this point
			 * Linux networking stack may be lost handling the PASS packets */
			if (info->flags & FP_INFO_FLAG_NAT) {
				/* Update addresses and ports */
				ipv6_copy((u32 *)&iph->saddr, info->nat_saddr);
				ipv6_copy((u32 *)&iph->daddr, info->nat_daddr);
				tcph->source_port = info->nat_sport;
				tcph->dest_port = info->nat_dport;

				check = tcph->checksum + info->trans_csum_corr;
				if (check + 1U >= 0x10000U)
					check++;
				tcph->checksum = (u16)check;
			}
			break;
		default:
			bpf_debug("%s: Unknown protocol:%u => XDP_PASS\n", module, (unsigned int)protocol);
			goto pass;
	}

	/* Reduce HOP limit */
	iph->hop_limit--;

	/* Add ifindex as metadata to the buffer head */
	if (bpf_xdp_adjust_head(ctx, 0 -(int)sizeof(int))) {
		bpf_debug("%s: bpf_xdp_adjust_head(%d) failure\n", module, 0 - (int)sizeof(int));
		goto pass;
	}

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(int) > data_end) {
		bpf_debug("%s: Invalid data(%p) + sizeof(int) > data_end(%p) => XDP_PASS\n",
				module, data, data_end);
		goto pass;
	}

	ifindex = (int *)(data);
	*ifindex = info->route_ifindex;

	return prepare_transmit(ctx);

pass:
	bpf_debug("%s: => XDP_PASS(%llu)\n", module, (u64)ctx->data_end - (u64)ctx->data);
	if (stats) {
		stats->packets_sp[GLOB_IP_MODE]++;
		stats->bytes_sp[GLOB_IP_MODE] += (u64)ctx->data_end - (u64)ctx->data;
	}
	return XDP_PASS;
}

static __always_inline int parse_ipv4(struct xdp_md *ctx)
{
	struct udp_hdr *udph;
	struct tcp_hdr *tcph;
	struct ipv4_flow ipv4_key = {};
	struct ipv4_info *info = NULL;
	unsigned int check;
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct ipv4_hdr *iph;
	struct ethhdr *eth = (struct ethhdr *)data;
	u16 h_proto;
	u64 nh_off = sizeof(struct ethhdr);
	int *ifindex, index_key_stat = GLOB_STAT;
	struct stats_entry *stats;
#ifdef DEBUG
	const char module[] = "IPV4";
#endif

	stats = bpf_map_lookup_elem(&fp_stats, &index_key_stat);
	if (!stats) {
		bpf_debug("%s: No stats enabled\n", module);
		goto pass;
	}

	if (data + nh_off > data_end) {
		bpf_debug("%s: Invalid data(%p) + nh_off > data_end(%p) => XDP_PASS\n",
			module, data, data_end);
		goto pass;
	}

	h_proto = eth->h_proto;

	if (h_proto == htons(ETHERTYPE_VLAN) ||
			h_proto == htons(ETHERTYPE_VLAN_STAG)) {
		nh_off += sizeof(struct vlan_hdr);
		if (data + nh_off > data_end) {
			bpf_debug("%s/VLAN: Invalid data(%p) + nh_off > data_end(%p) => XDP_PASS\n",
				module, data, data_end);
			goto pass;
		}
	}

	iph = (struct ipv4_hdr *) (data + nh_off);

	if ((void *)(iph + 1) > data_end) {
		bpf_debug("%s: Invalid IP header length => XDP_PASS\n", module);
		goto pass;
	}
	if (iph->ihl < 5
			|| iph->version != 4
			|| iph->frag_offset & htons(IP_OFFSET | IP_MF)
			|| iph->ttl <= 1) {
		bpf_debug("IPV4: Invalid IP header (%u %u %u) => XDP_PASS\n",
				(unsigned int)(iph->ihl), (unsigned int)(iph->version), (unsigned int)(iph->ttl));
		goto pass;
	}

	switch (iph->protocol) {
		case IPPROTOCOL_UDP:
			udph = (struct udp_hdr *) ((u8 *)iph + (unsigned char)(iph->ihl << 2));

			if ((void *)(udph + 1) > data_end) {
				bpf_debug("%s/UDP: Invalid udph(%p) + 1 > data_end(%p) => XDP_PASS\n",
						module, (void *)udph, data_end);
				goto pass;
			}

			ipv4_key.saddr = iph->source_addr;
			ipv4_key.daddr = iph->dest_addr;
			ipv4_key.protocol = iph->protocol;
			ipv4_key.sport = udph->source_port;
			ipv4_key.dport = udph->dest_port;

			info = bpf_map_lookup_elem(&fp_ipv4, &ipv4_key);
			if (!info) {
				bpf_debug("%s/UDP: No element found saddr:%x daddr:%x => XDP_PASS\n",
						module, ipv4_key.saddr, ipv4_key.daddr);
				goto pass;
			}

			/* Check for route validity */
			if (info->route_ifindex < 0) {
				bpf_debug("%s/UDP: Invalid route => XDP_PASS\n", module);
				goto pass;
			}

			/* Check for IP datagram length validity */
			if ((htons(iph->total_len) > info->mtu) || 
					(((u64)data_end - (u64)data - (u64)nh_off) > (u64)info->mtu)) {
				bpf_debug("%s/UDP: Invalid IP size (%u) > MTU (%u) => XDP_PASS\n",
						module, (unsigned int)(htons(iph->total_len)), (unsigned int)(info->mtu));
				goto pass;
			}

			info->active = 1U;

			/* WARNING!!! packet may be modified by xdp program after this point
			 * Linux networking stack may be lost handling the PASS packets */
			if (info->flags & FP_INFO_FLAG_NAT) {
				iph->source_addr = info->nat_saddr;
				iph->dest_addr = info->nat_daddr;
				udph->source_port = info->nat_sport;
				udph->dest_port = info->nat_dport;

				if (udph->checksum) {
					check = udph->checksum + info->trans_csum_corr;
					if (check + 1U >= 0x10000U)
						check++;
					udph->checksum = (u16)check;
				}
			}
			break;
		case IPPROTOCOL_TCP:
			tcph = (struct tcp_hdr *) ((u8 *)iph + (unsigned char)(iph->ihl << 2));

			if ((void *)(tcph + 1) > data_end) {
				bpf_debug("%s/TCP: Invalid tcph(%p) + 1 > data_end(%p) => XDP_PASS\n",
						module, (void *)tcph, data_end);
				return XDP_PASS;
			}

			/* Make sure all SYN/ACK (iow all SYN) packets are sent the Host even
			 * when the connection is already established. For some specific needs
			 * Host application may want to monitor _all_ syn/ack to modify MSS
			 * value */
			if (tcph->rst || tcph->fin || tcph->syn) {
				bpf_debug("IPV4/TCP: rst(%u)/fin(%u)/syn(%u) => XDP_PASS\n",
						(unsigned int)(tcph->rst), (unsigned int)(tcph->fin), (unsigned int)(tcph->syn));
				goto pass;
			}

			ipv4_key.saddr = iph->source_addr;
			ipv4_key.daddr = iph->dest_addr;
			ipv4_key.protocol = iph->protocol;
			ipv4_key.sport = tcph->source_port;
			ipv4_key.dport = tcph->dest_port;

			info = bpf_map_lookup_elem(&fp_ipv4, &ipv4_key);
			if (!info) {
				bpf_debug("%s/TCP: No element found saddr:%x daddr:%x => XDP_PASS\n",
						module, ipv4_key.saddr, ipv4_key.daddr);
				goto pass;
			}

			/* Check for route validity */
			if (info->route_ifindex < 0) {
				bpf_debug("%s/TCP: Invalid route => XDP_PASS\n", module);
				goto pass;
			}

			if ((htons(iph->total_len) > info->mtu) ||
					(((u64)data_end - (u64)data - (u64)nh_off) > (u64)info->mtu)) {
				bpf_debug("%s/TCP: Invalid IP size (%u) > MTU (%u) => XDP_PASS\n",
						module, (unsigned int)(htons(iph->total_len)), (unsigned int)(info->mtu));
				goto pass;
			}

			info->active = 1U;

			/* WARNING!!! packet may be modified by xdp program after this point
			 * Linux networking stack may be lost handling the PASS packets */
			if (info->flags & FP_INFO_FLAG_NAT) {
				/* Update addresses and ports */
				iph->source_addr = info->nat_saddr;
				iph->dest_addr = info->nat_daddr;
				tcph->source_port = info->nat_sport;
				tcph->dest_port = info->nat_dport;

				check = tcph->checksum + info->trans_csum_corr;
				if (check + 1U >= 0x10000U)
					check++;
				tcph->checksum = (u16)check;
			}
			break;
		default:
			bpf_debug("%s: Unknown protocol:%u => XDP_PASS\n", module, (unsigned int)(iph->protocol));
			goto pass;
	}

	/* Reduce TTL */
	iph->ttl--;

	/* Update IP checksum */
	check = iph->header_csum + info->ip_csum_corr;
	if (check + 1U >= 0x10000U)
		check++;
	iph->header_csum = (u16)check;

	/* Add ifindex as metadata to the buffer head */
	if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(int))) {
		bpf_debug("%s: bpf_xdp_adjust_head(%d) failure\n", module, 0 - (int)sizeof(int));
		goto pass;
	}

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	if (data + sizeof(int) > data_end) {
		bpf_debug("%s: Invalid data(%p) + sizeof(int) > data_end(%p) => XDP_PASS\n",
				module, data, data_end);
		goto pass;
	}

	ifindex = (int *)(data);
	*ifindex = info->route_ifindex;

	return prepare_transmit(ctx);

pass:
	bpf_debug("%s: => XDP_PASS(%llu)\n", module, (u64)ctx->data_end - (u64)ctx->data);
	if (stats) {
		stats->packets_sp[GLOB_IP_MODE]++;
		stats->bytes_sp[GLOB_IP_MODE] += (u64)ctx->data_end - (u64)ctx->data;
	}

	return XDP_PASS;
}

SEC("xdp_fp_bridge")
int xdp_fp_bridge_prog(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct stats_entry *stats = NULL;
	int *ff_disabled, index_key = GLOB_FF_DISABLE, index_key_stat = GLOB_STAT;

	if ((void *)(eth + 1) > data_end)
		goto pass;

	stats = bpf_map_lookup_elem(&fp_stats, &index_key_stat);
	if (!stats) {
		bpf_debug("%s: No stats enabled\n", module);
		goto pass;
	}

	ff_disabled =  bpf_map_lookup_elem(&fp_globals, &index_key);
	if (!ff_disabled || *ff_disabled) {
		bpf_debug("%s: fast forward disabled => XDP_PASS\n", module);
		goto pass;
	}
	__u32 in_port = ctx->ingress_ifindex;
	__u8 *src_mac = eth->h_source;
	__u8 *dst_mac = eth->h_dest;

	// Learn source MAC
	bpf_map_update_elem(&fp_mac_to_port, src_mac, &in_port, BPF_ANY);

	// Lookup destination MAC
	__u32 *out_port = bpf_map_lookup_elem(&fp_mac_to_port, dst_mac);

	if (out_port && *out_port != in_port) {
		// Forward to known port
		stats->packets_fp[GLOB_BRIDGE_MODE]++;
		stats->m_pkts_fp[GLOB_BRIDGE_MODE]++;
		stats->bytes_fp[GLOB_BRIDGE_MODE] += (u64)ctx->data_end - (u64)ctx->data;
		return bpf_redirect_map(&fp_tx_ports, *out_port, 0);
	}

	// Flood to all ports except ingress
	stats->packets_fp[GLOB_BRIDGE_MODE]++;
	stats->nm_pkts_fp[GLOB_BRIDGE_MODE]++;
	stats->bytes_fp[GLOB_BRIDGE_MODE] += (u64)ctx->data_end - (u64)ctx->data;
	return bpf_redirect_map(&fp_tx_ports, 0, BPF_F_BROADCAST | BPF_F_EXCLUDE_INGRESS);
pass:
	bpf_debug("%s: => XDP_PASS(%llu)\n", module, (u64)ctx->data_end - (u64)ctx->data);
	if (stats) {
		stats->packets_sp[GLOB_BRIDGE_MODE]++;
		stats->bytes_sp[GLOB_BRIDGE_MODE] += (u64)ctx->data_end - (u64)ctx->data;
	}

	return XDP_PASS;

}

SEC("xdp_fp")
int xdp_fp_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = (struct ethhdr *)data;
	int *ff_disabled, index_key = GLOB_FF_DISABLE, index_key_stat = GLOB_STAT;
	u64 nh_off = sizeof(struct ethhdr);
	u16 h_proto;
	struct stats_entry *stats;
#ifdef DEBUG
	const char module[] = "XDP";
#endif

	stats = bpf_map_lookup_elem(&fp_stats, &index_key_stat);
	if (!stats) {
		bpf_debug("%s: No stats enabled\n", module);
		goto pass;
	}

	if (data + nh_off > data_end) {
		bpf_debug("%s: Invalid data(%p) + nh_off > data_end(%p) => XDP_PASS\n",
			module, data, data_end);
		goto pass;
	}

	ff_disabled =  bpf_map_lookup_elem(&fp_globals, &index_key);
	if (!ff_disabled || *ff_disabled) {
		bpf_debug("%s: fast forward disabled => XDP_PASS\n", module);
		goto pass;
	}

	h_proto = eth->h_proto;

	if (h_proto == htons(ETHERTYPE_VLAN) ||
			h_proto == htons(ETHERTYPE_VLAN_STAG)) {
		struct vlan_ethhdr *vhdr = data;

		if ((void *)(vhdr + 1) > data_end) {
			bpf_debug("%s: Invalid vhdr(%p) + 1 > data_end(%p) => XDP_PASS\n",
					module, (void *)vhdr, data_end);
			goto pass;
		}
#ifdef VLAN_TRACING
		bpf_debug("%s: VLAN TPID(%x) VLAN TCI (%u)\n",
			module, htons(vhdr->h_vlan_proto), (unsigned int)htons(vhdr->h_vlan_TCI));
#endif
		h_proto = vhdr->h_vlan_encapsulated_proto;
	}

	if (h_proto == htons(ETHERTYPE_IPV4)) {
		/* bpf_debug("Calling IPV4 module\n"); */
		return parse_ipv4(ctx);
	}
	else if (h_proto == htons(ETHERTYPE_IPV6)) {
		/* bpf_debug("Calling IPV6 module\n"); */
		return parse_ipv6(ctx);
//		bpf_tail_call(ctx, &fp_modules, IPV6_ENTRY);
	}

	/* Fallthrough */
	bpf_debug("%s: Unmanaged protocol:%x => XDP_PASS\n", module, htons(h_proto));

pass:
	bpf_debug("%s: => XDP_PASS(%llu)\n", module, (u64)ctx->data_end - (u64)ctx->data);
	if (stats) {
		stats->packets_sp[GLOB_IP_MODE]++;
		stats->bytes_sp[GLOB_IP_MODE] += (u64)ctx->data_end - (u64)ctx->data;
	}

	return XDP_PASS;
}

char _license[] __section("license") = "GPL";
