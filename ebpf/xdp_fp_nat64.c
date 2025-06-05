#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>

#include <bpf/bpf_helpers.h>

#include <stdbool.h>
#include "xdp_fp.h"
#include "xdp_fp_common.h"
#include "ipv4.h"
#include "vlan.h"
#include "csum.h"
#include "transport.h"
#include "xdp_fp_maps.h"

static __always_inline bool is_ipv6_ext_hdr(__u8 nexthdr) {
	switch (nexthdr) {
		case 0:   // Hop-by-Hop Options
		case 43:  // Routing
		case 44:  // Fragment
		case 50:  // ESP
		case 51:  // AH
		case 60:  // Destination Options
		case 135: // Mobility
			return true;
		default:
			return false;
	}
}

SEC("nat64_siit")
int nat64_siit_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct ipv6hdr *ip6h;
	int nh_off;
	__be32 ipv4_src;
	const int ip6_hdr_len = IPV6_HEADER_LENGTH;
	const int ip4_hdr_len = IPV4_HEADER_LENGTH;
	int adjust;
	struct iphdr *iph;
        struct icmp6hdr *icmp6;
        struct icmphdr *icmp4;
	__be32 *route_id, ridx;
        struct route *route;
	u8 ttl, protocol;
#ifdef DEBUG
	const char module[] = "NAT64_SIIT";
#endif

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	ip6h = (void *)(eth + 1);
	if ((void *)(ip6h + 1) > data_end) return XDP_PASS;

	nh_off = sizeof(struct ethhdr);

	if (ip6h->nexthdr != IPPROTO_ICMPV6) {
		bpf_debug("%s, Only ICMP NAT64 supported\n", module);
		return XDP_PASS;
	}
	/* Drop frames which carry extensions headers */
	if (is_ipv6_ext_hdr(ip6h->nexthdr)) {
		bpf_debug("%s, extension headers not  supported\n", module);
		return XDP_PASS;
	}
	ttl = ip6h->hop_limit;
	protocol = ip6h->nexthdr;
	// Extract IPv4 address from IPv6 destination
	__be32 ipv4_dst = ip6h->daddr.s6_addr32[3];
        //__be32 ipv4_src = ip6h->saddr.s6_addr32[3]; // Simplified assumption

	__be32 *ipv4_src_ptr =  bpf_map_lookup_elem(&nat64_ip6_ip4_src_map, (struct in6_addr *)&ip6h->saddr);
	if (!ipv4_src_ptr) {
		bpf_debug("%s: IPv4_src not found\n", module);
		return XDP_PASS;
        }
        ipv4_src = *ipv4_src_ptr;
	// Calculate header sizes
	adjust = ip6_hdr_len - ip4_hdr_len;

	// Adjust head to make room for smaller IPv4 header
	if (bpf_xdp_adjust_head(ctx, adjust))
		return XDP_PASS;

	// Re-parse headers after head adjustment
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	iph = (void *)(eth + 1);
	if ((void *)(iph + 1) > data_end)
		return XDP_PASS;

	// Fill Ethernet type
	eth->h_proto = htons(ETH_P_IP);
	// Fill IPv4 header
	iph->version = 4;
	iph->ihl = 5;
	/* TOS is not handled */
	iph->tos = 0;
	iph->tot_len = htons((data_end - (void *)iph));
	/* Fragment case is not handled*/
	iph->id = 0;
	iph->frag_off = 0;
	iph->ttl = ttl;
	if (protocol == IPPROTO_ICMPV6)
		iph->protocol = IPPROTO_ICMP;
	else
		iph->protocol = protocol;

	iph->check = 0;
	iph->saddr = ipv4_src;
	iph->daddr = ipv4_dst;

	// Translate ICMPv6 to ICMPv4
	// Recalculate IPv4 checksum
	iph->check = __constant_htons(csum_fold_helper(csum_partial_helper((__u8 *)iph, sizeof(struct iphdr), data_end)));

	icmp6 = (void *)(iph + 1);
	icmp4 = (void *)(iph + 1);
	if ((void *)(icmp6 + 1) > data_end) return XDP_PASS;
	if ((void *)(icmp4 + 1) > data_end) return XDP_PASS;

	/* Switch case code referred from cilium */
	switch (icmp6->icmp6_type) {
		case ICMPV6_ECHO_REQUEST:
			icmp4->type = ICMP_ECHO;
			icmp4->un.echo.id = icmp6->icmp6_identifier;
			icmp4->un.echo.sequence = icmp6->icmp6_sequence;
			icmp4->code = 0;
			break;
		case ICMPV6_ECHO_REPLY:
			icmp4->type = ICMP_ECHOREPLY;
			icmp4->un.echo.id = icmp6->icmp6_identifier;
			icmp4->un.echo.sequence = icmp6->icmp6_sequence;
			icmp4->code = 0;
			break;
		case ICMPV6_DEST_UNREACH:
			icmp4->type = ICMP_DEST_UNREACH;
			switch (icmp6->icmp6_code) {
				case ICMPV6_NOROUTE:
				case ICMPV6_NOT_NEIGHBOUR:
				case ICMPV6_ADDR_UNREACH:
					icmp4->code = ICMP_HOST_UNREACH;
					break;
				case ICMPV6_ADM_PROHIBITED:
					icmp4->code = ICMP_HOST_ANO;
					break;
				case ICMPV6_PORT_UNREACH:
					icmp4->code = ICMP_PORT_UNREACH;
					break;
				default:
					return XDP_PASS;
			}
			break;
		case ICMPV6_TIME_EXCEED:
			icmp4->type = ICMP_TIME_EXCEEDED;
			icmp4->code = icmp6->icmp6_code;
			break;
		case ICMPV6_PARAMPROB:
			switch (icmp6->icmp6_code) {
				case ICMPV6_HDR_FIELD:
					icmp4->type = ICMP_PARAMETERPROB;
					icmp4->code = 0;
				break;
				case ICMPV6_UNK_NEXTHDR:
					icmp4->type = ICMP_DEST_UNREACH;
					icmp4->code = ICMP_PROT_UNREACH;
					break;
				}
			break;
		case ICMPV6_PKT_TOOBIG:
		default:
			return XDP_PASS; // Not handled
	}

	icmp4->checksum = 0;

	// Recalculate ICMP checksum
	icmp4->checksum = __constant_htons(csum_fold_helper(csum_partial_helper((__u8 *)icmp4, sizeof(struct icmphdr), data_end)));

	route_id  = bpf_map_lookup_elem(&nat64_dst_ip_route_map, &ipv4_dst);
	if (!route_id) {
		bpf_debug("%s: route_id not found\n", module);
		return XDP_PASS;
	}
	ridx = *route_id;
	route = bpf_map_lookup_elem(&fp_route, &ridx);
	if (!route) {
		bpf_debug("%s: Non existing route(%d) => XDP_PASS\n", module, index_key);
		return XDP_PASS;
	}
	if (route->redir_if_type == ARPHRD_ETHER) {
		if (bpf_xdp_adjust_head(ctx, (int)nh_off - 2 - (int)route->l2_hdr_size)) {
			bpf_debug("%s: bpf_xdp_adjust_head(%d) failure => XDP_PASS\n",
				module, (int)nh_off - 2 - (int)route->l2_hdr_size);
			return XDP_PASS;
		}

		data = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;

		if (data + MAX_L2_HEADER_SIZE > data_end) {
			bpf_debug("%s: Invalid data(%p) + MAX_L2_HEADER_SIZE > data_end(%p)\n",
				module, data, data_end);
			return XDP_PASS;
		}

		/* Copy full ethernet header (without the 2 bytes ether_type) */
		__builtin_memcpy(data, route->l2_hdr, (unsigned int)(2 * ETH_ALEN));
		/* Copy VLAN info in Ethernet header if present */
		if (route->l2_hdr_size > (u16)(2 * ETH_ALEN)) {
			__builtin_memcpy(data + 2 * ETH_ALEN,
				&route->l2_hdr[2 * ETH_ALEN], sizeof(struct vlan_hdr));
			/* Keep 2 bytes ether_type as per original ethernet data received */
			bpf_debug("%s: VLAN TPID(%x) VLAN TCI(%u)\n",
					module,
					htons(*(u16 *)(data + 2 * ETH_ALEN)),
					htons(*((u16 *)(data + 2 * ETH_ALEN) + 1)));
		}
	} else {
		bpf_debug("%s: Invalid redir_if_type(%d) => XDP_PASS\n",
				module, route->redir_if_type);
		return XDP_PASS;
	}
	return bpf_redirect(route->redir_ifindex, 0);
}

SEC("nat46_siit")
int nat46_siit_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = (struct ethhdr *)data;
	struct ip6_route_info *ip6_info;
	__u32 ridx;
	int nh_off;
	u16 h_proto;
	struct ipv6hdr *ip6h;
	struct in6_addr *ip6;
	const int ip6_hdr_len = IPV6_HEADER_LENGTH;
	const int ip4_hdr_len = IPV4_HEADER_LENGTH;
	const int adjust = ip4_hdr_len - ip6_hdr_len;
	struct ipv4_hdr *iph;
	__be32 ipv4_src;
	__be32 ipv4_dst;
	__be16 hdr_len;
	struct icmphdr *icmp4;
	struct icmp6hdr *icmp6;
        struct route *route;
	u8 ttl, protocol;
#ifdef DEBUG
	const char module[] = "NAT46_SIIT";
#endif

	/* this code to be removed, a route_info to be store in data while tail call */
	nh_off = sizeof(struct ethhdr);
	if (data + sizeof(int) > data_end) {
		bpf_debug("%s: Invalid data(%p) + sizeof(int) > data_end(%p) => XDP_PASS\n",
			module, data, data_end);
		return XDP_PASS;
	}

	if (data + nh_off > data_end) {
		bpf_debug("%s: Invalid data(%p) + nh_off > data_end(%p) => XDP_PASS\n",
			module, data, data_end);
                return XDP_PASS;
	}

	h_proto = eth->h_proto;

	if (h_proto == htons(ETH_P_8021Q) ||
			h_proto == htons(ETH_P_8021AD)) {
			nh_off += sizeof(struct vlan_hdr);
		if (data + nh_off > data_end) {
			bpf_debug("%s/VLAN: Invalid data(%p) + nh_off > data_end(%p) => XDP_PASS\n",
				module, data, data_end);
			return XDP_PASS;
		}
	}

	iph = (struct ipv4_hdr *) (data + nh_off);

	if ((void *)(iph + 1) > data_end) {
		bpf_debug("%s: Invalid IP header length => XDP_PASS\n", module);
		return XDP_PASS;
	}

	hdr_len = (__be16)(iph->ihl << 2);
	if (hdr_len != ip4_hdr_len) {
		bpf_debug("%s Not supported header length\n", module, hdr_len);
		return XDP_PASS;
	}
	if (iph->protocol != IPPROTO_ICMP) {
		bpf_debug("%s Only ICMP packets NAT46 supported\n", module);
		return XDP_PASS;
	}

	ipv4_src = iph->source_addr;
	ipv4_dst = iph->dest_addr;
	ttl = iph->ttl;
	protocol = iph->protocol;

	ip6_info = bpf_map_lookup_elem(&nat64_ip4_ip6_src_route_map, &ipv4_dst);
	if (!ip6_info) {
		return XDP_PASS;
	}
	/* Upto this */
        /* Retrieve ifindex as metadata from the buffer head */
	//ridx = *((int *)(data));
	 ridx = ip6_info->route_id;

	if (bpf_xdp_adjust_head(ctx, adjust))
		return XDP_PASS;

	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;

	eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	ip6h = (void *)(eth + 1);
	if ((void *)(ip6h + 1) > data_end)
		return XDP_PASS;

	ip6 = &ip6_info->ip6;
	// Set Ethernet type
	eth->h_proto = __constant_htons(ETH_P_IPV6);

	// Fill IPv6 header
	ip6h->version = 6;
	ip6h->priority = 0;
	//    memset(ip6h->flow_lbl, 0, sizeof(ip6h->flow_lbl));
	ip6h->payload_len = htons((data_end - (void *)(ip6h + 1)));
	if (protocol == IPPROTO_ICMP)
		ip6h->nexthdr = IPPROTO_ICMPV6;
	else
		ip6h->nexthdr = protocol;

	ip6h->hop_limit = ttl;
	ip6h->daddr = *ip6;

	// Embed IPv4 destination into IPv6 NAT64 prefix
	ip6h->saddr.s6_addr32[0] = __constant_htonl(0x0064ff9b); // 64:ff9b::
	ip6h->saddr.s6_addr32[1] = 0;
	ip6h->saddr.s6_addr32[2] = 0;
	ip6h->saddr.s6_addr32[3] = ipv4_src;

	// Translate ICMP to ICMPv6
	icmp4 = (void *)(ip6h + 1);
	icmp6 = (void *)(ip6h + 1);
	if ((void *)(icmp4 + 1) > data_end) return XDP_PASS;
	if ((void *)(icmp6 + 1) > data_end) return XDP_PASS;

	/* Switch case code referred from cilium */
	switch (icmp4->type) {
	case ICMP_ECHO:
		icmp6->icmp6_type = ICMPV6_ECHO_REQUEST;
		icmp6->icmp6_identifier = icmp4->un.echo.id;
		icmp6->icmp6_sequence = icmp4->un.echo.sequence;
		break;
	case ICMP_ECHOREPLY:
		icmp6->icmp6_type = ICMPV6_ECHO_REPLY;
		icmp6->icmp6_identifier = icmp4->un.echo.id;
		icmp6->icmp6_sequence = icmp4->un.echo.sequence;
		break;
	case ICMP_DEST_UNREACH:
		icmp6->icmp6_type = ICMPV6_DEST_UNREACH;
		switch (icmp4->code) {
		case ICMP_NET_UNREACH:
		case ICMP_HOST_UNREACH:
			icmp6->icmp6_code = ICMPV6_NOROUTE;
			break;
		case ICMP_PROT_UNREACH:
			icmp6->icmp6_type = ICMPV6_PARAMPROB;
			icmp6->icmp6_code = ICMPV6_UNK_NEXTHDR;
			icmp6->icmp6_pointer = 6;
			break;
		case ICMP_PORT_UNREACH:
			icmp6->icmp6_code = ICMPV6_PORT_UNREACH;
			break;
		case ICMP_SR_FAILED:
			icmp6->icmp6_code = ICMPV6_NOROUTE;
			break;
		case ICMP_NET_UNKNOWN:
		case ICMP_HOST_UNKNOWN:
		case ICMP_HOST_ISOLATED:
		case ICMP_NET_UNR_TOS:
		case ICMP_HOST_UNR_TOS:
			icmp6->icmp6_code = 0;
			break;
		case ICMP_NET_ANO:
		case ICMP_HOST_ANO:
		case ICMP_PKT_FILTERED:
			icmp6->icmp6_code = ICMPV6_ADM_PROHIBITED;
			break;
		case ICMP_FRAG_NEEDED:
		default:
			return XDP_PASS;
		}
		break;
	case ICMP_TIME_EXCEEDED:
		icmp6->icmp6_type = ICMPV6_TIME_EXCEED;
		break;
	case ICMP_PARAMETERPROB:
	default:
		return XDP_PASS;
	}

	icmp6->icmp6_cksum = 0;
	icmp6->icmp6_cksum = icmpv6_checksum(ip6h, icmp6, data_end);

	route = bpf_map_lookup_elem(&fp_route, &ridx);
	if (!route) {
		bpf_debug("%s: Non existing route(%d) => XDP_PASS\n", module, index_key);
		return XDP_PASS;
	}
	if (route->redir_if_type == ARPHRD_ETHER) {
		/* CMM doesn't count ether_type (2 bytes) in l2_hdr_size */
		if (bpf_xdp_adjust_head(ctx, (int)nh_off - 2 - (int)route->l2_hdr_size)) {
			bpf_debug("%s: bpf_xdp_adjust_head(%d) failure => XDP_PASS\n",
				module, (int)nh_off - 2 - (int)route->l2_hdr_size);
			return XDP_PASS;
		}

		data = (void *)(long)ctx->data;
		data_end = (void *)(long)ctx->data_end;

		if (data + MAX_L2_HEADER_SIZE > data_end) {
			bpf_debug("%s: Invalid data(%p) + MAX_L2_HEADER_SIZE > data_end(%p)\n",
				module, data, data_end);
			return XDP_PASS;
		}

		/* Copy full ethernet header (without the 2 bytes ether_type) */
		__builtin_memcpy(data, route->l2_hdr, (unsigned int)(2 * ETH_ALEN));
		/* Copy VLAN info in Ethernet header if present */
		if (route->l2_hdr_size > (u16)(2 * ETH_ALEN)) {
			__builtin_memcpy(data + 2 * ETH_ALEN,
					&route->l2_hdr[2 * ETH_ALEN], sizeof(struct vlan_hdr));
			/* Keep 2 bytes ether_type as per original ethernet data received */
			bpf_debug("%s: VLAN TPID(%x) VLAN TCI(%u)\n",
					module,
					htons(*(u16 *)(data + 2 * ETH_ALEN)),
					htons(*((u16 *)(data + 2 * ETH_ALEN) + 1)));
		}
	} else {
		bpf_debug("%s: Invalid redir_if_type(%d) => XDP_PASS\n",
				module, route->redir_if_type);
		return XDP_PASS;
	}

	return bpf_redirect(route->redir_ifindex, 0);
}
