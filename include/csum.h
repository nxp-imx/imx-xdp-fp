/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright 2025 NXP
 */

#ifndef _CSUM_H
#define _CSUM_H
#include "types.h"


static __always_inline u32 csum_partial_helper(u8 *buf, int len, void *data_end)
{
	u32 sum = 0;

	if (buf + len > (__u8 *)data_end)
		return 0;

#pragma unroll
	for (int i = 0; i < 128; i += 2) {
		if (i + 1 >= len)
			break;

		if (buf + i + 1 >= (u8 *)data_end)
			break;

		u16 word = ((u16)buf[i] << 8) | buf[i + 1];
		sum += word;
	}

	if (len & 1) {
		if (buf + len - 1 < (u8 *)data_end) {
			sum += ((u16)buf[len - 1]) << 8;
		}
	}

	return sum;
}

static __always_inline u16 csum_fold_helper(u32 csum)
{
	u32 sum;
	sum = (csum >> 16) + (csum & 0xffff);
	sum += (sum >> 16);

	return ~sum;
}

static __always_inline u32 csum_add(u32 csum, u32 addend)
{
	csum += addend;

	return csum + (csum < addend);
}

static __always_inline u16 icmpv6_checksum(struct ipv6hdr *ip6h, struct icmp6hdr *icmp6h, void *data_end)
{
	u32 csum = 0;
	u16 *next_iph_u16;
	u32 icmp_len = (u8 *)data_end - (u8 *)icmp6h;

	// Pseudo-header: source and destination addresses
	next_iph_u16 = (u16 *)&ip6h->saddr;
#pragma unroll
	for (int i = 0; i < sizeof(ip6h->saddr) >> 1; i++)
		csum = csum_add(csum, *next_iph_u16++);

	next_iph_u16 = (u16 *)&ip6h->daddr;

#pragma unroll
	for (int i = 0; i < sizeof(ip6h->daddr) >> 1; i++)
		csum = csum_add(csum, *next_iph_u16++);

	// Payload length
	csum = csum_add(csum, (u32)htons(icmp_len));

	// Next header (ICMPv6)
	csum = csum_add(csum, (u32)htons(IPPROTO_ICMPV6));

	// ICMPv6 header and payload
	u16 *buf = (u16 *)icmp6h;
#pragma unroll
	for (int i = 0; i < 256; i++) {
		if ((u8 *)(buf + 1) > (u8 *)data_end)
			break;
		csum = csum_add(csum, *buf++);
	}

	return csum_fold_helper(csum);
}

#endif /* _CSUM_H */
