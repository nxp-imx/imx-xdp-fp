/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright 2025 NXP
 */

#ifndef _IPV4_H
#define _IPV4_H
#include "types.h"

#define IP_OFFSET	0x1FFF
#define IP_MF		0x2000
#define IPV4_VERSION	4U

struct ipv4_hdr {
	u8 ihl:4;
	u8 version:4;
	u8 tos;
	u16 total_len;
	u16 id;
	u16 frag_offset;
	u8 ttl;
	u8 protocol;
	u16 header_csum;
	u32 source_addr;
	u32 dest_addr;
};

#endif /* _IPV4_H */
