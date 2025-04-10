/* Copyright 2019 NXP
 * NXP Confidential. This software is owned or controlled by NXP and may only be used strictly in
 * accordance with the applicable license terms.  By expressly accepting such terms or by
 * downloading, installing, activating and/or otherwise using the software, you are agreeing that
 * you have read, and that you agree to comply with and are bound by, such license terms.  If you
 * do not agree to be bound by the applicable license terms, then you may not retain, install,
 * activate or otherwise use the software.
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
