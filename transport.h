/* Copyright 2019 NXP
 * NXP Confidential. This software is owned or controlled by NXP and may only be used strictly in
 * accordance with the applicable license terms.  By expressly accepting such terms or by
 * downloading, installing, activating and/or otherwise using the software, you are agreeing that
 * you have read, and that you agree to comply with and are bound by, such license terms.  If you
 * do not agree to be bound by the applicable license terms, then you may not retain, install,
 * activate or otherwise use the software.
 */

#ifndef _TRANSPORT_H
#define _TRANSPORT_H
#include "types.h"

#define IPPROTOCOL_UDP 17
#define IPPROTOCOL_TCP 6

struct udp_hdr {
	u16 source_port;
	u16 dest_port;
	u16 length;
	u16 checksum;
};

struct tcp_hdr {
	u16 source_port;
	u16 dest_port;
	u32 seq_num;
	u32 ack_num;
	u16 res1:4,
		data_offset:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
	u16 window;
	u16 checksum;
	u16 urgent_pointer;
};

#endif /* _TRANSPORT_H */
