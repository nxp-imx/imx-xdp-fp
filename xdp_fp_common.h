/* Copyright 2019 NXP
 * NXP Confidential. This software is owned or controlled by NXP and may only be used strictly in
 * accordance with the applicable license terms.  By expressly accepting such terms or by
 * downloading, installing, activating and/or otherwise using the software, you are agreeing that
 * you have read, and that you agree to comply with and are bound by, such license terms.  If you
 * do not agree to be bound by the applicable license terms, then you may not retain, install,
 * activate or otherwise use the software.
 */

#ifndef _XDP_FP_COMMON_H
#define _XDP_FP_COMMON_H

#include "types.h"

#define MAX_IPV4_ENTRIES	512
#define MAX_IPV6_ENTRIES	512
#define MAX_FP_ROUTES		512

#define MAX_L2_HEADER_SIZE	18

#define FP_INFO_FLAG_FAST_PATH		(1 << 0)
#define FP_INFO_FLAG_NAT		(1 << 1)
#define FP_INFO_FLAG_CONNTRACK_ORIG	(1 << 2)

#define ARPHRD_ETHER	1
#define ARPHRD_RAWIP	519


enum {
	GLOB_ETHERNET_TYPE = 0,
	GLOB_RAWIP_TYPE,
	GLOB_IFTYPE_MAX,
};

enum {
	GLOB_FF_DISABLE,
	GLOB_MAX
};

enum {
	GLOB_STAT,
	GLOB_STAT_MAX
};

struct route {
	u32 flags;
	int redir_ifindex;
	u8 l2_hdr[MAX_L2_HEADER_SIZE];
	u32 l2_hdr_size;
	u16 mtu;
	u16 redir_if_type;
};

struct ipv4_flow {
	u32 saddr;
	u32 daddr;
	u16 sport;
	u16 dport;
	u8 protocol;
};

struct ipv4_info {
	u8 flags;
	u8 active;
	u32 nat_saddr;
	u32 nat_daddr;
	u16 nat_sport;
	u16 nat_dport;
	unsigned int ip_csum_corr;
	unsigned int trans_csum_corr;
	int route_ifindex;
	unsigned int last_timer;
	u16 mtu;
};

struct ipv6_flow {
	u32 saddr[4];
	u32 daddr[4];
	u16 sport;
	u16 dport;
	u8 protocol;
};

struct ipv6_info {
	u8 flags;
	u8 active;
	u32 nat_saddr[4];
	u32 nat_daddr[4];
	u16 nat_sport;
	u16 nat_dport;
	unsigned int trans_csum_corr;
	int route_ifindex;
	unsigned int last_timer;
	u16 mtu;
};

struct stats_entry {
	u64 packets_fp[GLOB_IFTYPE_MAX]; /* fast path => transmitted */
	u64 bytes_fp[GLOB_IFTYPE_MAX];
	u64 packets_sp[GLOB_IFTYPE_MAX]; /* slow path => pass */
	u64 bytes_sp[GLOB_IFTYPE_MAX];
};

#endif
