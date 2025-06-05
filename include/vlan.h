/* SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright 2025 NXP
 */

#ifndef _VLAN_H
#define _VLAN_H
#include <linux/if_ether.h>

#include "types.h"

struct vlan_hdr {
        u16  h_vlan_TCI;
        u16  h_vlan_encapsulated_proto;
};

struct vlan_ethhdr {
        unsigned char   h_dest[ETH_ALEN];
        unsigned char   h_source[ETH_ALEN];
        u16      h_vlan_proto;
        u16      h_vlan_TCI;
        u16      h_vlan_encapsulated_proto;
};

#endif /* _VLAN_H */
