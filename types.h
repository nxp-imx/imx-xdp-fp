/* Copyright 2019 NXP
 * NXP Confidential. This software is owned or controlled by NXP and may only be used strictly in
 * accordance with the applicable license terms.  By expressly accepting such terms or by
 * downloading, installing, activating and/or otherwise using the software, you are agreeing that
 * you have read, and that you agree to comply with and are bound by, such license terms.  If you
 * do not agree to be bound by the applicable license terms, then you may not retain, install,
 * activate or otherwise use the software.
 */

#ifndef _TYPES_H
#define _TYPES_H
#include <stdint.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define htons(x) ((u16)((((x) & 0xFF00) >> 8) | (((x) & 0x00FF) << 8)))

#endif /* _TYPES_H */
