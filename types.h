/* Copyright 2025 NXP
 */

#ifndef _TYPES_H
#define _TYPES_H
#include <stdint.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#ifndef htons
#define htons(x) ((u16)((((x) & 0xFF00) >> 8) | (((x) & 0x00FF) << 8)))
#endif

#endif /* _TYPES_H */
