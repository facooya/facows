/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#ifndef FAC_TYPE_H
#define FAC_TYPE_H

#define FAC_S8_MAX 127
#define FAC_S8_MIN (-FAC_S8_MAX - 1)
#define FAC_U8_MAX 255
#define FAC_S16_MAX 32767
#define FAC_S16_MIN (-FAC_S16_MAX - 1)
#define FAC_U16_MAX 65535
#define FAC_S32_MAX 2147483647
#define FAC_S32_MIN (-FAC_S32_MAX - 1)
#define FAC_U32_MAX 4294967295U
#define FAC_S64_MAX 9223372036854775807L
#define FAC_S64_MIN (-FAC_S64_MAX - 1L)
#define FAC_U64_MAX 18446744073709551615UL

typedef signed char s8;
typedef unsigned char u8;
typedef signed short int s16;
typedef unsigned short int u16;
typedef signed int s32;
typedef unsigned int u32;
typedef signed long int s64;
typedef unsigned long int u64;

static_assert(sizeof(s8) == 1, "factype: error: char not 1-byte\n");
static_assert(sizeof(s16) == 2, "factype: error: short not 1-byte\n");
static_assert(sizeof(s32) == 4, "factype: error: int not 4-byte\n");
static_assert(sizeof(s64) == 8, "factype: error: long not 8-byte\n");

#endif
