/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#ifndef FAC_TYPE_H
#define FAC_TYPE_H

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
