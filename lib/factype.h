/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#ifndef FAC_TYPE_H
#define FAC_TYPE_H

typedef signed char fac_s8;
typedef unsigned char fac_u8;
typedef signed short int fac_s16;
typedef unsigned short int fac_u16;
typedef signed int fac_s32;
typedef unsigned int fac_u32;
typedef signed long int fac_s64;
typedef unsigned long int fac_u64;

_Static_assert(sizeof(int) == 4, "factype: error: int not 4-byte");
_Static_assert(sizeof(long int) == 8, "factype: error: long not 8-byte");

#endif
