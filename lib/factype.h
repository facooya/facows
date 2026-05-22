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

#if defined(__x86_64__) && defined(__LP64__)
typedef signed long int fac_s64;
typedef unsigned long int fac_u64;
#else
typedef signed long long int fac_s64;
typedef unsigned long long int fac_u64;
#endif

#endif
