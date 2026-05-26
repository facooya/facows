/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#ifndef FAC_TYPE_H
#define FAC_TYPE_H

#define FAC_NULL ((void *) 0)
#define FAC_NUL '\0'

typedef signed char I8;
typedef unsigned char U8;
typedef signed short int I16;
typedef unsigned short int U16;
typedef signed int I32;
typedef unsigned int U32;
typedef signed long int I64;
typedef unsigned long int U64;

typedef char C8;

_Static_assert(sizeof(I8) == 1, "factype: error: char not 1-byte\n");
_Static_assert(sizeof(I16) == 2, "factype: error: short not 1-byte\n");
_Static_assert(sizeof(I32) == 4, "factype: error: int not 4-byte\n");
_Static_assert(sizeof(I64) == 8, "factype: error: long not 8-byte\n");

#define FAC_TRUE ((I32) 1)
#define FAC_FALSE ((I32) 0)

#endif
