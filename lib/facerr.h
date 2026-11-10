/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#ifndef FAC_ERR_H
#define FAC_ERR_H

#define FAC_ERR(fmt, ...) fprintf(stderr, "%s:%d: " fmt, __FILE__, __LINE__ __VA_OPT__(,) __VA_ARGS__)

#define FAC_ERR_LIMIT "limit exceeded\n"
#define FAC_ERR_LIM_N "limit exceeded: %lu\n"
#define FAC_ERR_RANGE "invalid range\n"
#define FAC_ERR_NULL "null pointer\n"
#define FAC_ERR_FORMAT "invalid format\n"

#endif
