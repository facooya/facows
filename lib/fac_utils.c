/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include "factype.h"
#include "fac_utils.h"

#include <string.h>

U64 fac_memclen(const C8 *s, const C8 c, const U64 n) {
	const C8 * const p = memchr(s, c, n);
	if (p == FAC_NULL) {
		return n;
	}
	return p - s;
}
