/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include "fac_utils.h"

#include <string.h>

U64 fac_memclen(const C8 *s, C8 c, U64 n) {
	char *p = memchr(s, c, n);
	if (p == NULL) {
		return n;
	}
	return p - s;
}
