/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include <string.h>

#include "fac_utils.h"

size_t fac_memclen(const char *s, char c, size_t n) {
	char *p = memchr(s, c, n);
	if (p == NULL) {
		return n;
	}
	return p - s;
}
