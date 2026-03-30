/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include <string.h>

#include "utils.h"

size_t fu_memclen(const char *s, char c, size_t n) {
	char *p = memchr(s, c, n);
	if (p == NULL) {
		return 0;
	}
	return p - s;
}

char *fu_memmem(const char *s1, size_t n1, const char *s2, size_t n2) {
	const char *p1 = s1;
	const char *p2;

	while (1) {
		p2 = memchr(p1, s2[0], n1);
		if (p2 == NULL) {
			break;
		}

		for (size_t i=0; i<n2; i++) {
			if (p2[i] != s2[i]) {
				break;
			}
			if (i+1 == n2) {
				return (char *) p2;
			}
		}

		n1 -= p2 - p1 + 1;
		p1 += p2 - p1 + 1;
	}

	return NULL;
}
