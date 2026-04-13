/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include <stdio.h>
#include <string.h>

#include "fac_utils.h"

size_t fac_memclen(const char *s, char c, size_t n) {
	char *p = memchr(s, c, n);
	if (p == NULL) {
		return n;
	}
	return p - s;
}

char *fac_memstr(const char *s1, const char *s2, size_t n) {
	size_t s2n = fac_memclen(s2, '\0', n);
	if (s2n == n) {
		return NULL;
	}

	const char *p1 = s1;
	const char *p2;

	while (1) {
		p2 = memchr(p1, s2[0], n);
		if (p2 == NULL) {
			break;
		}

		for (size_t i=0; i<s2n; i++) {
			if (p2[i] != s2[i]) {
				break;
			}
			if (i+1 == s2n) {
				return (char *) p2;
			}
		}

		n -= p2 - p1 + 1;
		p1 += p2 - p1 + 1;
	}

	return NULL;
}

char *fac_memrchr(const char *s, char c, size_t n) {
	s += n - 1;
	for (size_t i=0; i<n; i++) {
		if (*s == c) {
			return (char *) s;
		}
		s--;
	}

	return NULL;
}
