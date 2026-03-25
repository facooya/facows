/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#include "types.h"
#include "file.h"

static void _init_file(struct fws_file *file);

int file_parse(struct fws_file *file, char *uri, const char *web_root) {
	_init_file(file);

	char *p1 = uri;
	char *p2 = uri;
	ptrdiff_t n;

	for (size_t i=0; i<strlen(uri); i++) {
		if (uri[i] == '?' || uri[i] == '#') {
			break;
		}
		p2++;
	}
	n = p2 - p1;
	memcpy(file->uri_path, uri, n);
	file->uri_path[n] = '\0';

	// { path
	char tmp_path[4096];
	tmp_path[0] = '\0';
	strcat(tmp_path, web_root);

	p1 = file->uri_path;
	p2 = tmp_path;
	while (1) {
		if (*p1 == '\0') {
			*p2 = '\0';
			break;
		} else if (*p1 == '%') {
			if (isxdigit(*(p1+1)) != 0 && isxdigit(*(p1+2)) != 0) {
				uint8_t c1 = *(p1 + 1);
				uint8_t c2 = *(p1 + 2);

				if (isdigit(*(p1+1)) != 0) {
					c1 -= 0x30;
					c1 <<= 4;
				} else {
					if (c1 < 0x50) c1 = c1 + 0x20;
					c1 -= 0x57;
					c1 <<= 4;
				}

				if (isdigit(*(p1+2)) != 0) {
					c2 -= 0x30;
					c1 |= c2;
				} else {
					if (c2 < 0x50) c2 = c2 + 0x20;
					c2 -= 0x57;
					c1 |= c2;
				}

				*p2 = c1;
				p1 += 3;
				p2++;
			} else {
				*p2 = *p1;
				p1++;
				p2++;
			}
		} else {
			*p2 = *p1;
			p1++;
			p2++;
		}
	}
	realpath(tmp_path, file->path);
	// }

	return 0;
}

static void _init_file(struct fws_file *file) {
	file->uri_path[0] = '\0';
	file->path[0] = '\0';
}
