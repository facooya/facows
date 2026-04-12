/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <ctype.h>

#include "fac_utils.h"
#include "types.h"
#include "file.h"

static void _init_file(struct fws_file *file);
static int _build_tail(struct fws_file *file);

int file_parse(struct fws_file *file, char *uri, size_t uri_n, const char *web_root, size_t web_root_n) {
	_init_file(file);

	char *p1 = uri;
	char *p2 = uri;
	size_t n;

	size_t uri_len = fac_memclen(uri, '\0', uri_n);
	if (uri_len == uri_n) {
		return -1;
	}
	size_t web_root_len = fac_memclen(web_root, '\0', web_root_n);
	if (web_root_len == web_root_n) {
		return -1;
	}

	for (size_t i=0; i<uri_len; i++) {
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
	memcpy(tmp_path, web_root, web_root_len);
	tmp_path[web_root_len] = '\0';

	p1 = file->uri_path;
	p2 = tmp_path + web_root_len;
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

	// TODO: check root dir slash
	if (memcmp(file->path, web_root, web_root_len-1) != 0) {
		return -1;
	}

	int code = _build_tail(file);
	return code;
}

static void _init_file(struct fws_file *file) {
	file->uri_path[0] = '\0';
	file->path[0] = '\0';
}

static int _build_tail(struct fws_file *file) {
	struct stat file_stat;
	char *p = memchr(file->path, '\0', sizeof(file->path));
	if (p == NULL) {
		return -1;
	}

	if (stat(file->path, &file_stat) != 0) {
		const char html_str[] = ".html";
		memcpy(p, html_str, sizeof(html_str));
		if (stat(file->path, &file_stat) != 0) {
			return 404;
		}
		file->size = file_stat.st_size;

	} else if (S_ISDIR(file_stat.st_mode) == 1) {
		const char index_str[] = "/index.html";
		memcpy(p, index_str, sizeof(index_str));
		if (stat(file->path, &file_stat) == 0) {
			file->size = file_stat.st_size;
		} else {
			return 404;
		}

	} else {
		file->size = file_stat.st_size;
	}

	return 0;
}
