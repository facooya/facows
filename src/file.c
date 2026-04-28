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

static void _file_init(struct fws_file *file);
static int _raw_path_build(char *raw_path, const char *uri_path, const char *web_root, size_t web_root_len);
static int _uri_path_build(struct fws_file *file);
static int _path_build(struct fws_file *file, char *raw_path, int dir);

int file_parse(struct fws_file *file, const struct fws_http_req *http_req, const char *web_root, size_t web_root_n) {
	_file_init(file);

	memcpy(file->uri_path, http_req->path, http_req->path_n);
	file->uri_path[http_req->path_n] = '\0';
	file->uri_path_n = http_req->path_n;

	size_t web_root_len = fac_memclen(web_root, '\0', web_root_n);
	if (web_root_len == web_root_n) {
		return -1;
	}

	char raw_path[4096];
	_raw_path_build(raw_path, file->uri_path, web_root, web_root_len);

	int code = _uri_path_build(file);
	if (code == 301) {
		return code;
	} else if (code < 0) {
		return -1;
	}

	code = _path_build(file, raw_path, code);
	if (code != 0) {
		return code;
	}

	if (realpath(raw_path, file->path) == NULL) {
		return 404;
	}

	if (memcmp(file->path, web_root, web_root_len) != 0) {
		return -1;
	}

	return 0;
}

static void _file_init(struct fws_file *file) {
	file->uri_path[0] = '\0';
	file->uri_path_n = 0;
	file->path[0] = '\0';
	file->size = 0;
}

static int _uri_path_build(struct fws_file *file) {
	char *p1;

	// dir
	if (*(file->uri_path+(file->uri_path_n-1)) == '/') {
		return 1;
	}

	p1 = fac_memrchr(file->uri_path, '/', file->uri_path_n);
	if (p1 == NULL) {
		return -1;
	}

	// index
	p1++;
	if (memcmp(p1, "index", sizeof("index")) == 0) {
		file->uri_path_n -= (sizeof("index") - 1);
		file->uri_path[file->uri_path_n] = '\0';
		return 301;

	} else if (memcmp(p1, "index.html", sizeof("index.html")) == 0) {
		file->uri_path_n -= (sizeof("index.html") - 1);
		file->uri_path[file->uri_path_n] = '\0';
		return 301;
	}

	// extension
	p1 = file->uri_path + file->uri_path_n - (sizeof(".html") - 1);
	if (memcmp(p1, ".html", sizeof(".html")-1) == 0) {
		file->uri_path_n -= (sizeof(".html") - 1);
		file->uri_path[file->uri_path_n] = '\0';
		return 301;
	}

	return 0;
}

static int _path_build(struct fws_file *file, char *raw_path, int dir) {
	struct stat file_stat;
	char *p = memchr(raw_path, '\0', sizeof(file->path));
	if (p == NULL) {
		return -1;
	}

	if (dir == 1) {
		if (stat(raw_path, &file_stat) != 0) {
			return 404;
		} else {
			const char index_str[] = "index.html";
			memcpy(p, index_str, sizeof(index_str));

			if (stat(raw_path, &file_stat) == 0) {
				file->size = file_stat.st_size;
			} else {
				return 404;
			}
		}

	} else {
		if (stat(raw_path, &file_stat) != 0) {
			const char html_str[] = ".html";
			memcpy(p, html_str, sizeof(html_str));
			if (stat(raw_path, &file_stat) != 0) {
				return 404;
			}
			file->size = file_stat.st_size;

		} else {
			file->size = file_stat.st_size;
		}
	}

	return 0;
}

static int _raw_path_build(char *raw_path, const char *uri_path, const char *web_root, size_t web_root_len) {
	memcpy(raw_path, web_root, web_root_len);
	raw_path[web_root_len] = '\0';

	const char *p1 = uri_path;
	char *p2 = raw_path + web_root_len;
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
					if (c1 < 0x50) {
						c1 += 0x20;
					}
					c1 -= 0x57;
					c1 <<= 4;
				}

				if (isdigit(*(p1+2)) != 0) {
					c2 -= 0x30;
					c1 |= c2;
				} else {
					if (c2 < 0x50) {
						c2 += 0x20;
					}
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

	return 0;
}
