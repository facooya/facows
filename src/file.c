/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include "factype.h"
#include "fac_utils.h"
#include "types.h"
#include "file.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>

static void _file_init(struct fws_file *file);
static I32 _raw_path_build(C8 *raw_path, const C8 *uri_path, const C8 *web_root, U64 web_root_len);
static I32 _uri_path_build(struct fws_file *file);
static I32 _path_build(struct fws_file *file, C8 *raw_path, I32 dir);

I32 file_parse(struct fws_file *file, const struct fws_http_req *http_req, const C8 *web_root, U64 web_root_n) {
	C8 *path_rp = NULL;

	I32 ret = 0;

	_file_init(file);

	memcpy(file->uri_path, http_req->path, http_req->path_n);
	file->uri_path[http_req->path_n] = '\0';
	file->uri_path_n = http_req->path_n;

	U64 web_root_len = fac_memclen(web_root, '\0', web_root_n);
	if (web_root_len == web_root_n) {
		ret = -1;
		goto out;
	}

	C8 raw_path[4096];
	_raw_path_build(raw_path, file->uri_path, web_root, web_root_len);

	I32 code = _uri_path_build(file);
	if (code == 301) {
		ret = code;
		goto out;
	} else if (code < 0) {
		ret = -1;
		goto out;
	}

	code = _path_build(file, raw_path, code);
	if (code != 0) {
		ret = code;
		goto out;
	}

	path_rp = realpath(raw_path, FAC_NULL);
	if (path_rp == FAC_NULL) {
		ret = 404;
		goto out;
	}
	U64 path_rp_n = fac_memclen(path_rp, FAC_NUL, sizeof(file->path));
	if (path_rp_n >= sizeof(file->path)) {
		ret = -1;
		goto out;
	}
	memcpy(file->path, path_rp, path_rp_n+1);
	free(path_rp);
	path_rp = NULL;

	if (memcmp(file->path, web_root, web_root_len) != 0) {
		ret = -1;
		goto out;
	}

	ret = 0;
out:
	free(path_rp);
	path_rp = NULL;
	return ret;
}

static void _file_init(struct fws_file *file) {
	file->uri_path[0] = '\0';
	file->uri_path_n = 0;
	file->path[0] = '\0';
	file->size = 0;
}

static I32 _uri_path_build(struct fws_file *file) {
	C8 *p1 = FAC_NULL;

	if (*(file->uri_path+(file->uri_path_n-1)) == '/') {
		return 1;
	}

	p1 = memrchr(file->uri_path, '/', file->uri_path_n);
	if (p1 == FAC_NULL) {
		return -1;
	}

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

	I32 size = file->uri_path_n - (sizeof(".html") - 1);
	if (size <= 0) {
		return 0;
	}
	p1 = file->uri_path + file->uri_path_n - (sizeof(".html") - 1);
	if (memcmp(p1, ".html", sizeof(".html")-1) == 0) {
		file->uri_path_n -= (sizeof(".html") - 1);
		file->uri_path[file->uri_path_n] = '\0';
		return 301;
	}

	return 0;
}

static I32 _path_build(struct fws_file *file, C8 *raw_path, I32 dir) {
	struct stat file_stat;
	C8 *p = memchr(raw_path, '\0', sizeof(file->path));
	if (p == FAC_NULL) {
		return -1;
	}

	if (dir == 1) {
		if (stat(raw_path, &file_stat) != 0) {
			return 404;
		} else {
			const C8 index_str[] = "index.html";
			memcpy(p, index_str, sizeof(index_str));

			if (stat(raw_path, &file_stat) == 0) {
				file->size = file_stat.st_size;
			} else {
				return 404;
			}
		}

	} else {
		if (stat(raw_path, &file_stat) != 0) {
			const C8 html_str[] = ".html";
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

static I32 _raw_path_build(C8 *raw_path, const C8 *uri_path, const C8 *web_root, U64 web_root_len) {
	memcpy(raw_path, web_root, web_root_len);
	raw_path[web_root_len] = '\0';

	const C8 *p1 = uri_path;
	C8 *p2 = raw_path + web_root_len;
	while (1) {
		if (*p1 == '\0') {
			*p2 = '\0';
			break;
		} else if (*p1 == '%') {
			if (isxdigit((U8)*(p1+1)) != 0 && isxdigit((U8)*(p1+2)) != 0) {
				U8 c1 = *(p1 + 1);
				U8 c2 = *(p1 + 2);

				if (isdigit((U8)*(p1+1)) != 0) {
					c1 -= 0x30;
					c1 <<= 4;
				} else {
					if (c1 < 0x50) {
						c1 += 0x20;
					}
					c1 -= 0x57;
					c1 <<= 4;
				}

				if (isdigit((U8)*(p1+2)) != 0) {
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
