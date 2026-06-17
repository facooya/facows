/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include "factype.h"
#include "types.h"
#include "file.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>

static const C8 index_str[] = "index";
static const C8 index_html_str[] = "index.html";
static const C8 html_ext_str[] = ".html";

static I32 _raw_path_build(C8 *raw_path_buf, const C8 *uri_path, const C8 *web_root, U64 web_root_len);
static I32 _uri_path_build(struct fws_file *file);
static I32 _path_build(struct fws_file *file, C8 *raw_path_buf, I32 dir);

I32 file_parse(struct fws_file *file, const struct fws_http_req *http_req, const C8 *web_root, U64 web_root_n) {
	C8 *path_rp = nullptr;
	I32 ret = 0;

	memset(file, 0, sizeof(struct fws_file));
	memcpy(file->uri_path, http_req->path, http_req->path_n);
	file->uri_path[http_req->path_n] = '\0';
	file->uri_path_n = http_req->path_n;

	U64 web_root_len = strnlen(web_root, web_root_n);
	if (web_root_len == web_root_n) {
		ret = -1;
		goto out;
	}

	C8 raw_path_buf[4096];
	_raw_path_build(raw_path_buf, file->uri_path, web_root, web_root_len);

	I32 code = _uri_path_build(file);
	if (code == 301) {
		ret = code;
		goto out;
	} else if (code < 0) {
		ret = -1;
		goto out;
	}

	code = _path_build(file, raw_path_buf, code);
	if (code != 0) {
		ret = code;
		goto out;
	}

	path_rp = realpath(raw_path_buf, nullptr);
	if (path_rp == nullptr) {
		ret = 404;
		goto out;
	}
	U64 path_rp_n = strnlen(path_rp, sizeof(file->path));
	if (path_rp_n >= sizeof(file->path)) {
		ret = -1;
		goto out;
	}
	memcpy(file->path, path_rp, path_rp_n+1);
	free(path_rp);
	path_rp = nullptr;

	ret = memcmp(file->path, web_root, web_root_len);
	if (ret != 0) {
		ret = -1;
		goto out;
	}

	ret = 0;
out:
	free(path_rp);
	path_rp = nullptr;
	return ret;
}

static I32 _uri_path_build(struct fws_file *file) {
	C8 *p1 = nullptr;
	I32 ret = 0;

	const C8 last_chr = *(file->uri_path+(file->uri_path_n-1));
	if (last_chr == '/') {
		return 1;
	}

	p1 = memrchr(file->uri_path, '/', file->uri_path_n);
	if (p1 == nullptr) {
		return -1;
	}

	p1++;
	ret = memcmp(p1, index_str, sizeof(index_str));
	if (ret == 0) {
		file->uri_path_n -= (sizeof(index_str) - 1);
		file->uri_path[file->uri_path_n] = '\0';
		return 301;

	}
	ret = memcmp(p1, index_html_str, sizeof(index_html_str));
	if (ret == 0) {
		file->uri_path_n -= (sizeof(index_html_str) - 1);
		file->uri_path[file->uri_path_n] = '\0';
		return 301;
	}

	I32 size = file->uri_path_n - (sizeof(html_ext_str) - 1);
	if (size <= 0) {
		return 0;
	}
	p1 = file->uri_path + file->uri_path_n - (sizeof(html_ext_str) - 1);
	if (memcmp(p1, html_ext_str, sizeof(html_ext_str)-1) == 0) {
		file->uri_path_n -= (sizeof(html_ext_str) - 1);
		file->uri_path[file->uri_path_n] = '\0';
		return 301;
	}

	return 0;
}

static I32 _path_build(struct fws_file *file, C8 *raw_path_buf, I32 dir) {
	I32 ret = 0;

	C8 *p = memchr(raw_path_buf, '\0', sizeof(file->path));
	if (p == nullptr) {
		return -1;
	}

	struct stat file_stat = {0};
	if (dir == 1) {
		ret = stat(raw_path_buf, &file_stat);
		if (ret != 0) {
			return 404;
		} else {
			memcpy(p, index_html_str, sizeof(index_html_str));

			ret = stat(raw_path_buf, &file_stat);
			if (ret == 0) {
				file->size = file_stat.st_size;
			} else {
				return 404;
			}
		}

	} else {
		ret = stat(raw_path_buf, &file_stat);
		if (ret != 0) {
			memcpy(p, html_ext_str, sizeof(html_ext_str));
			ret = stat(raw_path_buf, &file_stat);
			if (ret != 0) {
				return 404;
			}
			file->size = file_stat.st_size;

		} else {
			file->size = file_stat.st_size;
		}
	}

	return 0;
}

static I32 _raw_path_build(C8 *raw_path_buf, const C8 *uri_path, const C8 *web_root, U64 web_root_len) {
	memcpy(raw_path_buf, web_root, web_root_len);
	raw_path_buf[web_root_len] = '\0';

	const C8 *p1 = uri_path;
	C8 *p2 = raw_path_buf + web_root_len;
	while (1) {
		if (*p1 == '\0') {
			*p2 = '\0';
			break;
		} else if (*p1 == '%') {
			const I32 is_hex_fst_chr = isxdigit((U8)*(p1+1));
			const I32 is_hex_sec_chr = isxdigit((U8)*(p1+2));
			if (is_hex_fst_chr != 0 && is_hex_sec_chr != 0) {
				U8 c1 = *(p1 + 1);
				U8 c2 = *(p1 + 2);

				if (is_hex_fst_chr != 0) {
					c1 -= 0x30;
					c1 <<= 4;
				} else {
					if (c1 < 0x50) {
						c1 += 0x20;
					}
					c1 -= 0x57;
					c1 <<= 4;
				}

				if (is_hex_sec_chr != 0) {
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
