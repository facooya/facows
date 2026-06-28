/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include "factype.h"
#include "types.h"
#include "file.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>

static const char index_str[] = "index";
static const char index_html_str[] = "index.html";
static const char html_ext_str[] = ".html";

static s32 _raw_path_build(
	char *path_buf,
	const char *uri_path,
	const char *web_root,
	u64 web_root_len,
	const struct fws_http_req *http_req
);
static s32 _uri_path_build(struct fws_file *file);
static s32 _path_build(struct fws_file *file, char *path_buf, s32 dir);

s32 file_parse(
	struct fws_file *file,
	const struct fws_http_req *http_req,
	const char *web_root,
	u64 web_root_n
) {
	char *path_rp = nullptr;
	s32 ret = 0;

	memset(file, 0, sizeof(struct fws_file));
	memcpy(file->uri_path, http_req->path, http_req->path_n);
	file->uri_path[http_req->path_n] = '\0';
	file->uri_path_n = http_req->path_n;

	u64 web_root_len = strnlen(web_root, web_root_n);
	if (web_root_len == web_root_n) {
		ret = -1;
		goto out;
	}

	char path_buf[4096] = {0};
	_raw_path_build(path_buf, file->uri_path, web_root, web_root_len, http_req);

	s32 code = _uri_path_build(file);
	if (code == 301) {
		ret = code;
		goto out;
	} else if (code < 0) {
		ret = -1;
		goto out;
	}

	code = _path_build(file, path_buf, code);
	if (code != 0 && code != 204) {
		ret = code;
		goto out;
	}

	path_rp = realpath(path_buf, nullptr);
	if (path_rp == nullptr) {
		ret = 404;
		goto out;
	}

	u64 path_rp_n = strnlen(path_rp, sizeof(file->path));
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

static s32 _uri_path_build(struct fws_file *file) {
	char *p1 = nullptr;
	s32 ret = 0;

	const char last_chr = *(file->uri_path+(file->uri_path_n-1));
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

	s32 size = file->uri_path_n - (sizeof(html_ext_str) - 1);
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

static s32 _path_build(struct fws_file *file, char *path_buf, s32 dir) {
	s32 ret = 0;

	char *p = memchr(path_buf, '\0', sizeof(file->path));
	if (p == nullptr) {
		return -1;
	}

	struct stat file_stat = {0};
	if (dir == 1) {
		ret = stat(path_buf, &file_stat);
		if (ret != 0) {
			return 404;
		} else {
			memcpy(p, index_html_str, sizeof(index_html_str));

			ret = stat(path_buf, &file_stat);
			if (ret == 0) {
				file->size = file_stat.st_size;
			} else {
				return 404;
			}
		}

	} else {
		ret = stat(path_buf, &file_stat);
		if (ret != 0) {
			memcpy(p, html_ext_str, sizeof(html_ext_str));
			ret = stat(path_buf, &file_stat);
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

static s32 _raw_path_build(
	char *path_buf,
	const char *uri_path,
	const char *web_root,
	u64 web_root_len,
	const struct fws_http_req *http_req
) {
	char *path_buf_p = path_buf;
	memcpy(path_buf_p, web_root, web_root_len);
	path_buf_p += web_root_len;
	*path_buf_p = '/';
	path_buf_p++;
	u64 subdomain_len = strnlen(http_req->subdomain, sizeof(http_req->subdomain));
	memcpy(path_buf_p, http_req->subdomain, subdomain_len);
	path_buf_p += subdomain_len;
	*path_buf_p = '\0';

	const char *p1 = uri_path;
	char *p2 = path_buf_p;
	while (1) {
		if (*p1 == '\0') {
			*p2 = '\0';
			break;
		} else if (*p1 == '%') {
			const s32 is_hex_fst_chr = isxdigit((u8)*(p1+1));
			const s32 is_hex_sec_chr = isxdigit((u8)*(p1+2));
			if (is_hex_fst_chr != 0 && is_hex_sec_chr != 0) {
				u8 c1 = *(p1 + 1);
				u8 c2 = *(p1 + 2);

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
