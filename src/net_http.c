/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include "factype.h"
#include "facerr.h"
#include "types.h"
#include "net.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/ssl.h>

static s32 _line_parse(const char *req_buf, struct fws_http_req *http_req);
static void _uri_parse(struct fws_http_req *http_req);
static s32 _header_parse(const char *req_buf, struct fws_http_req *http_req,
		const char *domain, u64 domain_n);
//static s32 _err_check(const struct fws_http_req *http_req);
static s32 _etag_get(char *dst, const char *src, const char *path);
static s32 _cache_get(char *dst, u64 dst_max, const char *src_cache, u64 src_cache_len,
		const char *src_ext);

s32 net_http_req_parse(char *req_buf, struct fws_http_req *http_req, const char *domain, u64 domain_n) {
	constexpr u64 req_max = sizeof(((struct fws_data_ctx*)nullptr)->req_buf);
	memset(http_req, 0, sizeof(struct fws_http_req));
	_line_parse(req_buf, http_req);
	_uri_parse(http_req);

	for (u64 i=0; i<strnlen(req_buf, req_max); i++) {
		req_buf[i] = tolower(req_buf[i]);
	}

	_header_parse(req_buf, http_req, domain, domain_n);
	return 0;
}

s32 net_http_res_build(const struct fws_conf *conf_p, const struct tm *fws_time,
		const struct fws_http_req *http_req, struct fws_http_res *http_res, const char *path,
		u64 path_n) {
	memset(http_res, 0, sizeof(struct fws_http_res));
	strftime(http_res->date, sizeof(http_res->date), "%a, %d %b %Y %H:%M:%S GMT", fws_time);

	const s32 etag_ret = _etag_get(http_res->etag, http_req->etag, path);
	if (etag_ret < 0) {
		fprintf(stderr, "net_http_res_build(): _etag_get(): etag: null\n");
		return -1;
	}
	if (etag_ret == 304) {
		http_res->code = 304;
	} else {
		http_res->code = 200;
	}
	http_res->connection = 0;

	const char *p1 = path;
	const char *p2;
	u64 n = strnlen(p1, path_n);
	s32 ret = 0;

	while (true) {
		p2 = memchr(p1, '.', n);
		if (p2 == nullptr) {
			break;
		}

		n -= p2 - p1 + 1;
		p1 = p2 + 1;
	}

	char ext_buf[32] = {0};
	bool has_find = false;
	const char *p_start = conf_p->mime;
	s32 mime_n = strnlen(conf_p->mime, sizeof(conf_p->mime));

	while (mime_n > 0) {
		const char *p_ext_start = memchr(p_start, '[', mime_n);
		if (p_ext_start == nullptr) {
			fprintf(stderr, "net_http_res_build(): error: invalid missing '['\n");
			return -1;
		}
		const s64 mime_len = p_ext_start - p_start;
		if (mime_len < 0) {
			FAC_ERR(FAC_ERR_RANGE);
			return -1;
		}
		const char *p_ext_end = memchr(p_ext_start, ']', mime_n-mime_len);
		if (p_ext_end == nullptr) {
			fprintf(stderr, "net_http_res_build(): error: invalid missing ']'\n");
			return -1;
		}
		s64 ext_n = p_ext_end - p_ext_start;
		if (ext_n < 0) {
			FAC_ERR(FAC_ERR_RANGE);
			return -1;
		}
		s64 mime_next_off = (p_ext_end + 1) - p_start;
		p_ext_start++; /* skip '[' */

		/* [info]
		*(p_ext_start-1) == '['
		*p_ext_end == ']'
		*/
		while (ext_n > 0) {
			const char *p_ext_end = memchr(p_ext_start, ',', ext_n);
			if (p_ext_end == nullptr) {
				p_ext_end = memchr(p_ext_start, ']', ext_n);
				if (p_ext_end == nullptr) {
					fprintf(stderr, "net_http_res_build(): error: invalid\n");
					return -1;
				}
			}
			if (p_ext_end < p_ext_start) {
				fprintf(stderr, "net_http_res_build(): p_ext_end-p_ext_start: invalid\n");
				return -1;
			}
			s64 ext_len = p_ext_end - p_ext_start;
			if ((u64)ext_len >= sizeof(ext_buf)) {
				fprintf(stderr, "net_http_res_build(): error: invalid extension size\n");
				return -1;
			}
			memset(ext_buf, '\0', sizeof(ext_buf));
			memcpy(ext_buf, p_ext_start, ext_len);
			ext_buf[ext_len] = '\0';

			ret = memcmp(p1, ext_buf, ext_len+1);
			if (ret == 0) {
				if ((u64)mime_len >= sizeof(http_res->content)) {
					fprintf(stderr, "net_http_res_build(): error: invalid mime size");
					return -1;
				}
				memset(http_res->content, '\0', sizeof(http_res->content));
				memcpy(http_res->content, p_start, mime_len);

				u64 cache_len = strnlen(conf_p->cache, sizeof(conf_p->cache));
				const s32 cache_ret = _cache_get(http_res->cache, sizeof(http_res->cache),
						conf_p->cache, cache_len, ext_buf);
				if (cache_ret < 0) {
					return -1;
				}

				has_find = true;
				break;
			}

			p_ext_start += (ext_len + 1); /* skip ',' */
			ext_n -= (ext_len + 1);
			if (*p_ext_start == ']') {
				break;
			}
		}

		if (has_find) {
			break;
		}

		p_start += mime_next_off;
		mime_n -= mime_next_off;
	}

	if (!has_find) {
		memset(http_res->content, '\0', sizeof(http_res->content));
		memcpy(http_res->content, conf_p->mime_default, strnlen(conf_p->mime_default, sizeof(conf_p->mime_default)));
	}

	return 0;
}

void net_http_path_redir(struct fws_http_req *http_req, const struct fws_conf *conf,
		const struct fws_file *file, struct fws_data_ctx *client_ctx) {
	static const char res_301_fmt[] = "HTTP/1.1 301 Moved permanently\r\n"
		"Location: https://%s%s\r\nContent-Length: 0\r\nConnection: keep-alive\r\n"
		"Keep-Alive: timeout=3\r\n\r\n";
	char host_buf[512];
	net_host_build(host_buf, http_req, conf);

	u64 n = snprintf(nullptr, 0, res_301_fmt, host_buf, file->uri_path);
	char *res_buf = calloc(n+1, 1);
	snprintf(res_buf, n+1, res_301_fmt, host_buf, file->uri_path);
	net_443_write(client_ctx, res_buf, n);
	free(res_buf);
	res_buf = nullptr;
}

bool net_http_origin_self_check(const struct fws_http_req *http_req, const struct fws_conf *conf_p) {
	u64 domain_len = strnlen(conf_p->domain, sizeof(conf_p->domain));
	if (domain_len == sizeof(conf_p->domain)) {
		return false;
	}
	const char *p_scan = memmem(http_req->origin, sizeof(http_req->origin), conf_p->domain, domain_len);
	if (p_scan == nullptr) {
		return false;
	}
	if (*(p_scan-1) != '.' && *(p_scan-1) != '/') {
		return false;
	}
	if (*(p_scan+domain_len) != ':' && *(p_scan+domain_len) != '\0') {
		return false;
	}
	return true;
}

static s32 _line_parse(const char *req_buf, struct fws_http_req *http_req) {
	const char *p1 = req_buf;
	const char *p2 = memchr(p1, ' ', sizeof(http_req->method));
	u64 n;
	if (p2 == nullptr) {
		return 1;
	}
	n = p2 - p1;
	if (n >= sizeof(http_req->method)) {
		return 1;
	}
	memcpy(http_req->method, p1, n);
	http_req->method[n] = '\0';

	p1 += n + 1;
	p2 = memchr(p1, ' ', sizeof(http_req->uri));
	if (p2 == nullptr) {
		return 1;
	}
	n = p2 - p1;
	if (n >= sizeof(http_req->uri)) {
		return 1;
	}
	memcpy(http_req->uri, p1, n);
	http_req->uri[n] = '\0';

	p1 += n + 1;
	p2 = memchr(p1, '\r', sizeof(http_req->version));
	if (p2 == nullptr) {
		return 1;
	}
	n = p2 - p1;
	if (n >= sizeof(http_req->version)) {
		return 1;
	}
	memcpy(http_req->version, p1, n);
	http_req->version[n] = '\0';
	return 0;
}

static void _uri_parse(struct fws_http_req *http_req) {
	char *p1 = http_req->uri;
	char *p2;
	u64 uri_len = strnlen(http_req->uri, sizeof(http_req->uri));

	http_req->path = p1;
	p2 = memchr(http_req->uri, '?', uri_len);
	if (p2 == nullptr) {
		http_req->path_n = uri_len;
	} else {
		http_req->path_n = p2 - p1;
		http_req->query = p2 + 1;
		http_req->query_n = uri_len - (http_req->path_n + 1);
	}
}

static s32 _header_parse(const char *req_buf, struct fws_http_req *http_req, const char *domain, u64 domain_n) {
	enum key_idx {HOST, UA, AL, ORIGIN, ETAG};
	constexpr u64 req_key_max = 64;
	constexpr u64 req_value_max = 1024;
	static const char *const keyword[] = {"host", "user-agent", "accept-language", "origin", "if-none-match"};

	const char *p1 = req_buf;
	const char *p2 = memchr(p1, '\r', req_value_max);
	s32 ret = 0;
	u64 n = 0;

	if (p2 == nullptr || *(p2+1) != '\n') {
		return 1;
	}
	p1 = p2 + 2;

	while (true) {
		if (memcmp(p1, "\r\n", sizeof("\r\n")-1) == 0) {
			break;
		}

		p2 = memchr(p1, ':', req_key_max);
		if (p2 == nullptr) {
			return 1;
		}

		for (u64 i=0; i<sizeof(keyword)/sizeof(keyword[0]); i++) {
			if (memcmp(p1, keyword[i], strnlen(keyword[i], sizeof(keyword[i]))) == 0) {
				p1 = p2 + 1;
				p2 = memchr(p1, '\r', req_value_max);
				if (p2 == nullptr) {
					return 1;
				}
				while (*p1 == ' ') {
					p1++;
				}
				n = p2 - p1;

				/* p2: value start */
				/* n: value size */
				switch (i) {
					case HOST:
						if (http_req->subdomain[0] != '\0') {
							return 1;
						}

						if (memcmp(p1, domain, strnlen(domain, domain_n)) == 0) {
							memcpy(http_req->subdomain, "www", sizeof("www"));
						} else {
							p2 = p1;
							for (u64 i=0; i<sizeof(http_req->subdomain); i++) {
								if (p2[i] == '.') {
									p2 += i;
									break;
								}
							}
							n = p2 - p1;
							memcpy(http_req->subdomain, p1, n);
							http_req->subdomain[n] = '\0';
						}
						break;

					case UA:
						static const char *const os_type[] = {"android", "windows", "iphone", "ipad", "macintoch", "linux"};
						static const char *const browser_type[] = {"fxios", "crios", "firefox", "edg", "chrome", "safari"};
						if (http_req->os[0] != '\0' || http_req->browser[0] != '\0') {
							return 1;
						}

						const u64 os_max = sizeof(((struct fws_http_req *) nullptr)->os);
						const char *p3 = nullptr;
						const char *p4 = nullptr;
						s32 flag = 0;
						for (u64 i=0; i<sizeof(os_type)/sizeof(os_type[0]); i++) {
							p3 = p1;
							while (1) {
								p4 = memchr(p3, os_type[i][0], p2-p3+1);
								if (p4 == nullptr) {
									break;
								}
								u64 os_n = strnlen(os_type[i], os_max);
								if (os_n == os_max) {
									fprintf(stderr, "_header_parse(): warning: os_n == os_max\n");
								} else {
									os_n++; /* Add null character */
								}
								ret = memcmp(p4, os_type[i], os_n);
								if (ret == 0) {
									memcpy(http_req->os, os_type[i], os_n);
									flag = 1;
									break;
								} else {
									p3 = p4 + 1;
								}
							}
							if (flag) {
								break;
							}
						}
						if (!flag) {
							memcpy(http_req->os, "-", sizeof("-"));
						}

						const u64 browser_max = sizeof(((struct fws_http_req *) nullptr)->browser);
						flag = 0;
						for (u64 i=0; i<sizeof(browser_type)/sizeof(browser_type[0]); i++) {
							p3 = p1;
							while (true) {
								p4 = memchr(p3, browser_type[i][0], p2-p3+1);
								if (p4 == nullptr) {
									break;
								}
								u64 browser_n = strnlen(browser_type[i], browser_max);
								if (browser_n == browser_max) {
									fprintf(stderr, "_header_parse(): warning: browser_n == browser_max\n");
								} else {
									browser_n++; /* Add null character */
								}
								ret = memcmp(p4, browser_type[i], browser_n);
								if (ret == 0) {
									memcpy(http_req->browser, browser_type[i], browser_n);
									flag = 1;
									break;
								} else {
									p3 = p4 + 1;
								}
							}
							if (flag) {
								break;
							}
						}
						if (!flag) {
							memcpy(http_req->browser, "-", sizeof("-"));
						}
						break;

					case AL:
						if (http_req->lang[0] != '\0') {
							return 1;
						}

						p2 = p1;
						while (true) {
							if (*p2 == ',') {
								break;
							} else if (*p2 == ';') {
								break;
							} else if (*p2 == '\n') {
								break;
							}
							p2++;
						}
						n = p2 - p1;
						memcpy(http_req->lang, p1, n);
						http_req->lang[n] = '\0';
						break;

					case ORIGIN:
						memcpy(http_req->origin, p1, n);
						http_req->origin[n] = '\0';
						break;

					case ETAG:
						constexpr u64 etag_max = sizeof(((struct fws_http_req*)nullptr)->etag);
						const char *p_etag_start = p1;
						if (*p_etag_start == '"') {
							p_etag_start++;
						} else {
							FAC_ERR(FAC_ERR_FORMAT);
							break;
						}
						const char *p_etag_end = memchr(p_etag_start, '"', n-1);
						if (p_etag_end == nullptr) {
							FAC_ERR(FAC_ERR_NULL);
							break;
						}
						const u64 etag_len = p_etag_end - p_etag_start;
						if (etag_len >= etag_max) {
							FAC_ERR(FAC_ERR_LIMIT);
							break;
						}
						memcpy(http_req->etag, p_etag_start, etag_len);
						http_req->etag[etag_len] = '\0';
						break;
				}
				break;
			}
		}

		p2 = memchr(p1, '\r', req_value_max);
		if (p2 == nullptr || *(p2+1) != '\n') {
			return 1;
		}
		p1 = p2 + 2;
	}

	return 0;
}

/*static s32 _err_check(const struct fws_http_req *http_req) {
	if (memcmp(http_req->method, "GET", strnlen(http_req->method, sizeof(http_req->method))) != 0) {
		// attack_log
		return 1; // 405 Method Not Allowed
	}

	if (memcmp(http_req->version, "HTTP/1.1", strnlen(http_req->version, sizeof(http_req->version))) != 0) {
		// warn_log
		return 1;
	}

	if (http_req->subdomain[0] == '\0') {
		return 1; // 400 bad
	}
	return 0;
}*/

static s32 _etag_get(char *dst, const char *src, const char *path) {
	constexpr u64 etag_n = sizeof(((struct fws_http_res*)nullptr)->etag);
	s32 etag_fd = -1;
	s32 ret = -1;

	const u64 etag_len = strnlen(src, etag_n);
	if (etag_len == etag_n) {
		fprintf(stderr, "_etag_get(): strnlen(): failure\n");
		ret = -1;
		goto out;
	}
	etag_fd = open(path, O_RDONLY);
	if (etag_fd < 0) {
		fprintf(stderr, "_etag_get(): open(): failure\n");
		ret = -1;
		goto out;
	}

	struct stat etag_stat = {0};
	const s32 stat_ret = fstat(etag_fd, &etag_stat);
	if (stat_ret < 0) {
		fprintf(stderr, "_etag_get(): fstat(): failure\n");
		ret = -1;
		goto out;
	}
	snprintf(dst, etag_n, "%lu_%lu", etag_stat.st_mtime, etag_stat.st_size);

	const s32 cmp_ret = memcmp(dst, src, etag_len+1);
	if (cmp_ret == 0) {
		memcpy(dst, src, etag_len+1);
		ret = 304;
		goto out;
	}

	ret = 0;
out:
	if (etag_fd >= 0) {
		close(etag_fd);
		etag_fd = -1;
	}
	return ret;
}

static s32 _cache_get(char *dst, u64 dst_max, const char *src_cache, u64 src_cache_len,
		const char *src_ext) {
	constexpr char no_cache_str[] = "no-cache";
	constexpr u64 no_cache_len = sizeof(no_cache_str)-1;
	char cache_buf[dst_max];
	memset(cache_buf, '\0', dst_max);

	s32 cache_cnt = 0;
	s32 cache_acc = 0;
	const char *p1 = src_cache;
	while (true) {
		if ((src_cache_len-cache_acc) <= 0) {
			break;
		}
		const char *p2 = memchr(p1, '[', src_cache_len-cache_acc);
		if (p2 == nullptr) {
			break;
		}
		s64 cache_n = p2 - p1;
		if (cache_n < 0) {
			break;
		}
		cache_cnt++;
		cache_acc += cache_n + 1;
		p1 = p2 + 1;
	}

	bool is_find = false;
	const char *p_start = src_cache;
	cache_acc = 0;
	while (cache_cnt > 0) {
		const char *p_end = memchr(p_start, '[', src_cache_len-cache_acc);
		if (p_end == nullptr) {
			FAC_ERR(FAC_ERR_NULL);
			return -1;
		}
		s64 cache_len = p_end - p_start;
		if (cache_len < 0) {
			FAC_ERR(FAC_ERR_RANGE);
			return -1;
		}
		memcpy(cache_buf, p_start, cache_len);
		cache_buf[cache_len] = '\0';
		p_start = p_end + 1;
		cache_acc += cache_len + 1;

		p_end = memchr(p_start, ']', src_cache_len-cache_acc);
		if (p_end == nullptr) {
			FAC_ERR(FAC_ERR_NULL);
			return -1;
		}

		s64 arr_len = p_end - p_start;
		if (arr_len < 0) {
			FAC_ERR(FAC_ERR_RANGE);
			return -1;
		}
		arr_len++;
		const char *p_arr_start = p_start;
		s32 arr_acc = 0;
		while (true) {
			const char *p_arr_end = memchr(p_arr_start, ',', arr_len-arr_acc);
			if (p_arr_end == nullptr) {
				p_arr_end = memchr(p_arr_start, ']', arr_len);
				if (p_arr_end == nullptr) {
					break;
				}
			}
			s64 ext_len = p_arr_end - p_arr_start;
			if (ext_len < 0) {
				FAC_ERR(FAC_ERR_RANGE);
				return -1;
			}
			char ext_buf[32] = {0};
			memcpy(ext_buf, p_arr_start, ext_len);
			ext_buf[ext_len] = '\0';

			s32 ext_cmp_ret = memcmp(ext_buf, src_ext, ext_len+1);
			if (ext_cmp_ret == 0) {
				is_find = true;
				break;
			}

			p_arr_start = p_arr_end + 1;
			arr_acc += ext_len + 1;
		}
		if (is_find) {
			memcpy(dst, cache_buf, cache_len);
			dst[cache_len] = '\0';
			break;
		}

		s64 cache_arr_len = p_end - p_start;
		p_start = p_end + 1;
		cache_acc += cache_arr_len + 1;
		cache_cnt--;
	}

	if (!is_find) {
		memcpy(dst, no_cache_str, no_cache_len);
		dst[no_cache_len] = '\0';
	}

	return 0;
}
