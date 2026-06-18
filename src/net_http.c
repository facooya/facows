/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include "factype.h"
#include "types.h"
#include "net.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <openssl/ssl.h>

static s32 _line_parse(const char *req_buf, struct fws_http_req *http_req);
static void _uri_parse(struct fws_http_req *http_req);
static s32 _header_parse(const char *req_buf, struct fws_http_req *http_req, const char *domain, u64 domain_n);
//static s32 _err_check(const struct fws_http_req *http_req);

s32 net_http_req_parse(char *req_buf, struct fws_http_req *http_req, const char *domain, u64 domain_n) {
	constexpr u64 req_max = 8192;
	memset(http_req, 0, sizeof(struct fws_http_req));
	_line_parse(req_buf, http_req);
	_uri_parse(http_req);

	for (u64 i=0; i<strnlen(req_buf, req_max); i++) {
		req_buf[i] = tolower(req_buf[i]);
	}

	_header_parse(req_buf, http_req, domain, domain_n);
	return 0;
}

s32 net_http_res_build(struct fws_http_res *http_res, const char *path, u64 path_n) {
	memset(http_res, 0, sizeof(struct fws_http_res));

	time_t raw_time;
	time(&raw_time);
	struct tm tm;
	gmtime_r(&raw_time, &tm);
	strftime(http_res->date, sizeof(http_res->date), "%a, %d %b %Y %H:%M:%S GMT", &tm);

	http_res->code = 200;
	http_res->connection = 0;

	const char *p1 = path;
	const char *p2;
	u64 n = strnlen(p1, path_n);

	while (1) {
		p2 = memchr(p1, '.', n);
		if (p2 == nullptr) {
			break;
		}

		n -= p2 - p1 + 1;
		p1 = p2 + 1;
	}

	if (memcmp(p1, "html", sizeof("html")) == 0) {
		memcpy(http_res->content, "text/html", sizeof("text/html"));
	} else if (memcmp(p1, "css", sizeof("css")) == 0) {
		memcpy(http_res->content, "text/css", sizeof("text/css"));
	} else if (memcmp(p1, "svg", sizeof("svg")) == 0) {
		memcpy(http_res->content, "image/svg+xml", sizeof("image/svg+xml"));
	} else if (memcmp(p1, "php", sizeof("php")) == 0) {
		memcpy(http_res->content, "text/html", sizeof("text/html"));
	} else {
		return 1;
	}

	return 0;
}

void net_http_path_redir(struct fws_http_req *http_req, const struct fws_conf *conf, const struct fws_file *file, u8 *ssl_opq) {
	static const char res_301_fmt[] = "HTTP/1.1 301 Moved permanently\r\nLocation: https://%s%s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
	SSL *ssl = (SSL *) ssl_opq;
	char host_buf[512];
	net_host_build(host_buf, http_req, conf);

	u64 n = snprintf(nullptr, 0, res_301_fmt, host_buf, file->uri_path);
	char *res_buf = malloc(n+1);
	snprintf(res_buf, n+1, res_301_fmt, host_buf, file->uri_path);
	SSL_write(ssl, res_buf, n);
	free(res_buf);
	res_buf = nullptr;
}

static s32 _line_parse(const char *req_buf, struct fws_http_req *http_req) {
	// { method
	const char *p1 = req_buf;
	const char *p2 = memchr(p1, ' ', sizeof(http_req->method));
	u64 n;
	if (p2 == nullptr) {
		// err_log
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
	constexpr u64 req_key_max = 64;
	constexpr u64 req_value_max = 1024;
	enum key_idx {HOST, UA, AL};
	static const char *const keyword[] = {"host", "user-agent", "accept-language"};

	const char *p1 = req_buf;
	const char *p2 = memchr(p1, '\r', req_value_max);
	u64 n;

	if (p2 == nullptr || *(p2+1) != '\n') {
		return 1;
	}
	p1 = p2 + 2;

	while (1) {
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
						static const char *const browser_type[] = {"firefox", "edg", "chrome", "safari"};
						if (http_req->os[0] != '\0' || http_req->browser[0] != '\0') {
							return 1;
						}

						const char *p3;
						const char *p4;
						s32 flag = 0;
						for (u64 i=0; i<sizeof(os_type)/sizeof(os_type[0]); i++) {
							p3 = p1;
							while (1) {
								p4 = memchr(p3, os_type[i][0], p2-p3+1);
								if (p4 == nullptr) {
									break;
								}
								if (memcmp(p4, os_type[i], strnlen(os_type[i], sizeof(os_type[i]))) == 0) {
									memcpy(http_req->os, os_type[i], sizeof(os_type[i]));
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

						flag = 0;
						for (u64 i=0; i<sizeof(browser_type)/sizeof(browser_type[0]); i++) {
							p3 = p1;
							while (1) {
								p4 = memchr(p3, browser_type[i][0], p2-p3+1);
								if (p4 == nullptr) {
									break;
								}
								if (memcmp(p4, browser_type[i], strnlen(browser_type[i], sizeof(browser_type[i]))) == 0) {
									memcpy(http_req->browser, browser_type[i], sizeof(browser_type[i]));
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
						while (1) {
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
