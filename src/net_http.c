/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include "factype.h"
#include "fac_utils.h"
#include "types.h"
#include "net.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <openssl/ssl.h>

#define RES_301 "HTTP/1.1 301 Moved permanently\r\nLocation: https://%s%s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"

#define REQ_MAX 8192
#define REQ_KEY_MAX 64
#define REQ_VALUE_MAX 1024
#define REQ_UA_MAX 16

static void _http_init(struct fws_http_req *http_req);
static I32 _line_parse(const C8 *req_buf, struct fws_http_req *http_req);
static void _uri_parse(struct fws_http_req *http_req);
static I32 _header_parse(const C8 *req_buf, struct fws_http_req *http_req, const C8 *domain, U64 domain_n);
//static I32 _err_check(const struct fws_http_req *http_req);
static void _res_init(struct fws_http_res *http_res);

I32 net_http_req_parse(C8 *req_buf, struct fws_http_req *http_req, const C8 *domain, U64 domain_n) {
	_http_init(http_req);
	_line_parse(req_buf, http_req);
	_uri_parse(http_req);

	for (U64 i=0; i<fac_memclen(req_buf, '\0', REQ_MAX); i++) {
		req_buf[i] = tolower(req_buf[i]);
	}

	_header_parse(req_buf, http_req, domain, domain_n);
	return 0;
}

I32 net_http_res_build(struct fws_http_res *http_res, const C8 *path, U64 path_n) {
	_res_init(http_res);

	time_t raw_time;
	time(&raw_time);
	struct tm tm;
	gmtime_r(&raw_time, &tm);
	strftime(http_res->date, sizeof(http_res->date), "%a, %d %b %Y %H:%M:%S GMT", &tm);

	http_res->code = 200;
	http_res->connection = 0;

	const C8 *p1 = path;
	const C8 *p2;
	U64 n = fac_memclen(p1, '\0', path_n);

	while (1) {
		p2 = memchr(p1, '.', n);
		if (p2 == FAC_NULL) {
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

void net_http_path_redir(struct fws_http_req *http_req, const struct fws_conf *conf, const struct fws_file *file, U8 *ssl_opq) {
	SSL *ssl = (SSL *) ssl_opq;
	C8 host_buf[512];
	net_host_build(host_buf, http_req, conf);

	U64 n = snprintf(FAC_NULL, 0, RES_301, host_buf, file->uri_path);
	C8 *res_buf = malloc(n+1);
	snprintf(res_buf, n+1, RES_301, host_buf, file->uri_path);
	SSL_write(ssl, res_buf, n);
	free(res_buf);
	res_buf = FAC_NULL;
}

static void _res_init(struct fws_http_res *http_res) {
	http_res->date[0] = '\0';
	http_res->content[0] = '\0';
}

static void _http_init(struct fws_http_req *http_req) {
	http_req->ip[0] = '\0';
	http_req->lang[0] = '\0';
	http_req->version[0] = '\0';
	http_req->method[0] = '\0';
	http_req->os[0] = '\0';
	http_req->browser[0] = '\0';
	http_req->subdomain[0] = '\0';
	http_req->uri[0] = '\0';
	http_req->path = FAC_NULL;
	http_req->path_n = 0;
	http_req->query = FAC_NULL;
	http_req->query_n = 0;
}

static I32 _line_parse(const C8 *req_buf, struct fws_http_req *http_req) {
	// { method
	const C8 *p1 = req_buf;
	const C8 *p2 = memchr(p1, ' ', sizeof(http_req->method));
	U64 n;
	if (p2 == FAC_NULL) {
		// err_log
		return 1;
	}
	n = p2 - p1;
	if (n >= sizeof(http_req->method)) {
		// err_log
		return 1;
	}
	memcpy(http_req->method, p1, n);
	http_req->method[n] = '\0';
	// }

	// { uri
	p1 += n + 1;
	p2 = memchr(p1, ' ', sizeof(http_req->uri));
	if (p2 == FAC_NULL) {
		// err log
		return 1;
	}
	n = p2 - p1;
	if (n >= sizeof(http_req->uri)) {
		// err log
		return 1;
	}
	memcpy(http_req->uri, p1, n);
	http_req->uri[n] = '\0';
	// }

	// { version
	p1 += n + 1;
	p2 = memchr(p1, '\r', sizeof(http_req->version));
	if (p2 == FAC_NULL) {
		// err log
		return 1;
	}
	n = p2 - p1;
	if (n >= sizeof(http_req->version)) {
		// err log
		return 1;
	}
	memcpy(http_req->version, p1, n);
	http_req->version[n] = '\0';
	// }
	return 0;
}

static void _uri_parse(struct fws_http_req *http_req) {
	C8 *p1 = http_req->uri;
	C8 *p2;
	U64 uri_len = fac_memclen(http_req->uri, '\0', sizeof(http_req->uri));

	http_req->path = p1;
	p2 = memchr(http_req->uri, '?', uri_len);
	if (p2 == FAC_NULL) {
		http_req->path_n = uri_len;
	} else {
		http_req->path_n = p2 - p1;
		http_req->query = p2 + 1;
		http_req->query_n = uri_len - (http_req->path_n + 1);
	}
}

static I32 _header_parse(const C8 *req_buf, struct fws_http_req *http_req, const C8 *domain, U64 domain_n) {
	enum key_idx {HOST, UA, AL};
	const C8 keyword[][REQ_KEY_MAX] = {"host", "user-agent", "accept-language"};

	const C8 *p1 = req_buf;
	const C8 *p2 = memchr(p1, '\r', REQ_VALUE_MAX);
	U64 n;

	if (p2 == FAC_NULL || *(p2+1) != '\n') {
		// err log
		return 1;
	}
	p1 = p2 + 2;

	while (1) {
		if (memcmp(p1, "\r\n", sizeof("\r\n")-1) == 0) {
			break;
		}

		p2 = memchr(p1, ':', REQ_KEY_MAX);
		if (p2 == FAC_NULL) {
			return 1; // 400 bad
		}

		for (U64 i=0; i<sizeof(keyword)/REQ_KEY_MAX; i++) {
			if (memcmp(p1, keyword[i], fac_memclen(keyword[i], '\0', sizeof(keyword[i]))) == 0) {
				p1 = p2 + 1;
				p2 = memchr(p1, '\r', REQ_VALUE_MAX);
				if (p2 == FAC_NULL) {
					return 1; // 400 bad
				}
				while (*p1 == ' ') {
					p1++;
				}
				n = p2 - p1;

				// p1: value start
				// n: value size
				switch (i) {
					case HOST:
						if (http_req->subdomain[0] != '\0') {
							return 1; // 400
						}

						if (memcmp(p1, domain, fac_memclen(domain, '\0', domain_n)) == 0) {
							memcpy(http_req->subdomain, "www", sizeof("www"));
						} else {
							p2 = p1;
							for (U64 i=0; i<sizeof(http_req->subdomain); i++) {
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
						if (http_req->os[0] != '\0' || http_req->browser[0] != '\0') {
							return 1; // 400
						}

						const C8 os_type[][REQ_UA_MAX] = {"android", "windows", "iphone", "ipad", "macintoch", "linux"};
						const C8 browser_type[][REQ_UA_MAX] = {"firefox", "edg", "chrome", "safari"};

						const C8 *p3;
						const C8 *p4;
						// { os
						I32 flag = 0;
						for (U64 i=0; i<sizeof(os_type)/sizeof(os_type[0]); i++) {
							p3 = p1;
							while (1) {
								p4 = memchr(p3, os_type[i][0], p2-p3+1);
								if (p4 == FAC_NULL) {
									break;
								}
								if (memcmp(p4, os_type[i], fac_memclen(os_type[i], '\0', sizeof(os_type[i]))) == 0) {
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
						// }

						// { browser
						flag = 0;
						for (U64 i=0; i<sizeof(browser_type)/sizeof(browser_type[0]); i++) {
							p3 = p1;
							while (1) {
								p4 = memchr(p3, browser_type[i][0], p2-p3+1);
								if (p4 == FAC_NULL) {
									break;
								}
								if (memcmp(p4, browser_type[i], fac_memclen(browser_type[i], '\0', sizeof(browser_type[i]))) == 0) {
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
						// }
						break;

					case AL:
						if (http_req->lang[0] != '\0') {
							return 1; // 400
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

		p2 = memchr(p1, '\r', REQ_VALUE_MAX);
		if (p2 == FAC_NULL || *(p2+1) != '\n') {
			return 1; // 400 bad
		}
		p1 = p2 + 2;
	}

	return 0;
}

/*static I32 _err_check(const struct fws_http_req *http_req) {
	if (memcmp(http_req->method, "GET", fac_memclen(http_req->method, '\0', sizeof(http_req->method))) != 0) {
		// attack_log
		return 1; // 405 Method Not Allowed
	}

	if (memcmp(http_req->version, "HTTP/1.1", fac_memclen(http_req->version, '\0', sizeof(http_req->version))) != 0) {
		// warn_log
		return 1;
	}

	if (http_req->subdomain[0] == '\0') {
		return 1; // 400 bad
	}
	return 0;
}*/
