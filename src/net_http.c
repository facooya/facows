/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include "types.h"
#include "utils.h"
#include "net.h"

#define REQ_MAX 8192
#define REQ_KEY_MAX 64
#define REQ_VALUE_MAX 1024
#define REQ_UA_MAX 16

static void _init_http(struct fws_http_req *http_req);
static int _parse_line(const char *req_buf, struct fws_http_req *http_req);
static int _parse_header(const char *req_buf, struct fws_http_req *http_req, const char *domain, size_t domain_n);
static int _check_err(const struct fws_http_req *http_req);
static void _init_res(struct fws_http_res *http_res);

int net_http_req_parse(char *req_buf, struct fws_http_req *http_req, const char *domain, size_t domain_n) {
	_init_http(http_req);
	_parse_line(req_buf, http_req);

	for (size_t i=0; i<fu_memclen(req_buf, '\0', REQ_MAX); i++) {
		req_buf[i] = tolower(req_buf[i]);
	}

	_parse_header(req_buf, http_req, domain, domain_n);
	return 0;
}

int net_http_res_build(struct fws_http_res *http_res, const char *path, size_t path_n) {
	_init_res(http_res);

	time_t raw_time;
	time(&raw_time);
	struct tm *tm;
	tm = gmtime(&raw_time);
	strftime(http_res->date, sizeof(http_res->date), "%a, %d %b %Y %H:%M:%S GMT", tm);

	http_res->code = 200;
	http_res->connection = 0;

	const char *p1 = path;
	const char *p2;
	size_t n = fu_memclen(p1, '\0', path_n);

	while (1) {
		p2 = memchr(p1, '.', n);
		if (p2 == NULL) {
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

static void _init_res(struct fws_http_res *http_res) {
	http_res->date[0] = '\0';
	http_res->content[0] = '\0';
}

static void _init_http(struct fws_http_req *http_req) {
	http_req->ip[0] = '\0';
	http_req->lang[0] = '\0';
	http_req->version[0] = '\0';
	http_req->method[0] = '\0';
	http_req->host[0] = '\0';
	http_req->os[0] = '\0';
	http_req->browser[0] = '\0';
	http_req->uri[0] = '\0';
}

static int _parse_line(const char *req_buf, struct fws_http_req *http_req) {
	// { method
	const char *p1 = req_buf;
	const char *p2 = memchr(p1, ' ', sizeof(http_req->method));
	size_t n;
	if (p2 == NULL) {
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
	if (p2 == NULL) {
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
	if (p2 == NULL) {
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
}

static int _parse_header(const char *req_buf, struct fws_http_req *http_req, const char *domain, size_t domain_n) {
	enum key_idx {HOST, UA, AL};
	const char keyword[][REQ_KEY_MAX] = {"host", "user-agent", "accept-language"};

	const char *p1 = req_buf;
	const char *p2 = memchr(p1, '\r', REQ_VALUE_MAX);
	size_t n;

	if (p2 == NULL || *(p2+1) != '\n') {
		// err log
		return 1;
	}
	p1 = p2 + 2;

	while (1) {
		if (memcmp(p1, "\r\n", sizeof("\r\n")-1) == 0) {
			break;
		}

		p2 = memchr(p1, ':', REQ_KEY_MAX);
		if (p2 == NULL) {
			return 1; // 400 bad
		}

		for (size_t i=0; i<sizeof(keyword)/REQ_KEY_MAX; i++) {
			if (memcmp(p1, keyword[i], fu_memclen(keyword[i], '\0', sizeof(keyword[i]))) == 0) {
				p1 = p2 + 1;
				p2 = memchr(p1, '\r', REQ_VALUE_MAX);
				if (p2 == NULL) {
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
						if (http_req->host[0] != '\0') {
							return 1; // 400
						}

						if (memcmp(p1, domain, fu_memclen(domain, '\0', domain_n)) == 0) {
							memcpy(http_req->host, "www", sizeof("www"));
						} else {
							p2 = p1;
							for (size_t i=0; i<sizeof(http_req->host); i++) {
								if (p2[i] == '.') {
									p2 += i;
									break;
								}
							}
							n = p2 - p1;
							memcpy(http_req->host, p1, n);
							http_req->host[n] = '\0';
						}
						break;

					case UA:
						if (http_req->os[0] != '\0' || http_req->browser[0] != '\0') {
							return 1; // 400
						}

						const char os_type[][REQ_UA_MAX] = {"android", "windows", "iphone", "ipad", "macintoch", "linux"};
						const char browser_type[][REQ_UA_MAX] = {"firefox", "edg", "chrome", "safari"};

						const char *p3;
						const char *p4;
						// { os
						int flag = 0;
						for (size_t i=0; i<sizeof(os_type)/sizeof(os_type[0]); i++) {
							p3 = p1;
							while (1) {
								p4 = memchr(p3, os_type[i][0], p2-p3+1);
								if (p4 == NULL) {
									break;
								}
								if (memcmp(p4, os_type[i], fu_memclen(os_type[i], '\0', sizeof(os_type[i]))) == 0) {
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
						for (size_t i=0; i<sizeof(browser_type)/sizeof(browser_type[0]); i++) {
							p3 = p1;
							while (1) {
								p4 = memchr(p3, browser_type[i][0], p2-p3+1);
								if (p4 == NULL) {
									break;
								}
								if (memcmp(p4, browser_type[i], fu_memclen(browser_type[i], '\0', sizeof(browser_type[i]))) == 0) {
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
		if (p2 == NULL || *(p2+1) != '\n') {
			return 1; // 400 bad
		}
		p1 = p2 + 2;
	}

	return 0;
}

static int _check_err(const struct fws_http_req *http_req) {
	if (memcmp(http_req->method, "GET", fu_memclen(http_req->method, '\0', sizeof(http_req->method))) != 0) {
		// attack_log
		return 1; // 405 Method Not Allowed
	}

	if (memcmp(http_req->version, "HTTP/1.1", fu_memclen(http_req->version, '\0', sizeof(http_req->version))) != 0) {
		// warn_log
		return 1;
	}

	if (http_req->host[0] == '\0') {
		return 1; // 400 bad
	}
}
