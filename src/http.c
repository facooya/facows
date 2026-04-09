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
#include "http.h"

#define REQ_MAX 8192
#define REQ_KEY_MAX 64
#define REQ_VALUE_MAX 1024
#define REQ_UA_MAX 16

static void _init_http(struct fws_http *http);
static int _parse_line(const char *req_buf, struct fws_http *http);
static int _parse_header(const char *req_buf, struct fws_http *http, const char *domain, size_t domain_n);
static int _check_err(const struct fws_http *http);
static void _init_res(struct fws_http_res *res);

int http_parse(char *req_buf, struct fws_http *http, const char *domain, size_t domain_n) {
	_init_http(http);
	_parse_line(req_buf, http);

	for (size_t i=0; i<fu_memclen(req_buf, '\0', REQ_MAX); i++) {
		req_buf[i] = tolower(req_buf[i]);
	}

	_parse_header(req_buf, http, domain, domain_n);
	return 0;
}

int http_build_res(struct fws_http_res *res, const char *path, size_t path_n) {
	_init_res(res);

	time_t raw_time;
	time(&raw_time);
	struct tm *tm;
	tm = gmtime(&raw_time);
	strftime(res->date, sizeof(res->date), "%a, %d %b %Y %H:%M:%S GMT", tm);

	res->code = 200;
	res->connection = 0;

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
		memcpy(res->content, "text/html", sizeof("text/html"));
	} else if (memcmp(p1, "css", sizeof("css")) == 0) {
		memcpy(res->content, "text/css", sizeof("text/css"));
	} else if (memcmp(p1, "svg", sizeof("svg")) == 0) {
		memcpy(res->content, "image/svg+xml", sizeof("image/svg+xml"));
	} else if (memcmp(p1, "php", sizeof("php")) == 0) {
		memcpy(res->content, "text/html", sizeof("text/html"));
	} else {
		return 1;
	}

	return 0;
}

static void _init_res(struct fws_http_res *res) {
	res->date[0] = '\0';
	res->content[0] = '\0';
}

static void _init_http(struct fws_http *http) {
	http->ip[0] = '\0';
	http->lang[0] = '\0';
	http->version[0] = '\0';
	http->method[0] = '\0';
	http->host[0] = '\0';
	http->os[0] = '\0';
	http->browser[0] = '\0';
	http->uri[0] = '\0';
}

static int _parse_line(const char *req_buf, struct fws_http *http) {
	// { method
	const char *p1 = req_buf;
	const char *p2 = memchr(p1, ' ', sizeof(http->method));
	size_t n;
	if (p2 == NULL) {
		// err_log
		return 1;
	}
	n = p2 - p1;
	if (n >= sizeof(http->method)) {
		// err_log
		return 1;
	}
	memcpy(http->method, p1, n);
	http->method[n] = '\0';
	// }

	// { uri
	p1 += n + 1;
	p2 = memchr(p1, ' ', sizeof(http->uri));
	if (p2 == NULL) {
		// err log
		return 1;
	}
	n = p2 - p1;
	if (n >= sizeof(http->uri)) {
		// err log
		return 1;
	}
	memcpy(http->uri, p1, n);
	http->uri[n] = '\0';
	// }

	// { version
	p1 += n + 1;
	p2 = memchr(p1, '\r', sizeof(http->version));
	if (p2 == NULL) {
		// err log
		return 1;
	}
	n = p2 - p1;
	if (n >= sizeof(http->version)) {
		// err log
		return 1;
	}
	memcpy(http->version, p1, n);
	http->version[n] = '\0';
	// }
}

static int _parse_header(const char *req_buf, struct fws_http *http, const char *domain, size_t domain_n) {
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
						if (http->host[0] != '\0') {
							return 1; // 400
						}

						if (memcmp(p1, domain, fu_memclen(domain, '\0', domain_n)) == 0) {
							memcpy(http->host, "www", sizeof("www"));
						} else {
							p2 = p1;
							for (size_t i=0; i<sizeof(http->host); i++) {
								if (p2[i] == '.') {
									p2 += i;
									break;
								}
							}
							n = p2 - p1;
							memcpy(http->host, p1, n);
							http->host[n] = '\0';
						}
						break;

					case UA:
						if (http->os[0] != '\0' || http->browser[0] != '\0') {
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
									memcpy(http->os, os_type[i], sizeof(os_type[i]));
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
							memcpy(http->os, "-", sizeof("-"));
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
									memcpy(http->browser, browser_type[i], sizeof(browser_type[i]));
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
							memcpy(http->browser, "-", sizeof("-"));
						}
						// }
						break;

					case AL:
						if (http->lang[0] != '\0') {
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
						memcpy(http->lang, p1, n);
						http->lang[n] = '\0';
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

static int _check_err(const struct fws_http *http) {
	if (memcmp(http->method, "GET", fu_memclen(http->method, '\0', sizeof(http->method))) != 0) {
		// attack_log
		return 1; // 405 Method Not Allowed
	}

	if (memcmp(http->version, "HTTP/1.1", fu_memclen(http->version, '\0', sizeof(http->version))) != 0) {
		// warn_log
		return 1;
	}

	if (http->host[0] == '\0') {
		return 1; // 400 bad
	}
}
