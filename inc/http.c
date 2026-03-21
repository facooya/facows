/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>

#include "types.h"
#include "http.h"

#define REQ_MAX 8192
#define REQ_KEY_MAX 64
#define REQ_LINE_MAX 1024

static int _parse_line(const char *req_buf, struct http *http);
static int _parse_header(const char *req_buf, struct http *http, const char *domain);
static int _check_err(const struct http *http);

int http_parse(char *req_buf, struct http *http, const char *domain) {
	_parse_line(req_buf, http);

	for (size_t i=0; i<strnlen(req_buf, REQ_MAX); i++) {
		req_buf[i] = tolower(req_buf[i]);
	}

	_parse_header(req_buf, http, domain);
	return 0;
}

static int _parse_line(const char *req_buf, struct http *http) {
	// { method
	const char *start = req_buf;
	const char *end = memchr(start, ' ', sizeof(http->method));
	if (end == NULL) {
		// err_log
		return 1;
	}
	ptrdiff_t size = end - start;
	if (size >= sizeof(http->method)) {
		// err_log
		return 1;
	}
	strncpy(http->method, start, size);
	http->method[size] = '\0';
	// }

	// { path
	start += size + 1;
	end = memchr(start, ' ', sizeof(http->path));
	if (end == NULL) {
		// err log
		return 1;
	}
	size = end - start;
	if (size >= sizeof(http->path)) {
		// err log
		return 1;
	}
	strncpy(http->path, start, size);
	http->path[size] = '\0';
	// }

	// { version
	start += size + 1;
	end = memchr(start, '\r', sizeof(http->version));
	if (end == NULL) {
		// err log
		return 1;
	}
	size = end - start;
	if (size >= sizeof(http->version)) {
		// err log
		return 1;
	}
	strncpy(http->version, start, size);
	http->version[size] = '\0';
	// }
}

static int _parse_header(const char *req_buf, struct http *http, const char *domain) {
	enum key_idx {HOST, USER_AGENT, ACCEPT_LANG};
	const char keyword[][REQ_KEY_MAX] = {"host", "user-agent", "accept-language"};
	const char *start = req_buf;
	const char *end = memmem(start, REQ_LINE_MAX, "\r\n", 2);
	if (end == NULL) {
		// err log
		return 1;
	}
	start = end + 2;

	while (1) {
		if (strncmp(start, "\r\n", 2) == 0) {
			break;
		}

		const char *keyword_end = memchr(start, ':', REQ_KEY_MAX);
		if (keyword_end == NULL) {
			return 1; // 400 bad
		}

		const char *value_end;
		for (size_t i=0; i<sizeof(keyword)/REQ_KEY_MAX; i++) {
			if (strncmp(start, keyword[i], strlen(keyword[i])) == 0) {
				value_end = memmem(start, REQ_LINE_MAX, "\r\n", 2);
				if (value_end == NULL) {
					return 1; // 400 bad
				}
				ptrdiff_t n = value_end - start;

				switch (i) {
					case HOST:
						if (http->host[0] != '\0') {
							return 1; // 400 bad
						}
						break;
					case USER_AGENT:
						if (http->os[0] != '\0' || http->browser[0] != '\0') {
							return 1; // 400 bad
						}
						break;
					case ACCEPT_LANG:
						if (http->lang[0] != '\0') {
							return 1; // 400 bad
						}
						break;
				}
				break;
			}
		}

		value_end = memmem(start, REQ_LINE_MAX, "\r\n", 2);
		if (value_end == NULL) {
			return 1; // 400 bad
		}
		start = value_end + 2;
	}

	return 0;
}

static int _check_err(const struct http *http) {
	if (strncmp(http->method, "GET", strnlen(http->method, sizeof(http->method))) != 0) {
		// attack_log
		return 1; // 405 Method Not Allowed
	}
	if (strncmp(http->version, "HTTP/1.1", strnlen(http->version, sizeof(http->version))) != 0) {
		// warn_log
		return 1;
	}
}
