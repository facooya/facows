/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include "factype.h"
#include "types.h"
#include "net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

s32 net_80_443_redir(s32 client_80_fd, const struct fws_conf *config) {
	static const char res_301_fmt[] = "HTTP/1.1 301 Move permanently\r\nLocation: https://%s%s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
	char recv_buf[8192] = {0};

	s32 recv_size;
	s32 recv_total_size = 0;
	while (1) {
		recv_size = recv(client_80_fd, recv_buf, sizeof(recv_buf)-1, 0);
		if (recv_size == 0) {
			break;
		} else if (recv_size == -1) {
			return -1;
		}

		recv_total_size += recv_size;
		recv_buf[recv_total_size] = '\0';

		if (recv_total_size >= 8191) {
			return -1;
		} else if (memmem(recv_buf, recv_total_size, "\r\n\r\n", sizeof("\r\n\r\n")-1) != nullptr) {
			break;
		}
	}

	struct fws_http_req http_req;
	http_req.subdomain[0] = '\0';
	http_req.uri[0] = '\0';

	const char *p1 = recv_buf;
	const char *p2 = memchr(p1, ' ', sizeof(http_req.method));
	u64 n;
	if (p2 == nullptr) {
		return -1;
	}
	n = p2 - p1;
	if (n >= sizeof(http_req.method)) {
		return -1;
	}
	p1 += n + 1;
	p2 = memchr(p1, ' ', sizeof(http_req.uri));
	if (p2 == nullptr) {
		return -1;
	}
	n = p2 - p1;
	if (n >= sizeof(http_req.uri)) {
		return -1;
	}
	memcpy(http_req.uri, p1, n);
	http_req.uri[n] = '\0';

	p1 = recv_buf;
	p2 = memmem(p1, 1024, "\r\n", sizeof("\r\n")-1);
	if (p2 == nullptr) {
		return -1;
	}
	p1 = p2 + 2;

	while (1) {
		if (memcmp(p1, "\r\n", sizeof("\r\n")-1) == 0) {
			break;
		}

		if (memcmp(p1, "Host", strnlen("host", sizeof("host"))) == 0) {
			if (http_req.subdomain[0] != '\0') {
				return -1;
			}

			p2 = memchr(p1, ':', 64);
			if (p2 == nullptr) {
				return -1;
			}
			p1 = p2 + 1;
			while (*p1 == ' ') {
				p1++;
			}

			if (memcmp(p1, config->domain, strnlen(config->domain, sizeof(config->domain))) == 0) {
				memcpy(http_req.subdomain, "www", sizeof("www"));
			} else {
				p2 = p1;
				for (u64 i=0; i<sizeof(http_req.subdomain); i++) {
					if (p2[i] == '.') {
						p2 += i;
						break;
					}
				}

				n = p2 - p1;
				memcpy(http_req.subdomain, p1, n);
				http_req.subdomain[n] = '\0';
			}
			break;
		}

		p2 = memmem(p1, 1024, "\r\n", sizeof("\r\n")-1);
		if (p2 == nullptr) {
			return -1;
		}
		p1 = p2 + 2;

	}

	char host_buf[512];
	net_host_build(host_buf, &http_req, config);

	u64 res_n = snprintf(nullptr, 0, res_301_fmt, host_buf, http_req.uri);
	char *res_buf = calloc(res_n+1, 1);
	if (res_buf == nullptr) {
		return -1;
	}
	snprintf(res_buf, res_n+1, res_301_fmt, host_buf, http_req.uri);
	send(client_80_fd, res_buf, strnlen(res_buf, sizeof(res_buf)), 0);
	free(res_buf);
	res_buf = nullptr;
	return 0;
}
