/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include "fac_utils.h"
#include "types.h"
#include "net.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>

#define RES_301 "HTTP/1.1 301 Move permanently\r\nLocation: https://%s%s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"

I32 net_80_443_redir(I32 client_80_fd, const struct fws_conf *config) {
	C8 recv_buf[8192] = {0};

	// { recv
	I32 recv_size;
	I32 recv_total_size = 0;
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
		} else if (memmem(recv_buf, recv_total_size, "\r\n\r\n", sizeof("\r\n\r\n")-1) != NULL) {
			break;
		}

	}
	// }

	// {{ http req
	struct fws_http_req http_req;
	http_req.subdomain[0] = '\0';
	http_req.uri[0] = '\0';

	// { parse uri
	const C8 *p1 = recv_buf;
	const C8 *p2 = memchr(p1, ' ', sizeof(http_req.method));
	U64 n;
	if (p2 == NULL) {
		return -1;
	}
	n = p2 - p1;
	if (n >= sizeof(http_req.method)) {
		return -1;
	}
	p1 += n + 1;
	p2 = memchr(p1, ' ', sizeof(http_req.uri));
	if (p2 == NULL) {
		return -1;
	}
	n = p2 - p1;
	if (n >= sizeof(http_req.uri)) {
		return -1;
	}
	memcpy(http_req.uri, p1, n);
	http_req.uri[n] = '\0';
	// }

	// { parse host
	p1 = recv_buf;
	p2 = memmem(p1, 1024, "\r\n", sizeof("\r\n")-1);
	if (p2 == NULL) {
		return -1;
	}
	p1 = p2 + 2;

	while (1) {
		if (memcmp(p1, "\r\n", sizeof("\r\n")-1) == 0) {
			break;
		}

		if (memcmp(p1, "Host", fac_memclen("host", '\0', sizeof("host"))) == 0) {
			if (http_req.subdomain[0] != '\0') {
				return -1;
			}

			p2 = memchr(p1, ':', 64);
			if (p2 == NULL) {
				return -1;
			}
			p1 = p2 + 1;
			while (*p1 == ' ') {
				p1++;
			}

			if (memcmp(p1, config->domain, fac_memclen(config->domain, '\0', sizeof(config->domain))) == 0) {
				memcpy(http_req.subdomain, "www", sizeof("www"));
			} else {
				p2 = p1;
				for (U64 i=0; i<sizeof(http_req.subdomain); i++) {
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
		if (p2 == NULL) {
			return -1;
		}
		p1 = p2 + 2;

	}
	// }
	// }}

	C8 host_buf[512];
	net_host_build(host_buf, &http_req, config);

	U64 res_n = snprintf(NULL, 0, RES_301, host_buf, http_req.uri);
	C8 *res_buf = malloc(res_n+1);
	if (res_buf == NULL) {
		return -1;
	}
	snprintf(res_buf, res_n+1, RES_301, host_buf, http_req.uri);
	send(client_80_fd, res_buf, fac_memclen(res_buf, '\0', sizeof(res_buf)), 0);
	free(res_buf);
	res_buf = NULL;
	return 0;
}
