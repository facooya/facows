/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include <stdio.h>

#include "types.h"
#include "utils.h"
#include "net.h"

int net_80_443_redir(int client_80_fd, const struct fws_conf *config) {
	char recv_buf[8192] = {0};
	char header_raw[] = "HTTP/1.1 301 Move permanently\r\nLocation: https://%s%s%s%s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
	char header_buf[1024] = {0};

	char port_str[7];
	port_str[0] = '\0';
	if (config->https_port != 443) {
		snprintf(port_str, sizeof(port_str), ":%hu", config->https_port);
	}

	// { recv
	int recv_size;
	int recv_total_size = 0;
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
		} else if (fu_memstr(recv_buf, "\r\n\r\n", recv_total_size) != NULL) {
			break;
		}

	}
	// }

	// {{ http
	struct fws_http http;
	http.host[0] = '\0';
	http.uri[0] = '\0';

	// { parse uri
	const char *p1 = recv_buf;
	const char *p2 = memchr(p1, ' ', sizeof(http.method));
	size_t n;
	if (p2 == NULL) {
		return -1;
	}
	n = p2 - p1;
	if (n >= sizeof(http.method)) {
		return -1;
	}
	p1 += n + 1;
	p2 = memchr(p1, ' ', sizeof(http.uri));
	if (p2 == NULL) {
		return -1;
	}
	n = p2 - p1;
	if (n >= sizeof(http.uri)) {
		return -1;
	}
	memcpy(http.uri, p1, n);
	http.uri[n] = '\0';
	// }

	// { parse host
	p1 = recv_buf;
	p2 = fu_memstr(p1, "\r\n", 1024);
	if (p2 == NULL) {
		return -1;
	}
	p1 = p2 + 2;

	while (1) {
		if (memcmp(p1, "\r\n", sizeof("\r\n")-1) == 0) {
			break;
		}

		if (memcmp(p1, "Host", fu_memclen("host", '\0', sizeof("host"))) == 0) {
			if (http.host[0] != '\0') {
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

			if (memcmp(p1, config->domain, fu_memclen(config->domain, '\0', sizeof(config->domain))) == 0) {
				memcpy(http.host, "www", sizeof("www"));
			} else {
				p2 = p1;
				for (size_t i=0; i<sizeof(http.host); i++) {
					if (p2[i] == '.') {
						p2 += i;
						break;
					}
				}

				n = p2 - p1;
				memcpy(http.host, p1, n);
				http.host[n] = '\0';
			}
			break;
		}

		p2 = fu_memstr(p1, "\r\n", 1024);
		if (p2 == NULL) {
			return -1;
		}
		p1 = p2 + 2;

	}
	// }
	// }}

	printf("%s, %s\n", http.host, http.uri);
	n = fu_memclen(http.host, '\0', sizeof(http.host));
	http.host[n] = '.';
	http.host[n+1] = '\0';

	snprintf(header_buf, sizeof(header_buf), header_raw, http.host, config->domain, port_str, http.uri);
	send(client_80_fd, header_buf, strlen(header_buf), 0);
	return 0;
}
