/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>

#include "fac_utils.h"
#include "types.h"
#include "net.h"

#define REQ_MAX 8192
#define REQ_KEY_MAX 64
#define REQ_VALUE_MAX 1024
#define REQ_UA_MAX 16

int net_server_init(int *server_fd, uint16_t port) {
	struct sockaddr_in6 server_addr;
	const int opt = 1;

	*server_fd = socket(AF_INET6, SOCK_STREAM, 0);
	setsockopt(*server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin6_family = AF_INET6;
	server_addr.sin6_addr = in6addr_any;
	server_addr.sin6_port = htons(port);

	bind(*server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));
	listen(*server_fd, 128);
	return 0;
}

void net_host_build(char *host_buf, const struct fws_http_req *http_req, const struct fws_conf *conf) {
	char port[8];
	port[0] = '\0';
	if (conf->https_port != 443) {
		snprintf(port, sizeof(port), ":%hu", conf->https_port);
	}

	size_t n = fac_memclen(http_req->subdomain, '\0', sizeof(http_req->subdomain));
	char *p = host_buf;
	*p = '\0';
	memcpy(p, http_req->subdomain, n);
	p += n;
	*p = '.';
	p++;
	*p = '\0';

	n = fac_memclen(conf->domain, '\0', sizeof(conf->domain));
	memcpy(p, conf->domain, n);
	p += n;
	*p = '\0';
	n = fac_memclen(port, '\0', sizeof(port));
	memcpy(p, port, n+1);
}
