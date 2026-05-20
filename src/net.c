/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>

#include "fac_utils.h"
#include "types.h"
#include "net.h"

#define REQ_MAX 8192
#define REQ_KEY_MAX 64
#define REQ_VALUE_MAX 1024
#define REQ_UA_MAX 16

int net_server_init(uint16_t port) {
	struct sockaddr_in6 server_addr;
	const int opt = 1;

	int server_fd = socket(AF_INET6, SOCK_STREAM, 0);
	if (server_fd < 0) {
		return -1;
	}
	setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin6_family = AF_INET6;
	server_addr.sin6_addr = in6addr_any;
	server_addr.sin6_port = htons(port);

	errno = 0;
	if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
		printf("%d\n", errno);
		close(server_fd);
		return -1;
	}
	listen(server_fd, 128);

	return server_fd;
}

void net_host_build(char *host_buf, const struct fws_http_req *http_req, const struct fws_conf *conf) {
	char port_buf[8] = {0};
	memset(port_buf, '\0', sizeof(port_buf));
	if (conf->https_port != 443) {
		snprintf(port_buf, sizeof(port_buf), ":%hu", conf->https_port);
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

	n = fac_memclen(port_buf, '\0', sizeof(port_buf));
	memcpy(p, port_buf, n);
	p += n;
	*p = '\0';
}
