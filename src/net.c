/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include "factype.h"
#include "types.h"
#include "net.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

s32 net_server_init(u16 port) {
	struct sockaddr_in6 server_addr;
	const s32 opt = 1;

	s32 server_fd = socket(AF_INET6, SOCK_STREAM, 0);
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

	u64 n = strnlen(http_req->subdomain, sizeof(http_req->subdomain));
	char *p = host_buf;
	*p = '\0';
	memcpy(p, http_req->subdomain, n);
	p += n;
	*p = '.';
	p++;
	*p = '\0';

	n = strnlen(conf->domain, sizeof(conf->domain));
	memcpy(p, conf->domain, n);
	p += n;
	*p = '\0';

	n = strnlen(port_buf, sizeof(port_buf));
	memcpy(p, port_buf, n);
	p += n;
	*p = '\0';
}
