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

s32 net_80_443_redir(s32 client_80_fd, const struct fws_conf *conf_p) {
	static const char res_301_fmt[] = "HTTP/1.1 301 Moved Permanently\r\nLocation: https://%s%s\r\nContent-Length: 0\r\nConnection: close\r\nServer: Facooya-Web-Server\r\n\r\n";
	static const char nl_str[] = "\r\n";
	static const char nl2_str[] = "\r\n\r\n";
	static const char host_key_str[] = "Host:";
	static const char www_str[] = "www";
	char *res_buf = nullptr;
	s32 ret = -1;
	const char *ret_p = nullptr;

	/* Receive request header */
	constexpr u64 recv_buf_cap = 8192;
	constexpr u64 recv_max = recv_buf_cap - 1;
	char recv_buf[recv_buf_cap] = {0};
	u32 recv_acc = 0;
	while (true) {
		s32 recv_size = recv(client_80_fd, recv_buf, sizeof(recv_buf)-1, 0);
		if (recv_size < 0) {
			ret = -1;
			goto out;
		}
		if (recv_size == 0) {
			break;
		}

		recv_acc += recv_size;
		recv_buf[recv_acc] = '\0';

		if (recv_acc >= recv_max) {
			ret = -1;
			goto out;
		}

		ret_p = memmem(recv_buf, recv_acc, nl2_str, sizeof(nl2_str)-1);
		if (ret_p != nullptr) {
			break;
		}
	}

	/* Parsing URI */
	struct fws_http_req http_req = {0};
	http_req.subdomain[0] = '\0';
	http_req.uri[0] = '\0';
	const char *p_start = recv_buf;
	const char *p_end = memchr(p_start, ' ', sizeof(http_req.method));
	if (p_end == nullptr) {
		ret = -1;
		goto out;
	}
	u64 n = p_end - p_start;
	if (n >= sizeof(http_req.method)) {
		ret = -1;
		goto out;
	}
	p_start += n + 1;
	p_end = memchr(p_start, ' ', sizeof(http_req.uri));
	if (p_end == nullptr) {
		ret = -1;
		goto out;
	}
	n = p_end - p_start;
	if (n >= sizeof(http_req.uri)) {
		ret = -1;
		goto out;
	}
	memcpy(http_req.uri, p_start, n);
	http_req.uri[n] = '\0';

	p_start = recv_buf;
	p_end = memmem(p_start, 1024, nl_str, sizeof(nl_str)-1);
	if (p_end == nullptr) {
		ret = -1;
		goto out;
	}
	p_start = p_end + 2;

	/* Parsing subdomain */
	ret = strnlen(conf_p->domain, sizeof(conf_p->domain));
	if (ret == sizeof(conf_p->domain)) {
		ret = -1;
		goto out;
	}
	u64 domain_len = (u64) ret;
	while (true) {
		ret = memcmp(p_start, nl_str, sizeof(nl_str)-1);
		if (ret == 0) {
			break;
		}

		ret = strncasecmp(p_start, host_key_str, sizeof(host_key_str)-1);
		if (ret == 0) {
			if (http_req.subdomain[0] != '\0') {
				ret = -1;
				goto out;
			}

			p_end = memchr(p_start, ':', 64);
			if (p_end == nullptr) {
				ret = -1;
				goto out;
			}
			p_start = p_end + 1;
			while (*p_start == ' ') {
				p_start++;
			}

			ret = memcmp(p_start, conf_p->domain, domain_len);
			if (ret == 0) {
				memcpy(http_req.subdomain, www_str, sizeof(www_str));
			} else {
				p_end = p_start;
				for (u64 i=0; i<sizeof(http_req.subdomain); i++) {
					if (p_end[i] == '.') {
						p_end += i;
						break;
					}
				}

				n = p_end - p_start;
				memcpy(http_req.subdomain, p_start, n);
				http_req.subdomain[n] = '\0';
			}
			break;
		}

		p_end = memmem(p_start, 1024, nl_str, sizeof(nl_str)-1);
		if (p_end == nullptr) {
			ret = -1;
			goto out;
		}
		p_start = p_end + 2;
	}

	/* Send 301 response */
	char host_buf[512] = {0};
	net_host_build(host_buf, &http_req, conf_p);

	u64 res_n = snprintf(nullptr, 0, res_301_fmt, host_buf, http_req.uri);
	res_buf = calloc(res_n+1, 1);
	if (res_buf == nullptr) {
		ret = -1;
		goto out;
	}
	snprintf(res_buf, res_n+1, res_301_fmt, host_buf, http_req.uri);
	ret = send(client_80_fd, res_buf, strnlen(res_buf, res_n+1), 0);
	if (ret < 0) {
		ret = -1;
		goto out;
	}

	ret = 0;
out:
	free(res_buf);
	res_buf = nullptr;
	return ret;
}
