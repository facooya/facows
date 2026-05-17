/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <unistd.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <nftables/libnftables.h>

#include "fac_utils.h"
#include "types.h"
#include "fws.h"
#include "net.h"
#include "file.h"

#define USER_WWW_DATA "www-data"
#define USER_APACHE "apache"
#define USER_HTTP "http"
#define USER_NOBODY "nobody"

struct fws_nft nft_list[1024] = {0};

void *fws_thread_run(void *arg) {
	const struct fws_args *args = (struct fws_args *) arg;
	const struct fws_conf *config = args->fws_conf;
	const struct sockaddr_in6 client_addr = args->client_addr;

	int client_fd = args->fd;
	int write_fd = args->write_fd;
	SSL_CTX *ssl_ctx = args->ssl_ctx;

	SSL *ssl = NULL;

	int ssl_flag = 1;
	char request_buf[8192];

	ssl = SSL_new(ssl_ctx);
	if (ssl == NULL) {
		ssl_flag = -1;
		goto out;
	}

	struct timeval sock_tv = {0};
	sock_tv.tv_sec = 2;
	sock_tv.tv_usec = 0;
	setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&sock_tv, sizeof(sock_tv));

	SSL_set_fd(ssl, client_fd);
	if (SSL_accept(ssl) <= 0) {
		ssl_flag = -1;
		goto out;
	}

	while (1) {
		if (net_443_read(ssl, request_buf, sizeof(request_buf)) != 0) {
			ssl_flag = -1;
			goto out;
		}

		struct fws_http_req http = {0};
		if (net_http_req_parse(request_buf, &http, config->domain, sizeof(config->domain)) != 0) {
			ssl_flag = -1;
			goto out;
		}

		struct fws_file file = {0};
		int status_code = file_parse(&file, &http, config->web_root, sizeof(config->web_root));

		if (status_code == 301) {
			net_http_path_redir(&http, config, &file, ssl);
			ssl_flag = -1;
			goto out;
		}

		if (config->nft == 1) {
			size_t path_size = fac_memclen(file.path, '\0', sizeof(file.path));
			char *path_p = file.path + path_size - (sizeof(".html") - 1);
			if (memcmp(path_p, ".html", sizeof(".html")) == 0) {
				pthread_mutex_lock(args->nft_lock);
				net_nft_dos_ip_send(&client_addr, nft_list, write_fd, sizeof(nft_list)/sizeof(nft_list[0]));
				pthread_mutex_unlock(args->nft_lock);
			}
		}

		if (status_code != 0) {
			if (net_443_err_write(ssl, status_code) < 0) {
				ssl_flag = -1;
				goto out;
			}

		} else {
			struct fws_http_res http_res = {0};
			net_http_res_build(&http_res, file.path, sizeof(file.path));
			if (net_443_res_write(ssl, &http_res, file.size) != 0) {
				ssl_flag = -1;
				goto out;
			}
			net_443_write(ssl, file.path);
		}
	}

out:
	if (ssl_flag >= 0) {
		SSL_shutdown(ssl);
		ssl_flag = -1;
	}
	SSL_free(ssl);
	ssl = NULL;
	if (client_fd >= 0) {
		close(client_fd);
		client_fd = -1;
	}
	(*args->fws_thread_n)--;
	free(arg);
	arg = NULL;

	return NULL;
}
