/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "types.h"
#include "utils.h"
#include "conf.h"
#include "net.h"
#include "http.h"
#include "file.h"

#define CONF_FILE "/etc/facows/facows.conf"

struct fws_args {
	int fd;
	SSL_CTX *ssl_ctx;
	struct fws_conf fws_conf;
	struct sockaddr_in6 client_addr;
};

void *fws_handler(void *arg) {
	struct fws_args *args = (struct fws_args *) arg;
	struct fws_conf config = args->fws_conf;
	struct sockaddr_in6 client_addr = args->client_addr;

	int client_fd = args->fd;
	SSL_CTX *ssl_ctx = args->ssl_ctx;

	char request_buf[8192];

	SSL *ssl = SSL_new(ssl_ctx);
	SSL_set_fd(ssl, client_fd);
	if (SSL_accept(ssl) <= 0) {
		net_exit_err(ssl, client_fd, arg);
		return NULL;
	}

	char ip_buf[INET6_ADDRSTRLEN];
	inet_ntop(AF_INET6, client_addr.sin6_addr.s6_addr, ip_buf, sizeof(ip_buf));
	printf("%s\n", ip_buf);

	while (1) {
		// { net_read()
		if (net_read(ssl, request_buf, sizeof(request_buf)) != 0) {
			net_exit_err(ssl, client_fd, arg);
			return NULL;
		}
		// }

		// { http_parse()
		struct fws_http http;
		if (http_parse(request_buf, &http, config.domain, sizeof(config.domain)) != 0) {
			net_exit_err(ssl, client_fd, arg);
			return NULL;
		}
		// }

		// { file_parse()
		struct fws_file file;
		int status_code = file_parse(&file, http.uri, sizeof(http.uri), config.web_root, sizeof(config.web_root));
		// }

		if (status_code != 0) {
			if (net_write_err(ssl, status_code) != 0) {
				net_exit_err(ssl, client_fd, arg);
				return NULL;
			}
		} else {
			struct fws_http_res res;
			http_build_res(&res, file.path, sizeof(file.path));
			if (net_write_res(ssl, res, file.size) != 0) {
				net_exit_err(ssl, client_fd, arg);
				return NULL;
			}
			net_write(ssl, file.path);
		}
	}

	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(client_fd);
	free(arg);

	return NULL;
}

int main() {
	// { init
	struct fws_conf config;
	if (conf_parse(CONF_FILE, &config) != 0) {
		return 0;
	}

	SSL_CTX *ssl_ctx;
	net_init_ssl(&ssl_ctx, &config);

	int server_fd;
	net_init_server(&server_fd, config.port);

	struct sockaddr_in6 client_addr;
	socklen_t client_addr_size = sizeof(client_addr);
	// }

	while (1) {
		int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_addr_size);

		struct fws_args *args = malloc(sizeof(struct fws_args));
		args->fd = client_fd;
		args->ssl_ctx = ssl_ctx;
		args->fws_conf = config;
		args->client_addr = client_addr;

		pthread_t thread;
		pthread_create(&thread, NULL, fws_handler, (void*)args);
		pthread_detach(thread);
	}

	close(server_fd);
	return 0;
}
