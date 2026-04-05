/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
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
#include "nft.h"

#define CONF_PATH "/etc/facows/facows.conf"

struct fws_nft nft_list[1024];

void *fws_handler(void *arg) {
	const struct fws_args *args = (struct fws_args *) arg;
	const struct fws_conf *config = args->fws_conf;
	const struct sockaddr_in6 *client_addr = args->client_addr;

	int client_fd = args->fd;
	SSL_CTX *ssl_ctx = args->ssl_ctx;

	char request_buf[8192];

	SSL *ssl = SSL_new(ssl_ctx);
	SSL_set_fd(ssl, client_fd);
	if (SSL_accept(ssl) <= 0) {
		net_exit_err(ssl, client_fd, arg);
		return NULL;
	}

	while (1) {
		// { net
		if (net_read(ssl, request_buf, sizeof(request_buf)) != 0) {
			net_exit_err(ssl, client_fd, arg);
			return NULL;
		}

		struct fws_http http;
		if (http_parse(request_buf, &http, config->domain, sizeof(config->domain)) != 0) {
			net_exit_err(ssl, client_fd, arg);
			return NULL;
		}
		// }

		// { file
		struct fws_file file;
		int status_code = file_parse(&file, http.uri, sizeof(http.uri), config->web_root, sizeof(config->web_root));

		size_t path_size = fu_memclen(file.path, '\0', sizeof(file.path));
		char *path_p = file.path + path_size - (sizeof(".html") - 1);
		if (memcmp(path_p, ".html", sizeof(".html")) == 0) {
			nft_ban_dos(client_addr, nft_list, sizeof(nft_list)/sizeof(struct fws_nft));
		}

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
		// }
	}

	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(client_fd);
	free(arg);

	return NULL;
}

void facows_end() {
	system("nft delete table inet facows");
	printf("\n");
	exit(0);
}

int main() {
	// { init
	struct fws_conf config;
	if (conf_parse(CONF_PATH, &config) != 0) {
		return 0;
	}

	signal(SIGINT, facows_end);
	signal(SIGTERM, facows_end);

	nft_init(config.port);

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
		args->fws_conf = &config;
		args->client_addr = &client_addr;

		pthread_t thread;
		pthread_create(&thread, NULL, fws_handler, (void*)args);
		pthread_detach(thread);
	}

	close(server_fd);
	facows_end();
	return 0;
}
