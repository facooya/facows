/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include "fac_utils.h"
#include "types.h"
#include "net.h"
#include "file.h"

#define CONF_PATH "/etc/facows/facows.conf"

volatile sig_atomic_t fws_flag;
pthread_mutex_t nft_lock;
struct fws_nft nft_list[1024];

static void *_fws_thread_run(void *arg);
static void _fws_exit(int sig);

int main() {
	// { init
	struct fws_conf config;
	if (file_conf_read(&config, CONF_PATH) != 0) {
		return 1;
	}

	signal(SIGINT, _fws_exit);
	signal(SIGTERM, _fws_exit);
	fws_flag = 0;

	net_nft_init(config.http_port, config.https_port);
	net_tc_init();

	SSL_CTX *ssl_ctx;
	net_443_init(&ssl_ctx, &config);

	int server_http_fd = net_server_init(config.http_port);
	int server_https_fd = net_server_init(config.https_port);
	if (server_http_fd < 0 || server_https_fd < 0) {
		return 1;
	}

	struct pollfd fds[2];
	fds[0].fd = server_http_fd;
	fds[0].events = POLLIN;
	fds[1].fd = server_https_fd;
	fds[1].events = POLLIN;

	struct sockaddr_in6 client_addr;
	socklen_t client_addr_size = sizeof(client_addr);

	pthread_mutex_init(&nft_lock, NULL);
	// }

	while (1) {
		if (poll(fds, 2, -1) < 0 && (fws_flag == SIGINT || fws_flag == SIGTERM)) {
			break;
		}

		if (fds[0].revents & POLLIN) {
			int client_http_fd = accept(server_http_fd, (struct sockaddr*)&client_addr, &client_addr_size);

			if (net_80_443_redir(client_http_fd, &config) < 0) {
				close(client_http_fd);
				continue;
			}

			close(client_http_fd);

		} else if (fds[1].revents & POLLIN) {
			int client_fd = accept(server_https_fd, (struct sockaddr*)&client_addr, &client_addr_size);

			struct fws_args *args = malloc(sizeof(struct fws_args));
			args->fd = client_fd;
			args->ssl_ctx = ssl_ctx;
			args->fws_conf = &config;
			args->client_addr = &client_addr;
	
			pthread_t fws_thread;
			pthread_create(&fws_thread, NULL, _fws_thread_run, (void*)args);
			pthread_detach(fws_thread);
		}
	}

	pthread_mutex_destroy(&nft_lock);
	close(server_http_fd);
	close(server_https_fd);

	system(
		"tc qdisc del dev ifb0 root;"
		"tc qdisc del dev eno1 ingress;"
		"ip link set dev ifb0 down;"
		"modprobe -r ifb;"
		"nft delete table inet facows;"
	);

	printf("\n");

	return 0;
}

static void *_fws_thread_run(void *arg) {
	const struct fws_args *args = (struct fws_args *) arg;
	const struct fws_conf *config = args->fws_conf;
	const struct sockaddr_in6 *client_addr = args->client_addr;

	int client_fd = args->fd;
	SSL_CTX *ssl_ctx = args->ssl_ctx;

	char request_buf[8192];

	SSL *ssl = SSL_new(ssl_ctx);
	SSL_set_fd(ssl, client_fd);
	if (SSL_accept(ssl) <= 0) {
		net_443_err_exit(ssl, client_fd, arg);
		return NULL;
	}

	while (1) {
		// { net
		if (net_443_read(ssl, request_buf, sizeof(request_buf)) != 0) {
			net_443_err_exit(ssl, client_fd, arg);
			return NULL;
		}

		struct fws_http_req http;
		if (net_http_req_parse(request_buf, &http, config->domain, sizeof(config->domain)) != 0) {
			net_443_err_exit(ssl, client_fd, arg);
			return NULL;
		}
		// }

		// { file
		struct fws_file file;
		int status_code = file_parse(&file, &http, config->web_root, sizeof(config->web_root));

		if (status_code == 301) {
			net_http_path_redir(&http, config, &file, ssl);

			SSL_shutdown(ssl);
			SSL_free(ssl);
			close(client_fd);
			free(arg);
			return NULL;
		}

		size_t path_size = fac_memclen(file.path, '\0', sizeof(file.path));
		char *path_p = file.path + path_size - (sizeof(".html") - 1);
		if (memcmp(path_p, ".html", sizeof(".html")) == 0) {
			pthread_mutex_lock(&nft_lock);
			net_nft_dos_ban(client_addr, nft_list, sizeof(nft_list)/sizeof(struct fws_nft));
			pthread_mutex_unlock(&nft_lock);
		}

		if (status_code != 0) {
			if (net_443_err_write(ssl, status_code) != 0) {
				net_443_err_exit(ssl, client_fd, arg);
				return NULL;
			}

		} else {
			struct fws_http_res http_res;
			net_http_res_build(&http_res, file.path, sizeof(file.path));
			if (net_443_res_write(ssl, &http_res, file.size) != 0) {
				net_443_err_exit(ssl, client_fd, arg);
				return NULL;
			}
			net_443_write(ssl, file.path);
		}
		// }
	}

	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(client_fd);
	free(arg);

	return NULL;
}

static void _fws_exit(int sig) {
	fws_flag = sig;
}
