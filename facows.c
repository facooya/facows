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

#include <sys/stat.h>
#include <fcntl.h>

#include "types.h"
#include "utils.h"
#include "conf.h"
#include "net.h"
#include "http.h"
#include "file.h"
#include "nft.h"

#define CONF_PATH "/etc/facows/facows.conf"

#define TC_PATH "/etc/facows/facows_tc.conf"
#define NET_NAME "eno1"
#define NET_VNAME "ifb0"
#define BANDWIDTH "90mbps"

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
	system("tc qdisc del dev ifb0 root");
	system("tc qdisc del dev eno1 ingress");
	system("ip link set dev ifb0 down");
	system("modprobe -r ifb");

	system("nft delete table netdev facows");
	system("nft delete table inet facows");
	printf("\n");
	exit(0);
}

void tc_init() {
	struct stat tc_st;
	stat(TC_PATH, &tc_st);
	off_t tc_size = tc_st.st_size;

	char tc_raw[1024];
	char tc_cmd[1024];

	int tc_fd = open(TC_PATH, O_RDONLY);
	read(tc_fd, tc_raw, sizeof(tc_raw)-1);
	tc_raw[tc_size] = '\0';
	close(tc_fd);

	snprintf(tc_cmd, sizeof(tc_cmd), tc_raw, NET_NAME, NET_VNAME, BANDWIDTH);
	system(tc_cmd);
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
	tc_init();

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
