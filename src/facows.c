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

#define CONF_PATH "/etc/facows/facows.conf"

volatile sig_atomic_t fws_flag = -1;

static void _fws_exit(int sig);

int main() {
	SSL_CTX *ssl_ctx = NULL;
	int pipe_fd[2] = {-1, -1};
	int pipe_read_fd = -1;
	int pipe_write_fd = -1;
	int server_http_fd = -1;
	int server_https_fd = -1;

	int ret = 0;

	signal(SIGINT, _fws_exit);
	signal(SIGTERM, _fws_exit);

	struct fws_conf conf = {0};
	if (file_conf_read(&conf, CONF_PATH) != 0) {
		ret = 1;
		goto out;
	}

	if (conf.nft == 1) {
		if (net_nft_init(&conf) < 0) {
			return 1;
		}
	}

	net_443_init(&ssl_ctx, &conf);

	if ((server_http_fd = net_server_init(conf.http_port)) < 0) {
		fprintf(stderr, "http socket failed\n");
		ret = 1;
		goto out;
	}
	if ((server_https_fd = net_server_init(conf.https_port)) < 0) {
		fprintf(stderr, "https socket failed\n");
		ret = 1;
		goto out;
	}

	if (pipe(pipe_fd) < 0) {
		fprintf(stderr, "pipe failed\n");
		ret = 1;
		goto out;
	}
	pipe_read_fd = pipe_fd[0];
	pipe_write_fd = pipe_fd[1];

	const pid_t pid = fork();
	if (pid < 0) {
		fprintf(stderr, "fork failed\n");
		ret = 1;
		goto out;
	}

	if (pid == 0) {
		fws_child_run(server_http_fd, server_https_fd, pipe_read_fd, pipe_write_fd, &fws_flag, ssl_ctx, &conf);
	} else {
		if (fws_parent_run(pipe_read_fd, pipe_write_fd, &fws_flag, pid, &conf) < 0) {
			ret = 1;
			goto out;
		}
	}

	ret = 0;
out:
	SSL_CTX_free(ssl_ctx);
	ssl_ctx = NULL;
	if (pipe_read_fd >= 0) {
		close(pipe_read_fd);
		pipe_read_fd = -1;
	}
	if (pipe_write_fd >= 0) {
		close(pipe_write_fd);
		pipe_write_fd = -1;
	}
	if (server_http_fd >= 0) {
		close(server_http_fd);
		server_http_fd = -1;
	}
	if (server_https_fd >= 0) {
		close(server_https_fd);
		server_https_fd = -1;
	}
	return ret;
}

static void _fws_exit(int sig) {
	fws_flag = sig;
}
