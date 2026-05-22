/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <sys/types.h>

#include "fac_utils.h"
#include "types.h"
#include "fws.h"
#include "net.h"
#include "file.h"

#define CONF_PATH "/etc/facows/facows.conf"

volatile sig_atomic_t fws_flag = -1;

static void _fws_exit(int sig);

int main() {
	struct fws_parent_ctx *parent_ctx = NULL;
	struct fws_child_ctx *child_ctx = NULL;
	int pipe_fd[2] = {-1, -1};
	int pipe_read_fd = -1;
	int pipe_write_fd = -1;

	int ret = 0;

	signal(SIGINT, _fws_exit);
	signal(SIGTERM, _fws_exit);

	struct fws_conf conf = {0};
	if (file_conf_read(&conf, CONF_PATH) < 0) {
		ret = 1;
		goto out;
	}

	assert(conf.nft == 0 || conf.nft == 1);
	if (conf.nft == 1) {
		if (net_nft_init(&conf) < 0) {
			return 1;
		}
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
		child_ctx = malloc(sizeof(struct fws_child_ctx));
		if (child_ctx == NULL) {
			ret = 1;
			goto out;
		}
		child_ctx->pipe_read_fd = pipe_read_fd;
		child_ctx->pipe_write_fd = pipe_write_fd;
		child_ctx->fws_flag = &fws_flag;
		child_ctx->conf = &conf;

		fws_child_run(child_ctx);
		free(child_ctx);
		child_ctx = NULL;

	} else {
		parent_ctx = malloc(sizeof(struct fws_parent_ctx));
		if (parent_ctx == NULL) {
			ret = 1;
			goto out;
		}
		parent_ctx->pipe_read_fd = pipe_read_fd;
		parent_ctx->pipe_write_fd = pipe_write_fd;
		parent_ctx->fws_flag = &fws_flag;
		parent_ctx->pid = pid;
		parent_ctx->conf = &conf;

		if (fws_parent_run(parent_ctx) < 0) {
			ret = 1;
			goto out;
		}
		free(parent_ctx);
		parent_ctx = NULL;
	}

	ret = 0;
out:
	free(child_ctx);
	child_ctx = NULL;
	free(parent_ctx);
	parent_ctx = NULL;
	if (pipe_read_fd >= 0) {
		close(pipe_read_fd);
		pipe_read_fd = -1;
	}
	if (pipe_write_fd >= 0) {
		close(pipe_write_fd);
		pipe_write_fd = -1;
	}
	return ret;
}

static void _fws_exit(int sig) {
	fws_flag = sig;
}
