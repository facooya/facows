/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include "factype.h"
#include "fac_utils.h"
#include "types.h"
#include "net.h"
#include "file.h"
#include "fws.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <assert.h>
#include <unistd.h>

_Atomic I32 sig_flag = -1;

static void _fws_exit(I32 sig);

I32 main(void) {
	static const C8 conf_path_str[] = "/etc/facows/facows.conf";
	struct fws_parent_ctx *parent_ctx_p = FAC_NULL;
	struct fws_child_ctx *child_ctx_p = FAC_NULL;
	I32 pipe_fds[2U] = {-1, -1};
	I32 pipe_read_fd = -1;
	I32 pipe_write_fd = -1;
	I32 ret = 0;

	struct sigaction fws_sa = {0};
	fws_sa.sa_handler = _fws_exit;
	ret = sigaction(SIGINT, &fws_sa, FAC_NULL);
	if (ret < 0) {
		fprintf(stderr, "main(): sigaction(): failed\n");
		ret = 1;
		goto out;
	}
	ret = sigaction(SIGTERM, &fws_sa, FAC_NULL);
	if (ret < 0) {
		fprintf(stderr, "main(): sigaction(): failed\n");
		ret = 1;
		goto out;
	}

	struct fws_conf conf = {0};
	ret = file_conf_read(&conf, conf_path_str);
	if (ret < 0) {
		fprintf(stderr, "main(): file_conf_read(): failed\n");
		ret = 1;
		goto out;
	}

	if (conf.nft == 1U) {
		ret = net_nft_init(&conf);
		if (ret < 0) {
			fprintf(stderr, "main(): net_nft_init(): failed\n");
			return 1;
		}
	}

	ret = pipe(pipe_fds);
	if (ret < 0) {
		fprintf(stderr, "main(): pipe(): pipe failed\n");
		ret = 1;
		goto out;
	}
	pipe_read_fd = pipe_fds[0U];
	pipe_write_fd = pipe_fds[1U];

	const I32 pid = fork();
	if (pid < 0) {
		fprintf(stderr, "main(): fork(): fork failed\n");
		ret = 1;
		goto out;
	}

	if (pid == 0) {
		child_ctx_p = malloc(sizeof(struct fws_child_ctx));
		if (child_ctx_p == FAC_NULL) {
			fprintf(stderr, "main(): malloc(): failed\n");
			ret = 1;
			goto out;
		}
		child_ctx_p->pipe_read_fd = pipe_read_fd;
		child_ctx_p->pipe_write_fd = pipe_write_fd;
		child_ctx_p->sig_flag_opq_p = (I32 *) &sig_flag;
		child_ctx_p->conf_p = &conf;

		fws_child_run(child_ctx_p);
		free(child_ctx_p);
		child_ctx_p = FAC_NULL;

	} else {
		parent_ctx_p = malloc(sizeof(struct fws_parent_ctx));
		if (parent_ctx_p == FAC_NULL) {
			fprintf(stderr, "main(): malloc(): failed\n");
			ret = 1;
			goto out;
		}
		parent_ctx_p->pipe_read_fd = pipe_read_fd;
		parent_ctx_p->pipe_write_fd = pipe_write_fd;
		parent_ctx_p->sig_flag_opq_p = (I32 *) &sig_flag;
		parent_ctx_p->pid = pid;
		parent_ctx_p->conf_p = &conf;

		ret = fws_parent_run(parent_ctx_p);
		if (ret < 0) {
			fprintf(stderr, "main(): fws_parent_run(): error\n");
			ret = 1;
			goto out;
		}
		free(parent_ctx_p);
		parent_ctx_p = FAC_NULL;
	}

	ret = 0;
out:
	free(child_ctx_p);
	child_ctx_p = FAC_NULL;
	free(parent_ctx_p);
	parent_ctx_p = FAC_NULL;
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

static void _fws_exit(I32 sig) {
	sig_flag = sig;
}
