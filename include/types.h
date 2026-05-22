/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#ifndef FWS_TYPES_H
#define FWS_TYPES_H

#include <stdatomic.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>

#include "factype.h"

struct fws_conf {
	fac_u8 nft;
	fac_u8 hsts;

	fac_u32 http_port;
	fac_u32 https_port;
	fac_u32 pps_limit;
	fac_u32 pps_burst;
	fac_u32 ban_time;
	fac_u32 hsts_max_age;

	char allow_ports[128];
	char domain[128];
	char web_root[128];
	char web_log[128];
	char ssl_cert[128];
	char ssl_key[128];
};

struct fws_nft {
	fac_u8 ip[16];
	int count;
	time_t time;
};

struct fws_http_res {
	int code;
	int connection;
	char content[16];
	char date[32];
};

struct fws_http_req {
	char ip[16];
	char lang[16];
	char version[16];
	char method[16];
	char os[16];
	char browser[16];
	char subdomain[64];
	char uri[4096];
	const char *path;
	size_t path_n;
	const char *query;
	size_t query_n;
};

struct fws_file {
	char uri_path[4096];
	size_t uri_path_n;
	char path[4096];
	off_t size;
};

struct fws_thread_ctx {
	int fd;
	int write_fd;
	SSL_CTX *ssl_ctx;
	struct sockaddr_in6 client_addr;
	const struct fws_conf *fws_conf;
	atomic_int *fws_thread_n;
	pthread_mutex_t *nft_lock;
};

struct fws_parent_ctx {
	int pipe_read_fd;
	int pipe_write_fd;
	volatile sig_atomic_t *fws_flag;
	pid_t pid;
	const struct fws_conf *conf;
};

struct fws_child_ctx {
	int pipe_read_fd;
	int pipe_write_fd;
	volatile sig_atomic_t *fws_flag;
	const struct fws_conf *conf;
};

#endif
