/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#ifndef FWS_TYPES_H
#define FWS_TYPES_H

#include <netinet/in.h>

#include "factype.h"

struct fws_conf {
	U8 nft;
	U8 hsts;
	U16 http_port;
	U16 https_port;
	U32 pps_limit;
	U32 pps_burst;
	U32 ban_time;
	U32 hsts_max_age;

	C8 allow_ports[128];
	C8 domain[128];
	C8 web_root[128];
	C8 web_log[128];
	C8 ssl_cert[128];
	C8 ssl_key[128];
};

struct fws_nft {
	U8 ip[16];
	I32 count;
	I64 time;
};

struct fws_http_res {
	I32 code;
	I32 connection;
	C8 content[16];
	C8 date[32];
};

struct fws_http_req {
	C8 ip[16];
	C8 lang[16];
	C8 version[16];
	C8 method[16];
	C8 os[16];
	C8 browser[16];
	C8 subdomain[64];
	C8 uri[4096];
	const C8 *path;
	I64 path_n;
	const C8 *query;
	I64 query_n;
};

struct fws_file {
	C8 uri_path[4096];
	I64 uri_path_n;
	C8 path[4096];
	I64 size;
};

struct fws_thread_ctx {
	I32 fd;
	I32 write_fd;
	_Atomic I32 *fws_thread_n;

	U8 *ssl_ctx_opq;
	struct sockaddr_in6 client_addr;
	const struct fws_conf *fws_conf;
	const U8 *nft_lock;
};

struct fws_parent_ctx {
	I32 pipe_read_fd;
	I32 pipe_write_fd;
	I64 pid;
	volatile _Atomic I32 *fws_flag;

	const struct fws_conf *conf;
};

struct fws_child_ctx {
	I32 pipe_read_fd;
	I32 pipe_write_fd;
	volatile _Atomic I32 *fws_flag;

	const struct fws_conf *conf;
};

#endif
