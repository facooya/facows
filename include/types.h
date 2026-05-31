/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#ifndef FWS_TYPES_H
#define FWS_TYPES_H

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
	U8 html_cnt;
	U8 no_html_cnt;
	U8 url_redir_cnt;
	U8 uri_redir_cnt;
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
	C8 *path;
	I64 path_n;
	C8 *query;
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

	U8 client_ip[16];
	U8 *ssl_ctx_opq;
	U8 *nft_lock_opq;
	struct fws_conf *fws_conf;
	struct fws_nft **nft_arr_pp;
};

struct fws_swap_ctx {
	I64 global_time;
	I64 swap_time;
	U8 *nft_lock_opq;
	I32 *sig_flag_opq_p;
	struct fws_nft *nft_arr_p;
	struct fws_nft *nft_swap_arr_p;
};

struct fws_parent_ctx {
	I32 pipe_read_fd;
	I32 pipe_write_fd;
	I64 pid;
	I32 *sig_flag_opq;

	struct fws_conf *conf;
};

struct fws_child_ctx {
	I32 pipe_read_fd;
	I32 pipe_write_fd;
	I32 *sig_flag_opq;

	struct fws_conf *conf;
};

#endif
