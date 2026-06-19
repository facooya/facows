/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#ifndef FWS_TYPES_H
#define FWS_TYPES_H

#include "factype.h"

struct fws_lookup {
	u64 offset;
	u8 type;
	char *key_name;
};

struct fws_conf {
	u16 http_port;
	u16 https_port;
	u32 pps_limit;
	u32 pps_burst;
	u32 ban_time;
	u32 ban_lim;
	u32 hsts_max_age;
	u32 lim_swap_time;
	u32 lim_page;
	u32 lim_res;

	bool use_nft;
	bool use_hsts;

	char allow_ports[128];
	char domain[128];
	char web_root[128];
	char web_log[128];
	char ssl_cert[128];
	char ssl_key[128];
};

struct fws_nft {
	u8 ip_buf[16];
	u16 html_cnt;
	u16 no_html_cnt;
	u16 dos_cnt;
};

struct fws_http_res {
	u32 hsts_max_age;
	s32 code;
	s32 connection;
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
	char *path;
	s64 path_n;
	char *query;
	s64 query_n;
};

struct fws_file {
	char uri_path[4096];
	s64 uri_path_n;
	char path[4096];
	s64 size;
};

struct fws_thrd_ctx {
	s32 fd;
	s32 write_fd;
	s32 *thrd_n_opq_p;

	u8 client_ip_buf[16];
	u8 *ssl_ctx_opq_p;
	u8 *nft_lock_opq_p;
	struct fws_conf *conf_p;
	struct fws_nft **nft_arr_pp;
};

struct fws_swap_ctx {
	s64 global_time;
	s64 swap_time;
	s32 *thrd_n_opq_p;
	u8 *nft_lock_opq_p;
	s32 *sig_flag_opq_p;
	struct fws_nft **nft_arr_pp;
	struct fws_nft *nft_swap_arr_p;
	struct fws_conf *conf_p;
};

struct fws_parent_ctx {
	s32 pipe_read_fd;
	s32 pipe_write_fd;
	s64 pid;
	s32 *sig_flag_opq_p;

	struct fws_conf *conf_p;
};

struct fws_child_ctx {
	s32 pipe_read_fd;
	s32 pipe_write_fd;
	s32 *sig_flag_opq_p;

	struct fws_conf *conf_p;
};

#endif
