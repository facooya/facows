/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#ifndef FWS_NET_H
#define FWS_NET_H

#include "factype.h"

struct nft_ctx;

int net_server_init(U16 port);
void net_host_build(char *host_buf, const struct fws_http_req *http_req, const struct fws_conf *conf);
int net_80_443_redir(int client_80_fd, const struct fws_conf *config);

int net_443_init(U8 **ssl_ctx_opq, const struct fws_conf *config);
int net_443_read(U8 *ssl_opq, char *dst_buf, U64 buf_size);
int net_443_write(U8 *ssl_opq, const char *path);
int net_443_res_write(U8 *ssl_opq, struct fws_http_res *http_res, I64 size);
int net_443_err_write(U8 *ssl_opq, int code);

int net_http_req_parse(char *req_buf, struct fws_http_req *http_req, const char *domain, U64 domain_n);
int net_http_res_build(struct fws_http_res *http_res, const char *path, U64 path_n);
void net_http_path_redir(struct fws_http_req *http_req, const struct fws_conf *conf, const struct fws_file *file, U8 *ssl_opq);

int net_nft_init(const struct fws_conf *conf);
int net_nft_fini(void);
void net_nft_dos_ban(struct nft_ctx *nft_ctx, const char *ip_buf, U32 ban_time);
void net_nft_dos_ip_send(const U8 *client_ip, struct fws_nft *nft_list, int write_fd, U64 nft_list_n);

#endif
