/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#ifndef FWS_NET_H
#define FWS_NET_H

#include "factype.h"

struct nft_ctx;

s32 net_server_init(u16 port);
void net_host_build(char *host_buf, const struct fws_http_req *http_req, const struct fws_conf *conf);
s32 net_80_443_redir(s32 client_80_fd, const struct fws_conf *config);

s32 net_443_init(u8 **ssl_ctx_opq, const struct fws_conf *config);
s32 net_443_read(u8 *ssl_opq, char *dst_buf, u64 buf_size);
s32 net_443_write(u8 *ssl_opq, const char *path);
s32 net_443_res_write(u8 *ssl_opq, struct fws_http_res *http_res, s64 size);
s32 net_443_err_write(u8 *ssl_opq, s32 code);

s32 net_http_req_parse(char *req_buf, struct fws_http_req *http_req, const char *domain, u64 domain_n);
s32 net_http_res_build(struct fws_http_res *http_res, const char *path, u64 path_n);
void net_http_path_redir(struct fws_http_req *http_req, const struct fws_conf *conf, const struct fws_file *file, u8 *ssl_opq);

s32 net_nft_init(const struct fws_conf *conf);
s32 net_nft_fini(void);
void net_nft_dos_ban(struct nft_ctx *nft_ctx, const char *ip_buf, u32 ban_time);
void net_nft_dos_ip_send(const u8 *client_ip, struct fws_nft *nft_list, s32 write_fd, u64 nft_list_n);

#endif
