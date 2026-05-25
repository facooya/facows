/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#ifndef FWS_NET_H
#define FWS_NET_H

#include "factype.h"

struct nft_ctx;

I32 net_server_init(U16 port);
void net_host_build(C8 *host_buf, const struct fws_http_req *http_req, const struct fws_conf *conf);
I32 net_80_443_redir(I32 client_80_fd, const struct fws_conf *config);

I32 net_443_init(U8 **ssl_ctx_opq, const struct fws_conf *config);
I32 net_443_read(U8 *ssl_opq, C8 *dst_buf, U64 buf_size);
I32 net_443_write(U8 *ssl_opq, const C8 *path);
I32 net_443_res_write(U8 *ssl_opq, struct fws_http_res *http_res, I64 size);
I32 net_443_err_write(U8 *ssl_opq, I32 code);

I32 net_http_req_parse(C8 *req_buf, struct fws_http_req *http_req, const C8 *domain, U64 domain_n);
I32 net_http_res_build(struct fws_http_res *http_res, const C8 *path, U64 path_n);
void net_http_path_redir(struct fws_http_req *http_req, const struct fws_conf *conf, const struct fws_file *file, U8 *ssl_opq);

I32 net_nft_init(const struct fws_conf *conf);
I32 net_nft_fini(void);
void net_nft_dos_ban(struct nft_ctx *nft_ctx, const C8 *ip_buf, U32 ban_time);
void net_nft_dos_ip_send(const U8 *client_ip, struct fws_nft *nft_list, I32 write_fd, U64 nft_list_n);

#endif
