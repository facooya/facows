/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#ifndef FWS_NET_H
#define FWS_NET_H

int net_server_init(int *server_fd, uint16_t port);
int net_80_443_redir(int client_80_fd, const struct fws_conf *config);

int net_443_init(SSL_CTX **ssl_ctx, const struct fws_conf *config);
int net_443_read(SSL *ssl, char *dst_buf, size_t buf_size);
int net_443_write(SSL *ssl, const char *path);
int net_443_res_write(SSL *ssl, struct fws_http_res *http_res, off_t size);
int net_443_err_write(SSL *ssl, int code);
void net_443_err_exit(SSL *ssl, int client_fd, void *arg);

int net_http_req_parse(char *req_buf, struct fws_http_req *http_req, const char *domain, size_t domain_n);
int net_http_res_build(struct fws_http_res *http_res, const char *path, size_t path_n);

void net_nft_init(uint16_t http_port, uint16_t https_port);
void net_nft_dos_ban(const struct sockaddr_in6 *client_addr, struct fws_nft *nft_list, size_t nft_list_n);
void net_tc_init(void);

#endif
