/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#ifndef NET_H
#define NET_H

int net_init_ssl(SSL_CTX **ssl_ctx, const struct fws_conf *config);
int net_init_server(int *server_fd, uint16_t port);
int net_read(SSL *ssl, char *dst_buf, size_t buf_size);
int net_write(SSL *ssl, const char *path);
int net_write_res(SSL *ssl, struct fws_http_res res, off_t size);
int net_write_err(SSL *ssl, int code);
void net_exit_err(SSL *ssl, int client_fd, void *arg);

#endif
