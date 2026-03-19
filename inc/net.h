/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#ifndef NET_H
#define NET_H

int net_init_ssl(SSL_CTX **ssl_ctx, struct Configure config);
int net_init_server(int *server_fd, short port);
int net_read(SSL *ssl, char *buf, size_t buf_size);
int net_write(SSL *ssl, char *path); // Add status
void net_exit_err(SSL *ssl, int client_fd);

#endif
