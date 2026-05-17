/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#ifndef FWS_H
#define FWS_H

void fws_child_run(int server_http_fd, int server_https_fd, int pipe_read_fd, int pipe_write_fd, volatile sig_atomic_t *fws_flag, SSL_CTX *ssl_ctx, const struct fws_conf *conf);

#endif
