/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#ifndef HTTP_H
#define HTTP_H

int http_parse(char *req_buf, struct fws_http *http, const char *domain, size_t domain_n);
int http_build_res(struct fws_http_res *res, const char *path, size_t path_n);

#endif
