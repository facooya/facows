/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#ifndef HTTP_H
#define HTTP_H

int http_parse(char *req_buf, struct fws_http *http, const char *domain);
int http_build_res(struct fws_http_res *res, const char *path);

#endif
