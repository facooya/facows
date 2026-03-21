/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#ifndef HTTP_H
#define HTTP_H

int http_parse(char *req_buf, struct http *http, const char *domain);

#endif
