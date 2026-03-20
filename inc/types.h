/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#ifndef TYPES_H
#define TYPES_H

#define CONFIG_MAX 128

struct config {
	short port;
	char domain[CONFIG_MAX];
	char web_root[CONFIG_MAX];
	char web_log[CONFIG_MAX];
	char ssl_cert[CONFIG_MAX];
	char ssl_key[CONFIG_MAX];
};

struct http {
};

struct log {
};

#endif
