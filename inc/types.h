/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#ifndef TYPES_H
#define TYPES_H

struct fws_conf {
	short port;
	char domain[64];
	char web_root[64];
	char web_log[64];
	char ssl_cert[128];
	char ssl_key[128];
};

struct fws_http {
	char ip[16];
	char lang[16];
	char version[16];
	char method[16];
	char host[16];
	char os[16];
	char browser[16];
	char uri[4096];
};

struct fws_file {
	char uri_path[4096];
	char path[4096];
	off_t size;
};

#endif
