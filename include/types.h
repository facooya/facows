/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include <stdint.h>
#include <sys/socket.h>
#include <openssl/ssl.h>

#ifndef FWS_TYPES_H
#define FWS_TYPES_H

struct fws_conf {
	uint8_t nft;
	uint8_t tc;
	uint16_t http_port;
	uint16_t https_port;
	char tc_bandwidth[16];
	char allow_ports[128];
	char domain[128];
	char web_root[128];
	char web_log[128];
	char ssl_cert[128];
	char ssl_key[128];
};

struct fws_nft {
	uint8_t ip[16];
	int count;
	time_t time;
};

struct fws_tc {
	uint8_t modprobe;
	char ifb_name[8];
	char net_name[16];
};

struct fws_http_res {
	int code;
	int connection;
	char content[16];
	char date[32];
};

struct fws_http_req {
	char ip[16];
	char lang[16];
	char version[16];
	char method[16];
	char os[16];
	char browser[16];
	char subdomain[64];
	char uri[4096];
	const char *path;
	size_t path_n;
	const char *query;
	size_t query_n;
};

struct fws_file {
	char uri_path[4096];
	size_t uri_path_n;
	char path[4096];
	off_t size;
};

struct fws_args {
	int fd;
	SSL_CTX *ssl_ctx;
	const struct fws_conf *fws_conf;
	const struct sockaddr_in6 *client_addr;
};

#endif
