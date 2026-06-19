/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include "factype.h"
#include "types.h"
#include "file.h"

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

enum {U32_T, U16_T, BOOL_T, CHAR_T};
#define CONF_LIST(X) \
	X(HTTP_PORT, http_port, U16_T) \
	X(HTTPS_PORT, https_port, U16_T) \
	X(ALLOW_PORTS, allow_ports, CHAR_T) \
	X(NFT, use_nft, BOOL_T) \
	X(LIM_SWAP_TIME, lim_swap_time, U32_T) \
	X(LIM_PAGE, lim_page, U32_T) \
	X(LIM_RES, lim_res, U32_T) \
	X(PPS_LIMIT, pps_limit, U32_T) \
	X(PPS_BURST, pps_burst, U32_T) \
	X(BAN_LIM, ban_lim, U32_T) \
	X(BAN_TIME, ban_time, U32_T) \
	X(DOMAIN, domain, CHAR_T) \
	X(WEB_ROOT, web_root, CHAR_T) \
	X(WEB_LOG, web_log, CHAR_T) \
	X(SSL_CERT, ssl_cert, CHAR_T) \
	X(SSL_KEY, ssl_key, CHAR_T) \
	X(HSTS, use_hsts, BOOL_T) \
	X(HSTS_MAX_AGE, hsts_max_age, U32_T)
#define CONF_LIST_ENUM(key, member, type) key,
#define CONF_LIST_LOOKUP(key, member, x_type) [key] = {.offset = offsetof(struct fws_conf, member), .type = x_type, .key_name = #key},

enum {CONF_LIST(CONF_LIST_ENUM) CONF_LIST_CAP};
struct fws_lookup conf_lookup[CONF_LIST_CAP] = {CONF_LIST(CONF_LIST_LOOKUP)};

static s32 _conf_parse(struct fws_conf *conf, const char *conf_buf, u64 conf_len);
static s32 _conf_parse_value(u64 i, const char *p, struct fws_conf *conf);
static s32 _tool_conf_str_set(char *member, const char *val, u64 member_n);
static s32 _tool_conf_bool_set(bool *member, const char *val);
static s32 _tool_allow_ports_check(const char *p);

s32 file_conf_read(struct fws_conf *conf, const char *path) {
	char *conf_buf = nullptr;
	s32 conf_fd = -1;
	s32 ret = 0;

	conf->allow_ports[0] = '\0';

	conf_fd = open(path, O_RDONLY);
	if (conf_fd < 0) {
		ret = -1;
		goto out;
	}

	struct stat conf_stat = {0};
	ret = fstat(conf_fd, &conf_stat);
	if (ret < 0) {
		ret = -1;
		goto out;
	}

	u64 conf_len = conf_stat.st_size + 1;
	conf_buf = malloc(conf_len+1);
	if (conf_buf == nullptr) {
		ret = -1;
		goto out;
	}

	s64 read_ret = read(conf_fd, conf_buf, conf_len-1);
	if (read_ret < 0) {
		ret = -1;
		goto out;
	}

	conf_buf[conf_len-1] = '\n';
	conf_buf[conf_len] = '\0';

	ret = _conf_parse(conf, conf_buf, conf_len);
	if (ret < 0) {
		ret = -1;
		goto out;
	}

	ret = 0;
out:
	free(conf_buf);
	conf_buf = nullptr;
	if (conf_fd >= 0) {
		close(conf_fd);
		conf_fd = -1;
	}
	return ret;
}

static s32 _conf_parse(struct fws_conf *conf, const char *conf_buf, u64 conf_len) {
	s32 ret = 0;
	const char *p_end = nullptr;
	u64 n = 0;
	const char *p = conf_buf;
	u64 total_n = 0;
	while (total_n < conf_len) {
		if (*p == '#') {
			goto next_line;
		}

		for (u64 i=0; i<CONF_LIST_CAP; i++) {
			constexpr u64 conf_key_max = 16;
			p_end = memchr(p, ' ', conf_key_max);
			if (p_end == nullptr) {
				return -1;
			}
			u64 conf_key_len = p_end - p;
			if (conf_key_len == conf_key_max) {
				goto next_line;
			}

			u64 key_len = strnlen(conf_lookup[i].key_name, conf_key_max);
			if (conf_key_len != key_len) {
				continue;
			}
			ret = memcmp(p, conf_lookup[i].key_name, key_len);
			if (ret != 0) {
				continue;
			}

			p += conf_key_len;
			total_n += conf_key_len;
			while (*p == ' ') {
				total_n++;
				p++;
			}

			ret = _conf_parse_value(i, p, conf);
			if (ret < 0) {
				return -1;
			}
			break;
		}

next_line:
		p_end = memchr(p, '\n', conf_len-total_n);
		if (p_end == nullptr) {
			return -1;
		}
		n = p_end - p;
		total_n += n + 1;
		p += n + 1;
		while (*p == '\n') {
			total_n++;
			p++;
		}
	}

	return 0;
}

static s32 _conf_parse_value(u64 i, const char *p, struct fws_conf *conf) {
	s32 ret = 0;
	const char *p2 = nullptr;
	u64 n = 0;
	s64 port = -1;
	switch (i) {
		case HTTP_PORT:
			port = strtol(p, nullptr, 10);
			if (port < 0 || port >= 65536) {
				fprintf(stderr, "file_conf/_conf_parse(): out of port range\n");
				return -1;
			}
			conf->http_port = (u16) port;
			break;
		case HTTPS_PORT:
			port = strtol(p, nullptr, 10);
			if (port < 0 || port >= 65536) {
				fprintf(stderr, "file_conf/_conf_parse(): out of port range\n");
				return -1;
			}
			conf->https_port = (u16) port;
			break;

		case ALLOW_PORTS:
			static const char comma_str[] = ", ";
			constexpr u64 comma_str_len = sizeof(comma_str) - 1;
			p2 = memchr(p, '\n', sizeof(conf->allow_ports)-1);
			if (p2 == nullptr) {
				printf("facows.conf: error: very large value, lower than %lu\n", sizeof(conf->allow_ports)-1);
				return -1;
			}
			ret = _tool_allow_ports_check(p);
			if (ret < 0) {
				return -1;
			}
			n = p2 - p;
			memcpy(conf->allow_ports, comma_str, comma_str_len);
			memcpy(conf->allow_ports+comma_str_len, p, n);
			conf->allow_ports[n+comma_str_len] = '\0';
			break;

		case LIM_SWAP_TIME:
			conf->lim_swap_time = (u32) strtol(p, nullptr, 10);
			break;
		case LIM_PAGE:
			conf->lim_page = (u32) strtol(p, nullptr, 10);
			break;
		case LIM_RES:
			conf->lim_res = (u32) strtol(p, nullptr, 10);
			break;

		case NFT:
			ret = _tool_conf_bool_set(&conf->use_nft, p);
			if (ret < 0) {
				return -1;
			}
			break;
		case PPS_LIMIT:
			conf->pps_limit = (u32) strtol(p, nullptr, 10);
			break;
		case PPS_BURST:
			conf->pps_burst = (u32) strtol(p, nullptr, 10);
			break;
		case BAN_LIM:
			conf->ban_lim = (u32) strtol(p, nullptr, 10);
			break;
		case BAN_TIME:
			conf->ban_time = (u32) strtol(p, nullptr, 10);
			break;

		case HSTS:
			ret = _tool_conf_bool_set(&conf->use_hsts, p);
			if (ret < 0) {
				return -1;
			}
			break;
		case HSTS_MAX_AGE:
			conf->hsts_max_age = (u32) strtol(p, nullptr, 10);
			break;

		case DOMAIN:
			ret = _tool_conf_str_set(conf->domain, p, sizeof(conf->domain));
			if (ret < 0) {
				return -1;
			}
			break;
		case WEB_ROOT:
			ret = _tool_conf_str_set(conf->web_root, p, sizeof(conf->web_root));
			if (ret < 0) {
				return -1;
			}
			break;
		case WEB_LOG:
			ret = _tool_conf_str_set(conf->web_log, p, sizeof(conf->web_log));
			if (ret < 0) {
				return -1;
			}
			break;
		case SSL_CERT:
			ret = _tool_conf_str_set(conf->ssl_cert, p, sizeof(conf->ssl_cert));
			if (ret < 0) {
				return -1;
			}
			break;
		case SSL_KEY:
			ret = _tool_conf_str_set(conf->ssl_key, p, sizeof(conf->ssl_key));
			if (ret < 0) {
				return -1;
			}
			break;
	}

	return 0;
}

static s32 _tool_conf_str_set(char *member, const char *val, u64 member_n) {
	const char *p1 = val + 1;
	if (*(p1-1) != '"') {
		printf("facows.conf: error: require double quote before write string\n");
		return -1;
	}

	const char *p2 = memchr(p1, '"', member_n-1);
	if (p2 == nullptr) {
		printf("facows.conf: error: very large value, lower than %zu\n", member_n-1);
		return -1;
	}

	u64 n = p2 - p1;
	memcpy(member, p1, n);
	member[n] = '\0';

	return 0;
}

static s32 _tool_conf_bool_set(bool *member, const char *val) {
	static const char true_str[] = "true";
	static const char false_str[] = "false";

	constexpr u64 true_str_len = sizeof(true_str) - 1;
	constexpr u64 false_str_len = sizeof(false_str) - 1;
	s32 true_cmp = memcmp(val, true_str, true_str_len);
	s32 false_cmp = memcmp(val, false_str, false_str_len);
	if (true_cmp == 0) {
		if (*(val+true_str_len) == ' ' || *(val+true_str_len) == '\n') {
			*member = true;
		} else {
			printf("facows.conf: error: bool type error\n");
			return -1;
		}
	} else if (false_cmp == 0) {
		if (*(val+false_str_len) == ' ' || *(val+false_str_len) == '\n') {
			*member = false;
		} else {
			printf("facows.conf: error: bool type error\n");
			return -1;
		}
	} else {
		printf("facows.conf: error: type error\n");
		return -1;
	}

	return 0;
}

static s32 _tool_allow_ports_check(const char *p) {
	char *ep = nullptr;
	while (*p != '\n' && *p != '\0') {
		s64 port = strtol(p, &ep, 10);
		if (p == ep) {
			p++;
			continue;
		}

		if (port < 0 || port >= 65536) {
			fprintf(stderr, "file_conf/_conf_parse(): out of port range\n");
			return -1;
		}

		p = ep;
		if (*p == ',') {
			p++;
		}
	}
	return 0;
}
