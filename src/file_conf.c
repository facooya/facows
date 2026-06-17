/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include "factype.h"
#include "types.h"
#include "file.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#define STR_LEN(str) (sizeof(str) - 1)
#define TRUE "true"
#define FALSE "false"
#define PREFIX_ALLOW_PORTS ", "

#define CONF_KEY_MAX 16
#define CONF_KEYS(KEY) \
	KEY(HTTP_PORT) \
	KEY(HTTPS_PORT) \
	KEY(NFT) \
	KEY(ALLOW_PORTS) \
	KEY(LIM_SWAP_TIME) \
	KEY(LIM_PAGE) \
	KEY(LIM_RES) \
	KEY(PPS_LIMIT) \
	KEY(PPS_BURST) \
	KEY(BAN_LIM) \
	KEY(BAN_TIME) \
	KEY(DOMAIN) \
	KEY(WEB_ROOT) \
	KEY(WEB_LOG) \
	KEY(SSL_CERT) \
	KEY(SSL_KEY) \
	KEY(HSTS) \
	KEY(HSTS_MAX_AGE)
#define CONF_KEYS_ENUM(key) key,
#define CONF_KEYS_ARR(key) #key,

static s32 _conf_parse(struct fws_conf *conf, const char *conf_buf, u64 conf_len);
static s32 _conf_parse_value(u64 i, const char *p, struct fws_conf *conf);
static s32 _tool_conf_str_set(char *member, const char *val, u64 member_n);
static s32 _tool_conf_bool_set(u8 *member, const char *val);
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
	enum {CONF_KEYS(CONF_KEYS_ENUM)};
	const char *keys[] = {CONF_KEYS(CONF_KEYS_ARR)};

	const char *p_end = nullptr;
	u64 n = 0;
	const char *p = conf_buf;
	u64 total_n = 0;
	while (total_n < conf_len) {
		if (*p == '#') {
			goto next_line;
		}

		for (u64 i=0; i<sizeof(keys)/sizeof(keys[0]); i++) {
			p_end = memchr(p, ' ', CONF_KEY_MAX);
			if (p_end == nullptr) {
				return -1;
			}
			u64 conf_key_len = p_end - p;
			if (conf_key_len == CONF_KEY_MAX) {
				goto next_line;
			}

			u64 key_len = strnlen(keys[i], CONF_KEY_MAX);
			if (conf_key_len != key_len) {
				continue;
			}
			ret = memcmp(p, keys[i], key_len);
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
	enum {CONF_KEYS(CONF_KEYS_ENUM)};
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
			p2 = memchr(p, '\n', sizeof(conf->allow_ports)-1);
			if (p2 == nullptr) {
				printf("facows.conf: error: very large value, lower than %zu\n", sizeof(conf->allow_ports)-1);
				return -1;
			}
			ret = _tool_allow_ports_check(p);
			if (ret < 0) {
				return -1;
			}
			n = p2 - p;
			memcpy(conf->allow_ports, PREFIX_ALLOW_PORTS, STR_LEN(PREFIX_ALLOW_PORTS));
			memcpy(conf->allow_ports+STR_LEN(PREFIX_ALLOW_PORTS), p, n);
			conf->allow_ports[n+STR_LEN(PREFIX_ALLOW_PORTS)] = '\0';
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
			ret = _tool_conf_bool_set(&conf->nft, p);
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
			ret = _tool_conf_bool_set(&conf->hsts, p);
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

static s32 _tool_conf_bool_set(u8 *member, const char *val) {
	if (memcmp(val, TRUE, STR_LEN(TRUE)) == 0) {
		if (*(val+STR_LEN(TRUE)) == ' ' || *(val+STR_LEN(TRUE)) == '\n') {
			*member = 1;
		} else {
			printf("facows.conf: error: bool type error\n");
			return -1;
		}
	} else if (memcmp(val, FALSE, STR_LEN(FALSE)) == 0) {
		if (*(val+STR_LEN(FALSE)) == ' ' || *(val+STR_LEN(FALSE)) == '\n') {
			*member = 0;
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
