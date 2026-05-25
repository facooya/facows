/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include "factype.h"
#include "fac_utils.h"
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
	KEY(PPS_LIMIT) \
	KEY(PPS_BURST) \
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

static I32 _conf_parse(struct fws_conf *conf, const C8 *conf_buf, U64 conf_len);
static I32 _conf_parse_value(U64 i, const C8 *p, struct fws_conf *conf);
static I32 _tool_conf_str_set(C8 *member, const C8 *val, U64 member_n);
static I32 _tool_conf_bool_set(U8 *member, const C8 *val);
static I32 _tool_allow_ports_check(const C8 *p);

I32 file_conf_read(struct fws_conf *conf, const C8 *path) {
	I32 ret = 0;
	I32 conf_fd = -1;
	C8 *conf_buf = FAC_NULL;

	conf->allow_ports[0] = '\0';

	conf_fd = open(path, O_RDONLY);
	if (conf_fd < 0) {
		ret = -1;
		goto out;
	}

	struct stat conf_stat = {0};
	if (fstat(conf_fd, &conf_stat) < 0) {
		ret = -1;
		goto out;
	}

	U64 conf_len = conf_stat.st_size + 1;
	conf_buf = malloc(conf_len+1);
	if (conf_buf == FAC_NULL) {
		ret = -1;
		goto out;
	}
	if (read(conf_fd, conf_buf, conf_len-1) < 0) {
		ret = -1;
		goto out;
	}

	conf_buf[conf_len-1] = '\n';
	conf_buf[conf_len] = '\0';

	if (_conf_parse(conf, conf_buf, conf_len)) {
		ret = -1;
		goto out;
	}

	ret = 0;
out:
	free(conf_buf);
	conf_buf = FAC_NULL;
	if (conf_fd >= 0) {
		close(conf_fd);
		conf_fd = -1;
		(void)conf_fd;
	}
	return ret;
}

static I32 _conf_parse(struct fws_conf *conf, const C8 *conf_buf, U64 conf_len) {
	assert(conf != FAC_NULL);
	assert(conf_buf != FAC_NULL);
	enum {CONF_KEYS(CONF_KEYS_ENUM)};
	const C8 *keys[] = {CONF_KEYS(CONF_KEYS_ARR)};

	U64 n = 0;
	const C8 *p = conf_buf;
	U64 total_n = 0;
	while (total_n < conf_len) {
		if (*p == '#') {
			goto next_line;
		}

		for (U64 i=0; i<sizeof(keys)/sizeof(keys[0]); i++) {
			U64 conf_key_len = fac_memclen(p, ' ', CONF_KEY_MAX);
			if (conf_key_len == CONF_KEY_MAX) {
				goto next_line;
			}

			U64 key_len = fac_memclen(keys[i], '\0', CONF_KEY_MAX);
			if (conf_key_len != key_len) {
				continue;
			}
			if (memcmp(p, keys[i], key_len) != 0) {
				continue;
			}

			p += conf_key_len;
			total_n += conf_key_len;
			while (*p == ' ') {
				total_n++;
				p++;
			}

			if (_conf_parse_value(i, p, conf) < 0) {
				return -1;
			}
			break;
		}

next_line:
		n = fac_memclen(p, '\n', conf_len - total_n);
		total_n += n + 1;
		p += n + 1;
		while (*p == '\n') {
			total_n++;
			p++;
		}
	}

	return 0;
}

static I32 _conf_parse_value(U64 i, const C8 *p, struct fws_conf *conf) {
	assert(p != FAC_NULL);
	enum {CONF_KEYS(CONF_KEYS_ENUM)};
	const C8 *p2 = FAC_NULL;
	U64 n = 0;
	I64 port = -1;
	switch (i) {
		case HTTP_PORT:
			port = strtol(p, FAC_NULL, 10);
			if (port < 0 || port >= 65536) {
				fprintf(stderr, "file_conf/_conf_parse(): out of port range\n");
				return -1;
			}
			conf->http_port = (U16) port;
			break;
		case HTTPS_PORT:
			port = strtol(p, FAC_NULL, 10);
			if (port < 0 || port >= 65536) {
				fprintf(stderr, "file_conf/_conf_parse(): out of port range\n");
				return -1;
			}
			conf->https_port = (U16) port;
			break;

		case ALLOW_PORTS:
			p2 = memchr(p, '\n', sizeof(conf->allow_ports)-1);
			if (p2 == FAC_NULL) {
				printf("facows.conf: error: very large value, lower than %zu\n", sizeof(conf->allow_ports)-1);
				return -1;
			}
			if (_tool_allow_ports_check(p) < 0) {
				return -1;
			}
			n = p2 - p;
			assert(n + STR_LEN(PREFIX_ALLOW_PORTS) < sizeof(conf->allow_ports));
			memcpy(conf->allow_ports, PREFIX_ALLOW_PORTS, STR_LEN(PREFIX_ALLOW_PORTS));
			memcpy(conf->allow_ports+STR_LEN(PREFIX_ALLOW_PORTS), p, n);
			conf->allow_ports[n+STR_LEN(PREFIX_ALLOW_PORTS)] = '\0';
			break;

		case NFT:
			if (_tool_conf_bool_set(&conf->nft, p) < 0) {
				return -1;
			}
			break;
		case PPS_LIMIT:
			conf->pps_limit = (U32) strtol(p, FAC_NULL, 10);
			break;
		case PPS_BURST:
			conf->pps_burst = (U32) strtol(p, FAC_NULL, 10);
			break;
		case BAN_TIME:
			conf->ban_time = (U32) strtol(p, FAC_NULL, 10);
			break;

		case HSTS:
			if (_tool_conf_bool_set(&conf->hsts, p) < 0) {
				return -1;
			}
			break;
		case HSTS_MAX_AGE:
			conf->hsts_max_age = (U32) strtol(p, FAC_NULL, 10);
			break;

		case DOMAIN:
			if (_tool_conf_str_set(conf->domain, p, sizeof(conf->domain)) < 0) {
				return -1;
			}
			break;
		case WEB_ROOT:
			if (_tool_conf_str_set(conf->web_root, p, sizeof(conf->web_root)) < 0) {
				return -1;
			}
			break;
		case WEB_LOG:
			if (_tool_conf_str_set(conf->web_log, p, sizeof(conf->web_log)) < 0) {
				return -1;
			}
			break;
		case SSL_CERT:
			if (_tool_conf_str_set(conf->ssl_cert, p, sizeof(conf->ssl_cert)) < 0) {
				return -1;
			}
			break;
		case SSL_KEY:
			if (_tool_conf_str_set(conf->ssl_key, p, sizeof(conf->ssl_key)) < 0) {
				return -1;
			}
			break;
	}

	return 0;
}

static I32 _tool_conf_str_set(C8 *member, const C8 *val, U64 member_n) {
	const C8 *p1 = val + 1;
	if (*(p1-1) != '"') {
		printf("facows.conf: error: require double quote before write string\n");
		return -1;
	}

	const C8 *p2 = memchr(p1, '"', member_n-1);
	if (p2 == FAC_NULL) {
		printf("facows.conf: error: very large value, lower than %zu\n", member_n-1);
		return -1;
	}

	U64 n = p2 - p1;
	memcpy(member, p1, n);
	member[n] = '\0';

	return 0;
}

static I32 _tool_conf_bool_set(U8 *member, const C8 *val) {
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

static I32 _tool_allow_ports_check(const C8 *p) {
	assert(p != FAC_NULL);
	C8 *ep = FAC_NULL;
	while (*p != '\n' && *p != '\0') {
		I64 port = strtol(p, &ep, 10);
		if (p == ep) {
			p++;
			continue;
		}

		assert(port > 0 || port < 65536);
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
