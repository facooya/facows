/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "fac_utils.h"
#include "types.h"
#include "file.h"

#define TRUE "true"
#define FALSE "false"
#define TRUE_N sizeof(TRUE) - 1
#define FALSE_N sizeof(FALSE) - 1

#define CONF_KEY_MAX 16
#define CONF_KEYS(KEY) \
	KEY(HTTP_PORT) \
	KEY(HTTPS_PORT) \
	KEY(NFT) \
	KEY(ALLOW_PORTS) \
	KEY(PPS_LIMIT) \
	KEY(PPS_BURST) \
	KEY(BAN_TIME) \
	KEY(TC) \
	KEY(BANDWIDTH) \
	KEY(DOMAIN) \
	KEY(WEB_ROOT) \
	KEY(WEB_LOG) \
	KEY(SSL_CERT) \
	KEY(SSL_KEY)
#define CONF_KEYS_ENUM(key) key,
#define CONF_KEYS_ARR(key) #key,

static int _conf_parse(struct fws_conf *conf, const char *conf_buf, size_t conf_len);
static int _tool_conf_str_set(char *member, const char *val, size_t member_n);
static int _tool_conf_bool_set(uint8_t *member, const char *val);

int file_conf_read(struct fws_conf *conf, const char *path) {
	int ret = 0;
	int conf_fd = -1;
	char *conf_buf = NULL;

	conf->allow_ports[0] = '\0';

	conf_fd = open(path, O_RDONLY);
	if (conf_fd < 0) {
		ret = -1;
		goto out;
	}

	struct stat conf_stat;
	fstat(conf_fd, &conf_stat);

	size_t conf_len = conf_stat.st_size + 1;
	conf_buf = malloc(conf_len+1);
	if (conf_buf == NULL) {
		ret = -1;
		goto out;
	}
	if (read(conf_fd, conf_buf, conf_len-1) < 0) {
		ret = -1;
		goto out;
	}
	close(conf_fd);
	conf_fd = -1;

	conf_buf[conf_len-1] = '\n';
	conf_buf[conf_len] = '\0';

	if (_conf_parse(conf, conf_buf, conf_len)) {
		ret = -1;
		goto out;
	}

	ret = 0;
out:
	free(conf_buf);
	conf_buf = NULL;
	if (conf_fd >= 0) {
		close(conf_fd);
		conf_fd = -1;
	}
	return ret;
}

static int _conf_parse(struct fws_conf *conf, const char *conf_buf, size_t conf_len) {
	enum {CONF_KEYS(CONF_KEYS_ENUM)};
	const char *keys[] = {CONF_KEYS(CONF_KEYS_ARR)};

	const char *p = conf_buf;
	size_t total_n = 0;
	while (total_n < conf_len) {
		if (*p == '#') {
			goto next_line;
		}

		for (size_t i=0; i<sizeof(keys)/sizeof(keys[0]); i++) {
			size_t conf_key_len = fac_memclen(p, ' ', CONF_KEY_MAX);
			if (conf_key_len == CONF_KEY_MAX) {
				goto next_line;
			}

			size_t key_len = fac_memclen(keys[i], '\0', CONF_KEY_MAX);
			if (conf_key_len == key_len) {
				if (memcmp(p, keys[i], key_len) == 0) {
					p += conf_key_len;
					total_n += conf_key_len;
					while (*p == ' ') {
						total_n++;
						p++;
					}

					switch (i) {
						case HTTP_PORT:
							conf->http_port = (uint16_t) strtol(p, NULL, 10);
							break;
						case HTTPS_PORT:
							conf->https_port = (uint16_t) strtol(p, NULL, 10);
							break;

						case ALLOW_PORTS:
							const char *p2 = memchr(p, '\n', sizeof(conf->allow_ports)-1);
							if (p2 == NULL) {
								printf("facows.conf: error: very large value, lower than %zu\n", sizeof(conf->allow_ports)-1);
								return -1;
							}
							size_t n = p2 - p;
							memcpy(conf->allow_ports, p, n);
							conf->allow_ports[n] = '\0';
							break;

						case NFT:
							if (_tool_conf_bool_set(&conf->nft, p) < 0) {
								return -1;
							}
							break;
						case PPS_LIMIT:
							conf->pps_limit = (uint32_t) strtol(p, NULL, 10);
							break;
						case PPS_BURST:
							conf->pps_burst = (uint32_t) strtol(p, NULL, 10);
							break;
						case BAN_TIME:
							conf->ban_time = (uint32_t) strtol(p, NULL, 10);
							break;

						case TC:
							if (_tool_conf_bool_set(&conf->tc, p) < 0) {
								return -1;
							}
							break;
						case BANDWIDTH:
							if (_tool_conf_str_set(conf->bandwidth, p, sizeof(conf->bandwidth)) < 0) {
								return -1;
							}
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

					break;
				}
			}
		}

next_line:
		size_t n = fac_memclen(p, '\n', conf_len - total_n);
		total_n += n + 1;
		p += n + 1;
		while (*p == '\n') {
			total_n++;
			p++;
		}
	}

	return 0;
}

static int _tool_conf_str_set(char *member, const char *val, size_t member_n) {
	const char *p1 = val + 1;
	if (*(p1-1) != '"') {
		printf("facows.conf: error: require double quote before write string\n");
		return -1;
	}

	const char *p2 = memchr(p1, '"', member_n-1);
	if (p2 == NULL) {
		printf("facows.conf: error: very large value, lower than %zu\n", member_n-1);
		return -1;
	}

	size_t n = p2 - p1;
	memcpy(member, p1, n);
	member[n] = '\0';

	return 0;
}

static int _tool_conf_bool_set(uint8_t *member, const char *val) {
	if (memcmp(val, TRUE, TRUE_N) == 0) {
		if (*(val+TRUE_N) == ' ' || *(val+TRUE_N) == '\n') {
			*member = 1;
		} else {
			printf("facows.conf: error: bool type error\n");
			return -1;
		}
	} else if (memcmp(val, FALSE, FALSE_N) == 0) {
		if (*(val+FALSE_N) == ' ' || *(val+FALSE_N) == '\n') {
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
