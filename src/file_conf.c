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

#define CONF_KEY_MAX 16

static int _conf_build(struct fws_conf *conf, const char *conf_buf, size_t conf_len);
static int _conf_write(const char *conf_buf, char *conf_dst, size_t conf_str_n);

int file_conf_parse(const char *path, struct fws_conf *conf) {
	int ret = 0;
	int conf_fd = -1;
	char *conf_buf = NULL;

	conf_fd = open(path, O_RDONLY);
	if (conf_fd < 0) {
		ret = -1;
		goto out;
	}

	struct stat conf_stat;
	fstat(conf_fd, &conf_stat);

	size_t conf_len = conf_stat.st_size + 1;
	conf_buf = malloc(conf_len+1);
	if (read(conf_fd, conf_buf, conf_len-1) < 0) {
		ret = -1;
		goto out;
	}
	close(conf_fd);
	conf_fd = -1;

	conf_buf[conf_len-1] = '\n';
	conf_buf[conf_len] = '\0';

	if (_conf_build(conf, conf_buf, conf_len)) {
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

static int _conf_build(struct fws_conf *conf, const char *conf_buf, size_t conf_len) {
	const char *key[] = {"HTTP_PORT", "HTTPS_PORT", "DOMAIN", "WEB_ROOT", "WEB_LOG", "SSL_CERT", "SSL_KEY"};

	const char *p = conf_buf;
	size_t total_n = 0;
	while (total_n < conf_len) {
		if (*p == '#') {
			goto next_line;
		}

		for (size_t i=0; i<sizeof(key)/sizeof(key[0]); i++) {
			size_t conf_key_len = fac_memclen(p, ' ', CONF_KEY_MAX);
			if (conf_key_len == CONF_KEY_MAX) {
				goto next_line;
			}

			size_t key_len = fac_memclen(key[i], '\0', CONF_KEY_MAX);
			if (conf_key_len == key_len) {
				if (memcmp(p, key[i], key_len) == 0) {
					p += conf_key_len;
					total_n += conf_key_len;
					while (*p == ' ') {
						total_n++;
						p++;
					}

					switch (i) {
						case 0:
							conf->http_port = (uint16_t) strtol(p, NULL, 10);
							break;

						case 1:
							conf->https_port = (uint16_t) strtol(p, NULL, 10);
							break;

						case 2:
							if (_conf_write(p, conf->domain, sizeof(conf->domain)) != 0) {
								return -1;
							}
							break;
						case 3:
							if (_conf_write(p, conf->web_root, sizeof(conf->web_root)) != 0) {
								return -1;
							}
							break;
						case 4:
							if (_conf_write(p, conf->web_log, sizeof(conf->web_log)) != 0) {
								return -1;
							}
							break;
						case 5:
							if (_conf_write(p, conf->ssl_cert, sizeof(conf->ssl_cert)) != 0) {
								return -1;
							}
							break;
						case 6:
							if (_conf_write(p, conf->ssl_key, sizeof(conf->ssl_key)) != 0) {
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

static int _conf_write(const char *conf_val, char *conf_dst, size_t conf_str_n) {
	const char *p1 = conf_val + 1;
	if (*(p1-1) != '"') {
		printf("facows.conf: error: require double quote before write string\n");
		return -1;
	}

	const char *p2 = memchr(p1, '"', conf_str_n);
	if (p2 == NULL) {
		printf("facows.conf: error: very large value, lower than %d\n", conf_str_n);
		return -1;
	}

	size_t n = p2 - p1;
	memcpy(conf_dst, p1, n);
	conf_dst[n] = '\0';

	return 0;
}
