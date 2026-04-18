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

static int _conf_write(const char *conf_buf, char *conf_dst, size_t conf_str_n);

int file_conf_parse(const char *path, struct fws_conf *config) {
	const char *key[] = {"HTTP_PORT", "HTTPS_PORT", "DOMAIN", "WEB_ROOT", "WEB_LOG", "SSL_CERT", "SSL_KEY"};

	int conf_fd = open(path, O_RDONLY);
	if (conf_fd < 0) {
		return -1;
	}

	struct stat conf_stat;
	fstat(conf_fd, &conf_stat);

	size_t conf_len = conf_stat.st_size + 1;
	char *conf_buf = malloc(conf_len+1);
	if (read(conf_fd, conf_buf, conf_len-1) < 0) {
		return -1;
	}
	conf_buf[conf_len-1] = '\n';
	conf_buf[conf_len] = '\0';

	const char *p1 = conf_buf;
	size_t total_n = 0;
	while (total_n < conf_len) {
		if (*p1 == '#') {
			goto next_line;
		}

		for (size_t i=0; i<sizeof(key)/sizeof(key[0]); i++) {
			size_t conf_key_len = fac_memclen(p1, ' ', CONF_KEY_MAX);
			if (conf_key_len == CONF_KEY_MAX) {
				goto next_line;
			}

			size_t key_len = fac_memclen(key[i], '\0', CONF_KEY_MAX);
			if (conf_key_len == key_len) {
				if (memcmp(p1, key[i], key_len) == 0) {
					p1 += conf_key_len;
					total_n += conf_key_len;
					while (*p1 == ' ') {
						total_n++;
						p1++;
					}

					switch (i) {
						case 0:
							config->http_port = (uint16_t) strtol(p1, NULL, 10);
							break;

						case 1:
							config->https_port = (uint16_t) strtol(p1, NULL, 10);
							break;

						case 2:
							if (_conf_write(p1, config->domain, sizeof(config->domain)) != 0) {
								return -1;
							}
							break;
						case 3:
							if (_conf_write(p1, config->web_root, sizeof(config->web_root)) != 0) {
								return -1;
							}
							break;
						case 4:
							if (_conf_write(p1, config->web_log, sizeof(config->web_log)) != 0) {
								return -1;
							}
							break;
						case 5:
							if (_conf_write(p1, config->ssl_cert, sizeof(config->ssl_cert)) != 0) {
								return -1;
							}
							break;
						case 6:
							if (_conf_write(p1, config->ssl_key, sizeof(config->ssl_key)) != 0) {
								return -1;
							}
							break;
					}

					break;
				}
			}
		}

next_line:
		size_t n = fac_memclen(p1, '\n', conf_len - total_n);
		total_n += n + 1;
		p1 += n + 1;
		while (*p1 == '\n') {
			total_n++;
			p1++;
		}
	}

	free(conf_buf);
	close(conf_fd);
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
