/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "utils.h"
#include "conf.h"

#define CONF_KEY_MAX 16

static int _write_str(const char *file_buf, char *dst_config, size_t config_str_size);

int conf_parse(const char *path, struct fws_conf *config) {
	const char *key[] = {"HTTP_PORT", "HTTPS_PORT", "DOMAIN", "WEB_ROOT", "WEB_LOG", "SSL_CERT", "SSL_KEY"};
	FILE *conf_file = fopen(path, "r");
	char file_buf[4096];
	char *p;
	while (fgets(file_buf, sizeof(file_buf), conf_file)) {
		if (file_buf[0] == '#') {
			continue;
		}

		for (size_t i=0; i<sizeof(key)/sizeof(key[0]); i++) {
			if (fu_memstr(file_buf, key[i], sizeof(file_buf)) != NULL) {
				switch (i) {
					case 0:
						p = memchr(file_buf, ' ', CONF_KEY_MAX);
						if (p == NULL) {
							return -1;
						}
						while (*p == ' ') {
							p++;
						}
						config->http_port = (uint16_t) strtol(p, NULL, 10);
						break;

					case 1:
						p = memchr(file_buf, ' ', CONF_KEY_MAX);
						if (p == NULL) {
							return -1;
						}
						while (*p == ' ') {
							p++;
						}
						config->https_port = (uint16_t) strtol(p, NULL, 10);
						break;

					case 2:
						if (_write_str(file_buf, config->domain, sizeof(config->domain)) != 0) {
							return -1;
						}
						break;
					case 3:
						if (_write_str(file_buf, config->web_root, sizeof(config->web_root)) != 0) {
							return -1;
						}
						break;
					case 4:
						if (_write_str(file_buf, config->web_log, sizeof(config->web_log)) != 0) {
							return -1;
						}
						break;
					case 5:
						if (_write_str(file_buf, config->ssl_cert, sizeof(config->ssl_cert)) != 0) {
							return -1;
						}
						break;
					case 6:
						if (_write_str(file_buf, config->ssl_key, sizeof(config->ssl_key)) != 0) {
							return -1;
						}
						break;
				}
				break;
			}
		}
	}
	fclose(conf_file);
	return 0;
}

static int _write_str(const char *file_buf, char *dst_config, size_t config_str_size) {
	char *p1;
	char *p2;
	size_t n;

	p1 = memchr(file_buf, ' ', CONF_KEY_MAX);
	if (p1 == NULL) {
		return -1;
	}

	while (*p1 == ' ') {
		p1++;
	}

	if (*(p1) != '"') {
		return -1;
	}

	p1++;
	p2 = memchr(p1, '"', config_str_size);
	if (p2 == NULL) {
		return -1;
	}

	n = p2 - p1;
	memcpy(dst_config, p1, n);
	dst_config[n] = '\0';
	return 0;
}
