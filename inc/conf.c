/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>

#include "types.h"
#include "conf.h"

#define CONF_KEY_MAX 16

int conf_parse(char *path, struct config *config) {
	const char *key[] = {"PORT", "DOMAIN", "WEB_ROOT", "WEB_LOG", "SSL_CERT", "SSL_KEY"};
	FILE *conf_file = fopen(path, "r");
	char file_buf[4096];
	while (fgets(file_buf, sizeof(file_buf), conf_file)) {
		if (file_buf[0] == '#') {
			continue;
		}
		for (size_t i=0; i<sizeof(key)/sizeof(key[0]); i++) {
			if (strstr(file_buf, key[i]) != NULL) {
				switch (i) {
					case 0:
						char *start = memchr(file_buf, ' ', CONF_KEY_MAX);
						if (start == NULL) {
							// conf err
							return 1;
						}
						while (*start == ' ') {
							start++;
						}
						config->port = (short) atoi(start);
						break;
					case 1:
						if (conf_write_str(file_buf, config->domain, sizeof(config->domain)) != 0) {
							return 1;
						}
						break;
					case 2:
						if (conf_write_str(file_buf, config->web_root, sizeof(config->web_root))) {
							return 1;
						}
						break;
					case 3:
						if (conf_write_str(file_buf, config->web_log, sizeof(config->web_log))) {
							return 1;
						}
						break;
					case 4:
						if (conf_write_str(file_buf, config->ssl_cert, sizeof(config->ssl_cert))) {
							return 1;
						}
						break;
					case 5:
						if (conf_write_str(file_buf, config->ssl_key, sizeof(config->ssl_key))) {
							return 1;
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

int conf_write_str(char *file_buf, char *config, size_t config_str_size) {
	char *start;
	char *end;
	ptrdiff_t n;

	start = memchr(file_buf, ' ', CONF_KEY_MAX);
	if (start == NULL) {
		// conf err
		return 1;
	}

	while (*start == ' ') {
		start++;
	}

	if (*(start) != '"') {
		// conf err
		return 1;
	}

	start++;
	end = memchr(start, '"', config_str_size);
	if (end == NULL) {
		// conf err
		return 1;
	}

	n = end - start;
	strncpy(config, start, n);
	config[n] = '\0';
	return 0;
}
