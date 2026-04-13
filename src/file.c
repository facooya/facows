/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <ctype.h>

#include "fac_utils.h"
#include "types.h"
#include "file.h"

#define CONF_KEY_MAX 16

static void _file_init(struct fws_file *file);
static int _tail_build(struct fws_file *file);
static int _str_write(const char *file_buf, char *dst_config, size_t config_str_size);

int file_parse(struct fws_file *file, char *uri, size_t uri_n, const char *web_root, size_t web_root_n) {
	_file_init(file);

	char *p1 = uri;
	char *p2 = uri;
	size_t n;

	size_t uri_len = fac_memclen(uri, '\0', uri_n);
	if (uri_len == uri_n) {
		return -1;
	}
	size_t web_root_len = fac_memclen(web_root, '\0', web_root_n);
	if (web_root_len == web_root_n) {
		return -1;
	}

	for (size_t i=0; i<uri_len; i++) {
		if (uri[i] == '?' || uri[i] == '#') {
			break;
		}
		p2++;
	}
	n = p2 - p1;
	memcpy(file->uri_path, uri, n);
	file->uri_path[n] = '\0';

	// { path
	char tmp_path[4096];
	memcpy(tmp_path, web_root, web_root_len);
	tmp_path[web_root_len] = '\0';

	p1 = file->uri_path;
	p2 = tmp_path + web_root_len;
	while (1) {
		if (*p1 == '\0') {
			*p2 = '\0';
			break;
		} else if (*p1 == '%') {
			if (isxdigit(*(p1+1)) != 0 && isxdigit(*(p1+2)) != 0) {
				uint8_t c1 = *(p1 + 1);
				uint8_t c2 = *(p1 + 2);

				if (isdigit(*(p1+1)) != 0) {
					c1 -= 0x30;
					c1 <<= 4;
				} else {
					if (c1 < 0x50) c1 = c1 + 0x20;
					c1 -= 0x57;
					c1 <<= 4;
				}

				if (isdigit(*(p1+2)) != 0) {
					c2 -= 0x30;
					c1 |= c2;
				} else {
					if (c2 < 0x50) c2 = c2 + 0x20;
					c2 -= 0x57;
					c1 |= c2;
				}

				*p2 = c1;
				p1 += 3;
				p2++;
			} else {
				*p2 = *p1;
				p1++;
				p2++;
			}
		} else {
			*p2 = *p1;
			p1++;
			p2++;
		}
	}
	realpath(tmp_path, file->path);
	// }

	// TODO: check root dir slash
	if (memcmp(file->path, web_root, web_root_len-1) != 0) {
		return -1;
	}

	int code = _tail_build(file);
	return code;
}

int file_conf_parse(const char *path, struct fws_conf *config) {
	const char *key[] = {"HTTP_PORT", "HTTPS_PORT", "DOMAIN", "WEB_ROOT", "WEB_LOG", "SSL_CERT", "SSL_KEY"};
	FILE *conf_file = fopen(path, "r");
	char file_buf[4096];
	char *p;
	while (fgets(file_buf, sizeof(file_buf), conf_file)) {
		if (file_buf[0] == '#') {
			continue;
		}

		for (size_t i=0; i<sizeof(key)/sizeof(key[0]); i++) {
			if (fac_memstr(file_buf, key[i], sizeof(file_buf)) != NULL) {
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
						if (_str_write(file_buf, config->domain, sizeof(config->domain)) != 0) {
							return -1;
						}
						break;
					case 3:
						if (_str_write(file_buf, config->web_root, sizeof(config->web_root)) != 0) {
							return -1;
						}
						break;
					case 4:
						if (_str_write(file_buf, config->web_log, sizeof(config->web_log)) != 0) {
							return -1;
						}
						break;
					case 5:
						if (_str_write(file_buf, config->ssl_cert, sizeof(config->ssl_cert)) != 0) {
							return -1;
						}
						break;
					case 6:
						if (_str_write(file_buf, config->ssl_key, sizeof(config->ssl_key)) != 0) {
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
static void _file_init(struct fws_file *file) {
	file->uri_path[0] = '\0';
	file->path[0] = '\0';
}

static int _tail_build(struct fws_file *file) {
	struct stat file_stat;
	char *p = memchr(file->path, '\0', sizeof(file->path));
	if (p == NULL) {
		return -1;
	}

	if (stat(file->path, &file_stat) != 0) {
		const char html_str[] = ".html";
		memcpy(p, html_str, sizeof(html_str));
		if (stat(file->path, &file_stat) != 0) {
			return 404;
		}
		file->size = file_stat.st_size;

	} else if (S_ISDIR(file_stat.st_mode) == 1) {
		const char index_str[] = "/index.html";
		memcpy(p, index_str, sizeof(index_str));
		if (stat(file->path, &file_stat) == 0) {
			file->size = file_stat.st_size;
		} else {
			return 404;
		}

	} else {
		file->size = file_stat.st_size;
	}

	return 0;
}

static int _str_write(const char *file_buf, char *dst_config, size_t config_str_size) {
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
