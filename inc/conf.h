/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#ifndef CONF_H
#define CONF_H

struct Configure {
	short port;
	char domain[64];
	char web_root[64];
	char web_log[64];
	char ssl_cert[128];
	char ssl_key[128];
};

int conf_parse(char *path, struct Configure *config);
int conf_write_str(char *file_buf, char *config, size_t config_str_size);

#endif
