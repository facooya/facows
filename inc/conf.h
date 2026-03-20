/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#ifndef CONF_H
#define CONF_H

int conf_parse(const char *path, struct config *config);
int conf_write_str(const char *file_buf, char *dst_config, size_t config_str_size);

#endif
