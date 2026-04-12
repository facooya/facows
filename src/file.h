/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#ifndef FWS_FILE_H
#define FWS_FILE_H

int file_parse(struct fws_file *file, char *uri, size_t uri_n, const char *web_root, size_t web_root_n);
int file_conf_parse(const char *conf_path, struct fws_conf *conf);

#endif
