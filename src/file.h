/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#ifndef FWS_FILE_H
#define FWS_FILE_H

#include "factype.h"

s32 file_parse(struct fws_file *file, const struct fws_http_req *http_req, const char *web_root, u64 web_root_n);
s32 file_conf_read(struct fws_conf *conf, const char *conf_path);

#endif
