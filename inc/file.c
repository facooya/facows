/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "file.h"

static void _init_file(struct fws_file *file);

int file_parse(struct fws_file *file, const char *uri, const char *web_root) {
	_init_file(file);

	const char *p1 = uri;
	const char *p2 = uri;
	ptrdiff_t n;

	for (size_t i=0; i<strlen(uri); i++) {
		if (uri[i] == '?' || uri[i] == '#') {
			break;
		}
		p2++;
	}
	n = p2 - p1;
	memcpy(file->uri_path, uri, n);
	file->uri_path[n] = '\0';

	/* TODO: path decoding */

	char tmp_path[4096];
	tmp_path[0] = '\0';

	strcat(tmp_path, web_root);
	strcat(tmp_path, file->uri_path);
	realpath(tmp_path, file->path);
	return 0;
}

static void _init_file(struct fws_file *file) {
	file->uri_path[0] = '\0';
	file->path[0] = '\0';
}
