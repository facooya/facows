/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/stat.h>

#include "types.h"
#include "tc.h"

#define TC_PATH "/etc/facows/facows_tc.conf"
#define NET_NAME "eno1"
#define NET_VNAME "ifb0"
#define BANDWIDTH "90mbps"

void tc_init(void) {
	struct stat tc_st;
	stat(TC_PATH, &tc_st);
	off_t tc_size = tc_st.st_size;

	char *tc_raw = malloc(tc_size+1);
	char *tc_cmd = malloc(tc_size+256);

	int tc_fd = open(TC_PATH, O_RDONLY);
	read(tc_fd, tc_raw, tc_size+1);
	tc_raw[tc_size] = '\0';
	close(tc_fd);

	snprintf(tc_cmd, tc_size+256, tc_raw, NET_NAME, NET_VNAME, BANDWIDTH);
	system(tc_cmd);

	free(tc_raw);
	free(tc_cmd);
	tc_raw = NULL;
	tc_cmd = NULL;
}
