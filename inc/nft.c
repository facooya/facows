/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "nft.h"

#define NFT_PATH "/etc/facows/facows_nft.conf"
#define NFT_CMD "nft -f - << EOF\n%s\nEOF\n"

void nft_init(short port) {
	struct stat nft_st;
	stat(NFT_PATH, &nft_st);
	off_t nft_size = nft_st.st_size;
	char *nft_raw = malloc(nft_size+1);
	char *nft_buf = malloc(nft_size+6);
	char *nft_cmd = malloc(nft_size+6+sizeof(NFT_CMD));

	int nft_fd = open(NFT_PATH, O_RDONLY);
	read(nft_fd, nft_raw, nft_size+1);
	nft_raw[nft_size] = '\0';
	close(nft_fd);

	snprintf(nft_buf, nft_size+6, nft_raw, port);
	snprintf(nft_cmd, nft_size+6+sizeof(NFT_CMD), NFT_CMD, nft_buf);
	system(nft_cmd);

	free(nft_raw);
	free(nft_buf);
	free(nft_cmd);
	nft_raw = NULL;
	nft_buf = NULL;
	nft_cmd = NULL;
}
