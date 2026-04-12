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
#include "net.h"

#define DOS_LIMIT 10
#define NFT_PATH "/etc/facows/facows_nft.conf"
#define NFT_CMD "nft -f - << EOF\n%s\nEOF\n"
#define NFT_BAN4 "nft add element netdev facows facows_ban4 {%s timeout 1m}"
#define NFT_BAN6 "nft add element netdev facows facows_ban6 {%s timeout 1m}"

void net_nft_init(uint16_t http_port, uint16_t https_port) {
	struct stat nft_st;
	stat(NFT_PATH, &nft_st);
	off_t nft_size = nft_st.st_size;
	char *nft_raw = malloc(nft_size+1);
	char *nft_buf = malloc(nft_size+11);
	char *nft_cmd = malloc(nft_size+11+sizeof(NFT_CMD));

	int nft_fd = open(NFT_PATH, O_RDONLY);
	read(nft_fd, nft_raw, nft_size+1);
	nft_raw[nft_size] = '\0';
	close(nft_fd);

	snprintf(nft_buf, nft_size+11, nft_raw, http_port, https_port);
	snprintf(nft_cmd, nft_size+11+sizeof(NFT_CMD), NFT_CMD, nft_buf);
	system(nft_cmd);

	free(nft_raw);
	free(nft_buf);
	free(nft_cmd);
	nft_raw = NULL;
	nft_buf = NULL;
	nft_cmd = NULL;
}

void net_nft_dos_ban(const struct sockaddr_in6 *client_addr, struct fws_nft *nft_list, size_t nft_list_n) {
	char ip_str[INET6_ADDRSTRLEN];
	char *ip_p = ip_str;
	inet_ntop(AF_INET6, client_addr->sin6_addr.s6_addr, ip_str, sizeof(ip_str));
	printf("%s\n", ip_str);

	char cmd_ban[256];
	if (memcmp(ip_str, "::ffff:", sizeof("::ffff:")-1) == 0) {
		ip_p += sizeof("::ffff:")-1;
		snprintf(cmd_ban, sizeof(cmd_ban), NFT_BAN4, ip_p);
	} else {
		snprintf(cmd_ban, sizeof(cmd_ban), NFT_BAN6, ip_p);
	}

	// TODO: search ip
	memcpy(nft_list[0].ip, client_addr->sin6_addr.s6_addr, 16);

	time_t ctime = time(NULL);

	if (nft_list[0].time == ctime) {
		nft_list[0].count++;

		if (nft_list[0].count > DOS_LIMIT) {
			system(cmd_ban);
		}

	} else {
		nft_list[0].count = 1;
		nft_list[0].time = ctime;
	}
}
