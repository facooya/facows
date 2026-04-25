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

#include <nftables/libnftables.h>

#include "types.h"
#include "net.h"

#define IPV4_MAP "::ffff:"
#define IPV4_MAP_N sizeof(IPV4_MAP) - 1

#define DOS_LIMIT 3
#define NFT_PATH "/etc/facows/facows_nft.conf"
#define NFT_CMD "nft -f - << EOF\n%s\nEOF\n"
#define NFT_BAN4 "nft add element inet facows facows_ban4 {%s timeout 1m}"
#define NFT_BAN6 "nft add element inet facows facows_ban6 {%s timeout 1m}"

#define NFT_INIT \
	"add table inet facows;\n" \
	"delete table inet facows;\n" \
	\
	"table inet facows {\n" \
		"set facows_ban4 {type ipv4_addr; flags timeout;}\n" \
		"set facows_ban6 {type ipv6_addr; flags timeout;}\n" \
		"set facows_flood4 {type ipv4_addr; flags dynamic;}\n" \
		"set facows_flood6 {type ipv6_addr; flags dynamic;}\n" \
	\
		"chain facows_prerouting {\n" \
			"type filter hook prerouting priority -300; policy accept;\n" \
			"ip saddr @facows_ban4 drop;\n" \
			"ip6 saddr @facows_ban6 drop;\n" \
			"update @facows_flood4 {ip saddr limit rate over %1$d/second burst %2$d packets} update @facows_ban4 {ip saddr timeout 1m} drop;\n" \
			"update @facows_flood6 {ip6 saddr limit rate over %1$d/second burst %2$d packets} update @facows_ban6 {ip6 saddr timeout 1m} drop;\n" \
		"}\n" \
	\
		"chain facows_input {\n" \
			"type filter hook input priority 0; policy drop;\n" \
			"iif \"lo\" accept;\n" \
			"ct state established,related accept;\n" \
			"tcp dport {%3$d, %4$d} accept;\n" \
			"tcp dport {%5$s} accept;\n" \
		"}\n" \
	"}"
#define NFT_FINI "delete table inet facows;"

int net_nft_init(const struct fws_conf *conf) {
	struct nft_ctx *nft_ctx;
	nft_ctx = nft_ctx_new(NFT_CTX_DEFAULT);
	if (nft_ctx == NULL) {
		printf("facows_nft: can not create nft context\n");
		return -1;
	}

	size_t n = snprintf(NULL, 0, NFT_INIT, 1000, 2000, conf->http_port, conf->https_port, conf->allow_ports);
	char *nft_buf = malloc(n+1);
	snprintf(nft_buf, n+1, NFT_INIT, 1000, 2000, conf->http_port, conf->https_port, conf->allow_ports);
	nft_run_cmd_from_buffer(nft_ctx, nft_buf);
	nft_ctx_free(nft_ctx);
	nft_ctx = NULL;
	free(nft_buf);
	nft_buf = NULL;
	return 0;
}

int net_nft_fini(void) {
	struct nft_ctx *nft_ctx;
	nft_ctx = nft_ctx_new(NFT_CTX_DEFAULT);
	if (nft_ctx == NULL) {
		printf("facows_nft: can not create nft context\n");
		return -1;
	}
	nft_run_cmd_from_buffer(nft_ctx, NFT_FINI);
	nft_ctx_free(nft_ctx);
	nft_ctx = NULL;

	return 0;
}

void net_nft_dos_ban(const struct sockaddr_in6 *client_addr, struct fws_nft *nft_list, size_t nft_list_n) {
	char ip_str[INET6_ADDRSTRLEN];
	char *ip_p = ip_str;
	inet_ntop(AF_INET6, client_addr->sin6_addr.s6_addr, ip_str, sizeof(ip_str));

	char cmd_ban[256];
	if (memcmp(ip_str, IPV4_MAP, IPV4_MAP_N) == 0) {
		ip_p += IPV4_MAP_N;
		snprintf(cmd_ban, sizeof(cmd_ban), NFT_BAN4, ip_p);
	} else {
		snprintf(cmd_ban, sizeof(cmd_ban), NFT_BAN6, ip_p);
	}

	time_t cur_sec = time(NULL);
	int nft_i = -1;
	for (size_t i=0; i<nft_list_n; i++) {
		if (memcmp(nft_list[i].ip, client_addr->sin6_addr.s6_addr, 16) == 0) {
			nft_i = i;
			break;
		}
	}

	if (nft_i < 0) {
		for (size_t i=0; i<nft_list_n; i++) {
			if (nft_list[i].time != cur_sec) {
				nft_i = i;
				break;
			}
		}

		if (nft_i < 0) {
			nft_i = nft_list_n;
		}

		memcpy(nft_list[nft_i].ip, client_addr->sin6_addr.s6_addr, 16);
	}

	if (nft_list[nft_i].time == cur_sec) {
		nft_list[nft_i].count++;

		if (nft_list[nft_i].count > DOS_LIMIT) {
			system(cmd_ban);
		}

	} else {
		nft_list[nft_i].count = 1;
		nft_list[nft_i].time = cur_sec;
	}
}
