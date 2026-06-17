/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include "factype.h"
#include "types.h"
#include "net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <nftables/libnftables.h>

#define STR_LEN(str) (sizeof(str) - 1)
#define ROUTE_PATH "/proc/net/route"
#define ROUTE_DST "00000000"
#define IPV4_MAP "::ffff:"
#define IPV4_MAP_N sizeof(IPV4_MAP) - 1

#define DOS_LIMIT 3
#define NFT_BAN4 "add element netdev facows facows_ban4 {%s timeout %dm}"
#define NFT_BAN6 "add element netdev facows facows_ban6 {%s timeout %dm}"

#define NFT_INIT \
	"add table netdev facows;\n" \
	"delete table netdev facows;\n" \
	"add table inet facows;\n" \
	"delete table inet facows;\n" \
	\
	"table netdev facows {\n" \
		"set facows_ban4 {type ipv4_addr; flags timeout;}\n" \
		"set facows_ban6 {type ipv6_addr; flags timeout;}\n" \
		"set facows_flood4 {type ipv4_addr; flags dynamic;}\n" \
		"set facows_flood6 {type ipv6_addr; flags dynamic;}\n" \
	\
		"chain facows_ingress {\n" \
			"type filter hook ingress device \"%7$s\" priority -300; policy accept;\n" \
			"ip saddr @facows_ban4 drop;\n" \
			"ip6 saddr @facows_ban6 drop;\n" \
			"update @facows_flood4 {ip saddr limit rate over %1$d/second burst %2$d packets} update @facows_ban4 {ip saddr timeout %3$dm} drop;\n" \
			"update @facows_flood6 {ip6 saddr limit rate over %1$d/second burst %2$d packets} update @facows_ban6 {ip6 saddr timeout %3$dm} drop;\n" \
		"}\n" \
	"}\n" \
	\
	"table inet facows {\n" \
		"chain facows_input {\n" \
			"type filter hook input priority 0; policy drop;\n" \
			"iif \"lo\" accept;\n" \
			"ct state established,related accept;\n" \
			"tcp dport {%4$d, %5$d %6$s} accept;\n" \
		"}\n" \
	"}"

#define NFT_FINI "delete table netdev facows; delete table inet facows;"

static I32 _name_get(C8 *buf, U64 buf_n);

I32 net_nft_init(const struct fws_conf *conf) {
	I32 ret = 0;
	struct nft_ctx *nft_ctx = FAC_NULL;
	C8 *nft_buf = FAC_NULL;

	C8 name_buf[16] = {0};
	if (_name_get(name_buf, sizeof(name_buf)) < 0) {
		ret = -1;
		goto out;
	}

	nft_ctx = nft_ctx_new(NFT_CTX_DEFAULT);
	if (nft_ctx == FAC_NULL) {
		printf("facows_nft: can not create nft context\n");
		ret = -1;
		goto out;
	}

	U64 n = snprintf(FAC_NULL, 0, NFT_INIT, conf->pps_limit, conf->pps_burst, conf->ban_time, conf->http_port, conf->https_port, conf->allow_ports, name_buf);
	nft_buf = malloc(n+1);
	snprintf(nft_buf, n+1, NFT_INIT, conf->pps_limit, conf->pps_burst, conf->ban_time, conf->http_port, conf->https_port, conf->allow_ports, name_buf);
	nft_run_cmd_from_buffer(nft_ctx, nft_buf);

	ret = 0;
out:
	nft_ctx_free(nft_ctx);
	nft_ctx = FAC_NULL;
	free(nft_buf);
	nft_buf = FAC_NULL;
	return ret;
}

I32 net_nft_fini(void) {
	I32 ret = 0;
	struct nft_ctx *nft_ctx = FAC_NULL;
	nft_ctx = nft_ctx_new(NFT_CTX_DEFAULT);
	if (nft_ctx == FAC_NULL) {
		printf("facows_nft: can not create nft context\n");
		ret = -1;
		goto out;
	}
	nft_run_cmd_from_buffer(nft_ctx, NFT_FINI);

	ret = 0;
out:
	nft_ctx_free(nft_ctx);
	nft_ctx = FAC_NULL;
	return ret;
}

void net_nft_dos_ban(struct nft_ctx *nft_ctx, const C8 *ip_buf, U32 ban_time) {
	const C8 *ip_p = ip_buf;
	C8 *nft_buf = FAC_NULL;
	U64 cmd_n = 0;

	if (memcmp(ip_buf, IPV4_MAP, IPV4_MAP_N) == 0) {
		ip_p += IPV4_MAP_N;
		cmd_n = snprintf(FAC_NULL, 0, NFT_BAN4, ip_p, ban_time);
		nft_buf = malloc(cmd_n+1);
		if (nft_buf == FAC_NULL) {
			goto out;
		}
		snprintf(nft_buf, cmd_n+1, NFT_BAN4, ip_p, ban_time);

	} else {
		cmd_n = snprintf(FAC_NULL, 0, NFT_BAN6, ip_p, ban_time);
		nft_buf = malloc(cmd_n+1);
		if (nft_buf == FAC_NULL) {
			goto out;
		}
		snprintf(nft_buf, cmd_n+1, NFT_BAN6, ip_p, ban_time);
	}

	nft_run_cmd_from_buffer(nft_ctx, nft_buf);

out:
	free(nft_buf);
	nft_buf = FAC_NULL;
}

static I32 _name_get(C8 *buf, U64 buf_n) {
	I32 ret = 0;
	FILE *fp = FAC_NULL;
	C8 *glp = FAC_NULL;
	U64 gln = 0;

	fp = fopen(ROUTE_PATH, "r");
	if (fp == FAC_NULL) {
		fprintf(stderr, "net_nft/_name_get(): open failed %s\n", ROUTE_PATH);
		ret = -1;
		goto out;
	}

	C8 dst_buf[16];
	C8 net_buf[16];
	while (getline(&glp, &gln, fp) != -1) {
		if (sscanf(glp, "%15s %15s", net_buf, dst_buf) == 2) {
			if (memcmp(dst_buf, ROUTE_DST, STR_LEN(ROUTE_DST)) == 0) {
				snprintf(buf, buf_n, "%s", net_buf);
				break;
			}
		}
	}

	if (ferror(fp)) {
		fprintf(stderr, "net_nft/_name_get(): read error\n");
		ret = -1;
		goto out;
	}
	if (buf[0] == '\0') {
		fprintf(stderr, "net_nft/_name_get(): not found\n");
		ret = -1;
		goto out;
	}

	ret = 0;
out:
	free(glp);
	glp = FAC_NULL;
	if (fp != FAC_NULL) {
		fclose(fp);
		fp = FAC_NULL;
	}
	return ret;
}
