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

static const char nft_init_fmt[] =
	"add table netdev facows;\n"
	"delete table netdev facows;\n"
	"add table inet facows;\n"
	"delete table inet facows;\n"
	"table netdev facows {\n"
		"set facows_ban4 {type ipv4_addr; flags timeout;}\n"
		"set facows_ban6 {type ipv6_addr; flags timeout;}\n"
		"set facows_flood4 {type ipv4_addr; flags dynamic;}\n"
		"set facows_flood6 {type ipv6_addr; flags dynamic;}\n"
		"chain facows_ingress {\n"
			"type filter hook ingress device \"%7$s\" priority -300; policy accept;\n"
			"ip saddr @facows_ban4 drop;\n"
			"ip6 saddr @facows_ban6 drop;\n"
			"ip protocol tcp tcp dport {%4$d, %5$d %6$s} update @facows_flood4 {ip saddr limit rate over %1$d/second burst %2$d packets} update @facows_ban4 {ip saddr timeout %3$dm} drop;\n"
			"ip6 nexthdr tcp tcp dport {%4$d, %5$d %6$s} update @facows_flood6 {ip6 saddr limit rate over %1$d/second burst %2$d packets} update @facows_ban6 {ip6 saddr timeout %3$dm} drop;\n"
		"}\n"
	"}\n"
	"table inet facows {\n"
		"chain facows_input {\n"
			"type filter hook input priority 0; policy drop;\n"
			"iif \"lo\" accept;\n"
			"ct state established,related accept;\n"
			"tcp dport {%4$d, %5$d %6$s} accept;\n"
		"}\n"
	"}";

static s32 _name_get(char *buf, u64 buf_n);

s32 net_nft_init(const struct fws_conf *conf) {
	s32 ret = 0;
	struct nft_ctx *nft_ctx = nullptr;
	char *nft_buf = nullptr;

	char name_buf[16] = {0};
	if (_name_get(name_buf, sizeof(name_buf)) < 0) {
		ret = -1;
		goto out;
	}

	nft_ctx = nft_ctx_new(NFT_CTX_DEFAULT);
	if (nft_ctx == nullptr) {
		printf("facows_nft: can not create nft context\n");
		ret = -1;
		goto out;
	}

	u64 n = snprintf(nullptr, 0, nft_init_fmt, conf->pps_limit, conf->pps_burst, conf->ban_time, conf->http_port, conf->https_port, conf->allow_ports, name_buf);
	nft_buf = calloc(n+1, 1);
	snprintf(nft_buf, n+1, nft_init_fmt, conf->pps_limit, conf->pps_burst, conf->ban_time, conf->http_port, conf->https_port, conf->allow_ports, name_buf);
	nft_run_cmd_from_buffer(nft_ctx, nft_buf);

	ret = 0;
out:
	nft_ctx_free(nft_ctx);
	nft_ctx = nullptr;
	free(nft_buf);
	nft_buf = nullptr;
	return ret;
}

s32 net_nft_fini(void) {
	static const char nft_fini_str[] = "delete table netdev facows; delete table inet facows;";
	s32 ret = 0;
	struct nft_ctx *nft_ctx = nullptr;
	nft_ctx = nft_ctx_new(NFT_CTX_DEFAULT);
	if (nft_ctx == nullptr) {
		printf("facows_nft: can not create nft context\n");
		ret = -1;
		goto out;
	}
	nft_run_cmd_from_buffer(nft_ctx, nft_fini_str);

	ret = 0;
out:
	nft_ctx_free(nft_ctx);
	nft_ctx = nullptr;
	return ret;
}

void net_nft_dos_ban(struct nft_ctx *nft_ctx, const char *ip_buf, u32 ban_time) {
	static const char ipv4_map_str[] = "::ffff:";
	static const char nft_ban4_fmt[] = "add element netdev facows facows_ban4 {%s timeout %dm}";
	static const char nft_ban6_fmt[] = "add element netdev facows facows_ban6 {%s timeout %dm}";
	constexpr u64 ipv4_map_str_len = sizeof(ipv4_map_str) - 1;
	const char *ip_p = ip_buf;
	char *nft_buf = nullptr;
	u64 cmd_n = 0;

	if (memcmp(ip_buf, ipv4_map_str, ipv4_map_str_len) == 0) {
		ip_p += ipv4_map_str_len;
		cmd_n = snprintf(nullptr, 0, nft_ban4_fmt, ip_p, ban_time);
		nft_buf = calloc(cmd_n+1, 1);
		if (nft_buf == nullptr) {
			goto out;
		}
		snprintf(nft_buf, cmd_n+1, nft_ban4_fmt, ip_p, ban_time);

	} else {
		cmd_n = snprintf(nullptr, 0, nft_ban6_fmt, ip_p, ban_time);
		nft_buf = calloc(cmd_n+1, 1);
		if (nft_buf == nullptr) {
			goto out;
		}
		snprintf(nft_buf, cmd_n+1, nft_ban6_fmt, ip_p, ban_time);
	}

	nft_run_cmd_from_buffer(nft_ctx, nft_buf);

out:
	free(nft_buf);
	nft_buf = nullptr;
}

static s32 _name_get(char *buf, u64 buf_n) {
	static const char route_path[] = "/proc/net/route";
	static const char route_dst[] = "00000000";
	s32 ret = 0;
	FILE *fp = nullptr;
	char *glp = nullptr;
	u64 gln = 0;

	fp = fopen(route_path, "r");
	if (fp == nullptr) {
		fprintf(stderr, "net_nft/_name_get(): open failed %s\n", route_path);
		ret = -1;
		goto out;
	}

	char dst_buf[16];
	char net_buf[16];
	while (getline(&glp, &gln, fp) != -1) {
		if (sscanf(glp, "%15s %15s", net_buf, dst_buf) == 2) {
			if (memcmp(dst_buf, route_dst, sizeof(route_dst)-1) == 0) {
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
	glp = nullptr;
	if (fp != nullptr) {
		fclose(fp);
		fp = nullptr;
	}
	return ret;
}
