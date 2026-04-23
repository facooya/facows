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

#define AWK_NET_PARSE "awk '$2 == \"00000000\" {printf \"%s\", $1}' /proc/net/route"

#define NET_NAME "eno1"
#define NET_VNAME "ifb0"
#define BANDWIDTH "90mbit"

#define CMD_IFB_ON "modprobe ifb numifbs=1;"
#define CMD_IFB_OFF "modprobe -r ifb;"
#define CMD_IFB_ADD "ip link add name %s type ifb;" // ifb_name
#define CMD_IFB_DEL "ip link del dev %s;"
#define CMD_IFB_UP "ip link set dev %s up;"
#define CMD_IFB_DOWN "ip link set dev %s down;"

#define CMD_TC \
	"tc qdisc replace dev %1$s handle ffff: ingress;" \
	"tc filter replace dev %1$s parent ffff: protocol ip flower action mirred egress redirect dev %2$s;" \
	"tc filter replace dev %1$s parent ffff: protocol ipv6 flower action mirred egress redirect dev %2$s;" \
	"tc qdisc replace dev %2$s root cake bandwidth %3$s triple-isolate nat wash ingress;"

#define CMD_TC_DEL "tc qdisc del dev %s ingress" // net_name

int net_tc_init(struct fws_tc *tc) {
	FILE *sh_file = popen(AWK_NET_PARSE, "r");
	if (sh_file == NULL) {
		printf("facows_tc: error: can not read netwrok interface name\n");
		return -1;
	}
	char net_name[16];
	fgets(net_name, sizeof(net_name), sh_file);
	printf("%s\n", net_name);
	pclose(sh_file);

	char ifb_name[] = "ifb0";

	char ifb_cmd[1024];
	char *p = ifb_cmd;
	size_t n = snprintf(p, sizeof(CMD_IFB_ON), CMD_IFB_ON);
	p += n;
	n = snprintf(NULL, 0, CMD_IFB_UP, ifb_name);
	snprintf(p, n+1, CMD_IFB_UP, ifb_name);
	system(ifb_cmd);

	n = snprintf(NULL, 0, CMD_TC, net_name, ifb_name, BANDWIDTH);
	char *tc_cmd = malloc(n+1);
	snprintf(tc_cmd, n+1, CMD_TC, net_name, ifb_name, BANDWIDTH);
	system(tc_cmd);

	free(tc_cmd);
	tc_cmd = NULL;

	return 0;
}
