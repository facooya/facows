/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <time.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "fac_utils.h"
#include "types.h"
#include "net.h"

#define AWK_NET_PARSE "awk '$2 == \"00000000\" {printf \"%s\", $1}' /proc/net/route"

#define NET_NAME "eno1"
#define NET_VNAME "ifb0"
#define BANDWIDTH "90mbit"

#define CMD_SYS_IFB_MOD "lsmod | grep ifb"
#define CMD_SYS_IFB_NUM "ls -1 /sys/class/net"

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

int net_tc_init(struct fws_tc *tc, const char *bandwidth) {
	FILE *sh_file = popen(AWK_NET_PARSE, "r");
	if (sh_file == NULL) {
		printf("facows_tc: error: can not read network interface name\n");
		return -1;
	}
	if (fgets(tc->net_name, sizeof(tc->net_name), sh_file) == NULL) {
		printf("facows_tc: error: can not read network interface name\n");
		return -1;
	}
	pclose(sh_file);

	size_t ifb_uniq = 0;
	if (access("/sys/module/ifb", F_OK) < 0) {
		tc->modprobe = 1;
		memcpy(tc->ifb_name, "ifb0", sizeof("ifb0"));

	} else {
		tc->modprobe = 0;
		DIR *net_list = opendir("/sys/class/net");
		if (net_list == NULL) {
			printf("facows_tc: error: can not open directory /sys/class/net\n");
			return -1;
		}

		while (1) {
			struct dirent *net_dir = readdir(net_list);

			if (net_dir == NULL) {
				snprintf(tc->ifb_name, sizeof(tc->ifb_name), "ifb%d", ifb_uniq);
				break;
			}

			if (memcmp(net_dir->d_name, "ifb", sizeof("ifb")-1) == 0) {
				long ifb_num = strtol(net_dir->d_name+3, NULL, 10);
				if (ifb_num >= ifb_uniq) {
					ifb_uniq = ifb_num + 1;
				}
			}
		}
		closedir(net_list);
	}

	if (tc->modprobe == 1) {
		size_t ifb_up_n = snprintf(NULL, 0, CMD_IFB_UP, tc->ifb_name);
		char *ifb_cmd = malloc(ifb_up_n+sizeof(CMD_IFB_ON));
		char *p = ifb_cmd;
		size_t n = snprintf(p, sizeof(CMD_IFB_ON), CMD_IFB_ON);
		p += n;
		snprintf(p, ifb_up_n+1, CMD_IFB_UP, tc->ifb_name);
		system(ifb_cmd);
		free(ifb_cmd);
		ifb_cmd = NULL;

	} else {
		size_t ifb_add_n = snprintf(NULL, 0, CMD_IFB_ADD, tc->ifb_name);
		size_t ifb_up_n = snprintf(NULL, 0, CMD_IFB_UP, tc->ifb_name);
		size_t n = ifb_add_n + ifb_up_n;
		char *ifb_cmd = malloc(n+1);
		char *p = ifb_cmd;
		n = snprintf(p, ifb_add_n+1, CMD_IFB_ADD, tc->ifb_name);
		p += n;
		snprintf(p, ifb_up_n+1, CMD_IFB_UP, tc->ifb_name);
		system(ifb_cmd);
		free(ifb_cmd);
		ifb_cmd = NULL;
	}

	size_t n = snprintf(NULL, 0, CMD_TC, tc->net_name, tc->ifb_name, bandwidth);
	char *tc_cmd = malloc(n+1);
	snprintf(tc_cmd, n+1, CMD_TC, tc->net_name, tc->ifb_name, bandwidth);
	system(tc_cmd);

	free(tc_cmd);
	tc_cmd = NULL;

	return 0;
}
