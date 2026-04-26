/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <libkmod.h>

#include "fac_utils.h"
#include "types.h"
#include "net.h"

#define AWK_NET_PARSE "awk '$2 == \"00000000\" {printf \"%s\", $1}' /proc/net/route"

#define CMD_IFB_ON "modprobe ifb numifbs=1;"
#define CMD_IFB_OFF "modprobe -r ifb;"
#define CMD_IFB_ADD "ip link add name %s type ifb;"
#define CMD_IFB_DEL "ip link del dev %s;"
#define CMD_IFB_UP "ip link set dev %s up;"

#define CMD_TC \
	"tc qdisc replace dev %1$s handle ffff: ingress;" \
	"tc filter replace dev %1$s parent ffff: protocol ip flower action mirred egress redirect dev %2$s;" \
	"tc filter replace dev %1$s parent ffff: protocol ipv6 flower action mirred egress redirect dev %2$s;" \
	"tc qdisc replace dev %2$s root handle fac0: cake bandwidth %3$s triple-isolate nat wash ingress;"

#define CMD_TC_DEL "tc qdisc del dev %s ingress;"

int net_tc_init(struct fws_tc *tc, const char *bandwidth) {
	struct kmod_ctx *kmod_ctx;
	struct kmod_module *kmod_mod;

	kmod_ctx = kmod_new(NULL, NULL);
	if (kmod_ctx == NULL) {
		printf("facows_tc: error: fail to create kernel module context\n");
		return -1;
	}

	if (kmod_module_new_from_name(kmod_ctx, "ifb", &kmod_mod) < 0) {
		printf("facows_tc: error: fail to load ifb module\n");
		kmod_unref(kmod_ctx);
		kmod_ctx = NULL;
		return -1;
	}

	if (kmod_module_get_initstate(kmod_mod) < 0) {
		tc->modprobe = 1;
		kmod_module_probe_insert_module(kmod_mod, KMOD_PROBE_APPLY_BLACKLIST, "numifbs=1", NULL, NULL, NULL);
		memcpy(tc->ifb_name, "ifb0", sizeof("ifb0"));

	} else {
		size_t ifb_uniq = 0;
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
				errno = 0;
				long ifb_num = strtol(net_dir->d_name+3, NULL, 10);
				if (errno != 0) {
					printf("facows_tc: error: ifb number parsing error\n");
					return -1;
				}

				if (ifb_num >= ifb_uniq) {
					ifb_uniq = ifb_num + 1;
				}
			}
		}
		closedir(net_list);
	}

	kmod_module_unref(kmod_mod);
	kmod_mod = NULL;
	kmod_unref(kmod_ctx);
	kmod_ctx = NULL;

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

	if (tc->modprobe == 1) {
		system("ip link set dev eno1 up;");

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

int net_tc_fini(const struct fws_tc *tc) {
	if (tc->modprobe == 1) {
		struct kmod_ctx *kmod_ctx;
		struct kmod_module *kmod_mod;
		kmod_ctx = kmod_new(NULL, NULL);
		if (kmod_module_new_from_name(kmod_ctx, "ifb", &kmod_mod) < 0) {
			kmod_unref(kmod_ctx);
			kmod_ctx = NULL;
			return -1;
		}

		kmod_module_remove_module(kmod_mod, 0);

		kmod_module_unref(kmod_mod);
		kmod_mod = NULL;
		kmod_unref(kmod_ctx);
		kmod_ctx = NULL;

		system("tc qdisc del dev eno1 ingress;");
		return 0;

	} else {
		size_t n1 = snprintf(NULL, 0, CMD_TC_DEL, tc->net_name);
		size_t n2 = snprintf(NULL, 0, CMD_IFB_DEL, tc->ifb_name);
		char *cmd_buf = malloc(n1+n2+1);
		snprintf(cmd_buf, n1+1, CMD_TC_DEL, tc->net_name);
		snprintf(cmd_buf+n1, n2+1, CMD_IFB_DEL, tc->ifb_name);
		system(cmd_buf);

		free(cmd_buf);
		cmd_buf = NULL;
		return 0;
	}
	return 0;
}
