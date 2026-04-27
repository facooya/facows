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
#include <net/if.h>

#include <netlink/netlink.h>
#include <netlink/route/route.h>
#include <netlink/route/nexthop.h>
#include <netlink/route/link.h>
#include <netlink/route/qdisc.h>
#include <netlink/route/classifier.h>
#include <netlink/route/cls/flower.h>
#include <netlink/route/act/mirred.h>

#include "fac_utils.h"
#include "types.h"
#include "net.h"

#define AWK_NET_PARSE "awk '$2 == \"00000000\" {printf \"%s\", $1}' /proc/net/route"

#define CMD_IFB_ADD "ip link add name %s type ifb;"
#define CMD_IFB_DEL "ip link del dev %s;"
#define CMD_IFB_UP "ip link set dev %s up;"

#define CMD_TC \
	"tc qdisc replace dev %1$s handle ffff: ingress;" \
	"tc filter replace dev %1$s parent ffff: protocol ip flower action mirred egress redirect dev %2$s;" \
	"tc filter replace dev %1$s parent ffff: protocol ipv6 flower action mirred egress redirect dev %2$s;" \
	"tc qdisc replace dev %2$s root handle fac0: cake bandwidth %3$s triple-isolate nat wash ingress;"

#define CMD_TC_DEL "tc qdisc del dev %s ingress;"

static int _mod_init(struct fws_tc *tc);

int net_tc_init(struct fws_tc *tc, const char *bandwidth) {
	if (_mod_init(tc) < 0) {
		return -1;
	}

	struct nl_sock *nl_sock;
	struct nl_cache *nl_cache;
	struct rtnl_link *rtnl_link;
	nl_sock = nl_socket_alloc();
	if (nl_sock == NULL) {
		printf("facows_tc: error: fail to net link socket\n");
		return -1;
	}
	if (nl_connect(nl_sock, NETLINK_ROUTE) < 0) {
		printf("facows_tc: error: fail to net link connection\n");
		nl_socket_free(nl_sock);
		nl_sock = NULL;
		return -1;
	}
	rtnl_link_alloc_cache(nl_sock, 0, &nl_cache);

	char ifb_buf[8];
	size_t ifb_num = 0;
	while (1) {
		size_t n = snprintf(ifb_buf, sizeof(ifb_buf), "ifb%d", ifb_num);
		rtnl_link = rtnl_link_get_by_name(nl_cache, ifb_buf);
		if (rtnl_link == NULL) {
			rtnl_link = rtnl_link_alloc();
			rtnl_link_set_name(rtnl_link, ifb_buf);
			rtnl_link_set_type(rtnl_link, "ifb");
			rtnl_link_set_flags(rtnl_link, IFF_UP);
			if (rtnl_link_add(nl_sock, rtnl_link, NLM_F_CREATE) < 0) {
				printf("facows_tc: error: can not add net link\n");
				rtnl_link_put(rtnl_link);
				return -1;
			}
			rtnl_link_put(rtnl_link);
			rtnl_link = NULL;

			memcpy(tc->ifb_name, ifb_buf, n+1);
			break;
		} else {
			rtnl_link_put(rtnl_link);
			rtnl_link = NULL;
		}

		ifb_num++;
		if (ifb_num > 30) {
			printf("facows_tc: error: ifb number large");
			nl_cache_put(nl_cache);
			nl_cache = NULL;
			return -1;
		}
	}

	struct nl_cache *rtnl_cache;
	struct rtnl_route *rtnl_route;
	struct rtnl_nexthop *rtnl_nh;
	struct nl_object *nl_obj, *nl_obj_tmp;

	rtnl_route_alloc_cache(nl_sock, 0, 0, &rtnl_cache);
	nl_obj = nl_cache_get_first(rtnl_cache);
	if (nl_obj == NULL) {
		printf("facows_tc: error: fail to find main network name\n");
		return -1;
	}

	while (1) {
		rtnl_route = (struct rtnl_route *) nl_obj;

		if (rtnl_route_get_table(rtnl_route) == RT_TABLE_MAIN && nl_addr_get_len(rtnl_route_get_dst(rtnl_route)) == 0) {
			rtnl_nh = rtnl_route_nexthop_n(rtnl_route, 0);
			int net_index = rtnl_route_nh_get_ifindex(rtnl_nh);
			rtnl_link_i2name(nl_cache, net_index, tc->net_name, sizeof(tc->net_name));
			break;
		}

		nl_obj = nl_cache_get_next(nl_obj);
		if (nl_obj == NULL) {
			printf("facows_tc: error: not found main network name\n");
			return -1;
		}
	}

	nl_cache_put(nl_cache);
	nl_cache = NULL;
	nl_cache_put(rtnl_cache);
	rtnl_cache = NULL;
	nl_socket_free(nl_sock);
	nl_sock = NULL;

	size_t n = snprintf(NULL, 0, CMD_TC, tc->net_name, tc->ifb_name, bandwidth);
	char *tc_cmd = malloc(n+1);
	snprintf(tc_cmd, n+1, CMD_TC, tc->net_name, tc->ifb_name, bandwidth);
	system(tc_cmd);

	free(tc_cmd);
	tc_cmd = NULL;

	return 0;
}

int net_tc_fini(const struct fws_tc *tc) {
	if (tc->mod == 1) {
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

static int _mod_init(struct fws_tc *tc) {
	int ret;
	struct kmod_ctx *kmod_ctx;
	struct kmod_module *kmod_mod;

	kmod_ctx = kmod_new(NULL, NULL);
	if (kmod_ctx == NULL) {
		printf("facows_tc: error: fail to create kernel module context\n");
		ret = -1;
		goto out;
	}

	ret = kmod_module_new_from_name(kmod_ctx, "ifb", &kmod_mod);
	if (ret < 0) {
		printf("facows_tc: error: fail to load ifb module\n");
		ret = -1;
		goto out;
	}

	ret = kmod_module_get_initstate(kmod_mod);
	if (ret < 0) {
		tc->mod = 1;
		ret = kmod_module_probe_insert_module(kmod_mod, KMOD_PROBE_APPLY_BLACKLIST, "numifbs=0", NULL, NULL, NULL);
		if (ret < 0) {
			printf("facows_tc: error: fail to insert module\n");
			ret = -1;
			goto out;
		}
	} else {
		tc->mod = 0;
	}

	ret = 0;
out:
	kmod_module_unref(kmod_mod);
	kmod_mod = NULL;
	kmod_unref(kmod_ctx);
	kmod_ctx = NULL;
	return ret;
}
