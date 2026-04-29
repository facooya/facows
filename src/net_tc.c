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
static int _ifb_set(struct fws_tc *tc, struct nl_sock *sock);
static int _net_set(struct fws_tc *tc, struct nl_sock *sock);

int net_tc_init(struct fws_tc *tc, const char *bandwidth) {
	int ret = 0;

	ret = _mod_init(tc);
	if (ret < 0) {
		return -1;
	}

	struct nl_sock *nl_sock = nl_socket_alloc();
	if (nl_sock == NULL) {
		printf("facows_tc: error: fail to net link socket\n");
		return -1;
	}

	ret = nl_connect(nl_sock, NETLINK_ROUTE);
	if (ret < 0) {
		printf("facows_tc: error: fail to net link connection\n");
		nl_socket_free(nl_sock);
		nl_sock = NULL;
		return -1;
	}

	ret = _ifb_set(tc, nl_sock);
	if (ret < 0) {
		return -1;
	}

	ret = _net_set(tc, nl_sock);
	if (ret < 0) {
		return -1;
	}

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
		struct kmod_ctx *kmod_ctx = NULL;
		struct kmod_module *kmod_mod = NULL;
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
	int ret = 0;
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

static int _ifb_set(struct fws_tc *tc, struct nl_sock *sock) {
	int ret = 0;
	struct nl_cache *nl_cache = NULL;
	struct rtnl_link *rtnl_link = NULL;

	ret = rtnl_link_alloc_cache(sock, 0, &nl_cache);
	if (ret < 0) {
		printf("facows_tc: error: fail to allocate link cache\n");
		ret = -1;
		goto out;
	}
	char ifb_buf[8] = {0};
	size_t ifb_num = 0;
	while (1) {
		size_t n = snprintf(ifb_buf, sizeof(ifb_buf), "ifb%zu", ifb_num);
		rtnl_link = rtnl_link_get_by_name(nl_cache, ifb_buf);
		if (rtnl_link == NULL) {
			rtnl_link = rtnl_link_alloc();
			if (rtnl_link == NULL) {
				printf("facows_tc: error: fail to allocate memory for link\n");
				ret = -1;
				goto out;
			}

			rtnl_link_set_name(rtnl_link, ifb_buf);
			rtnl_link_set_type(rtnl_link, "ifb");
			rtnl_link_set_flags(rtnl_link, IFF_UP);
			ret = rtnl_link_add(sock, rtnl_link, NLM_F_CREATE);
			if (ret < 0) {
				printf("facows_tc: error: can not add net link\n");
				ret = -1;
				goto out;
			}

			memcpy(tc->ifb_name, ifb_buf, n+1);
			break;

		} else {
			rtnl_link_put(rtnl_link);
			rtnl_link = NULL;
		}

		ifb_num++;
		if (ifb_num > 30) {
			printf("facows_tc: error: ifb number large");
			ret = -1;
			goto out;
		}
	}

	ret = 0;
out:
	rtnl_link_put(rtnl_link);
	rtnl_link = NULL;
	nl_cache_put(nl_cache);
	nl_cache = NULL;
	return ret;
}

static int _net_set(struct fws_tc *tc, struct nl_sock *sock) {
	int ret = 0;
	struct nl_cache *nl_cache, *rtnl_cache = NULL;
	struct nl_object *nl_obj = NULL;

	ret = rtnl_link_alloc_cache(sock, 0, &nl_cache);
	if (ret < 0) {
		printf("facows_tc: error: fail to allocate cache for net link\n");
		ret = -1;
		goto out;
	}
	ret = rtnl_route_alloc_cache(sock, 0, 0, &rtnl_cache);
	if (ret < 0) {
		printf("facows_tc: error: fail to allocate cache for net route\n");
		ret = -1;
		goto out;
	}

	nl_obj = nl_cache_get_first(rtnl_cache);
	if (nl_obj == NULL) {
		printf("facows_tc: error: fail to find main network name\n");
		ret = -1;
		goto out;
	}

	while (1) {
		struct rtnl_route *rtnl_route = NULL;
		struct nl_addr *nl_addr = NULL;

		rtnl_route = (struct rtnl_route *) nl_obj;
		int table_idx = rtnl_route_get_table(rtnl_route);
		nl_addr = rtnl_route_get_dst(rtnl_route);
		int addr_len = nl_addr_get_len(nl_addr);

		if (table_idx == RT_TABLE_MAIN && addr_len == 0) {
			struct rtnl_nexthop *rtnl_nh = NULL;
			rtnl_nh = rtnl_route_nexthop_n(rtnl_route, 0);
			if (rtnl_nh == NULL) {
				continue;
			}

			int net_index = rtnl_route_nh_get_ifindex(rtnl_nh);
			if (net_index <= 0) {
				continue;
			}

			char *i2name = rtnl_link_i2name(nl_cache, net_index, tc->net_name, sizeof(tc->net_name));
			if (i2name == NULL) {
				ret = -1;
				goto out;
			}
			break;
		}

		nl_obj = nl_cache_get_next(nl_obj);
		if (nl_obj == NULL) {
			printf("facows_tc: error: not found main network name\n");
			ret = -1;
			goto out;
		}
	}

	ret = 0;
out:
	nl_cache_put(nl_cache);
	nl_cache = NULL;
	nl_cache_put(rtnl_cache);
	rtnl_cache = NULL;
	return ret;
}
