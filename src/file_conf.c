/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include "factype.h"
#include "facerr.h"
#include "facerr.h"
#include "types.h"
#include "file.h"

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

/* Macros for 'facows.conf'. */
enum {U32_T, U16_T, BOOL_T, CHAR_T, AP_T, MAP_T};
#define CONF_LIST(X) \
	X(HTTP_PORT, http_port, U16_T) \
	X(HTTPS_PORT, https_port, U16_T) \
	X(ALLOW_PORTS, allow_ports, AP_T) \
	X(NFT, use_nft, BOOL_T) \
	X(LIM_SWAP_TIME, lim_swap_time, U32_T) \
	X(LIM_PAGE, lim_page, U32_T) \
	X(LIM_RES, lim_res, U32_T) \
	X(PPS_LIMIT, pps_limit, U32_T) \
	X(PPS_BURST, pps_burst, U32_T) \
	X(BAN_LIM, ban_lim, U32_T) \
	X(BAN_TIME, ban_time, U32_T) \
	X(DOMAIN, domain, CHAR_T) \
	X(WEB_ROOT, web_root, CHAR_T) \
	X(WEB_LOG, web_log, CHAR_T) \
	X(SSL_CERT, ssl_cert, CHAR_T) \
	X(SSL_KEY, ssl_key, CHAR_T) \
	X(KERNEL_TLS, use_ktls, BOOL_T) \
	X(HSTS, use_hsts, BOOL_T) \
	X(HSTS_MAX_AGE, hsts_max_age, U32_T) \
	X(MIME, mime, MAP_T) \
	X(MIME_DEFAULT, mime_default, CHAR_T) \
	X(CACHE, cache, MAP_T) \
	X(CACHE_DEFAULT, cache_default, CHAR_T)
#define CONF_LIST_ENUM(x_key, x_member, x_type) x_key,
#define CONF_LIST_LOOKUP(x_key, x_member, x_type) [x_key] = { \
	.offset = offsetof(struct fws_conf, x_member), \
	.size = sizeof(((struct fws_conf*)nullptr)->x_member), \
	.type = x_type, \
	.key = #x_key \
},

static s32 _conf_parse(struct fws_conf *conf_p, const char *conf_buf, u64 conf_len);
static s32 _conf_parse__line_next(const char **p_scan, const char **p_end,
		u64 *total_n, u64 *n, u64 conf_len);
static s32 _type_u32_parse(u64 conf_idx, const char *p_base, struct fws_conf *conf_p,
		const struct fws_lookup *conf_lookup_arr);
static s32 _type_u16_parse(u64 conf_idx, const char *p_base, struct fws_conf *conf_p,
		const struct fws_lookup *conf_lookup_arr);
static s32 _type_bool_parse(u64 conf_idx, const char *p_base, struct fws_conf *conf_p,
		const struct fws_lookup *conf_lookup_arr);
static s32 _type_char_parse(u64 conf_idx, const char *p_base, struct fws_conf *conf_p,
		const struct fws_lookup *conf_lookup_arr);
static s32 _type_ap_parse(u64 conf_idx, const char *p_base, struct fws_conf *conf_p,
		const struct fws_lookup *conf_lookup_arr);
static s32 _type_map_norm(u64 conf_idx, const char *p_base, struct fws_conf *conf_p,
		const struct fws_lookup *conf_lookup_arr);
static s32 _tool_get_str_n(const char *p_start, s32 max_n);

s32 file_conf_read(struct fws_conf *conf_p, const char *path) {
	char *conf_buf = nullptr;
	s32 conf_fd = -1;
	s32 ret = 0;

	conf_fd = open(path, O_RDONLY);
	if (conf_fd < 0) {
		FAC_ERR("%s\n", strerror(errno));
		ret = -1;
		goto out;
	}

	struct stat conf_stat = {};
	ret = fstat(conf_fd, &conf_stat);
	if (ret < 0) {
		FAC_ERR("%s\n", strerror(errno));
		ret = -1;
		goto out;
	}

	u64 conf_len = conf_stat.st_size + 1;
	conf_buf = calloc(conf_len+1, 1);
	if (conf_buf == nullptr) {
		FAC_ERR("%s\n", strerror(errno));
		ret = -1;
		goto out;
	}

	s64 read_ret = read(conf_fd, conf_buf, conf_len-1);
	if (read_ret < 0) {
		FAC_ERR("%s\n", strerror(errno));
		ret = -1;
		goto out;
	}

	conf_buf[conf_len-1] = '\n';
	conf_buf[conf_len] = '\0';

	ret = _conf_parse(conf_p, conf_buf, conf_len);
	if (ret < 0) {
		ret = -1;
		goto out;
	}

	ret = 0;
out:
	free(conf_buf);
	conf_buf = nullptr;
	if (conf_fd >= 0) {
		close(conf_fd);
		conf_fd = -1;
	}
	return ret;
}

static s32 _conf_parse(struct fws_conf *conf_p, const char *conf_buf, u64 conf_len) {
	enum {CONF_LIST(CONF_LIST_ENUM) CONF_LIST_CAP};
	static const struct fws_lookup conf_lookup_arr[CONF_LIST_CAP] = {CONF_LIST(CONF_LIST_LOOKUP)};
	static s32 (*const _conf_parse_val_arr[])(u64 conf_idx, const char *p_base,
			struct fws_conf *conf_p, const struct fws_lookup *conf_lookup_arr) = {
		[U32_T] = _type_u32_parse,
		[U16_T] = _type_u16_parse,
		[BOOL_T] = _type_bool_parse,
		[CHAR_T] = _type_char_parse,
		[AP_T] = _type_ap_parse,
		[MAP_T] = _type_map_norm
	};
	s32 ret = -1;

	const char *p_scan = conf_buf;
	const char *p_end = nullptr;
	u64 n = 0;
	u64 total_n = 0;
	while (total_n < conf_len) {
		if (*p_scan == '#') {
			ret = _conf_parse__line_next(&p_scan, &p_end, &total_n, &n, conf_len);
			if (ret < 0) {
				break;
			}
			continue;
		}

		for (u64 i=0; i<CONF_LIST_CAP; i++) {
			constexpr u64 conf_key_max = 16;
			p_end = memchr(p_scan, ' ', conf_key_max);
			if (p_end == nullptr) {
				ret = _conf_parse__line_next(&p_scan, &p_end, &total_n, &n, conf_len);
				if (ret < 0) {
					break;
				}
				continue;
			}
			s64 conf_key_len = p_end - p_scan;
			if (conf_key_len < 0) {
				FAC_ERR(FAC_ERR_RANGE);
				return -1;
			}

			s64 key_len = (s64)strnlen(conf_lookup_arr[i].key, conf_key_max);
			if (key_len == conf_key_max || key_len != conf_key_len) {
				continue;
			}
			ret = memcmp(p_scan, conf_lookup_arr[i].key, key_len);
			if (ret != 0) {
				continue;
			}

			p_scan += conf_key_len;
			total_n += conf_key_len;
			while (*p_scan == ' ') {
				total_n++;
				p_scan++;
			}

			ret = _conf_parse_val_arr[conf_lookup_arr[i].type](i, p_scan, conf_p, conf_lookup_arr);
			if (ret < 0) {
				return -1;
			}
			break;
		}

		ret = _conf_parse__line_next(&p_scan, &p_end, &total_n, &n, conf_len);
		if (ret < 0) {
			break;
		}
	}

	return 0;
}

static s32 _conf_parse__line_next(const char **p_scan, const char **p_end,
		u64 *total_n, u64 *n, u64 conf_len) {
	*p_end = memchr(*p_scan, '\n', conf_len-*total_n);
	if (*p_end == nullptr) {
		return -1;
	}

	*n = *p_end - *p_scan;
	*total_n += *n + 1;
	*p_scan += *n + 1;
	while (**p_scan == '\n') {
		*total_n += 1;
		*p_scan += 1;
	}

	return 0;
}

static s32 _type_u32_parse(u64 conf_idx, const char *p_base, struct fws_conf *conf_p,
		const struct fws_lookup *conf_lookup_arr) {
	char *end_p = nullptr;
	errno = 0;
	s64 num = strtol(p_base, &end_p, 10);
	if (p_base == end_p) {
		FAC_ERR("no exist number, conf: %s\n", conf_lookup_arr[conf_idx].key);
		return -1;
	}
	if (errno == ERANGE) {
		FAC_ERR("%s, conf: %s\n", strerror(errno), conf_lookup_arr[conf_idx].key);
		return -1;
	}
	if (*end_p != '\0' && *end_p != ' ' && *end_p != '\n') {
		FAC_ERR("invalid format, end_p: %d, conf: %s\n", *end_p, conf_lookup_arr[conf_idx].key);
		return -1;
	}
	if (num < 0 || num > (s64)FAC_U32_MAX) {
		FAC_ERR(FAC_ERR_RANGE);
		return -1;
	}
	u32 *member = (u32*)((u8*)conf_p + conf_lookup_arr[conf_idx].offset);
	*member = num;

	return 0;
}

static s32 _type_u16_parse(u64 conf_idx, const char *p_base, struct fws_conf *conf_p,
		const struct fws_lookup *conf_lookup_arr) {
	char *end_p = nullptr;
	errno = 0;
	s64 num = strtol(p_base, &end_p, 10);
	if (p_base == end_p) {
		FAC_ERR("no exist number, conf: %s\n", conf_lookup_arr[conf_idx].key);
		return -1;
	}
	if (errno == ERANGE) {
		FAC_ERR("%s, conf: %s\n", strerror(errno), conf_lookup_arr[conf_idx].key);
		return -1;
	}
	if (*end_p != '\0' && *end_p != ' ' && *end_p != '\n') {
		FAC_ERR("invalid format, end_p: %d, conf: %s\n", *end_p, conf_lookup_arr[conf_idx].key);
		return -1;
	}
	if (num < 0 || num > FAC_S16_MAX) {
		FAC_ERR(FAC_ERR_RANGE);
		return -1;
	}
	u16 *member = (u16*)((u8*)conf_p + conf_lookup_arr[conf_idx].offset);
	*member = (u16)num;
	return 0;
}

static s32 _type_bool_parse(u64 conf_idx, const char *p_base, struct fws_conf *conf_p,
		const struct fws_lookup *conf_lookup_arr) {
	static const char true_str[] = "true";
	static const char false_str[] = "false";
	constexpr u64 true_str_len = sizeof(true_str) - 1;
	constexpr u64 false_str_len = sizeof(false_str) - 1;

	s32 true_cmp = memcmp(p_base, true_str, true_str_len);
	s32 false_cmp = memcmp(p_base, false_str, false_str_len);
	bool *member = (bool*)((u8*)conf_p + conf_lookup_arr[conf_idx].offset);
	if (true_cmp == 0) {
		const char end_c = *(p_base + true_str_len);
		if (end_c == ' ' || end_c == '\r' || end_c == '\n' || end_c == '\0') {
			*member = true;
		} else {
			FAC_ERR("unsupport end char, end_c: %c\n", end_c);
			return -1;
		}
	} else if (false_cmp == 0) {
		const char end_c = *(p_base + false_str_len);
		if (end_c == ' ' || end_c == '\r' || end_c == '\n' || end_c == '\0') {
			*member = false;
		} else {
			FAC_ERR("unsupport end char, end_c: %c\n", end_c);
			return -1;
		}
	} else {
		FAC_ERR("not boolean type\n");
		return -1;
	}

	return 0;
}

static s32 _type_char_parse(u64 conf_idx, const char *p_base, struct fws_conf *conf_p,
		const struct fws_lookup *conf_lookup_arr) {
	const char *p1 = p_base;
	if (*p1 != '"') {
		FAC_ERR("require double quote before string, %c\n", *p1);
		return -1;
	}
	p1 += 1;

	const char *p2 = memchr(p1, '"', conf_lookup_arr[conf_idx].size-1);
	if (p2 == nullptr) {
		FAC_ERR(FAC_ERR_LIM_N, conf_lookup_arr[conf_idx].size);
		return -1;
	}

	s64 n = p2 - p1;
	if (n < 0 || n > (s64)conf_lookup_arr[conf_idx].size-1) {
		FAC_ERR(FAC_ERR_RANGE);
		return -1;
	}
	char *member = (char*)((u8*)conf_p + conf_lookup_arr[conf_idx].offset);
	memcpy(member, p1, (u64)n);
	member[n] = '\0';
	return 0;
}

static s32 _type_ap_parse(u64 conf_idx, const char *p_base, struct fws_conf *conf_p,
		const struct fws_lookup *conf_lookup_arr) {
	const char *p_end = memchr(p_base, '\n', conf_lookup_arr[conf_idx].size-1);
	if (p_end == nullptr) {
		p_end = memchr(p_base, '\0', conf_lookup_arr[conf_idx].size-1);
		if (p_end == nullptr) {
			FAC_ERR(FAC_ERR_LIM_N, conf_lookup_arr[conf_idx].size);
			return -1;
		}
	}

	const char *p_scan = p_base;
	char *end_p = nullptr;
	while (*p_scan != '\n' && *p_scan != '\0') {
		errno = 0;
		s64 port = strtol(p_scan, &end_p, 10);
		if (p_scan == end_p) {
			p_scan++;
			continue;
		}
		if (errno == ERANGE) {
			FAC_ERR("%s\n", strerror(errno));
			return -1;
		}
		if (port < 0 || port > FAC_S32_MAX) {
			FAC_ERR(FAC_ERR_RANGE);
			return -1;
		}

		p_scan = end_p;
		if (*p_scan == ',') {
			p_scan++;
		}
	}

	s64 n = p_end - p_base;
	if (n < 0) {
		FAC_ERR(FAC_ERR_RANGE);
		return -1;
	}

	static const char comma_str[] = ", ";
	constexpr u64 comma_str_len = sizeof(comma_str) - 1;
	char *member = (char*)((u8*)conf_p + conf_lookup_arr[conf_idx].offset);
	memcpy(member, comma_str, comma_str_len);
	memcpy(member+comma_str_len, p_base, (u64)n);
	member[n+comma_str_len] = '\0';
	return 0;
}

static s32 _type_map_norm(u64 conf_idx, const char *p_base, struct fws_conf *conf_p,
		const struct fws_lookup *conf_lookup_arr) {
	const char *p_start = memchr(p_base, '{', conf_lookup_arr[conf_idx].size-1);
	if (p_start == nullptr) {
		FAC_ERR("missing '{'\n");
		return -1;
	}
	const s64 map_skip2scan_n = p_base - p_start;
	if (map_skip2scan_n < 0) {
		FAC_ERR(FAC_ERR_RANGE);
		return -1;
	}
	p_start += map_skip2scan_n;
	p_start++; /* skip '{' */

	const char *p_end = memchr(p_start, '}', (conf_lookup_arr[conf_idx].size-1)-map_skip2scan_n);
	if (p_end == nullptr) {
		FAC_ERR("missing '}', or" FAC_ERR_LIM_N, conf_lookup_arr[conf_idx].size);
		return -1;
	}
	s64 map_rem_n = p_end - p_start;
	if (map_rem_n < 0 || map_rem_n >= (s64)conf_lookup_arr[conf_idx].size) {
		FAC_ERR(FAC_ERR_RANGE);
		return -1;
	}
	const char *p_scan = p_start;
	char *member = (char*)((u8*)conf_p + conf_lookup_arr[conf_idx].offset);
	char *p_dst = member;

	/* [info]
	p_start == p_scan
	*(p_start-1) == '{'
	*p_end == '}'
	map_rem_n = p_end - p_start;
	*/
	while (map_rem_n > 0) {
		/* get map key */
		p_start = memchr(p_scan, '"', map_rem_n);
		if (p_start == nullptr) {
			if (*(p_dst-1) == ']') {
				break;
			}
			FAC_ERR("missing '\"' at string start\n");
			return -1;
		}
		p_start++; /* skip start '"' */
		const s64 map_skip2str_n = p_start - p_scan;
		if (map_skip2str_n < 0) {
			FAC_ERR(FAC_ERR_RANGE);
			return -1;
		}
		map_rem_n -= map_skip2str_n;
		if (map_rem_n < 0) {
			FAC_ERR(FAC_ERR_RANGE);
			return -1;
		}
		const s32 map_str_len = _tool_get_str_n(p_start, map_rem_n);
		if (map_str_len < 0) {
			return -1;
		}
		map_rem_n -= map_str_len;
		if (map_rem_n < 0) {
			FAC_ERR(FAC_ERR_RANGE);
			return -1;
		}
		p_scan = p_start;
		p_scan += map_str_len;
		p_scan++; /* skip end '"' */
	
		memcpy(p_dst, p_start, map_str_len);
		p_dst += map_str_len;

		/* get map values */
		const char *p_ext_start = memchr(p_scan, '[', map_rem_n);
		if (p_ext_start == nullptr) {
			FAC_ERR("array not found\n");
			return -1;
		}
		p_ext_start++; /* skip '[' */
		const s64 map_skip2val_n = p_ext_start - p_scan;
		if (map_skip2val_n < 0) {
			FAC_ERR(FAC_ERR_RANGE);
			return -1;
		}
		p_scan += map_skip2val_n;
		map_rem_n -= map_skip2val_n;
		if (map_rem_n < 0) {
			FAC_ERR(FAC_ERR_RANGE);
			return -1;
		}

		const char *p_ext_scan = p_ext_start;
		const char *p_ext_end = memchr(p_ext_scan, ']', map_rem_n);
		if (p_ext_end == nullptr) {
			FAC_ERR("missing ']' at array end\n");
			return -1;
		}
		s64 ext_rem_n = p_ext_end - p_ext_start;
		if (ext_rem_n < 0) {
			FAC_ERR(FAC_ERR_RANGE);
			return -1;
		}
		memcpy(p_dst, "[", sizeof("["));
		p_dst++;
		p_scan += ext_rem_n;
		map_rem_n -= ext_rem_n;
		if (map_rem_n < 0) {
			FAC_ERR(FAC_ERR_RANGE);
			return -1;
		}
		bool has_ext_norm = false;

		/* [info]
		*(p_ext_scan-1) == '['
		*p_ext_end == ']'
		p_ext_scan == p_ext_start
		ext_rem_n == p_ext_end - p_ext_start
		*/
		while (ext_rem_n > 0) {
			p_ext_start = memchr(p_ext_scan, '"', ext_rem_n);
			if (p_ext_start == nullptr) {
				FAC_ERR("missing '\"' at string start\n");
				return -1;
			}
			s64 ext_skip = p_ext_start - p_ext_scan;
			if (ext_skip < 0) {
				FAC_ERR(FAC_ERR_RANGE);
				return -1;
			}
			ext_rem_n -= ext_skip;
			p_ext_scan = p_ext_start;

			/* skip start '"' */
			p_ext_start++;
			p_ext_scan++;
			ext_rem_n--;

			if (ext_rem_n <= 0) {
				FAC_ERR("missing '\"' at string start\n");
				return -1;
			}

			const s32 ext_len = _tool_get_str_n(p_ext_start, ext_rem_n);
			if (ext_len < 0) {
				return -1;
			}
			memcpy(p_dst, p_ext_start, ext_len);
			p_dst += ext_len;

			/* next */
			p_ext_start = memchr(p_ext_scan, ',', ext_rem_n);
			if (p_ext_start == nullptr) {
				memcpy(p_dst, "]", sizeof("]"));
				p_dst++;
				has_ext_norm = true;
				break;
			}
			memcpy(p_dst, ",", sizeof(","));
			p_dst++;

			ext_skip = p_ext_start - p_ext_scan;
			if (ext_skip < 0) {
				FAC_ERR(FAC_ERR_RANGE);
				return -1;
			}
			ext_rem_n -= ext_skip;
			if (ext_rem_n < 0) {
				FAC_ERR(FAC_ERR_RANGE);
				return -1;
			}
			p_ext_scan = p_ext_start;
		}
		*p_dst = '\0';
		if (!has_ext_norm) {
			FAC_ERR("normalize failure\n");
			return -1;
		}
	}

	return 0;
}

static s32 _tool_get_str_n(const char *p_start, s32 max_n) {
	const char *p_end = memchr(p_start, '"', max_n);
	if (p_end == nullptr) {
		FAC_ERR("missing '\"' at string end\n");
		return -1;
	}
	if (p_start == p_end) {
		FAC_ERR("string empty\n");
		return -1;
	}

	s64 n = p_end - p_start;
	if (n < 0 || n > FAC_S32_MAX) {
		FAC_ERR(FAC_ERR_RANGE);
		return -1;
	}

	return n;
}
