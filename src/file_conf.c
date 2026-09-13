/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include "factype.h"
#include "types.h"
#include "file.h"

#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

/* Macros for 'facows.conf'. */
enum {U32_T, U16_T, BOOL_T, CHAR_T, AP_T, MIME_T};
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
	X(HSTS, use_hsts, BOOL_T) \
	X(HSTS_MAX_AGE, hsts_max_age, U32_T) \
	X(MIME, mime, MIME_T) \
	X(MIME_DEFAULT, mime_default, CHAR_T)
#define CONF_LIST_ENUM(x_key, x_member, x_type) x_key,
#define CONF_LIST_LOOKUP(x_key, x_member, x_type) [x_key] = { \
	.offset = offsetof(struct fws_conf, x_member), \
	.size = sizeof(((struct fws_conf *) nullptr)->x_member), \
	.type = x_type, \
	.key = #x_key \
},

static s32 _conf_parse(struct fws_conf *conf_p, const char *conf_buf, u64 conf_len);
static s32 _type_u32_parse(
	u64 conf_idx,
	const char *p_base,
	struct fws_conf *conf_p,
	const struct fws_lookup *conf_lookup_arr
);
static s32 _type_u16_parse(
	u64 conf_idx,
	const char *p_base,
	struct fws_conf *conf_p,
	const struct fws_lookup *conf_lookup_arr
);
static s32 _type_bool_parse(
	u64 conf_idx,
	const char *p_base,
	struct fws_conf *conf_p,
	const struct fws_lookup *conf_lookup_arr
);
static s32 _type_char_parse(
	u64 conf_idx,
	const char *p_base,
	struct fws_conf *conf_p,
	const struct fws_lookup *conf_lookup_arr
);
static s32 _type_ap_parse(
	u64 conf_idx,
	const char *p_base,
	struct fws_conf *conf_p,
	const struct fws_lookup *conf_lookup_arr
);
static s32 _type_mime_parse(
	u64 conf_idx,
	const char *p_base,
	struct fws_conf *conf_p,
	const struct fws_lookup *conf_lookup_arr
);
static s32 _tool_get_str_n(const char *p_start, s32 max_n);

s32 file_conf_read(struct fws_conf *conf_p, const char *path) {
	char *conf_buf = nullptr;
	s32 conf_fd = -1;
	s32 ret = 0;

	conf_fd = open(path, O_RDONLY);
	if (conf_fd < 0) {
		ret = -1;
		goto out;
	}

	struct stat conf_stat = {0};
	ret = fstat(conf_fd, &conf_stat);
	if (ret < 0) {
		ret = -1;
		goto out;
	}

	u64 conf_len = conf_stat.st_size + 1;
	conf_buf = calloc(conf_len+1, 1);
	if (conf_buf == nullptr) {
		ret = -1;
		goto out;
	}

	s64 read_ret = read(conf_fd, conf_buf, conf_len-1);
	if (read_ret < 0) {
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
	static s32 (*const _conf_parse_val_arr[])(
		u64 conf_idx,
		const char *p_base,
		struct fws_conf *conf_p,
		const struct fws_lookup *conf_lookup_arr
	) = {
		[U32_T] = _type_u32_parse,
		[U16_T] = _type_u16_parse,
		[BOOL_T] = _type_bool_parse,
		[CHAR_T] = _type_char_parse,
		[AP_T] = _type_ap_parse,
		[MIME_T] = _type_mime_parse
	};
	s32 ret = 0;

	memset(conf_p, 0, sizeof(struct fws_conf));
	const char *p_scan = conf_buf;
	const char *p_end = nullptr;
	u64 n = 0;
	u64 total_n = 0;
	while (total_n < conf_len) {
		if (*p_scan == '#') {
			goto next_line;
		}

		for (u64 i=0; i<CONF_LIST_CAP; i++) {
			constexpr u64 conf_key_max = 16;
			p_end = memchr(p_scan, ' ', conf_key_max);
			if (p_end == nullptr) {
				goto next_line;
			}
			if (p_end < p_scan) {
				fprintf(stderr, "_conf_parse(): p_end-p_scan: invalid range\n");
				return -1;
			}
			u64 conf_key_len = p_end - p_scan;

			u64 key_len = strnlen(conf_lookup_arr[i].key, conf_key_max);
			if (conf_key_len != key_len) {
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

next_line:
		p_end = memchr(p_scan, '\n', conf_len-total_n);
		if (p_end == nullptr) {
			return -1;
		}
		n = p_end - p_scan;
		total_n += n + 1;
		p_scan += n + 1;
		while (*p_scan == '\n') {
			total_n++;
			p_scan++;
		}
	}
	return 0;
}

static s32 _type_u32_parse(u64 conf_idx, const char *p_base, struct fws_conf *conf_p, const struct fws_lookup *conf_lookup_arr) {
	u32 *member = (u32 *) ((u8 *) conf_p + conf_lookup_arr[conf_idx].offset);
	*member = (u32) strtol(p_base, nullptr, 10);
	return 0;
}

static s32 _type_u16_parse(u64 conf_idx, const char *p_base, struct fws_conf *conf_p, const struct fws_lookup *conf_lookup_arr) {
	s64 port = strtol(p_base, nullptr, 10);
	if (port < 0 || port >= 65536) {
		fprintf(stderr, "file_conf/_conf_parse(): out of port range\n");
		return -1;
	}
	u16 *member = (u16 *) ((u8 *) conf_p + conf_lookup_arr[conf_idx].offset);
	*member = (u16) port;
	return 0;
}

static s32 _type_bool_parse(u64 conf_idx, const char *p_base, struct fws_conf *conf_p, const struct fws_lookup *conf_lookup_arr) {
	static const char true_str[] = "true";
	static const char false_str[] = "false";
	constexpr u64 true_str_len = sizeof(true_str) - 1;
	constexpr u64 false_str_len = sizeof(false_str) - 1;

	s32 true_cmp = memcmp(p_base, true_str, true_str_len);
	s32 false_cmp = memcmp(p_base, false_str, false_str_len);
	bool *member = (bool *) ((u8 *) conf_p + conf_lookup_arr[conf_idx].offset);
	if (true_cmp == 0) {
		if (*(p_base+true_str_len) == ' ' || *(p_base+true_str_len) == '\n') {
			*member = true;
		} else {
			printf("facows.conf: error: bool type error\n");
			return -1;
		}
	} else if (false_cmp == 0) {
		if (*(p_base+false_str_len) == ' ' || *(p_base+false_str_len) == '\n') {
			*member = false;
		} else {
			printf("facows.conf: error: bool type error\n");
			return -1;
		}
	} else {
		printf("facows.conf: error: type error\n");
		return -1;
	}

	return 0;
}

static s32 _type_char_parse(u64 conf_idx, const char *p_base, struct fws_conf *conf_p, const struct fws_lookup *conf_lookup_arr) {
	const char *p1 = p_base + 1;
	if (*(p1-1) != '"') {
		printf("facows.conf: error: require double quote before write string\n");
		return -1;
	}

	const char *p2 = memchr(p1, '"', conf_lookup_arr[conf_idx].size-1);
	if (p2 == nullptr) {
		printf("facows.conf: error: very large value, lower than %zu\n", conf_lookup_arr[conf_idx].size-1);
		return -1;
	}

	u64 n = (u64) (p2 - p1);
	char *member = (char *) ((u8 *) conf_p + conf_lookup_arr[conf_idx].offset);
	memcpy(member, p1, n);
	member[n] = '\0';
	return 0;
}

static s32 _type_ap_parse(u64 conf_idx, const char *p_base, struct fws_conf *conf_p, const struct fws_lookup *conf_lookup_arr) {
	static const char comma_str[] = ", ";
	constexpr u64 comma_str_len = sizeof(comma_str) - 1;

	const char *p_end = memchr(p_base, '\n', conf_lookup_arr[conf_idx].size-1);
	if (p_end == nullptr) {
		printf("facows.conf: error: very large value, lower than %lu\n", conf_lookup_arr[conf_idx].size-1);
		return -1;
	}

	const char *p_scan = p_base;
	char *ep = nullptr;
	while (*p_scan != '\n' && *p_scan != '\0') {
		s64 port = strtol(p_scan, &ep, 10);
		if (p_scan == ep) {
			p_scan++;
			continue;
		}

		if (port < 0 || port >= 65536) {
			fprintf(stderr, "file_conf/_conf_parse(): out of port range\n");
			return -1;
		}

		p_scan = ep;
		if (*p_scan == ',') {
			p_scan++;
		}
	}

	u64 n = (u64) (p_end - p_base);

	char *member = (char *) ((u8 *) conf_p + conf_lookup_arr[conf_idx].offset);
	memcpy(member, comma_str, comma_str_len);
	memcpy(member+comma_str_len, p_base, n);
	member[n+comma_str_len] = '\0';
	return 0;
}

static s32 _type_mime_parse(
	u64 conf_idx,
	const char *p_base,
	struct fws_conf *conf_p,
	const struct fws_lookup *conf_lookup_arr
) {
	const char *p_start = memchr(p_base, '{', conf_lookup_arr[conf_idx].size-1);
	if (p_start == nullptr) {
		fprintf(stderr, "facows.conf: error: missing '{' at MIME\n");
		return -1;
	}
	if (p_base < p_start) {
		fprintf(stderr, "_type_mime_parse(): p_base-p_start: invalid range\n");
		return -1;
	}
	s32 mime_skip = p_base - p_start;
	p_start += mime_skip;
	p_start++; /* skip '{' */

	const char *p_end = memchr(p_start, '}', (conf_lookup_arr[conf_idx].size-1)-mime_skip);
	if (p_end == nullptr) {
		fprintf(stderr, "facows.conf: error: missing '}' at MIME or too long lower than %lu\n", conf_lookup_arr[conf_idx].size-1);
		return -1;
	}
	if (p_end < p_start) {
		fprintf(stderr, "_type_mime_parse(): p_end-p_start: invalid range\n");
		return -1;
	}
	s32 mime_n = p_end - p_start;
	if ((u32) mime_n >= conf_lookup_arr[conf_idx].size) {
		fprintf(stderr, "_type_mime_parse(): mime_n: invalid size\n");
		return -1;
	}
	const char *p_scan = p_start;
	char *p_dst = conf_p->mime;

	/* [info]
	p_start == p_scan
	*(p_start-1) == '{'
	*p_end == '}'
	mime_n = p_end - p_start;
	*/
	while (mime_n > 0) {
		/* get mime type string */
		p_start = memchr(p_scan, '"', mime_n);
		if (p_start == nullptr) {
			if (*(p_dst-1) == ']') {
				break;
			}
			fprintf(stderr, "facows.conf: error: missing '\"' at string start\n");
			return -1;
		}
		p_start++; /* skip start '"' */
		if (p_start < p_scan) {
			fprintf(stderr, "_type_mime_parse(): p_scan-p_start: invalid range\n");
			return -1;
		}
		s32 mime_skip = p_start - p_scan;
		mime_n -= mime_skip;
		s32 mime_len = _tool_get_str_n(p_start, mime_n);
		if (mime_len < 0) {
			return -1;
		}
		mime_n -= mime_len;
		p_scan = p_start;
		p_scan += mime_len;
		p_scan++; /* skip end '"' */
	
		memcpy(p_dst, p_start, mime_len);
		p_dst += mime_len;

		/* get mime file extension */
		const char *p_ext_start = memchr(p_scan, '[', mime_n);
		if (p_ext_start == nullptr) {
			fprintf(stderr, "facows.conf: error: array not found\n");
			return -1;
		}
		p_ext_start++; /* skip '[' */
		if (p_ext_start < p_scan) {
			fprintf(stderr, "_type_mime_parse(): p_ext_start-p_scan: invalid range\n");
			return -1;
		}
		mime_skip = p_ext_start - p_scan;
		p_scan += mime_skip;
		mime_n -= mime_skip;

		const char *p_ext_scan = p_ext_start;
		const char *p_ext_end = memchr(p_ext_scan, ']', mime_n);
		if (p_ext_end == nullptr) {
			fprintf(stderr, "facows.conf: error: missing ']' at array end\n");
			return -1;
		}
		if (p_ext_end < p_ext_start) {
			fprintf(stderr, "_type_mime_parse(): p_ext_end-p_ext_start: invalid range\n");
			return -1;
		}
		s32 ext_n = p_ext_end - p_ext_start;
		memcpy(p_dst, "[", sizeof("[")-1);
		p_dst++;
		p_scan += ext_n;
		mime_n -= ext_n;
		bool has_ext_norm = false;

		/* [info]
		*(p_ext_scan-1) == '['
		*p_ext_end == ']'
		p_ext_scan == p_ext_start
		ext_n == p_ext_end - p_ext_start
		*/
		while (ext_n > 0) {
			p_ext_start = memchr(p_ext_scan, '"', ext_n);
			if (p_ext_start == nullptr) {
				fprintf(stderr, "facows.conf: error: missing '\"' at string start\n");
				return -1;
			}
			if (p_ext_start < p_ext_scan) {
				fprintf(stderr, "_type_mime_parse(): error: invalid range\n");
				return -1;
			}
			s32 ext_skip = p_ext_start - p_ext_scan;
			ext_n -= ext_skip;
			p_ext_scan = p_ext_start;

			/* skip start '"' */
			p_ext_start++;
			p_ext_scan++;
			ext_n--;

			if (ext_n <= 0) {
				fprintf(stderr, "facows.conf: error: missing '\"' at string end\n");
				return -1;
			}

			s32 ext_len = _tool_get_str_n(p_ext_start, ext_n);
			if (ext_len < 0) {
				return -1;
			}
			memcpy(p_dst, p_ext_start, ext_len);
			p_dst += ext_len;

			/* next */
			p_ext_start = memchr(p_ext_scan, ',', ext_n);
			if (p_ext_start == nullptr) {
				memcpy(p_dst, "]", sizeof("]")-1);
				p_dst++;
				has_ext_norm = true;
				break;
			}
			memcpy(p_dst, ",", sizeof(",")-1);
			p_dst++;

			if (p_ext_start < p_ext_scan) {
				fprintf(stderr, "_type_mime_parse(): p_ext_start-p_ext_scan: invalid range\n");
				return -1;
			}
			ext_skip = p_ext_start - p_ext_scan;
			ext_n -= ext_skip;
			p_ext_scan = p_ext_start;
		}
		*p_dst = '\0';
		if (!has_ext_norm) {
			return -1;
		}
	}

	return 0;
}

s32 _tool_get_str_n(const char *p_start, s32 max_n) {
	const char *p_end = memchr(p_start, '"', max_n);
	if (p_end == nullptr) {
		fprintf(stderr, "_tool_get_str_n(): error: missing '\"' at string end\n");
		return -1;
	}
	if (p_start > p_end) {
		fprintf(stderr, "_tool_get_str_n(): error: string empty\n");
		return -1;
	}
	return p_end - p_start;
}
