/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include "factype.h"
#include "facerr.h"
#include "types.h"
#include "net.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

s32 net_443_init(u8 **ssl_ctx_opq, const struct fws_conf *config) {
	SSL_CTX **ssl_ctx = (SSL_CTX **) ssl_ctx_opq;
	const SSL_METHOD *ssl_method = nullptr;
	ssl_method = TLS_server_method();
	*ssl_ctx = SSL_CTX_new(ssl_method);
	if (SSL_CTX_use_certificate_chain_file(*ssl_ctx, config->ssl_cert) <= 0) {
		fprintf(stderr, "ssl certification error\n");
		return -1;
	}
	if (SSL_CTX_use_PrivateKey_file(*ssl_ctx, config->ssl_key, SSL_FILETYPE_PEM) <= 0) {
		fprintf(stderr, "ssl private key error\n");
		return -1;
	}

	SSL_CTX_set_session_cache_mode(*ssl_ctx, SSL_SESS_CACHE_OFF);
	SSL_CTX_set_options(*ssl_ctx, SSL_OP_ENABLE_KTLS);
	return 0;
}

s32 net_443_read(struct fws_data_ctx *client_ctx) {
	constexpr u64 buf_n = sizeof(((struct fws_data_ctx*)nullptr)->req_buf);
	SSL *ssl = (SSL *) client_ctx->ssl_opq_p;
	s32 ret = -1;
	s32 err_code = 0;

	struct epoll_event ctl = {0};
	u64 acc_read_n = 0;
	if (client_ctx->acc_read_n != 0) {
		acc_read_n = client_ctx->acc_read_n;
	}
	while (true) {
		ERR_clear_error();
		const s32 read_ret = SSL_read(ssl, client_ctx->req_buf+acc_read_n, buf_n-acc_read_n-1);

		if (read_ret <= 0) {
			err_code = SSL_get_error(ssl, read_ret);
			if (err_code == SSL_ERROR_WANT_READ) {
				ctl.events = EPOLLIN;
				ctl.data.ptr = (void *) client_ctx;
				epoll_ctl(client_ctx->epfd, EPOLL_CTL_MOD, client_ctx->fd, &ctl);
				client_ctx->acc_read_n = acc_read_n;
				break;
			} else if (err_code == SSL_ERROR_WANT_WRITE) {
				ctl.events = EPOLLOUT;
				ctl.data.ptr = (void *) client_ctx;
				epoll_ctl(client_ctx->epfd, EPOLL_CTL_MOD, client_ctx->fd, &ctl);
				client_ctx->acc_read_n = acc_read_n;
				break;

			} else if (err_code == SSL_ERROR_SYSCALL) {
				ret = -1;
				goto out;
			} else if (err_code == SSL_ERROR_ZERO_RETURN) {
				ret = -1;
				goto out;
			} else if (err_code == SSL_ERROR_SSL) {
				ret = -1;
				goto out;
			}
			ret = -1;
			goto out;
		}

		acc_read_n += read_ret;
		if (acc_read_n >= buf_n-1) {
			ret = -431;
			goto out;
		}

		char *end_ret = memmem(client_ctx->req_buf, acc_read_n, "\r\n\r\n", sizeof("\r\n\r\n")-1);
		if (end_ret != nullptr) {
			/* TODO: SSL_pending() */
			client_ctx->req_buf[acc_read_n] = '\0';
			client_ctx->acc_read_n = 0;
			ret = 1;
			goto out;
		}
	}

	ret = 0;
out:
	if (err_code != SSL_ERROR_WANT_WRITE) {
		ctl.events = EPOLLIN;
		ctl.data.ptr = (void *) client_ctx;
		epoll_ctl(client_ctx->epfd, EPOLL_CTL_MOD, client_ctx->fd, &ctl);
	}
	if (ret < 0) {
		client_ctx->acc_read_n = 0;
	}
	return ret;
}

s32 net_443_write(struct fws_data_ctx *client_ctx, char *src_buf, u64 buf_size) {
	SSL *ssl = (SSL *) client_ctx->ssl_opq_p;
	s32 ret = -1;
	struct epoll_event ctl = {0};
	s32 err_code = 0;

	ERR_clear_error();
	const s32 write_ret = SSL_write(ssl, src_buf, buf_size);

	if (write_ret > 0) {
		ret = 1;
		goto out;

	} else if (write_ret <= 0) {
		/* TODO: log */
		err_code = SSL_get_error(ssl, ret);
		if (err_code == SSL_ERROR_WANT_WRITE) {
			ctl.events = EPOLLOUT;
			ctl.data.ptr = (void *) client_ctx;
			epoll_ctl(client_ctx->epfd, EPOLL_CTL_MOD, client_ctx->fd, &ctl);
			ret = 0;
			goto out;
		} else if (err_code == SSL_ERROR_WANT_READ) {
			ctl.events = EPOLLIN;
			ctl.data.ptr = (void *) client_ctx;
			epoll_ctl(client_ctx->epfd, EPOLL_CTL_MOD, client_ctx->fd, &ctl);
			ret = 0;
			goto out;

		} else if (err_code == SSL_ERROR_SYSCALL) {
			ret = -1;
			goto out;
		} else if (err_code == SSL_ERROR_ZERO_RETURN) {
			ret = -1;
			goto out;
		} else if (err_code == SSL_ERROR_SSL) {
			ret = -1;
			goto out;
		}
		ret = -1;
		goto out;
	}

	ret = 0;
out:
	if (err_code != SSL_ERROR_WANT_WRITE) {
		ctl.events = EPOLLIN;
		ctl.data.ptr = (void *) client_ctx;
		epoll_ctl(client_ctx->epfd, EPOLL_CTL_MOD, client_ctx->fd, &ctl);
	}
	return ret;
}

s32 net_443_file_write(struct fws_data_ctx *client_ctx, const char *path) {
	s32 fd = -1;
	s32 ret = -1;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		ret = -1;
		goto out;
	}
	s64 read_size = 0;
	u64 read_acc_size = 0;
	if (client_ctx->file_len > 0) {
		read_acc_size = client_ctx->file_len;
	}
	ret = lseek(fd, read_acc_size, SEEK_SET);
	if (ret < 0) {
		fprintf(stderr, "net_443_file_write(): lseek(): error\n");
		ret = -1;
		goto out;
	}
	while ((read_size = read(fd, client_ctx->file_buf, 4096)) > 0) {
		ret = net_443_write(client_ctx, client_ctx->file_buf, read_size);
		if (ret == 0) {
			client_ctx->file_len = read_acc_size;
			ret = 1;
			goto out;
		} else if (ret < 0) {
			client_ctx->file_len = 0;
			ret = -1;
			goto out;
		}
		read_acc_size += read_size;
	}

	client_ctx->file_len = 0;
	ret = 0;
out:
	if (fd >= 0) {
		close(fd);
		fd = -1;
	}
	return ret;
}

s32 net_443_res_write(struct fws_data_ctx *client_ctx, struct fws_http_res *http_res, s64 file_size,
		const struct fws_http_req *http_req) {
	enum {CODE_200, CODE_304};
	struct res_status {s32 code; const char *msg;};
	static const struct res_status res_status[] = {
		[CODE_200] = {.code = 200, .msg = "OK"}, /* default */
		[CODE_304] = {.code = 304, .msg = "Not Modified"}
	};
	static constexpr char res_status_fmt[] = "HTTP/1.1 %d %s\r\n";
	static constexpr char res_content_fmt[] = "Content-Type: %s\r\nContent-Length: %lu\r\n";
	static constexpr char res_date_fmt[] = "Date: %s\r\n";
	static constexpr char res_cache_fmt[] = "Cache-Control: max-age=%u\r\nETag: \"%s\"\r\n";
	static constexpr char res_hsts_fmt[] = "Strict-Transport-Security: max-age=%u;\r\n";
	static constexpr char res_acao_fmt[] = "Access-Control-Allow-Origin: %s\r\n";
	static constexpr char res_server_str[] = "Server: Facooya-Web-Server\r\n";
	static constexpr char res_connection_str[] = "Connection: keep-alive\r\nKeep-Alive: timeout=3\r\n";
	static constexpr char res_last_str[] = "\r\n";
	s32 ret = -1;

	constexpr u64 res_buf_cap = 8192;
	char res_buf[res_buf_cap] = {0};
	char *res_buf_p = res_buf;

	/* Status */
	constexpr u64 etag_n = sizeof(((struct fws_http_res*)nullptr)->etag);
	const s32 etag_cmp_ret = memcmp(http_res->etag, http_req->etag, etag_n);
	s32 status_code = CODE_200;
	if (etag_cmp_ret == 0) {
		status_code = CODE_304;
	}
	const s32 res_status_len = snprintf(res_buf_p, res_buf_cap, res_status_fmt,
			res_status[status_code].code, res_status[status_code].msg);
	if (res_status_len < 0) {
		FAC_ERR(strerror(errno));
		ret = -1;
		goto out;
	}
	res_buf_p += res_status_len;

	/* Server and Connection */
	const s32 res_str_len = snprintf(res_buf_p, res_buf_cap, "%s%s", res_server_str,
			res_connection_str);
	if (res_str_len < 0) {
		FAC_ERR(strerror(errno));
		ret = -1;
		goto out;
	}
	res_buf_p += res_str_len;

	/* Date */
	const s32 res_date_len = snprintf(res_buf_p, res_buf_cap, res_date_fmt, http_res->date);
	if (res_date_len < 0) {
		FAC_ERR(strerror(errno));
		ret = -1;
		goto out;
	}
	res_buf_p += res_date_len;

	/* Cache */
	const s32 res_cache_len = snprintf(res_buf_p, res_buf_cap, res_cache_fmt,
			client_ctx->conf_p->cache_max_age, http_res->etag);
	if (res_cache_len < 0) {
		FAC_ERR(strerror(errno));
		ret = -1;
		goto out;
	}
	res_buf_p += res_cache_len;

	/* Content */
	if (status_code == CODE_200) {
		const s32 res_content_len = snprintf(res_buf_p, res_buf_cap, res_content_fmt,
				http_res->content, file_size);
		if (res_content_len < 0) {
			FAC_ERR(strerror(errno));
			ret = -1;
			goto out;
		}
		res_buf_p += res_content_len;
	}

	/* HSTS */
	if (http_res->hsts_max_age != 0) {
		const s32 res_hsts_len = snprintf(res_buf_p, res_buf_cap, res_hsts_fmt, http_res->hsts_max_age);
		if (res_hsts_len < 0) {
			FAC_ERR(strerror(errno));
			ret = -1;
			goto out;
		}
		res_buf_p += res_hsts_len;
	}

	/* ACAO */
	if (http_res->is_origin_self) {
		const s32 res_acao_len = snprintf(res_buf_p, res_buf_cap, res_acao_fmt, http_req->origin);
		if (res_acao_len < 0) {
			FAC_ERR(strerror(errno));
			ret = -1;
			goto out;
		}
		res_buf_p += res_acao_len;
	}

	/* Finally */
	memcpy(res_buf_p, res_last_str, sizeof(res_last_str)-1);
	res_buf_p += sizeof(res_last_str)-1;
	res_buf_p = '\0';

	const u32 res_len = strnlen(res_buf, res_buf_cap);
	if (res_len == res_buf_cap) {
		FAC_ERR(FAC_ERR_LIMIT);
		ret = -1;
		goto out;
	}

	ret = net_443_write(client_ctx, res_buf, res_len);
	if (ret <= 0) {
		ret = -1;
		goto out;
	}

	ret = 0;
out:
	return ret;
}

s32 net_443_err_write(struct fws_data_ctx *client_ctx, s32 code) {
	struct http_msg { s32 code; char *msg; };
	static const struct http_msg http_msg[] = {
		{.code = 500, .msg = "Internal Server Error"}, /* default */
		{.code = 400, .msg = "Bad Request"},
		{.code = 403, .msg = "Forbidden"},
		{.code = 404, .msg = "File Not Found"},
		{.code = 405, .msg = "Method Not Allowed"},
		{.code = 414, .msg = "URI Too Long"},
		{.code = 429, .msg = "Too Many Requests"},
		{.code = 431, .msg = "Request Header Fields Too Large"},
		{.code = 501, .msg = "Not Implemented"}
	};
	static const char res_err_fmt[] =
		"HTTP/1.1 %d %s\r\nContent-Type: text/html\r\nContent-Length: %lu\r\n"
		"Server: Facooya-Web-Server\r\nConnection: close\r\n\r\n";
	static const char res_429_fmt[] =
		"HTTP/1.1 %d %s\r\nContent-Type: text/html\r\n"
		"Content-Length: %lu\r\nRetry-After: 60\r\nServer: Facooya-Web-Server\r\n"
		"Connection: close\r\n\r\n";
	static const char err_page_path[] = "/usr/share/facows/error_page.html";

	struct stat html_stat = {0};
	u64 html_n = 0;
	u64 msg_i = 0;
	u64 res_n = 0;
	s32 ret = 0;

	char *html_fmt = nullptr;
	char *html_buf = nullptr;
	char *res_buf = nullptr;
	s32 html_fd = -1;

	html_fd = open(err_page_path, O_RDONLY);
	if (html_fd < 0) {
		ret = -1;
		goto out;
	}
	if (fstat(html_fd, &html_stat) < 0) {
		ret = -1;
		goto out;
	}
	html_fmt = calloc(html_stat.st_size+1, 1);
	if (html_fmt == nullptr) {
		ret = -1;
		goto out;
	}
	if (read(html_fd, html_fmt, html_stat.st_size) <= 0) {
		ret = -1;
		goto out;
	}
	html_fmt[html_stat.st_size] = '\0';
	if (html_fd >= 0) {
		close(html_fd);
		html_fd = -1;
	}

	for (u64 i=0; i<(sizeof(http_msg)/sizeof(http_msg[0])); i++) {
		if (http_msg[i].code == code) {
			msg_i = i;
			break;
		}
	}

	ret = snprintf(nullptr, 0, html_fmt, http_msg[msg_i].code, http_msg[msg_i].code, http_msg[msg_i].msg);
	if (ret < 0) {
		ret = -1;
		goto out;
	}
	html_n = (u64) ret;
	html_buf = calloc(html_n+1, 1);
	if (html_buf == nullptr) {
		ret = -1;
		goto out;
	}
	ret = snprintf(html_buf, html_n+1, html_fmt, http_msg[msg_i].code, http_msg[msg_i].code, http_msg[msg_i].msg);
	if (ret < 0) {
		ret = -1;
		goto out;
	}

	if (code == 429) {
		ret = snprintf(nullptr, 0, res_429_fmt, http_msg[msg_i].code, http_msg[msg_i].msg, html_n);
		if (ret < 0) {
			ret = -1;
			goto out;
		}
		res_n = (u64) ret;
		res_buf = calloc(res_n+1, 1);
		if (res_buf == nullptr) {
			ret = -1;
			goto out;
		}
		ret = snprintf(res_buf, res_n+1, res_429_fmt, http_msg[msg_i].code, http_msg[msg_i].msg, html_n);
		if (ret < 0) {
			ret = -1;
			goto out;
		}

	} else {
		ret = snprintf(nullptr, 0, res_err_fmt, http_msg[msg_i].code, http_msg[msg_i].msg, html_n);
		if (ret < 0) {
			ret = -1;
			goto out;
		}
		res_n = (u64) ret;
		res_buf = calloc(res_n+1, 1);
		if (res_buf == nullptr) {
			ret = -1;
			goto out;
		}
		ret = snprintf(res_buf, res_n+1, res_err_fmt, http_msg[msg_i].code, http_msg[msg_i].msg, html_n);
		if (ret < 0) {
			ret = -1;
			goto out;
		}
	}

	ret = net_443_write(client_ctx, res_buf, res_n);
	if (ret <= 0) {
		ret = -1;
		goto out;
	}
	ret = net_443_write(client_ctx, html_buf, html_n);
	if (ret <= 0) {
		ret = -1;
		goto out;
	}

	ret = 0;
out:
	free(res_buf);
	res_buf = nullptr;
	free(html_buf);
	html_buf = nullptr;
	free(html_fmt);
	html_fmt = nullptr;
	if (html_fd >= 0) {
		close(html_fd);
		html_fd = -1;
	}
	return ret;
}
