/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <string.h>
#include <sys/stat.h>

#include "fac_utils.h"
#include "types.h"
#include "net.h"

#define SHARE_DIR "/usr/share/facows/"
#define SHARE_ERR_HTML "/usr/share/facows/error_page.html"

#define HTTP_MSG_200 "OK"
#define HTTP_MSG_400 "Bad Request"
#define HTTP_MSG_403 "Forbidden"
#define HTTP_MSG_404 "File Not Found"
#define HTTP_MSG_405 "Method Not Allowed"
#define HTTP_MSG_414 "URI Too Long"
#define HTTP_MSG_429 "Too Many Requests"
#define HTTP_MSG_431 "Request Header Fields Too Large"
#define HTTP_MSG_500 "Internal Server Error"
#define HTTP_MSG_501 "Not Implemented"

#define HTTP_ERR_RES "HTTP/1.1 %d %s\r\nContent-Type: text/html\r\nContent-Length: %zu\r\n\r\n"
#define HTTP_RES "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %zu\r\nDate: %s\r\n\r\n"

static const struct {
	int code;
	const char *msg;
} http_msg[] = {
	{500, HTTP_MSG_500},
	{400, HTTP_MSG_400},
	{403, HTTP_MSG_403},
	{404, HTTP_MSG_404},
	{405, HTTP_MSG_405},
	{414, HTTP_MSG_414},
	{429, HTTP_MSG_429},
	{431, HTTP_MSG_431},
	{501, HTTP_MSG_501}
};

int net_443_init(SSL_CTX **ssl_ctx, const struct fws_conf *config) {
	SSL_library_init();
	const SSL_METHOD *ssl_method;
	ssl_method = TLS_server_method();
	*ssl_ctx = SSL_CTX_new(ssl_method);
	if (SSL_CTX_use_certificate_file(*ssl_ctx, config->ssl_cert, SSL_FILETYPE_PEM) <= 0) {
		fprintf(stderr, "ssl certification error\n");
		return 1;
	}
	if (SSL_CTX_use_PrivateKey_file(*ssl_ctx, config->ssl_key, SSL_FILETYPE_PEM) <= 0) {
		fprintf(stderr, "ssl private key error\n");
		return 1;
	}
	return 0;
}

int net_443_read(SSL *ssl, char *dst_buf, size_t buf_size) {
	int total_read_size = 0;
	int read_ret = 0;
	while (1) {
		read_ret = SSL_read(ssl, dst_buf+total_read_size, buf_size-total_read_size-1);
		if (read_ret <= 0) {
			const int err_code = SSL_get_error(ssl, read_ret);
			if (err_code == SSL_ERROR_WANT_READ) {
				continue;
			} else if (err_code == SSL_ERROR_ZERO_RETURN) {
				return 400;
			}
			return 500;
		}

		total_read_size += read_ret;
		if (total_read_size >= 4095) {
			return 431;
		} else if (fac_memstr(dst_buf, "\r\n\r\n", total_read_size) != NULL) {
			break;
		}
	}
	return 0;
}

int net_443_write(SSL *ssl, const char *path) {
	int ret = 0;

	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		ret = -1;
		goto out;
	}
	char file_buf[4096];
	ssize_t read_size;
	while ((read_size = read(fd, file_buf, sizeof(file_buf))) > 0) {
		if (SSL_write(ssl, file_buf, read_size) <= 0) {
			ret = 1;
			goto out;
		}
	}

	ret = 0;
out:
	if (fd >= 0) {
		close(fd);
		fd = -1;
	}
	return ret;
}

int net_443_res_write(SSL *ssl, struct fws_http_res *http_res, off_t size) {
	char *res_buf = NULL;
	int ret = 0;

	size_t n = snprintf(NULL, 0, HTTP_RES, http_res->content, size, http_res->date);
	res_buf = malloc(n+1);
	if (res_buf == NULL) {
		ret = -1;
		goto out;
	}

	snprintf(res_buf, n+1, HTTP_RES, http_res->content, size, http_res->date);
	SSL_write(ssl, res_buf, n);

	ret = 0;
out:
	free(res_buf);
	res_buf = NULL;
	return ret;
}

int net_443_err_write(SSL *ssl, int code) {
	char *html_fmt = NULL;
	char *html_buf = NULL;
	char *res_buf = NULL;
	int html_fd = -1;

	int ret = 0;

	html_fd = open(SHARE_ERR_HTML, O_RDONLY);
	if (html_fd < 0) {
		ret = -1;
		goto out;
	}
	struct stat html_stat = {0};
	if (fstat(html_fd, &html_stat) < 0) {
		ret = -1;
		goto out;
	}
	html_fmt = malloc(html_stat.st_size+1);
	if (html_fmt == NULL) {
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

	size_t msg_idx = 0;
	size_t html_n = 0;
	size_t res_n = 0;
	for (size_t i=0; i<(sizeof(http_msg)/sizeof(http_msg[0])); i++) {
		if (http_msg[i].code == code) {
			msg_idx = i;
			break;
		}
	}

	html_n = snprintf(NULL, 0, html_fmt, http_msg[msg_idx].code, http_msg[msg_idx].code, http_msg[msg_idx].msg);
	html_buf = malloc(html_n+1);
	if (html_buf == NULL) {
		ret = -1;
		goto out;
	}
	snprintf(html_buf, html_n+1, html_fmt, http_msg[msg_idx].code, http_msg[msg_idx].code, http_msg[msg_idx].msg);

	res_n = snprintf(NULL, 0, HTTP_ERR_RES, http_msg[msg_idx].code, http_msg[msg_idx].msg, html_n);
	res_buf = malloc(res_n+1);
	if (res_buf == NULL) {
		ret = -1;
		goto out;
	}
	snprintf(res_buf, res_n+1, HTTP_ERR_RES, http_msg[msg_idx].code, http_msg[msg_idx].msg, html_n);

	SSL_write(ssl, res_buf, res_n);
	SSL_write(ssl, html_buf, html_n);

	ret = 0;
out:
	free(res_buf);
	res_buf = NULL;
	free(html_buf);
	html_buf = NULL;
	free(html_fmt);
	html_fmt = NULL;
	if (html_fd >= 0) {
		close(html_fd);
		html_fd = -1;
	}
	return ret;
}
