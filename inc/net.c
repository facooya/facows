/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <string.h>

#include "types.h"
#include "net.h"

#define SHARE_DIR "/usr/share/facows/"

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

#define HTTP_ERR_RES "HTTP/1.1 %d %s\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n"

int net_init_ssl(SSL_CTX **ssl_ctx, const struct fws_conf *config) {
	SSL_library_init();
	const SSL_METHOD *ssl_method;
	ssl_method = TLS_server_method();
	*ssl_ctx = SSL_CTX_new(ssl_method);
	if (SSL_CTX_use_certificate_file(*ssl_ctx, config->ssl_cert, SSL_FILETYPE_PEM) <= 0) {
		printf("SSL ERROR certificate\n");
		return 1;
	}
	if (SSL_CTX_use_PrivateKey_file(*ssl_ctx, config->ssl_key, SSL_FILETYPE_PEM) <= 0) {
		printf("SSL ERROR private key\n");
		return 1;
	}
	return 0;
}

int net_init_server(int *server_fd, short port) {
	struct sockaddr_in6 server_addr;
	const int opt = 1;

	*server_fd = socket(AF_INET6, SOCK_STREAM, 0);
	setsockopt(*server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin6_family = AF_INET6;
	server_addr.sin6_addr = in6addr_any;
	server_addr.sin6_port = htons(port);

	bind(*server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr));
	listen(*server_fd, 128);
	return 0;
}

int net_read(SSL *ssl, char *dst_buf, size_t buf_size) {
	int total_read_size = 0;
	int read_ret = 0;
	while (1) {
		read_ret = SSL_read(ssl, dst_buf+total_read_size, buf_size-total_read_size-1);
		if (read_ret <= 0) {
			const int err_code = SSL_get_error(ssl, read_ret);
			if (err_code == SSL_ERROR_WANT_READ) {
				continue;
			} else if (err_code == SSL_ERROR_ZERO_RETURN) {
				return 400; // Bad Request
			}
			return 500; // Internal Server Error
		}

		total_read_size += read_ret;
		dst_buf[total_read_size] = '\0';

		if (strstr(dst_buf, "\r\n\r\n")) {
			break;
		}

		if (total_read_size >= 4095) {
			return 431; // Request Header Fields Too Large
		}
	}
	return 0;
}

int net_write(SSL *ssl, const char *path) {
	int fd = open(path, O_RDONLY);
	char file_buf[4096];
	ssize_t read_size;
	while (read_size = read(fd, file_buf, sizeof(file_buf))) {
		if (SSL_write(ssl, file_buf, read_size) <= 0) {
			return 1;
		}
	}
	close(fd);
	return 0;
}

int net_write_res(SSL *ssl, struct fws_http_res res, off_t size) {
	char res_buf[8192];
	snprintf(res_buf, sizeof(res_buf), "HTTP/1.1 %d OK\r\nContent-Type: %s\r\nContent-Length: %ld\r\nDate: %s\r\n\r\n", res.code, res.content, size, res.date);
	SSL_write(ssl, res_buf, strlen(res_buf));
	return 0;
}

int net_write_err(SSL *ssl, int code) {
	const char path_err_page[] = "error_page.html";
	char err_html[1024] = {0};
	char err_html_temp[1024] = {0};
	char res[1024] = {0};
	char v_path[1024];
	v_path[0] = '\0';
	char path[1024];
	path[0] = '\0';

	memcpy(v_path, SHARE_DIR, sizeof(SHARE_DIR)-1);
	memcpy(v_path+sizeof(SHARE_DIR)-1, path_err_page, sizeof(path_err_page));
	realpath(v_path, path);

	int fd = open(path, O_RDONLY);
	if (fd < 0) {
		return 1;
	}
	read(fd, err_html_temp, sizeof(err_html_temp));
	close(fd);

	switch (code) {
		case 400:
			snprintf(err_html, sizeof(err_html), err_html_temp, code, code, HTTP_MSG_400);
			snprintf(res, sizeof(res), HTTP_ERR_RES, code, HTTP_MSG_400, strlen(err_html));
			break;

		case 403:
			snprintf(err_html, sizeof(err_html), err_html_temp, code, code, HTTP_MSG_403);
			snprintf(res, sizeof(res), HTTP_ERR_RES, code, HTTP_MSG_403, strlen(err_html));
			break;

		case 404:
			snprintf(err_html, sizeof(err_html), err_html_temp, code, code, HTTP_MSG_404);
			snprintf(res, sizeof(res), HTTP_ERR_RES, code, HTTP_MSG_404, strlen(err_html));
			break;

		case 405:
			snprintf(err_html, sizeof(err_html), err_html_temp, code, code, HTTP_MSG_405);
			snprintf(res, sizeof(res), HTTP_ERR_RES, code, HTTP_MSG_405, strlen(err_html));
			break;

		case 414:
			snprintf(err_html, sizeof(err_html), err_html_temp, code, code, HTTP_MSG_414);
			snprintf(res, sizeof(res), HTTP_ERR_RES, code, HTTP_MSG_414, strlen(err_html));
			break;

		case 429:
			snprintf(err_html, sizeof(err_html), err_html_temp, code, code, HTTP_MSG_429);
			snprintf(res, sizeof(res), HTTP_ERR_RES, code, HTTP_MSG_429, strlen(err_html));
			break;

		case 431:
			snprintf(err_html, sizeof(err_html), err_html_temp, code, code, HTTP_MSG_431);
			snprintf(res, sizeof(res), HTTP_ERR_RES, code, HTTP_MSG_431, strlen(err_html));
			break;

		case 500:
			snprintf(err_html, sizeof(err_html), err_html_temp, code, code, HTTP_MSG_500);
			snprintf(res, sizeof(res), HTTP_ERR_RES, code, HTTP_MSG_500, strlen(err_html));
			break;

		case 501:
			snprintf(err_html, sizeof(err_html), err_html_temp, code, code, HTTP_MSG_501);
			snprintf(res, sizeof(res), HTTP_ERR_RES, code, HTTP_MSG_501, strlen(err_html));
			break;

		default:
			snprintf(err_html, sizeof(err_html), err_html_temp, code, code, HTTP_MSG_500);
			snprintf(res, sizeof(res), HTTP_ERR_RES, code, HTTP_MSG_500, strlen(err_html));
			break;
	}

	SSL_write(ssl, res, strlen(res));
	SSL_write(ssl, err_html, strlen(err_html));
	return 0;
}

void net_exit_err(SSL *ssl, int client_fd) {
	SSL_free(ssl);
	close(client_fd);
	exit(1);
}
