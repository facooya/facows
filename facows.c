/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>
#include <fcntl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "types.h"
#include "conf.h"
#include "net.h"
#include "http.h"
#include "file.h"

#define CONF_FILE "/etc/facows/facows.conf"
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

#define HTTP_STATUS "HTTP/1.1 %d %s\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n"

struct BlackList {
	uint8_t ip[16];
	time_t time;
};

int respone_send_status(SSL *ssl, char *path, size_t file_size) {
	char time_buf[64];
	time_t raw_time;
	time(&raw_time);
	struct tm *time_info;
	time_info = gmtime(&raw_time);
	strftime(time_buf, sizeof(time_buf), "%a, %d %b %Y %H:%M:%S GMT", time_info);

	char status[1024] = {0};
	const char *p1 = path;
	const char *p2;
	while (1) {
		p2 = memchr(p1, '.', strlen(p1));
		if (p2 == NULL) {
			break;
		}
		p1 = p2 + 1;
	}

	if (strncmp(p1, "html", sizeof("html")) == 0) {
		snprintf(status, sizeof(status), "HTTP/1.1 200 OK\r\nKeep-Alive: timeout=1\r\nContent-Type: text/html\r\nContent-Length: %ld\r\n\r\n", file_size);
	} else if (strncmp(p1, "css", sizeof("css")) == 0) {
		snprintf(status, sizeof(status), "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nKeep-Alive: timeout=1\r\nContent-Type: text/css\r\nContent-Length: %ld\r\nDate: %s\r\n\r\n", file_size, time_buf);
	} else if (strncmp(p1, "svg", sizeof("svg")) == 0) {
		snprintf(status, sizeof(status), "HTTP/1.1 200 OK\r\nContent-Type: image/svg+xml\r\nContent-Length: %ld\r\n\r\n", file_size);
	} else if (strncmp(p1, "php", sizeof("php")) == 0) {
		snprintf(status, sizeof(status), "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %ld\r\n\r\n", file_size);
	} else {
		return 1;
	}
	SSL_write(ssl, status, strlen(status));

	return 0;
}

int main() {
	// { init
	struct fws_conf config;
	if (conf_parse(CONF_FILE, &config) != 0) {
		// conf err
		return 0;
	}

	struct BlackList black_list[1024];
	char request_buf[4096];
	char log[1024];
	signal(SIGCHLD, SIG_IGN);

	SSL_CTX *ssl_ctx;
	net_init_ssl(&ssl_ctx, &config);

	int server_fd;
	net_init_server(&server_fd, config.port);

	int client_fd;
	struct sockaddr_in6 client_addr;
	socklen_t client_addr_size = sizeof(client_addr);
	// }

	while (1) {
		client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_addr_size);
		pid_t pid = fork();

		if (pid == 0) {
			// { init
			close(server_fd);
			SSL *ssl = SSL_new(ssl_ctx);
			SSL_set_fd(ssl, client_fd);
			if (SSL_accept(ssl) <= 0) {
				net_exit_err(ssl, client_fd);
			}
			// }

			// { ip
			time_t raw_time;
			time(&raw_time);

			char ip_buf[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, client_addr.sin6_addr.s6_addr, ip_buf, sizeof(ip_buf));
			memcpy(black_list[0].ip, client_addr.sin6_addr.s6_addr, 16);
			black_list[0].time = raw_time;

			printf("IP: %s\n", ip_buf);
			// }

			while (1) {
				// { net_read()
				if (net_read(ssl, request_buf, sizeof(request_buf)) != 0) {
					net_exit_err(ssl, client_fd);
				}
				// }

				// { http_parse()
				struct fws_http http;
				if (http_parse(request_buf, &http, config.domain) != 0) {
					net_exit_err(ssl, client_fd);
				}
				// }

				// { file_parse()
				struct fws_file file;
				int status_code = file_parse(&file, http.uri, config.web_root);
				// }

				if (status_code != 0) {
					char err_html_temp[1024] = {0};
					char err_html[1024] = {0};
					char status[1024] = {0};
					char v_path[512];
					const char path_err_page[] = "error_page.html";

					strncpy(v_path, SHARE_DIR, sizeof(SHARE_DIR)-1);
					strcat(v_path, path_err_page);
					realpath(v_path, file.path);

					int fd = open(file.path, O_RDONLY);
					if (fd < 0) {
						// internal server err
						net_exit_err(ssl, client_fd);
					}
					read(fd, err_html_temp, sizeof(err_html_temp));
					close(fd);

					switch (status_code) {
						case 400:
							snprintf(err_html, sizeof(err_html), err_html_temp, status_code, status_code, HTTP_MSG_400);
							file.size = strlen(err_html);
							snprintf(status, sizeof(status), HTTP_STATUS, status_code, HTTP_MSG_400, file.size);
							break;

						case 403:
							snprintf(err_html, sizeof(err_html), err_html_temp, status_code, status_code, HTTP_MSG_403);
							file.size = strlen(err_html);
							snprintf(status, sizeof(status), HTTP_STATUS, status_code, HTTP_MSG_403, file.size);
							break;

						case 404:
							snprintf(err_html, sizeof(err_html), err_html_temp, status_code, status_code, HTTP_MSG_404);
							file.size = strlen(err_html);
							snprintf(status, sizeof(status), HTTP_STATUS, status_code, HTTP_MSG_404, file.size);
							break;

						case 405:
							snprintf(err_html, sizeof(err_html), err_html_temp, status_code, status_code, HTTP_MSG_405);
							file.size = strlen(err_html);
							snprintf(status, sizeof(status), HTTP_STATUS, status_code, HTTP_MSG_405, file.size);
							break;

						case 414:
							snprintf(err_html, sizeof(err_html), err_html_temp, status_code, status_code, HTTP_MSG_414);
							file.size = strlen(err_html);
							snprintf(status, sizeof(status), HTTP_STATUS, status_code, HTTP_MSG_414, file.size);
							break;

						case 429:
							snprintf(err_html, sizeof(err_html), err_html_temp, status_code, status_code, HTTP_MSG_429);
							file.size = strlen(err_html);
							snprintf(status, sizeof(status), HTTP_STATUS, status_code, HTTP_MSG_414, file.size);
							break;


						case 431:
							snprintf(err_html, sizeof(err_html), err_html_temp, status_code, status_code, HTTP_MSG_431);
							file.size = strlen(err_html);
							snprintf(status, sizeof(status), HTTP_STATUS, status_code, HTTP_MSG_431, file.size);
							break;

						case 500:
							snprintf(err_html, sizeof(err_html), err_html_temp, status_code, status_code, HTTP_MSG_500);
							file.size = strlen(err_html);
							snprintf(status, sizeof(status), HTTP_STATUS, status_code, HTTP_MSG_500, file.size);
							break;

						case 501:
							snprintf(err_html, sizeof(err_html), err_html_temp, status_code, status_code, HTTP_MSG_501);
							file.size = strlen(err_html);
							snprintf(status, sizeof(status), HTTP_STATUS, status_code, HTTP_MSG_501, file.size);
							break;

						default:
							snprintf(err_html, sizeof(err_html), err_html_temp, status_code, status_code, HTTP_MSG_500);
							file.size = strlen(err_html);
							snprintf(status, sizeof(status), HTTP_STATUS, status_code, HTTP_MSG_500, file.size);
							break;
					}

					SSL_write(ssl, status, strlen(status));
					SSL_write(ssl, err_html, strlen(err_html));

					SSL_free(ssl);
					close(client_fd);
					exit(0);
				}

				struct fws_http_res res;
				http_build_res(&res, file.path);
				printf("RES: %s, %d", res.content, res.code);
				//if (net_write_header(ssl, res, file.size) != 0) {
					//net_exit_err(ssl, client_fd);
				//}
				if (respone_send_status(ssl, file.path, file.size) != 0) {
					// warn log
					net_exit_err(ssl, client_fd);
				}
				net_write(ssl, file.path);
			}

			SSL_shutdown(ssl);
			SSL_free(ssl);
			close(client_fd);
			exit(0);

		} else if (pid > 0) {
			close(client_fd);
		} else {
			close(client_fd);
		}
	}

	close(server_fd);
	return 0;
}
