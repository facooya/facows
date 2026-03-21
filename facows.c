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

#define CONF_FILE "/etc/facows/facows.conf"
#define SHARE_DIR "/usr/share/facows/"

#define PATH_MAX 512

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

int http_build_path(char *path, char *http_path, char *web_root) {
	char v_path[PATH_MAX];
	strcpy(v_path, web_root);
	strcat(v_path, http_path);
	realpath(v_path, path);

	if (strlen(path) > PATH_MAX-1) {
		// warn
		return 2;
	}

	size_t web_root_size = strlen(web_root);
	if (strlen(path)+1 == web_root_size) {
		size_t size = strlen(path);
		path[size] = '/';
		path[size+1] = '\0';
	}

	if (strncmp(path, web_root, web_root_size) != 0) {
		// attack
		return 1;
	}

	return 0;
}

int respone_build_path(char *path, size_t *size) {
	struct stat st;
	if (stat(path, &st) != 0) {
		const char html_str[] = ".html";
		strcat(path, html_str);
		if (stat(path, &st) != 0) {
			// warn log
			return 404;
		}
	}
	*size = st.st_size;

	const char index_str[] = "index.html";
	if (S_ISDIR(st.st_mode) == 1) {
		strcat(path, index_str);
		if (stat(path, &st) == 0) {
			*size = st.st_size;
		} else {
			// warn log
			return 404;
		}
	}

	return 0;
}

int respone_send_status(SSL *ssl, char *path, size_t file_size) {
	char time_buf[64];
	time_t raw_time;
	time(&raw_time);
	struct tm *time_info;
	time_info = gmtime(&raw_time);
	strftime(time_buf, sizeof(time_buf), "%a, %d %b %Y %H:%M:%S GMT", time_info);

	char status[1024] = {0};
	if (memmem(path, 512, ".html", 5) != NULL) {
		snprintf(status, sizeof(status), "HTTP/1.1 200 OK\r\nKeep-Alive: timeout=1\r\nContent-Type: text/html\r\nContent-Length: %ld\r\n\r\n", file_size);
	} else if (memmem(path, 512, ".css", 4) != NULL) {
		snprintf(status, sizeof(status), "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nKeep-Alive: timeout=1\r\nContent-Type: text/css\r\nContent-Length: %ld\r\nDate: %s\r\n\r\n", file_size, time_buf);
	} else if (memmem(path, 512, ".svg", 4) != NULL) {
		snprintf(status, sizeof(status), "HTTP/1.1 200 OK\r\nContent-Type: image/svg+xml\r\nContent-Length: %ld\r\n\r\n", file_size);
	} else if (memmem(path, 512, ".php", 4) != NULL) {
		snprintf(status, sizeof(status), "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %ld\r\n\r\n", file_size);
	} else {
		return 1;
	}
	SSL_write(ssl, status, strlen(status));

	return 0;
}

int main() {
	// { init
	struct config config;
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
				struct http http = {0};
				if (http_parse(request_buf, &http, config.domain) != 0) {
					net_exit_err(ssl, client_fd);
				}
				printf("HTTP: %s, %s, %s, %s, %s, %s, %s\n", http.method, http.path, http.version, http.host, http.lang, http.browser, http.os);
				// }

				// { http_build_path()
				char path[512];
				if (http_build_path(path, http.path, config.web_root) != 0) {
					net_exit_err(ssl, client_fd);
				}
				// }

				size_t file_size = 0;
				int status_code = respone_build_path(path, &file_size);
				if (status_code != 0) {
					char err_html_temp[1024] = {0};
					char err_html[1024] = {0};
					char status[1024] = {0};
					char v_path[512];
					const char path_err_page[] = "error_page.html";

					strncpy(v_path, SHARE_DIR, sizeof(SHARE_DIR)-1);
					strcat(v_path, path_err_page);
					realpath(v_path, path);

					int fd = open(path, O_RDONLY);
					if (fd < 0) {
						// internal server err
						net_exit_err(ssl, client_fd);
					}
					read(fd, err_html_temp, sizeof(err_html_temp));
					close(fd);

					switch (status_code) {
						case 400:
							snprintf(err_html, sizeof(err_html), err_html_temp, status_code, status_code, HTTP_MSG_400);
							file_size = strlen(err_html);
							snprintf(status, sizeof(status), HTTP_STATUS, status_code, HTTP_MSG_400, file_size);
							break;

						case 403:
							snprintf(err_html, sizeof(err_html), err_html_temp, status_code, status_code, HTTP_MSG_403);
							file_size = strlen(err_html);
							snprintf(status, sizeof(status), HTTP_STATUS, status_code, HTTP_MSG_403, file_size);
							break;

						case 404:
							snprintf(err_html, sizeof(err_html), err_html_temp, status_code, status_code, HTTP_MSG_404);
							file_size = strlen(err_html);
							snprintf(status, sizeof(status), HTTP_STATUS, status_code, HTTP_MSG_404, file_size);
							break;

						case 405:
							snprintf(err_html, sizeof(err_html), err_html_temp, status_code, status_code, HTTP_MSG_405);
							file_size = strlen(err_html);
							snprintf(status, sizeof(status), HTTP_STATUS, status_code, HTTP_MSG_405, file_size);
							break;

						case 414:
							snprintf(err_html, sizeof(err_html), err_html_temp, status_code, status_code, HTTP_MSG_414);
							file_size = strlen(err_html);
							snprintf(status, sizeof(status), HTTP_STATUS, status_code, HTTP_MSG_414, file_size);
							break;

						case 429:
							snprintf(err_html, sizeof(err_html), err_html_temp, status_code, status_code, HTTP_MSG_429);
							file_size = strlen(err_html);
							snprintf(status, sizeof(status), HTTP_STATUS, status_code, HTTP_MSG_414, file_size);
							break;


						case 431:
							snprintf(err_html, sizeof(err_html), err_html_temp, status_code, status_code, HTTP_MSG_431);
							file_size = strlen(err_html);
							snprintf(status, sizeof(status), HTTP_STATUS, status_code, HTTP_MSG_431, file_size);
							break;

						case 500:
							snprintf(err_html, sizeof(err_html), err_html_temp, status_code, status_code, HTTP_MSG_500);
							file_size = strlen(err_html);
							snprintf(status, sizeof(status), HTTP_STATUS, status_code, HTTP_MSG_500, file_size);
							break;

						case 501:
							snprintf(err_html, sizeof(err_html), err_html_temp, status_code, status_code, HTTP_MSG_501);
							file_size = strlen(err_html);
							snprintf(status, sizeof(status), HTTP_STATUS, status_code, HTTP_MSG_501, file_size);
							break;

						default:
							snprintf(err_html, sizeof(err_html), err_html_temp, status_code, status_code, HTTP_MSG_500);
							file_size = strlen(err_html);
							snprintf(status, sizeof(status), HTTP_STATUS, status_code, HTTP_MSG_500, file_size);
							break;
					}

					SSL_write(ssl, status, strlen(status));
					SSL_write(ssl, err_html, strlen(err_html));

					SSL_free(ssl);
					close(client_fd);
					exit(0);
				}

				if (respone_send_status(ssl, path, file_size) != 0) {
					// warn log
					net_exit_err(ssl, client_fd);
				}
				net_write(ssl, path);
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
