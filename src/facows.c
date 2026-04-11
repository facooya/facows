/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include "types.h"
#include "utils.h"
#include "conf.h"
#include "net.h"
#include "http.h"
#include "file.h"
#include "nft.h"
#include "tc.h"

#define CONF_PATH "/etc/facows/facows.conf"

struct fws_nft nft_list[1024];

void *fws_handler(void *arg) {
	const struct fws_args *args = (struct fws_args *) arg;
	const struct fws_conf *config = args->fws_conf;
	const struct sockaddr_in6 *client_addr = args->client_addr;

	int client_fd = args->fd;
	SSL_CTX *ssl_ctx = args->ssl_ctx;

	char request_buf[8192];

	SSL *ssl = SSL_new(ssl_ctx);
	SSL_set_fd(ssl, client_fd);
	if (SSL_accept(ssl) <= 0) {
		net_exit_err(ssl, client_fd, arg);
		return NULL;
	}

	while (1) {
		// { net
		if (net_read(ssl, request_buf, sizeof(request_buf)) != 0) {
			net_exit_err(ssl, client_fd, arg);
			return NULL;
		}

		struct fws_http http;
		if (http_parse(request_buf, &http, config->domain, sizeof(config->domain)) != 0) {
			net_exit_err(ssl, client_fd, arg);
			return NULL;
		}
		// }

		// { file
		struct fws_file file;
		int status_code = file_parse(&file, http.uri, sizeof(http.uri), config->web_root, sizeof(config->web_root));

		size_t path_size = fu_memclen(file.path, '\0', sizeof(file.path));
		char *path_p = file.path + path_size - (sizeof(".html") - 1);
		if (memcmp(path_p, ".html", sizeof(".html")) == 0) {
			nft_ban_dos(client_addr, nft_list, sizeof(nft_list)/sizeof(struct fws_nft));
		}

		if (status_code != 0) {
			if (net_write_err(ssl, status_code) != 0) {
				net_exit_err(ssl, client_fd, arg);
				return NULL;
			}

		} else {
			struct fws_http_res res;
			http_build_res(&res, file.path, sizeof(file.path));
			if (net_write_res(ssl, res, file.size) != 0) {
				net_exit_err(ssl, client_fd, arg);
				return NULL;
			}
			net_write(ssl, file.path);
		}
		// }
	}

	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(client_fd);
	free(arg);

	return NULL;
}

void fws_end() {
	// TODO: close server fd
	system("tc qdisc del dev ifb0 root");
	system("tc qdisc del dev eno1 ingress");
	system("ip link set dev ifb0 down");
	system("modprobe -r ifb");

	system("nft delete table netdev facows");
	system("nft delete table inet facows");
	printf("\n");
	exit(0);
}

int main() {
	// { init
	struct fws_conf config;
	if (conf_parse(CONF_PATH, &config) != 0) {
		return 0;
	}

	signal(SIGINT, fws_end);
	signal(SIGTERM, fws_end);

	nft_init(config.http_port, config.https_port);
	tc_init();

	SSL_CTX *ssl_ctx;
	net_init_ssl(&ssl_ctx, &config);

	int server_http_fd;
	net_init_server(&server_http_fd, config.http_port);

	int server_https_fd;
	net_init_server(&server_https_fd, config.https_port);

	struct pollfd fds[2];
	fds[0].fd = server_http_fd;
	fds[0].events = POLLIN;
	fds[1].fd = server_https_fd;
	fds[1].events = POLLIN;

	struct sockaddr_in6 client_addr;
	socklen_t client_addr_size = sizeof(client_addr);
	// }

	while (1) {
		poll(fds, 2, -1);

		if (fds[0].revents & POLLIN) {
			int client_http_fd = accept(server_http_fd, (struct sockaddr*)&client_addr, &client_addr_size);

			int flag = 0;
			char recv_buf[8192] = {0};
			char header_raw[] = "HTTP/1.1 301 Move permanently\r\nLocation: https://%s%s%s%s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
			char header_buf[1024] = {0};

			char port_str[7];
			port_str[0] = '\0';
			if (config.https_port != 443) {
				snprintf(port_str, sizeof(port_str), ":%hu", config.https_port);
			}

			// { recv
			int recv_size;
			int recv_total_size = 0;
			while (1) {
				recv_size = recv(client_http_fd, recv_buf, sizeof(recv_buf)-1, 0);
				if (recv_size == 0) {
					break;
				} else if (recv_size == -1) {
					flag = 1;
					break;
				}

				recv_total_size += recv_size;
				recv_buf[recv_total_size] = '\0';

				if (recv_total_size >= 8191) {
					flag = 1;
					break;
				} else if (fu_memstr(recv_buf, "\r\n\r\n", recv_total_size) != NULL) {
					break;
				}

			}
			if (flag == 1) {
				close(client_http_fd);
				continue;
			}
			// }

			// {{ http
			struct fws_http http;
			http.host[0] = '\0';
			http.uri[0] = '\0';

			// { parse uri
			const char *p1 = recv_buf;
			const char *p2 = memchr(p1, ' ', sizeof(http.method));
			size_t n;
			if (p2 == NULL) {
				close(client_http_fd);
				continue;
			}
			n = p2 - p1;
			if (n >= sizeof(http.method)) {
				close(client_http_fd);
				continue;
			}
			p1 += n + 1;
			p2 = memchr(p1, ' ', sizeof(http.uri));
			if (p2 == NULL) {
				close(client_http_fd);
				continue;
			}
			n = p2 - p1;
			if (n >= sizeof(http.uri)) {
				close(client_http_fd);
				continue;
			}
			memcpy(http.uri, p1, n);
			http.uri[n] = '\0';
			// }

			// { parse host
			flag = 0;
			p1 = recv_buf;
			p2 = fu_memstr(p1, "\r\n", 1024);
			if (p2 == NULL) {
				close(client_http_fd);
				continue;
			}
			p1 = p2 + 2;

			while (1) {
				if (memcmp(p1, "\r\n", sizeof("\r\n")-1) == 0) {
					break;
				}

				if (memcmp(p1, "Host", fu_memclen("host", '\0', sizeof("host"))) == 0) {
					if (http.host[0] != '\0') {
						flag = 1;
						break;
					}

					p2 = memchr(p1, ':', 64);
					if (p2 == NULL) {
						flag = 1;
						break;
					}
					p1 = p2 + 1;
					while (*p1 == ' ') {
						p1++;
					}

					if (memcmp(p1, config.domain, fu_memclen(config.domain, '\0', sizeof(config.domain))) == 0) {
						memcpy(http.host, "www", sizeof("www"));
					} else {
						p2 = p1;
						for (size_t i=0; i<sizeof(http.host); i++) {
							if (p2[i] == '.') {
								p2 += i;
								break;
							}
						}

						n = p2 - p1;
						memcpy(http.host, p1, n);
						http.host[n] = '\0';
					}
					break;
				}

				p2 = fu_memstr(p1, "\r\n", 1024);
				if (p2 == NULL) {
					flag = 1;
					break;
				}
				p1 = p2 + 2;

			}
			if (flag) {
				close(client_http_fd);
				continue;
			}
			// }
			// }}

			printf("%s, %s\n", http.host, http.uri);
			n = fu_memclen(http.host, '\0', sizeof(http.host));
			http.host[n] = '.';
			http.host[n+1] = '\0';

			snprintf(header_buf, sizeof(header_buf), header_raw, http.host, config.domain, port_str, http.uri);
			send(client_http_fd, header_buf, strlen(header_buf), 0);

			close(client_http_fd);

		} else if (fds[1].revents & POLLIN) {
			int client_fd = accept(server_https_fd, (struct sockaddr*)&client_addr, &client_addr_size);

			struct fws_args *args = malloc(sizeof(struct fws_args));
			args->fd = client_fd;
			args->ssl_ctx = ssl_ctx;
			args->fws_conf = &config;
			args->client_addr = &client_addr;
	
			pthread_t thread;
			pthread_create(&thread, NULL, fws_handler, (void*)args);
			pthread_detach(thread);
		}
	}

	close(server_http_fd);
	close(server_https_fd);
	fws_end();
	return 0;
}
