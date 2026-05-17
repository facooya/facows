/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <unistd.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <nftables/libnftables.h>

#include "fac_utils.h"
#include "types.h"
#include "fws.h"
#include "net.h"
#include "file.h"

#define CONF_PATH "/etc/facows/facows.conf"
#define USER_WWW_DATA "www-data"
#define USER_APACHE "apache"
#define USER_HTTP "http"
#define USER_NOBODY "nobody"

pthread_mutex_t nft_lock = {0};
volatile sig_atomic_t fws_flag = -1;
atomic_int fws_thread_n = 0;

static void _fws_exit(int sig);

int main() {
	SSL_CTX *ssl_ctx = NULL;
	int pipe_fd[2] = {-1, -1};
	int pipe_read_fd = -1;
	int pipe_write_fd = -1;
	int server_http_fd = -1;
	int server_https_fd = -1;

	int ret = 0;

	signal(SIGINT, _fws_exit);
	signal(SIGTERM, _fws_exit);

	struct fws_conf config = {0};
	if (file_conf_read(&config, CONF_PATH) != 0) {
		ret = 1;
		goto out;
	}

	if (config.nft == 1) {
		if (net_nft_init(&config) < 0) {
			return 1;
		}
	}

	net_443_init(&ssl_ctx, &config);

	if ((server_http_fd = net_server_init(config.http_port)) < 0) {
		fprintf(stderr, "http socket failed\n");
		ret = 1;
		goto out;
	}
	if ((server_https_fd = net_server_init(config.https_port)) < 0) {
		fprintf(stderr, "https socket failed\n");
		ret = 1;
		goto out;
	}

	if (pipe(pipe_fd) < 0) {
		fprintf(stderr, "pipe failed\n");
		ret = 1;
		goto out;
	}
	pipe_read_fd = pipe_fd[0];
	pipe_write_fd = pipe_fd[1];

	const pid_t pid = fork();
	if (pid < 0) {
		fprintf(stderr, "fork failed\n");
		ret = 1;
		goto out;
	}

	if (pid == 0) {
		int nft_lock_flag = -1;
		struct passwd *pw = NULL;
		const char *user_name[] = {USER_WWW_DATA, USER_APACHE, USER_HTTP, USER_NOBODY};
		for (size_t i=0; i<(sizeof(user_name)/sizeof(user_name[0])); i++) {
			if ((pw = getpwnam(user_name[i])) != NULL) {
				break;
			}
			if ((i+1) == (sizeof(user_name)/sizeof(user_name[0]))) {
				fprintf(stderr, "user not found\n");
				ret = 1;
				goto c_out;
			}
		}

		if (setgid(pw->pw_gid) != 0) {
			fprintf(stderr, "set group failed\n");
			ret = 1;
			goto c_out;
		}
		if (setuid(pw->pw_uid) != 0) {
			fprintf(stderr, "set user failed\n");
			ret = 1;
			goto c_out;
		}

		if (pipe_read_fd >= 0) {
			close(pipe_read_fd);
			pipe_read_fd = -1;
		}

		struct pollfd fws_fd[2];
		fws_fd[0].fd = server_http_fd;
		fws_fd[0].events = POLLIN;
		fws_fd[1].fd = server_https_fd;
		fws_fd[1].events = POLLIN;

		struct sockaddr_in6 client_addr = {0};
		socklen_t client_addr_size = sizeof(client_addr);
		if (pthread_mutex_init(&nft_lock, NULL) != 0) {
			fprintf(stderr, "mutex init failed\n");
			ret = 1;
			goto c_out;
		}
		nft_lock_flag = 1;
		printf("Facows start\n");

		while (1) {
			if (poll(fws_fd, 2, -1) < 0 && (fws_flag == SIGINT || fws_flag == SIGTERM)) {
				break;
			}

			if ((fws_fd[0].revents & POLLIN) != 0) {
				int client_http_fd = accept(server_http_fd, (struct sockaddr*)&client_addr, &client_addr_size);

				if (net_80_443_redir(client_http_fd, &config) < 0) {
					if (client_http_fd >= 0) {
						close(client_http_fd);
						client_http_fd = -1;
					}
					continue;
				}

				if (client_http_fd >= 0) {
					close(client_http_fd);
					client_http_fd = -1;
				}

			} else if ((fws_fd[1].revents & POLLIN) != 0) {
				int client_fd = accept(server_https_fd, (struct sockaddr*)&client_addr, &client_addr_size);

				struct fws_args *args = malloc(sizeof(struct fws_args));
				if (args == NULL) {
					ret = 1;
					goto c_out;
				}
				args->fd = client_fd;
				args->write_fd = pipe_write_fd;
				args->ssl_ctx = ssl_ctx;
				args->client_addr = client_addr;
				args->fws_conf = &config;
				args->fws_thread_n = &fws_thread_n;
				args->nft_lock = &nft_lock;

				fws_thread_n++;
				pthread_t fws_thread;
				pthread_create(&fws_thread, NULL, fws_thread_run, (void*)args);
				pthread_detach(fws_thread);
			}
		}

		ret = 0;
c_out:
		struct timespec thread_ts = {0};
		thread_ts.tv_sec = 0;
		thread_ts.tv_nsec = 100000000;
		while (fws_thread_n > 0) {
			nanosleep(&thread_ts, NULL);
		}

		if (nft_lock_flag >= 0) {
			pthread_mutex_destroy(&nft_lock);
			nft_lock_flag = -1;
		}
		if (pipe_read_fd >= 0) {
			close(pipe_read_fd);
			pipe_read_fd = -1;
		}
		if (pipe_write_fd >= 0) {
			close(pipe_write_fd);
			pipe_write_fd = -1;
		}
		if (server_http_fd >= 0) {
			close(server_http_fd);
			server_http_fd = -1;
		}
		if (server_https_fd >= 0) {
			close(server_https_fd);
			server_https_fd = -1;
		}
		_exit(ret);

	} else {
		if (pipe_write_fd >= 0) {
			close(pipe_write_fd);
			pipe_write_fd = -1;
		}

		struct nft_ctx *nft_ctx = NULL;
		nft_ctx = nft_ctx_new(NFT_CTX_DEFAULT);
		if (nft_ctx == NULL) {
			fprintf(stderr, "nft context allocation error\n");
			ret = 1;
			goto p_out;
		}

		struct pollfd nft_fd;
		nft_fd.fd = pipe_read_fd;
		nft_fd.events = POLLIN | POLLHUP | POLLERR;

		while (1) {
			errno = 0;
			if (poll(&nft_fd, 1, -1) < 0) {
				if (errno == EINTR && (fws_flag == SIGINT || fws_flag == SIGTERM)) {
					break;
				}
				fprintf(stderr, "poll error\n");
				ret = 1;
				goto p_out;
			}

			if ((nft_fd.revents & (POLLIN|POLLHUP|POLLERR)) != 0) {
				char ip_buf[INET6_ADDRSTRLEN] = {0};
				if (read(nft_fd.fd, ip_buf, INET6_ADDRSTRLEN) <= 0) {
					break;
				} else {
					net_nft_dos_ban(nft_ctx, ip_buf, config.ban_time);
				}
			}
		}

		if (pipe_read_fd >= 0) {
			close(pipe_read_fd);
			pipe_read_fd = -1;
		}

		waitpid(pid, NULL, 0);
		if (config.nft == 1) {
			net_nft_fini();
		}

		ret = 0;
p_out:
		nft_ctx_free(nft_ctx);
		nft_ctx = NULL;
		if (pipe_read_fd >= 0) {
			close(pipe_read_fd);
			pipe_read_fd = -1;
		}
		if (pipe_write_fd >= 0) {
			close(pipe_write_fd);
			pipe_write_fd = -1;
		}
		goto out;
	}

	ret = 0;
out:
	SSL_CTX_free(ssl_ctx);
	ssl_ctx = NULL;
	if (pipe_read_fd >= 0) {
		close(pipe_read_fd);
		pipe_read_fd = -1;
	}
	if (pipe_write_fd >= 0) {
		close(pipe_write_fd);
		pipe_write_fd = -1;
	}
	if (server_http_fd >= 0) {
		close(server_http_fd);
		server_http_fd = -1;
	}
	if (server_https_fd >= 0) {
		close(server_https_fd);
		server_https_fd = -1;
	}
	return ret;
}

static void _fws_exit(int sig) {
	fws_flag = sig;
}
