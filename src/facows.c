/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include <stdio.h>
#include <stdlib.h>
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
#include "net.h"
#include "file.h"

#define CONF_PATH "/etc/facows/facows.conf"
#define USER_WWW_DATA "www-data"
#define USER_APACHE "apache"
#define USER_HTTP "http"
#define USER_NOBODY "nobody"

pthread_mutex_t nft_lock = {0};

volatile sig_atomic_t fws_flag = -1;
struct fws_nft nft_list[1024] = {0};

static void *_fws_thread_run(void *arg);
static void _fws_exit(int sig);

int main() {
	int pipe_fd[2] = {-1, -1};
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

	SSL_CTX *ssl_ctx = NULL;
	net_443_init(&ssl_ctx, &config);

	if ((server_http_fd = net_server_init(config.http_port)) < 0) {
		ret = 1;
		goto out;
	}
	if ((server_https_fd = net_server_init(config.https_port)) < 0) {
		ret = 1;
		goto out;
	}

	if (pipe(pipe_fd) < 0) {
		fprintf(stderr, "pipe failed\n");
		ret = 1;
		goto out;
	}

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

		if (pipe_fd[0] >= 0) {
			close(pipe_fd[0]);
			pipe_fd[0] = -1;
		}

		struct pollfd fws_fd[2];
		fws_fd[0].fd = server_http_fd;
		fws_fd[0].events = POLLIN;
		fws_fd[1].fd = server_https_fd;
		fws_fd[1].events = POLLIN;

		struct sockaddr_in6 client_addr;
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
				args->write_fd = pipe_fd[1];
				args->ssl_ctx = ssl_ctx;
				args->fws_conf = &config;
				args->client_addr = &client_addr;

				pthread_t fws_thread;
				pthread_create(&fws_thread, NULL, _fws_thread_run, (void*)args);
				pthread_detach(fws_thread);
			}
		}

		ret = 0;
c_out:
		if (nft_lock_flag >= 0) {
			pthread_mutex_destroy(&nft_lock);
			nft_lock_flag = -1;
		}
		if (server_http_fd >= 0) {
			close(server_http_fd);
			server_http_fd = -1;
		}
		if (server_https_fd >= 0) {
			close(server_https_fd);
			server_https_fd = -1;
		}
		if (pipe_fd[0] >= 0) {
			close(pipe_fd[0]);
			pipe_fd[0] = -1;
		}
		if (pipe_fd[1] >= 0) {
			close(pipe_fd[1]);
			pipe_fd[1] = -1;
		}
		_exit(ret);

	} else {
		if (pipe_fd[1] >= 0) {
			close(pipe_fd[1]);
			pipe_fd[1] = -1;
		}

		struct nft_ctx *nft_ctx = NULL;
		nft_ctx = nft_ctx_new(NFT_CTX_DEFAULT);
		if (nft_ctx == NULL) {
			fprintf(stderr, "nft context allocation error\n");
			ret = 1;
			goto p_out;
		}

		struct pollfd nft_fd;
		nft_fd.fd = pipe_fd[0];
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

		if (pipe_fd[0] >= 0) {
			close(pipe_fd[0]);
			pipe_fd[0] = -1;
		}

		waitpid(pid, NULL, 0);
		if (config.nft == 1) {
			net_nft_fini();
		}

		ret = 0;
p_out:
		nft_ctx_free(nft_ctx);
		nft_ctx = NULL;
		if (pipe_fd[0] >= 0) {
			close(pipe_fd[0]);
			pipe_fd[0] = -1;
		}
		if (pipe_fd[1] >= 0) {
			close(pipe_fd[1]);
			pipe_fd[1] = -1;
		}
		goto out;
	}

	ret = 0;
out:
	SSL_CTX_free(ssl_ctx);
	ssl_ctx = NULL;
	if (server_http_fd >= 0) {
		close(server_http_fd);
		server_http_fd = -1;
	}
	if (server_https_fd >= 0) {
		close(server_https_fd);
		server_https_fd = -1;
	}
	if (pipe_fd[0] >= 0) {
		close(pipe_fd[0]);
		pipe_fd[0] = -1;
	}
	if (pipe_fd[1] >= 0) {
		close(pipe_fd[1]);
		pipe_fd[1] = -1;
	}
	return ret;
}

static void *_fws_thread_run(void *arg) {
	const struct fws_args *args = (struct fws_args *) arg;
	const struct fws_conf *config = args->fws_conf;
	const struct sockaddr_in6 *client_addr = args->client_addr;

	int client_fd = args->fd;
	int write_fd = args->write_fd;
	SSL_CTX *ssl_ctx = args->ssl_ctx;

	SSL *ssl = NULL;

	int ssl_flag = 1;
	char request_buf[8192];

	ssl = SSL_new(ssl_ctx);
	if (ssl == NULL) {
		ssl_flag = -1;
		goto out;
	}

	SSL_set_fd(ssl, client_fd);
	if (SSL_accept(ssl) <= 0) {
		ssl_flag = -1;
		goto out;
	}

	while (1) {
		if (net_443_read(ssl, request_buf, sizeof(request_buf)) != 0) {
			ssl_flag = -1;
			goto out;
		}

		struct fws_http_req http;
		if (net_http_req_parse(request_buf, &http, config->domain, sizeof(config->domain)) != 0) {
			ssl_flag = -1;
			goto out;
		}

		struct fws_file file;
		int status_code = file_parse(&file, &http, config->web_root, sizeof(config->web_root));

		if (status_code == 301) {
			net_http_path_redir(&http, config, &file, ssl);
			ssl_flag = -1;
			goto out;
		}

		if (config->nft == 1) {
			size_t path_size = fac_memclen(file.path, '\0', sizeof(file.path));
			char *path_p = file.path + path_size - (sizeof(".html") - 1);
			if (memcmp(path_p, ".html", sizeof(".html")) == 0) {
				pthread_mutex_lock(&nft_lock);
				net_nft_dos_ip_send(client_addr, nft_list, write_fd, sizeof(nft_list)/sizeof(nft_list[0]));
				pthread_mutex_unlock(&nft_lock);
			}
		}

		if (status_code != 0) {
			if (net_443_err_write(ssl, status_code) != 0) {
				ssl_flag = -1;
				goto out;
			}

		} else {
			struct fws_http_res http_res;
			net_http_res_build(&http_res, file.path, sizeof(file.path));
			if (net_443_res_write(ssl, &http_res, file.size) != 0) {
				ssl_flag = -1;
				goto out;
			}
			net_443_write(ssl, file.path);
		}
	}

out:
	if (ssl_flag >= 0) {
		SSL_shutdown(ssl);
		ssl_flag = -1;
	}
	SSL_free(ssl);
	ssl = NULL;
	if (client_fd >= 0) {
		close(client_fd);
		client_fd = -1;
	}
	free(arg);
	arg = NULL;

	return NULL;
}

static void _fws_exit(int sig) {
	fws_flag = sig;
}
