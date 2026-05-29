/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include "factype.h"
#include "fac_utils.h"
#include "types.h"
#include "net.h"
#include "file.h"
#include "fws.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <pthread.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <nftables/libnftables.h>

#define USER_WWW_DATA "www-data"
#define USER_APACHE "apache"
#define USER_HTTP "http"
#define USER_NOBODY "nobody"

struct fws_nft nft_table_a[1024] = {0};
struct fws_nft nft_table_b[1024] = {0};

struct fws_nft *nft_table = nft_table_a;
struct fws_nft *nft_table_swap = nft_table_b;

static void *_fws_thread_run(void *thread_args);
static void *_fws_swap_thread_run(void *swap_ctx_opq);
static void _fws_swap_run(struct fws_swap_ctx *swap_ctx);

void fws_child_run(struct fws_child_ctx *child_ctx) {
	SSL_CTX *ssl_ctx = FAC_NULL;
	struct passwd *pw = FAC_NULL;
	I32 server_http_fd = -1;
	I32 server_https_fd = -1;
	I32 client_http_fd = -1;
	I32 client_fd = -1;

	I32 ret = 0;
	I32 nft_lock_flag = -1;
	_Atomic I32 fws_thread_n = 0;
	struct timespec thread_ts = {0};
	pthread_mutex_t nft_lock = {0};

	net_443_init((U8**)&ssl_ctx, child_ctx->conf);

	if ((server_http_fd = net_server_init(child_ctx->conf->http_port)) < 0) {
		fprintf(stderr, "http socket failed\n");
		ret = 1;
		goto out;
	}
	if ((server_https_fd = net_server_init(child_ctx->conf->https_port)) < 0) {
		fprintf(stderr, "https socket failed\n");
		ret = 1;
		goto out;
	}

	const C8 *user_name[] = {USER_WWW_DATA, USER_APACHE, USER_HTTP, USER_NOBODY};
	for (U64 i=0; i<(sizeof(user_name)/sizeof(user_name[0])); i++) {
		if ((pw = getpwnam(user_name[i])) != FAC_NULL) {
			break;
		}
		if ((i+1) == (sizeof(user_name)/sizeof(user_name[0]))) {
			fprintf(stderr, "user not found\n");
			ret = 1;
			goto out;
		}
	}

	if (setgid(pw->pw_gid) != 0) {
		fprintf(stderr, "set group failed\n");
		ret = 1;
		goto out;
	}
	if (setuid(pw->pw_uid) != 0) {
		fprintf(stderr, "set user failed\n");
		ret = 1;
		goto out;
	}

	if (child_ctx->pipe_read_fd >= 0) {
		close(child_ctx->pipe_read_fd);
		child_ctx->pipe_read_fd = -1;
	}

	assert(server_http_fd >= 0 && server_https_fd >= 0);
	struct pollfd fws_fd[2];
	fws_fd[0].fd = server_http_fd;
	fws_fd[0].events = POLLIN;
	fws_fd[1].fd = server_https_fd;
	fws_fd[1].events = POLLIN;

	struct sockaddr_in6 client_addr = {0};
	socklen_t client_addr_size = sizeof(client_addr);
	if (pthread_mutex_init(&nft_lock, FAC_NULL) != 0) {
		fprintf(stderr, "mutex init failed\n");
		ret = 1;
		goto out;
	}
	nft_lock_flag = 1;

	struct fws_swap_ctx *swap_ctx = malloc(sizeof(struct fws_swap_ctx));
	swap_ctx->nft_table = nft_table;
	swap_ctx->nft_table_swap = nft_table_swap;
	pthread_t fws_swap_thread;
	pthread_create(&fws_swap_thread, FAC_NULL, _fws_swap_thread_run, swap_ctx);
	pthread_detach(fws_swap_thread);

	assert(child_ctx->fws_flag != FAC_NULL);
	printf("Facows start\n");
	while (1) {
		if (poll(fws_fd, 2, -1) < 0 && (*child_ctx->fws_flag == SIGINT || *child_ctx->fws_flag == SIGTERM)) {
			break;
		}

		if ((fws_fd[0].revents & POLLIN) != 0) {
			client_http_fd = accept(server_http_fd, (struct sockaddr*)&client_addr, &client_addr_size);

			if (net_80_443_redir(client_http_fd, child_ctx->conf) < 0) {
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
			client_fd = accept(server_https_fd, (struct sockaddr*)&client_addr, &client_addr_size);

			struct fws_thread_ctx *thread_ctx = malloc(sizeof(struct fws_thread_ctx));
			if (thread_ctx == FAC_NULL) {
				ret = 1;
				goto out;
			}
			memset(thread_ctx, 0, sizeof(struct fws_thread_ctx));
			memcpy(thread_ctx->client_ip, client_addr.sin6_addr.s6_addr, sizeof(client_addr.sin6_addr.s6_addr));
			thread_ctx->fd = client_fd;
			thread_ctx->write_fd = child_ctx->pipe_write_fd;
			thread_ctx->ssl_ctx_opq = (U8 *) ssl_ctx;
			thread_ctx->fws_conf = child_ctx->conf;
			thread_ctx->fws_thread_n = &fws_thread_n;
			thread_ctx->nft_lock_opq = (U8 *) &nft_lock;

			fws_thread_n++;
			pthread_t fws_thread;
			pthread_create(&fws_thread, FAC_NULL, _fws_thread_run, (void*)thread_ctx);
			pthread_detach(fws_thread);
		}
	}

	ret = 0;
out:
	thread_ts.tv_sec = 0;
	thread_ts.tv_nsec = 100000000;
	while (fws_thread_n > 0) {
		nanosleep(&thread_ts, FAC_NULL);
	}

	SSL_CTX_free(ssl_ctx);
	ssl_ctx = FAC_NULL;
	if (nft_lock_flag >= 0) {
		pthread_mutex_destroy(&nft_lock);
		nft_lock_flag = -1;
	}
	if (client_http_fd >= 0) {
		close(client_http_fd);
		client_http_fd = -1;
	}
	if (client_fd >= 0) {
		close(client_fd);
		client_fd = -1;
	}

	if (server_http_fd >= 0) {
		close(server_http_fd);
		server_http_fd = -1;
	}
	if (server_https_fd >= 0) {
		close(server_https_fd);
		server_https_fd = -1;
	}
	if (child_ctx->pipe_read_fd >= 0) {
		close(child_ctx->pipe_read_fd);
		child_ctx->pipe_read_fd = -1;
	}
	if (child_ctx->pipe_write_fd >= 0) {
		close(child_ctx->pipe_write_fd);
		child_ctx->pipe_write_fd = -1;
	}
	_exit(ret);
}

I32 fws_parent_run(struct fws_parent_ctx *parent_ctx) {
	I32 ret = 0;

	if (parent_ctx->pipe_write_fd >= 0) {
		close(parent_ctx->pipe_write_fd);
		parent_ctx->pipe_write_fd = -1;
	}

	struct nft_ctx *nft_ctx = FAC_NULL;
	nft_ctx = nft_ctx_new(NFT_CTX_DEFAULT);
	if (nft_ctx == FAC_NULL) {
		fprintf(stderr, "nft context allocation error\n");
		ret = -1;
		goto out;
	}

	struct pollfd nft_fd = {0};
	nft_fd.fd = parent_ctx->pipe_read_fd;
	nft_fd.events = POLLIN | POLLHUP | POLLERR;

	while (1) {
		errno = 0;
		if (poll(&nft_fd, 1, -1) < 0) {
			if (errno == EINTR && (*parent_ctx->fws_flag == SIGINT || *parent_ctx->fws_flag == SIGTERM)) {
				break;
			}
			ret = -1;
			goto out;
		}

		if ((nft_fd.revents & (POLLIN|POLLHUP|POLLERR)) != 0) {
			C8 ip_buf[INET6_ADDRSTRLEN] = {0};
			if (read(nft_fd.fd, ip_buf, INET6_ADDRSTRLEN) <= 0) {
				break;
			} else {
				net_nft_dos_ban(nft_ctx, ip_buf, parent_ctx->conf->ban_time);
			}
		}
	}

	if (parent_ctx->pipe_read_fd >= 0) {
		close(parent_ctx->pipe_read_fd);
		parent_ctx->pipe_read_fd = -1;
	}

	waitpid(parent_ctx->pid, FAC_NULL, 0);
	if (parent_ctx->conf->nft == 1) {
		net_nft_fini();
	}

	ret = 0;
out:
	nft_ctx_free(nft_ctx);
	nft_ctx = FAC_NULL;
	if (parent_ctx->pipe_read_fd >= 0) {
		close(parent_ctx->pipe_read_fd);
		parent_ctx->pipe_read_fd = -1;
	}
	if (parent_ctx->pipe_write_fd >= 0) {
		close(parent_ctx->pipe_write_fd);
		parent_ctx->pipe_write_fd = -1;
	}
	return ret;
}

static void *_fws_thread_run(void *thread_args) {
	struct fws_thread_ctx *thread_ctx = (struct fws_thread_ctx *) thread_args;
	const struct fws_conf *conf = thread_ctx->fws_conf;
	pthread_mutex_t *nft_lock = (pthread_mutex_t *) thread_ctx->nft_lock_opq;

	I32 client_fd = thread_ctx->fd;
	I32 write_fd = thread_ctx->write_fd;
	SSL_CTX *ssl_ctx = (SSL_CTX *) thread_ctx->ssl_ctx_opq;

	SSL *ssl = FAC_NULL;

	I32 ssl_flag = 1;
	C8 request_buf[8192];

	ssl = SSL_new(ssl_ctx);
	if (ssl == FAC_NULL) {
		ssl_flag = -1;
		goto out;
	}

	struct timeval sock_tv = {0};
	sock_tv.tv_sec = 2;
	sock_tv.tv_usec = 0;
	setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (const C8*)&sock_tv, sizeof(sock_tv));

	SSL_set_fd(ssl, client_fd);
	if (SSL_accept(ssl) <= 0) {
		ssl_flag = -1;
		goto out;
	}

	while (1) {
		if (net_443_read((U8*)ssl, request_buf, sizeof(request_buf)) != 0) {
			ssl_flag = -1;
			goto out;
		}

		struct fws_http_req http = {0};
		if (net_http_req_parse(request_buf, &http, conf->domain, sizeof(conf->domain)) != 0) {
			ssl_flag = -1;
			goto out;
		}

		struct fws_file file = {0};
		I32 status_code = file_parse(&file, &http, conf->web_root, sizeof(conf->web_root));

		if (status_code == 301) {
			net_http_path_redir(&http, conf, &file, (U8*)ssl);
			ssl_flag = -1;
			goto out;
		}

		if (conf->nft == 1) {
			I32 html_cnt = 0;
			U64 path_size = fac_memclen(file.path, FAC_NUL, sizeof(file.path));
			C8 *path_p = file.path + path_size - (sizeof(".html") - 1);
			if (memcmp(path_p, ".html", sizeof(".html")) == 0) {
				html_cnt++;
			}

			I32 ip_send = FAC_FALSE;
			C8 ip_buf[INET6_ADDRSTRLEN] = {0};
			U8 *client_ip = thread_ctx->client_ip;
			U8 empty_ip[16] = {0};
			I32 ip_cmp = 0;
			inet_ntop(AF_INET6, client_ip, ip_buf, INET6_ADDRSTRLEN);

			pthread_mutex_lock(nft_lock);
			I32 nft_i = 0;
			for (I32 i=0; i<(I32)(sizeof(nft_table_a)/sizeof(nft_table_a[0])); i++) {
				ip_cmp = memcmp(nft_table[i].ip, client_ip, 16);
				if (ip_cmp == 0) {
					nft_i = i;
					break;
				}

				ip_cmp = memcmp(nft_table[i].ip, empty_ip, 16);
				if (ip_cmp == 0) {
					nft_i = i;
					memcpy(nft_table[nft_i].ip, client_ip, 16);
					break;
				}
				nft_i = i;
			}
			nft_table[nft_i].html_cnt += html_cnt;
			if (nft_table[nft_i].html_cnt > 3U) {
				ip_send = FAC_TRUE;
			}
			pthread_mutex_unlock(nft_lock);

			if (ip_send == FAC_TRUE) {
				write(write_fd, ip_buf, INET6_ADDRSTRLEN);
			}
		}

		if (status_code != 0) {
			if (net_443_err_write((U8*)ssl, status_code) < 0) {
				ssl_flag = -1;
				goto out;
			}

		} else {
			struct fws_http_res http_res = {0};
			net_http_res_build(&http_res, file.path, sizeof(file.path));
			if (net_443_res_write((U8*)ssl, &http_res, file.size) != 0) {
				ssl_flag = -1;
				goto out;
			}
			net_443_write((U8*)ssl, file.path);
		}
	}

out:
	if (ssl_flag >= 0) {
		SSL_shutdown(ssl);
		ssl_flag = -1;
	}
	SSL_free(ssl);
	ssl = FAC_NULL;
	if (client_fd >= 0) {
		close(client_fd);
		client_fd = -1;
	}

	(*thread_ctx->fws_thread_n)--;
	free(thread_args);
	thread_args = FAC_NULL;
	return FAC_NULL;
}

static void *_fws_swap_thread_run(void *swap_ctx_opq) {
	struct fws_swap_ctx *swap_ctx = (struct fws_swap_ctx *) swap_ctx_opq;

	I64 global_time = time(FAC_NULL);
	I64 swap_time = global_time;

	swap_ctx->global_time = global_time;
	swap_ctx->swap_time = swap_time;

	while (FAC_TRUE) {
		poll(FAC_NULL, 0, 1000);
		swap_ctx->global_time = time(FAC_NULL);
		_fws_swap_run(swap_ctx);
	}
	free(swap_ctx_opq);
	swap_ctx_opq = FAC_NULL;
	return FAC_NULL;
}

static void _fws_swap_run(struct fws_swap_ctx *swap_ctx) {
	if (swap_ctx->global_time - swap_ctx->swap_time < 2) {
		return;
	}

	struct fws_nft *nft_table_tmp = swap_ctx->nft_table;
	swap_ctx->nft_table = swap_ctx->nft_table_swap;
	swap_ctx->nft_table_swap = nft_table_tmp;
	memset(swap_ctx->nft_table_swap, 0, sizeof(nft_table_a));

	swap_ctx->global_time = time(FAC_NULL);
	swap_ctx->swap_time = swap_ctx->global_time;
}
