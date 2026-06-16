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

static const U64 nft_arr_cap = 1024U;

static void *_fws_thrd_run(void *thrd_ctx_opq_p);
static void *_fws_swap_thrd_run(void *swap_ctx_opq_p);
static void _fws_swap_run(struct fws_swap_ctx *swap_ctx_p);

void fws_child_run(struct fws_child_ctx *child_ctx_p) {
	static const C8 www_data_str[] = "www-data";
	static const C8 apache_str[] = "apache";
	static const C8 http_str[] = "http";
	static const C8 nobody_str[] = "nobody";
	static const C8 * const uname_str_arr[] = {www_data_str, apache_str, http_str, nobody_str};
	SSL_CTX *ssl_ctx_p = FAC_NULL;
	struct fws_nft *nft_a_arr_p = FAC_NULL;
	struct fws_nft *nft_b_arr_p = FAC_NULL;
	I32 server_http_fd = -1;
	I32 server_https_fd = -1;
	I32 client_http_fd = -1;
	I32 client_fd = -1;
	_Atomic I32 thrd_n = 0;
	I32 ret = 0;

	nft_a_arr_p = calloc(nft_arr_cap, sizeof(struct fws_nft));
	if (nft_a_arr_p == FAC_NULL) {
		ret = 1;
		goto out;
	}
	nft_b_arr_p = calloc(nft_arr_cap, sizeof(struct fws_nft));
	if (nft_b_arr_p == FAC_NULL) {
		ret = 1;
		goto out;
	}

	ret = net_443_init((U8**)&ssl_ctx_p, child_ctx_p->conf_p);
	if (ret < 0) {
		ret = 1;
		goto out;
	}

	server_http_fd = net_server_init(child_ctx_p->conf_p->http_port);
	if (server_http_fd < 0) {
		fprintf(stderr, "http socket failed\n");
		ret = 1;
		goto out;
	}
	server_https_fd = net_server_init(child_ctx_p->conf_p->https_port);
	if (server_https_fd < 0) {
		fprintf(stderr, "https socket failed\n");
		ret = 1;
		goto out;
	}

	struct passwd *passwd_p = FAC_NULL;
	for (U64 i=0U; i<(sizeof(uname_str_arr)/sizeof(uname_str_arr[0U])); i++) {
		passwd_p = getpwnam(uname_str_arr[i]);
		if (passwd_p != FAC_NULL) {
			break;
		}
		if ((i+1U) == (sizeof(uname_str_arr)/sizeof(uname_str_arr[0U]))) {
			fprintf(stderr, "user not found\n");
			ret = 1;
			goto out;
		}
	}

	ret = setgid(passwd_p->pw_gid);
	if (ret != 0) {
		fprintf(stderr, "set group failed\n");
		ret = 1;
		goto out;
	}
	ret = setuid(passwd_p->pw_uid);
	if (ret != 0) {
		fprintf(stderr, "set user failed\n");
		ret = 1;
		goto out;
	}

	if (child_ctx_p->pipe_read_fd >= 0) {
		close(child_ctx_p->pipe_read_fd);
		child_ctx_p->pipe_read_fd = -1;
	}

	struct pollfd fws_fds[2U] = {0};
	fws_fds[0U].fd = server_http_fd;
	fws_fds[0U].events = POLLIN;
	fws_fds[1U].fd = server_https_fd;
	fws_fds[1U].events = POLLIN;

	pthread_mutex_t nft_lock = {0};
	I32 nft_lock_flag = -1;
	if (pthread_mutex_init(&nft_lock, FAC_NULL) != 0) {
		fprintf(stderr, "mutex init failed\n");
		ret = 1;
		goto out;
	}
	nft_lock_flag = 1;

	struct fws_nft *nft_arr_p = nft_a_arr_p;
	struct fws_nft *nft_swap_arr_p = nft_b_arr_p;
	struct fws_swap_ctx *swap_ctx_p = calloc(1U, sizeof(struct fws_swap_ctx));
	_Atomic I32 *sig_flag_p = (_Atomic I32 *) child_ctx_p->sig_flag_opq_p;
	swap_ctx_p->nft_arr_pp = &nft_arr_p;
	swap_ctx_p->nft_swap_arr_p = nft_swap_arr_p;
	swap_ctx_p->nft_lock_opq_p = (U8 *) &nft_lock;
	swap_ctx_p->sig_flag_opq_p = (I32 *) sig_flag_p;
	swap_ctx_p->thrd_n_opq_p = (I32 *) &thrd_n;
	swap_ctx_p->conf_p = child_ctx_p->conf_p;

	thrd_n++;
	U64 fws_swap_thrd = 0U;
	pthread_create(&fws_swap_thrd, FAC_NULL, _fws_swap_thrd_run, swap_ctx_p);
	pthread_detach(fws_swap_thrd);

	printf("Facows start\n");
	while (FAC_TRUE) {
		if (poll(fws_fds, 2, -1) < 0 && (*sig_flag_p == SIGINT || *sig_flag_p == SIGTERM)) {
			break;
		}

		struct sockaddr_in6 client_addr = {0};
		if ((fws_fds[0U].revents & POLLIN) != 0) {
			client_http_fd = accept(server_http_fd, (struct sockaddr*)&client_addr, (U32*)&client_addr);

			if (net_80_443_redir(client_http_fd, child_ctx_p->conf_p) < 0) {
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

		} else if ((fws_fds[1U].revents & POLLIN) != 0) {
			client_fd = accept(server_https_fd, (struct sockaddr*)&client_addr, (U32*)&client_addr);

			struct fws_thrd_ctx *thrd_ctx_p = calloc(1U, sizeof(struct fws_thrd_ctx));
			if (thrd_ctx_p == FAC_NULL) {
				ret = 1;
				goto out;
			}
			memset(thrd_ctx_p, 0, sizeof(struct fws_thrd_ctx));
			memcpy(thrd_ctx_p->client_ip_buf, client_addr.sin6_addr.s6_addr, sizeof(client_addr.sin6_addr.s6_addr));
			thrd_ctx_p->fd = client_fd;
			thrd_ctx_p->write_fd = child_ctx_p->pipe_write_fd;
			thrd_ctx_p->ssl_ctx_opq_p = (U8 *) ssl_ctx_p;
			thrd_ctx_p->conf_p = child_ctx_p->conf_p;
			thrd_ctx_p->nft_arr_pp = &nft_arr_p;
			thrd_ctx_p->nft_lock_opq_p = (U8 *) &nft_lock;
			thrd_ctx_p->thrd_n_opq_p = (I32 *) &thrd_n;

			thrd_n++;
			U64 fws_thrd = 0U;
			pthread_create(&fws_thrd, FAC_NULL, _fws_thrd_run, (void*)thrd_ctx_p);
			pthread_detach(fws_thrd);
		}
	}

	ret = 0;
out:
	{ /* thrd wait for terminate */
		U64 thrd_join_ms = 0U;
		while (thrd_n > 0) {
			poll(FAC_NULL, 0, 100);
			thrd_join_ms += 100U;
			if (thrd_join_ms > 5000U) {
				break;
			}
		}
	}

	/* 300ms wait for safety */
	poll(FAC_NULL, 0, 300);
	if (nft_lock_flag >= 0) {
		pthread_mutex_destroy(&nft_lock);
		nft_lock_flag = -1;
	}

	SSL_CTX_free(ssl_ctx_p);
	ssl_ctx_p = FAC_NULL;
	free(nft_a_arr_p);
	nft_a_arr_p = FAC_NULL;
	free(nft_b_arr_p);
	nft_b_arr_p = FAC_NULL;

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
	if (child_ctx_p->pipe_read_fd >= 0) {
		close(child_ctx_p->pipe_read_fd);
		child_ctx_p->pipe_read_fd = -1;
	}
	if (child_ctx_p->pipe_write_fd >= 0) {
		close(child_ctx_p->pipe_write_fd);
		child_ctx_p->pipe_write_fd = -1;
	}
	_exit(ret);
}

I32 fws_parent_run(struct fws_parent_ctx *parent_ctx_p) {
	struct nft_ctx *nft_ctx = FAC_NULL;
	I32 ret = 0;

	if (parent_ctx_p->pipe_write_fd >= 0) {
		close(parent_ctx_p->pipe_write_fd);
		parent_ctx_p->pipe_write_fd = -1;
	}

	nft_ctx = nft_ctx_new(NFT_CTX_DEFAULT);
	if (nft_ctx == FAC_NULL) {
		fprintf(stderr, "nft context allocation error\n");
		ret = -1;
		goto out;
	}

	struct pollfd nft_fd = {0};
	nft_fd.fd = parent_ctx_p->pipe_read_fd;
	nft_fd.events = POLLIN | POLLHUP | POLLERR;

	while (FAC_TRUE) {
		errno = 0;
		ret = poll(&nft_fd, 1, -1);
		if (ret < 0) {
			const I32 poll_err = errno;
			_Atomic I32 *sig_flag_p = (_Atomic I32 *) parent_ctx_p->sig_flag_opq_p;
			const I32 sig_cond = (*sig_flag_p == SIGINT || *sig_flag_p == SIGTERM);
			const I32 poll_cond = (poll_err == EINTR && sig_cond);
			if (poll_cond == FAC_TRUE) {
				break;
			}
			ret = -1;
			goto out;
		}

		const I32 nft_event = nft_fd.revents & (POLLIN|POLLHUP|POLLERR);
		if (nft_event != 0) {
			C8 ip_buf[INET6_ADDRSTRLEN] = {0};
			ret = read(nft_fd.fd, ip_buf, INET6_ADDRSTRLEN);
			if (ret <= 0) {
				break;
			} else {
				net_nft_dos_ban(nft_ctx, ip_buf, parent_ctx_p->conf_p->ban_time);
			}
		}
	}

	if (parent_ctx_p->pipe_read_fd >= 0) {
		close(parent_ctx_p->pipe_read_fd);
		parent_ctx_p->pipe_read_fd = -1;
	}

	ret = waitpid(parent_ctx_p->pid, FAC_NULL, 0);
	if (ret < 0) {
		fprintf(stderr, "fws_parent_run(): waitpid(): error\n");
		ret = -1;
		goto out;
	}
	if (parent_ctx_p->conf_p->nft == 1U) {
		ret = net_nft_fini();
		if (ret < 0) {
			fprintf(stderr, "fws_parent_run(): net_nft_fini(): error\n");
			ret = -1;
			goto out;
		}
	}

	ret = 0;
out:
	nft_ctx_free(nft_ctx);
	nft_ctx = FAC_NULL;
	if (parent_ctx_p->pipe_read_fd >= 0) {
		close(parent_ctx_p->pipe_read_fd);
		parent_ctx_p->pipe_read_fd = -1;
	}
	if (parent_ctx_p->pipe_write_fd >= 0) {
		close(parent_ctx_p->pipe_write_fd);
		parent_ctx_p->pipe_write_fd = -1;
	}
	return ret;
}

static void *_fws_thrd_run(void *thrd_ctx_opq_p) {
	static const U8 empty_ip_buf[16U] = {0};
	SSL *ssl = FAC_NULL;
	struct fws_thrd_ctx *thrd_ctx_p = FAC_NULL;
	I32 client_fd = -1;
	I32 ssl_shutdown_flag = -1;
	I32 ret = 0;

	thrd_ctx_p = (struct fws_thrd_ctx *) thrd_ctx_opq_p;

	client_fd = thrd_ctx_p->fd;
	if (client_fd < 0) {
		ret = -1;
		goto out;
	}

	struct timeval sock_tv = {0};
	sock_tv.tv_sec = 2;
	sock_tv.tv_usec = 0;
	ret = setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, (const C8*)&sock_tv, sizeof(sock_tv));
	if (ret < 0) {
		ret = -1;
		goto out;
	}

	SSL_CTX *ssl_ctx_p = (SSL_CTX *) thrd_ctx_p->ssl_ctx_opq_p;
	ssl = SSL_new(ssl_ctx_p);
	if (ssl == FAC_NULL) {
		ret = -1;
		goto out;
	}

	ret = SSL_set_fd(ssl, client_fd);
	if (ret <= 0) {
		ret = -1;
		goto out;
	}
	ret = SSL_accept(ssl);
	if (ret <= 0) {
		ret = -1;
		goto out;
	}
	ssl_shutdown_flag = 1;

	pthread_mutex_t *nft_lock_p = (pthread_mutex_t *) thrd_ctx_p->nft_lock_opq_p;
	const struct fws_conf *conf_p = thrd_ctx_p->conf_p;
	while (FAC_TRUE) {
		static const C8 html_ext_str[] = ".html";
		C8 req_buf[8192U] = {0};
		ret = net_443_read((U8*)ssl, req_buf, sizeof(req_buf));
		if (ret != 0) {
			ret = -1;
			goto out;
		}

		struct fws_http_req http = {0};
		ret = net_http_req_parse(req_buf, &http, conf_p->domain, sizeof(conf_p->domain));
		if (ret != 0) {
			ret = -1;
			goto out;
		}

		struct fws_file file = {0};
		I32 status_code = file_parse(&file, &http, conf_p->web_root, sizeof(conf_p->web_root));
		if (status_code == 301) {
			net_http_path_redir(&http, conf_p, &file, (U8*)ssl);
			ret = -1;
			goto out;
		}

		U8 is_html = (U8) FAC_FALSE;
		U64 path_size = fac_memclen(file.path, FAC_NUL, sizeof(file.path));
		C8 *path_p = file.path + path_size - (sizeof(html_ext_str) - 1);
		ret = memcmp(path_p, html_ext_str, sizeof(html_ext_str));
		if (ret == 0) {
			is_html = (U8) FAC_TRUE;
		}

		const U8 *client_ip_buf = thrd_ctx_p->client_ip_buf;
		C8 ip_buf[INET6_ADDRSTRLEN] = {0};
		inet_ntop(AF_INET6, client_ip_buf, ip_buf, INET6_ADDRSTRLEN);

		pthread_mutex_lock(nft_lock_p);
		struct fws_nft *nft_arr = *thrd_ctx_p->nft_arr_pp;

		/* get nft_i */
		I32 nft_i = 0;
		for (U32 i=0; i<nft_arr_cap; i++) {
			I32 ip_cmp = memcmp(nft_arr[i].ip_buf, client_ip_buf, 16);
			if (ip_cmp == 0) {
				nft_i = i;
				break;
			}

			ip_cmp = memcmp(nft_arr[i].ip_buf, empty_ip_buf, 16);
			if (ip_cmp == 0) {
				nft_i = i;
				memcpy(nft_arr[nft_i].ip_buf, client_ip_buf, 16);
				break;
			}
			nft_i = i;
		}

		/* check dos at 429 */
		if (nft_arr[nft_i].html_cnt > conf_p->lim_page || nft_arr[nft_i].no_html_cnt > conf_p->lim_res) {
			nft_arr[nft_i].dos_cnt++;

			if (conf_p->nft == 1U && nft_arr[nft_i].dos_cnt > conf_p->ban_lim) {
				write(thrd_ctx_p->write_fd, ip_buf, INET6_ADDRSTRLEN);
			}

			pthread_mutex_unlock(nft_lock_p);
			status_code = 429;
			ret = net_443_err_write((U8*)ssl, status_code);
			if (ret < 0) {
				ret = -1;
				goto out;
			}
			goto out;
		}

		/* check 429 */
		if (is_html == (U8)FAC_TRUE || status_code != 0) {
			nft_arr[nft_i].html_cnt++;
		} else {
			nft_arr[nft_i].no_html_cnt++;
		}
		if (nft_arr[nft_i].html_cnt > conf_p->lim_res || nft_arr[nft_i].no_html_cnt > conf_p->lim_res) {
			nft_arr[nft_i].dos_cnt++;
			status_code = 429;
		}
		pthread_mutex_unlock(nft_lock_p);

		if (status_code != 0) {
			ret = net_443_err_write((U8*)ssl, status_code);
			if (ret < 0) {
				ret = -1;
				goto out;
			}

		} else {
			struct fws_http_res http_res = {0};
			net_http_res_build(&http_res, file.path, sizeof(file.path));
			if (conf_p->hsts == 1U) {
				http_res.hsts_max_age = conf_p->hsts_max_age;
			}
			ret = net_443_res_write((U8*)ssl, &http_res, file.size);
			if (ret != 0) {
				ret = -1;
				goto out;
			}
			net_443_write((U8*)ssl, file.path);
		}
	}

	ret = 0;
out:
	/* ssl shutdown */
	if (ssl_shutdown_flag >= 0) {
		U32 ssl_timeout = 0U;
		I32 ssl_stat = SSL_shutdown(ssl);
		if (ssl_stat == 0) {
			while (ssl_timeout < 2000U) {
				I32 poll_ret = poll(FAC_NULL, 0, 100);
				if (poll_ret < 0) {
					break;
				}
				ssl_stat = SSL_shutdown(ssl);
				if (ssl_stat == 1) {
					break;
				}
				ssl_timeout += 100U;
			}
		}
	}

	SSL_free(ssl);
	ssl = FAC_NULL;

	if (client_fd >= 0) {
		close(client_fd);
		client_fd = -1;
	}

	{
		_Atomic I32 *thrd_n_p = (_Atomic I32 *) thrd_ctx_p->thrd_n_opq_p;
		(*thrd_n_p)--;
	}
	free(thrd_ctx_p);
	thrd_ctx_p = FAC_NULL;
	return FAC_NULL;
}

static void *_fws_swap_thrd_run(void *swap_ctx_opq_p) {
	struct fws_swap_ctx *swap_ctx_p = FAC_NULL;
	I64 global_time = time(FAC_NULL);
	I64 swap_time = global_time;

	swap_ctx_p = (struct fws_swap_ctx *) swap_ctx_opq_p;
	swap_ctx_p->global_time = global_time;
	swap_ctx_p->swap_time = swap_time;

	_Atomic I32 *sig_flag_p = (_Atomic I32 *) swap_ctx_p->sig_flag_opq_p;
	while (FAC_TRUE) {
		I32 ret = poll(FAC_NULL, 0, 1000);
		if (ret < 0) {
			break;
		}
		if (*sig_flag_p == SIGINT) {
			break;
		}
		swap_ctx_p->global_time = time(FAC_NULL);
		_fws_swap_run(swap_ctx_p);
	}

	_Atomic I32 *thrd_n_p = (_Atomic I32 *) swap_ctx_p->thrd_n_opq_p;
	(*thrd_n_p)--;
	free(swap_ctx_p);
	swap_ctx_p = FAC_NULL;
	return FAC_NULL;
}

static void _fws_swap_run(struct fws_swap_ctx *swap_ctx_p) {
	if (swap_ctx_p->global_time - swap_ctx_p->swap_time < swap_ctx_p->conf_p->lim_swap_time) {
		return;
	}

	pthread_mutex_t *nft_lock_p = (pthread_mutex_t *) swap_ctx_p->nft_lock_opq_p;
	pthread_mutex_lock(nft_lock_p);
	struct fws_nft *nft_table_tmp_p = *swap_ctx_p->nft_arr_pp;
	*swap_ctx_p->nft_arr_pp = swap_ctx_p->nft_swap_arr_p;
	swap_ctx_p->nft_swap_arr_p = nft_table_tmp_p;
	pthread_mutex_unlock(nft_lock_p);
	memset(swap_ctx_p->nft_swap_arr_p, 0, sizeof(struct fws_nft)*nft_arr_cap);

	swap_ctx_p->global_time = time(FAC_NULL);
	swap_ctx_p->swap_time = swap_ctx_p->global_time;
}
