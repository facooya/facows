/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include "factype.h"
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
#include <sys/epoll.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <nftables/libnftables.h>

constexpr u64 nft_arr_cap = 1024;

static s32 _fws_80_run(struct fws_data_ctx *data_ctx_p);
static s32 _fws_443_run(struct fws_data_ctx *data_ctx_p);
static void *_fws_swap_thrd_run(void *swap_ctx_opq_p);
static void _fws_swap_run(struct fws_swap_ctx *swap_ctx_p);

void fws_child_run(struct fws_child_ctx *child_ctx_p) {
	static constexpr u32 maxEvent = 32;
	static const char www_data_str[] = "www-data";
	static const char apache_str[] = "apache";
	static const char http_str[] = "http";
	static const char nobody_str[] = "nobody";
	static const char *const uname_str_arr[] = {www_data_str, apache_str, http_str, nobody_str};
	SSL_CTX *ssl_ctx_p = nullptr;
	struct fws_nft *nft_a_arr_p = nullptr;
	struct fws_nft *nft_b_arr_p = nullptr;
	s32 fws_epfd = -1;
	s32 server_http_fd = -1;
	s32 server_https_fd = -1;
	s32 client_http_fd = -1;
	s32 client_fd = -1;
	_Atomic s32 thrd_n = 0;
	s32 ret = 0;

	nft_a_arr_p = calloc(nft_arr_cap, sizeof(struct fws_nft));
	if (nft_a_arr_p == nullptr) {
		ret = 1;
		goto out;
	}
	nft_b_arr_p = calloc(nft_arr_cap, sizeof(struct fws_nft));
	if (nft_b_arr_p == nullptr) {
		ret = 1;
		goto out;
	}

	ret = net_443_init((u8**)&ssl_ctx_p, child_ctx_p->conf_p);
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

	struct passwd *passwd_p = nullptr;
	for (u64 i=0; i<(sizeof(uname_str_arr)/sizeof(uname_str_arr[0])); i++) {
		passwd_p = getpwnam(uname_str_arr[i]);
		if (passwd_p != nullptr) {
			break;
		}
		if ((i+1) == (sizeof(uname_str_arr)/sizeof(uname_str_arr[0]))) {
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

	struct fws_data_ctx *http_data_ctx_p = calloc(1, sizeof(struct fws_data_ctx));
	struct fws_data_ctx *https_data_ctx_p = calloc(1, sizeof(struct fws_data_ctx));
	struct epoll_event fws_ctl = {0};
	struct epoll_event fws_event[maxEvent] = {0};
	fws_epfd = epoll_create1(0);

	http_data_ctx_p->conf_p = child_ctx_p->conf_p;
	http_data_ctx_p->ssl_ctx_opq_p = nullptr;
	http_data_ctx_p->fd = server_http_fd;
	fws_ctl.events = EPOLLIN;
	fws_ctl.data.ptr = http_data_ctx_p;
	epoll_ctl(fws_epfd, EPOLL_CTL_ADD, server_http_fd, &fws_ctl);

	https_data_ctx_p->fd = server_https_fd;
	fws_ctl.events = EPOLLIN;
	fws_ctl.data.ptr = https_data_ctx_p;
	epoll_ctl(fws_epfd, EPOLL_CTL_ADD, server_https_fd, &fws_ctl);

	pthread_mutex_t nft_lock = {0};
	s32 nft_lock_flag = -1;
	if (pthread_mutex_init(&nft_lock, nullptr) != 0) {
		fprintf(stderr, "nft mutex init failed\n");
		ret = 1;
		goto out;
	}
	nft_lock_flag = 1;

	struct fws_nft *nft_arr_p = nft_a_arr_p;
	struct fws_nft *nft_swap_arr_p = nft_b_arr_p;
	struct fws_swap_ctx *swap_ctx_p = calloc(1, sizeof(struct fws_swap_ctx));
	_Atomic s32 *sig_flag_p = (_Atomic s32 *) child_ctx_p->sig_flag_opq_p;
	swap_ctx_p->nft_arr_pp = &nft_arr_p;
	swap_ctx_p->nft_swap_arr_p = nft_swap_arr_p;
	swap_ctx_p->nft_lock_opq_p = (u8 *) &nft_lock;
	swap_ctx_p->sig_flag_opq_p = (s32 *) sig_flag_p;
	swap_ctx_p->thrd_n_opq_p = (s32 *) &thrd_n;
	swap_ctx_p->conf_p = child_ctx_p->conf_p;

	thrd_n++;
	u64 fws_swap_thrd = 0;
	pthread_create(&fws_swap_thrd, nullptr, _fws_swap_thrd_run, swap_ctx_p);
	pthread_detach(fws_swap_thrd);

	printf("Facows start\n");
	while (true) {
		errno = 0;
		s32 event_n = epoll_wait(fws_epfd, fws_event, maxEvent, -1);
		bool sig_cond = (*sig_flag_p == SIGINT) || (*sig_flag_p == SIGTERM);
		if (ret < 0 && sig_cond) {
			break;
		}

		printf("EVENT_N: %d\n", event_n);
		for (s32 i=0; i<event_n; i++) {
			printf("EVENT: %u\n", fws_event[i].events);

			struct sockaddr_in6 client_addr = {0};
			u32 client_addr_len = sizeof(client_addr);
			struct fws_data_ctx *data_ctx_p = fws_event[i].data.ptr;
			if (data_ctx_p->fd == server_http_fd) {
				client_http_fd = accept4(server_http_fd, (struct sockaddr*)&client_addr, &client_addr_len, SOCK_NONBLOCK|SOCK_CLOEXEC);
				if (client_http_fd < 0) {
					fprintf(stderr, "fws_child_run(): error: http connect %d\n", client_http_fd);
					continue;
				}

				struct fws_data_ctx *ctl_data_ctx_p = calloc(1, sizeof(struct fws_data_ctx));
				if (ctl_data_ctx_p == nullptr) {
					ret = 1;
					goto out;
				}
				ctl_data_ctx_p->conf_p = child_ctx_p->conf_p;
				ctl_data_ctx_p->fd = client_http_fd;
				ctl_data_ctx_p->ssl_ctx_opq_p = nullptr;

				fws_ctl.events = EPOLLIN|EPOLLRDHUP|EPOLLHUP|EPOLLERR;
				fws_ctl.data.ptr = ctl_data_ctx_p;
				ret = epoll_ctl(fws_epfd, EPOLL_CTL_ADD, client_http_fd, &fws_ctl);
				if (ret < 0) {
					close(client_http_fd);
					client_http_fd = -1;
					continue;
				}
				continue;

			} else if (data_ctx_p->fd == server_https_fd) {
				client_fd = accept4(server_https_fd, (struct sockaddr*)&client_addr, &client_addr_len, SOCK_NONBLOCK|SOCK_CLOEXEC);
				if (client_fd < 0) {
					fprintf(stderr, "fws_child_run(): error: https connect %d\n", client_fd);
					continue;
				}
				int one = 1;
				setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

				struct fws_data_ctx *ctl_data_ctx_p = calloc(1, sizeof(struct fws_data_ctx));
				if (ctl_data_ctx_p == nullptr) {
					ret = 1;
					goto out;
				}
				memcpy(
					ctl_data_ctx_p->client_ip_buf,
					client_addr.sin6_addr.s6_addr,
					sizeof(client_addr.sin6_addr.s6_addr)
				);
				ctl_data_ctx_p->write_fd = child_ctx_p->pipe_write_fd;
				ctl_data_ctx_p->nft_arr_pp = &nft_arr_p;
				ctl_data_ctx_p->nft_lock_opq_p = (u8 *) &nft_lock;
				ctl_data_ctx_p->sig_flag_opq_p = (s32 *) sig_flag_p;
				ctl_data_ctx_p->conf_p = child_ctx_p->conf_p;
				ctl_data_ctx_p->fd = client_fd;
				ctl_data_ctx_p->ssl_ctx_opq_p = (u8 *) ssl_ctx_p;
				ctl_data_ctx_p->epfd = fws_epfd;
				ctl_data_ctx_p->ctl_opq_p = (u8 *) &fws_ctl;

				fws_ctl.events = EPOLLIN|EPOLLRDHUP|EPOLLHUP|EPOLLERR;
				fws_ctl.data.ptr = ctl_data_ctx_p;
				ret = epoll_ctl(fws_epfd, EPOLL_CTL_ADD, client_fd, &fws_ctl);
				if (ret < 0) {
					close(client_fd);
					client_fd = -1;
					continue;
				}
				continue;
			}

			if (data_ctx_p->ssl_ctx_opq_p == nullptr) {
				ret = _fws_80_run(data_ctx_p);
				printf("80: %d\n", ret);
			} else {
				ret = _fws_443_run(data_ctx_p);
				if (ret < 0) {
					epoll_ctl(fws_epfd, EPOLL_CTL_DEL, data_ctx_p->fd, nullptr);
					if (data_ctx_p->fd >= 0) {
						close(data_ctx_p->fd);
						data_ctx_p->fd = -1;
					}
					SSL_free((SSL*)data_ctx_p->ssl_opq_p);
					data_ctx_p->ssl_opq_p = nullptr;
					free(data_ctx_p);
					data_ctx_p = nullptr;
				}
				printf("443: %d\n", ret);
			}
			continue;
		}
	}

	ret = 0;
out:
	/* Thread wait for terminate */
	/*u64 thrd_join_ms = 0;
	while (thrd_n > 0) {
		poll(nullptr, 0, 100);
		thrd_join_ms += 100;
		if (thrd_join_ms > 5000) {
			fprintf(stderr, "fws_child_run(): thread join timeout %d\n", thrd_n);
			break;
		}
	}*/

	/* Wait 300 ms for safety */
	poll(nullptr, 0, 300);
	if (nft_lock_flag >= 0) {
		pthread_mutex_destroy(&nft_lock);
		nft_lock_flag = -1;
	}

	SSL_CTX_free(ssl_ctx_p);
	ssl_ctx_p = nullptr;
	free(nft_a_arr_p);
	nft_a_arr_p = nullptr;
	free(nft_b_arr_p);
	nft_b_arr_p = nullptr;

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

s32 fws_parent_run(struct fws_parent_ctx *parent_ctx_p) {
	static constexpr char log_file_str[] = "/facows.log";
	static constexpr u32 web_log_n = sizeof(((struct fws_conf*)0)->web_log);
	struct nft_ctx *nft_ctx = nullptr;
	s32 log_fd = -1;
	s32 ep_fd = -1;
	s32 ret = 0;

	if (parent_ctx_p->pipe_write_fd >= 0) {
		close(parent_ctx_p->pipe_write_fd);
		parent_ctx_p->pipe_write_fd = -1;
	}

	nft_ctx = nft_ctx_new(NFT_CTX_DEFAULT);
	if (nft_ctx == nullptr) {
		fprintf(stderr, "nft context allocation error\n");
		ret = -1;
		goto out;
	}

	char log_path_buf[256] = {0};
	char *p = log_path_buf;
	memcpy(p, parent_ctx_p->conf_p->web_log, strnlen(parent_ctx_p->conf_p->web_log, web_log_n));
	p += strnlen(parent_ctx_p->conf_p->web_log, web_log_n);
	memcpy(p, log_file_str, sizeof(log_file_str)-1);
	p += sizeof(log_file_str) - 1;
	*p = '\0';

	log_fd = open(log_path_buf, (O_WRONLY|O_APPEND|O_CREAT), 0640);
	if (log_fd < 0) {
		fprintf(stderr, "fws_parent_run(): warning: can not open log file\n");
		ret = -1;
		goto out;
	}

	struct epoll_event ep_ctl = {0};
	struct epoll_event ep_event = {0};
	ep_fd = epoll_create1(0);
	ep_ctl.events = EPOLLIN;
	ep_ctl.data.fd = parent_ctx_p->pipe_read_fd;
	epoll_ctl(ep_fd, EPOLL_CTL_ADD, parent_ctx_p->pipe_read_fd, &ep_ctl);

	while (true) {
		errno = 0;
		ret = epoll_wait(ep_fd, &ep_event, 1, -1);
		if (ret < 0) {
			const s32 ep_err = errno;
			_Atomic s32 *sig_flag_p = (_Atomic s32 *) parent_ctx_p->sig_flag_opq_p;
			const s32 sig_cond = (*sig_flag_p == SIGINT || *sig_flag_p == SIGTERM);
			const s32 ep_cond = (ep_err == EINTR && sig_cond);
			if (ep_cond == 1) {
				break;
			}
			ret = -1;
			goto out;
		}

		if (ep_event.events & (EPOLLIN|EPOLLHUP)) {
			char read_buf[1024] = {0};
			ret = read(ep_event.data.fd, read_buf, sizeof(read_buf)-1);
			if (ret <= 0) {
				fprintf(stderr, "fws_parent_run(): error: read(): %d\n", ret);
				if (ep_event.events & EPOLLHUP) {
					fprintf(stderr, "fws_parent_run(): error: EPOLLHUP\n");
					break;
				}
				continue;
			}
			read_buf[ret] = '\0';

			if (*read_buf == '1') {
				net_nft_dos_ban(nft_ctx, read_buf+1, parent_ctx_p->conf_p->ban_time);
			} else if (*read_buf == '2') {
				ret = write(log_fd, read_buf+1, ret-1);
				if (ret <= 0) {
					fprintf(stderr, "fws_parent_run(): error: write(): %d\n", ret);
				}
				fdatasync(log_fd);
			} else {
				fprintf(stderr, "fws_parent_run(): warning: unknown header\n");
				continue;
			}

		} else {
			fprintf(stderr, "fws_parent_run(): error: not EPOLLIN and not EPOLLHUP, %u\n", ep_event.events);
			ret = -1;
			goto out;
		}
	}

	if (parent_ctx_p->pipe_read_fd >= 0) {
		close(parent_ctx_p->pipe_read_fd);
		parent_ctx_p->pipe_read_fd = -1;
	}

	s32 wait_status = 0;
	ret = waitpid(parent_ctx_p->pid, &wait_status, WNOHANG);
	if (WIFEXITED(wait_status)) {
		fprintf(stderr, "EXIT: %d\n", WEXITSTATUS(wait_status));
	} else if (WIFSIGNALED(wait_status)) {
		fprintf(stderr, "SIG: %d\n", WTERMSIG(wait_status));
	}

	if (ret < 0) {
		fprintf(stderr, "fws_parent_run(): waitpid(): error\n");
		ret = -1;
		goto out;
	}
	if (parent_ctx_p->conf_p->use_nft) {
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
	nft_ctx = nullptr;
	if (ep_fd >= 0) {
		close(ep_fd);
		ep_fd = -1;
	}
	if (log_fd >= 0) {
		close(log_fd);
		log_fd = -1;
	}
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

static s32 _fws_80_run(struct fws_data_ctx *data_ctx_p) {
	s32 ret = -1;

	struct timeval sock_tv = {0};
	sock_tv.tv_sec = 2;
	sock_tv.tv_usec = 0;
	ret = setsockopt(data_ctx_p->fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&sock_tv, sizeof(sock_tv));
	if (ret < 0) {
		ret = -1;
		goto out;
	}

	ret = net_80_443_redir(data_ctx_p->fd, data_ctx_p->conf_p);
	if (ret < 0) {
		ret = -1;
		goto out;
	}

	ret = 0;
out:
	if (data_ctx_p->fd >= 0) {
		close(data_ctx_p->fd);
		data_ctx_p->fd = -1;
	}

	free(data_ctx_p);
	data_ctx_p = nullptr;
	return ret;
}

static s32 _fws_443_run(struct fws_data_ctx *data_ctx_p) {
	static constexpr u32 logSSL = 0;
	static constexpr u32 logKTLS = 1;
	static constexpr u32 logRead = 2;
	static constexpr u32 logReqParse = 3;
	static constexpr u8 empty_ip_buf[16] = {0};
	SSL *ssl = nullptr;
	bool is_end = false;
	bool need_ssl_shutdown = false;
	s32 ret = 0;
	u32 log_flag = 0; /* ssl, ktls, read, req parse */

	struct epoll_event ctl = {0};

	const u8 *client_ip_buf = data_ctx_p->client_ip_buf;
	char ip_buf[INET6_ADDRSTRLEN] = {0};
	inet_ntop(AF_INET6, client_ip_buf, ip_buf, INET6_ADDRSTRLEN);

	time_t raw_time = {0};
	time(&raw_time);
	struct tm tm = {0};
	gmtime_r(&raw_time, &tm);
	char time_buf[16] = {0};
	strftime(time_buf, sizeof(time_buf), "%Y%m%d%H%M%S", &tm);

	char log_buf[1024] = {0};
	s32 log_acc = snprintf(log_buf, sizeof(log_buf), "%d%s %s", 2, ip_buf, time_buf);

	if (data_ctx_p->ssl_status == 0) {
		SSL_CTX *ssl_ctx_p = (SSL_CTX *) data_ctx_p->ssl_ctx_opq_p;
		ssl = SSL_new(ssl_ctx_p);
		if (ssl == nullptr) {
			log_flag |= (1 << logSSL);
			ret = -1;
			goto out;
		}
	
		ret = SSL_set_fd(ssl, data_ctx_p->fd);
		if (ret <= 0) {
			log_flag |= (1 << logSSL);
			ret = -1;
			goto out;
		}
		data_ctx_p->ssl_opq_p = (u8 *) ssl;
	} else {
		ssl = (SSL *) data_ctx_p->ssl_opq_p;
	}

	printf("STATUS: %d\n", data_ctx_p->ssl_status);
	if (data_ctx_p->ssl_status != 10) {
		ERR_clear_error();
		ret = SSL_accept(ssl);
		if (ret <= 0) {
			s32 ssl_err = SSL_get_error(ssl, ret);
			if (ssl_err == SSL_ERROR_WANT_READ) {
				ctl.events = EPOLLIN|EPOLLRDHUP|EPOLLHUP|EPOLLERR;
				data_ctx_p->ssl_status = ssl_err;
				ctl.data.ptr = data_ctx_p;
				epoll_ctl(data_ctx_p->epfd, EPOLL_CTL_MOD, data_ctx_p->fd, &ctl);
				printf("SSL: %d\n", ssl_err);
				return ssl_err;
	
			} else if (ssl_err == SSL_ERROR_WANT_WRITE) {
				ctl.events = EPOLLOUT|EPOLLRDHUP|EPOLLHUP|EPOLLERR;
				data_ctx_p->ssl_status = ssl_err;
				ctl.data.ptr = data_ctx_p;
				epoll_ctl(data_ctx_p->epfd, EPOLL_CTL_MOD, data_ctx_p->fd, &ctl);
				printf("SSL: %d\n", ssl_err);
				return ssl_err;
			}
			printf("ERROR_SSL: %d\n", ssl_err);
	
			log_flag |= (1 << logSSL);
			ret = -1;
			goto out;
		}
		ctl.events = EPOLLIN|EPOLLRDHUP|EPOLLHUP|EPOLLERR;
		data_ctx_p->ssl_status = 10;
		ctl.data.ptr = data_ctx_p;
		epoll_ctl(data_ctx_p->epfd, EPOLL_CTL_MOD, data_ctx_p->fd, &ctl);
		need_ssl_shutdown = true;
	}

	/* Check for supporting 'kTLS'. */
	BIO *bio = SSL_get_wbio(ssl);
	bool is_ktls = (bool) (bio != nullptr && BIO_get_ktls_send(bio) == 1);
	if (!is_ktls) {
		log_flag |= (1 << logKTLS);
	}
	bio = SSL_get_rbio(ssl);
	is_ktls = (bool) (bio != nullptr && BIO_get_ktls_recv(bio) == 1);
	if (!is_ktls) {
		log_flag |= (1 << logKTLS);
	}

	pthread_mutex_t *nft_lock_p = (pthread_mutex_t *) data_ctx_p->nft_lock_opq_p;
	const struct fws_conf *conf_p = data_ctx_p->conf_p;
	struct fws_http_req http_req = {0};
	while (true) {
		static const char html_ext_str[] = ".html";
		char req_buf[8192] = {0};
		ret = net_443_read((u8*)ssl, req_buf, sizeof(req_buf), data_ctx_p->fd, data_ctx_p->sig_flag_opq_p);
		if (ret < 0) {
			printf("net_443_read(): error: %d\n", ret);
			log_flag |= (1 << logRead);
			ret = -1;
			goto out;
		} else if (ret == 0) {
			break;
		}

		ret = net_http_req_parse(req_buf, &http_req, conf_p->domain, sizeof(conf_p->domain));
		if (ret != 0) {
			log_flag |= (1 << logReqParse);
			ret = -1;
			goto out;
		}

		/* webroot = webroot + subdomain */
		char web_root_buf[256] = {0};
		char *web_root_buf_p = web_root_buf;
		u64 conf_web_root_len = strnlen(conf_p->web_root, sizeof(conf_p->web_root));
		memcpy(web_root_buf_p, conf_p->web_root, conf_web_root_len);
		web_root_buf_p += conf_web_root_len;
		*web_root_buf_p = '\0';
		if (http_req.subdomain[0] != '\0') {
			*web_root_buf_p = '/';
			web_root_buf_p++;
			u64 req_subdomain_len = strnlen(http_req.subdomain, sizeof(http_req.subdomain));
			memcpy(web_root_buf_p, http_req.subdomain, req_subdomain_len);
			web_root_buf_p += req_subdomain_len;
			*web_root_buf_p = '\0';
		}

		struct fws_file file = {0};
		s32 status_code = file_parse(&file, &http_req, web_root_buf, sizeof(web_root_buf));
		if (status_code == 301) {
			net_http_path_redir(&http_req, conf_p, &file, (u8*)ssl, data_ctx_p->sig_flag_opq_p);
			ret = -1;
			goto out;
		}

		bool is_html = false;
		u64 path_size = strnlen(file.path, sizeof(file.path));
		char *path_p = file.path + path_size - (sizeof(html_ext_str) - 1);
		ret = memcmp(path_p, html_ext_str, sizeof(html_ext_str));
		if (ret == 0) {
			is_html = true;
		}

		pthread_mutex_lock(nft_lock_p);
		struct fws_nft *nft_arr = *data_ctx_p->nft_arr_pp;

		/* get nft_i */
		u32 nft_i = 0;
		for (u64 i=0; i<nft_arr_cap; i++) {
			s32 ip_cmp = memcmp(nft_arr[i].ip_buf, client_ip_buf, 16);
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

			if (conf_p->use_nft && nft_arr[nft_i].dos_cnt > conf_p->ban_lim) {
				char nft_buf[INET6_ADDRSTRLEN+1] = {0};
				s32 nft_n = snprintf(nft_buf, sizeof(nft_buf)-1, "%d%s", 1, ip_buf);
				if ((u32)nft_n >= sizeof(nft_buf)) {
					fprintf(stderr, "nft_buf: error: invalid 'nft_n' \n");
					ret = -1;
					goto out;
				}
				nft_buf[nft_n] = '\0';
				write(data_ctx_p->write_fd, nft_buf, nft_n+1);
			}

			pthread_mutex_unlock(nft_lock_p);
			status_code = 429;
			ret = net_443_err_write((u8*)ssl, status_code, data_ctx_p->sig_flag_opq_p);
			if (ret < 0) {
				ret = -1;
				goto out;
			}
			goto out;
		}

		/* check 429 */
		if (is_html || status_code != 0) {
			nft_arr[nft_i].html_cnt++;
		} else {
			nft_arr[nft_i].no_html_cnt++;
		}
		if (nft_arr[nft_i].html_cnt > conf_p->lim_page || nft_arr[nft_i].no_html_cnt > conf_p->lim_res) {
			nft_arr[nft_i].dos_cnt++;
			status_code = 429;
		}
		pthread_mutex_unlock(nft_lock_p);

		if (status_code != 0) {
			ret = net_443_err_write((u8*)ssl, status_code, data_ctx_p->sig_flag_opq_p);
			if (ret < 0) {
				ret = -1;
				goto out;
			}
			is_end = true;

		} else {
			struct fws_http_res http_res = {0};
			net_http_res_build(conf_p, &http_res, file.path, sizeof(file.path));
			if (http_req.origin[0] != '\0') {
				http_res.is_origin_self = net_http_origin_self_check(&http_req, conf_p);
			}
			if (conf_p->use_hsts) {
				http_res.hsts_max_age = conf_p->hsts_max_age;
			}
			ret = net_443_res_write((u8*)ssl, &http_res, file.size, &http_req, data_ctx_p->sig_flag_opq_p);
			if (ret != 0) {
				ret = -1;
				goto out;
			}
			net_443_file_write((u8*)ssl, file.path, data_ctx_p->sig_flag_opq_p);
			is_end = true;
		}
	}

	ret = 0;
out:
	log_acc += snprintf(log_buf+log_acc, sizeof(log_buf)-log_acc, " %02u %s %s %s %s %s %s %s\n", log_flag, http_req.version, http_req.method, http_req.subdomain, http_req.uri, http_req.lang, http_req.os, http_req.browser);

	log_buf[log_acc] = '\0';
	write(data_ctx_p->write_fd, log_buf, log_acc);

	if (is_end && ret == 0) {
		epoll_ctl(data_ctx_p->epfd, EPOLL_CTL_DEL, data_ctx_p->fd, nullptr);
		/* Shutdown for ssl, check every 100 ms, timeout 2 sec. */
		if (need_ssl_shutdown) {
			u32 ssl_timeout = 0;
			s32 ssl_stat = SSL_shutdown(ssl);
			if (ssl_stat == 0) {
				while (ssl_timeout < 2000) {
					s32 poll_ret = poll(nullptr, 0, 100);
					if (poll_ret < 0) {
						break;
					}
					ssl_stat = SSL_shutdown(ssl);
					if (ssl_stat == 1) {
						break;
					}
					ssl_timeout += 100;
				}
			}
		}

		SSL_free(ssl);
		ssl = nullptr;

		if (data_ctx_p->fd >= 0) {
			close(data_ctx_p->fd);
			data_ctx_p->fd = -1;
		}

		free(data_ctx_p);
		data_ctx_p = nullptr;
	}
	return ret;
}

static void *_fws_swap_thrd_run(void *swap_ctx_opq_p) {
	struct fws_swap_ctx *swap_ctx_p = nullptr;
	s64 global_time = time(nullptr);
	s64 swap_time = global_time;

	swap_ctx_p = (struct fws_swap_ctx *) swap_ctx_opq_p;
	swap_ctx_p->global_time = global_time;
	swap_ctx_p->swap_time = swap_time;

	_Atomic s32 *sig_flag_p = (_Atomic s32 *) swap_ctx_p->sig_flag_opq_p;
	while (true) {
		s32 ret = poll(nullptr, 0, 1000);
		if (ret < 0) {
			break;
		}
		if (*sig_flag_p == SIGINT || *sig_flag_p == SIGTERM) {
			break;
		}
		swap_ctx_p->global_time = time(nullptr);
		_fws_swap_run(swap_ctx_p);
	}

	_Atomic s32 *thrd_n_p = (_Atomic s32 *) swap_ctx_p->thrd_n_opq_p;
	(*thrd_n_p)--;
	free(swap_ctx_p);
	swap_ctx_p = nullptr;
	fprintf(stdout, "_fws_swap_thrd_run(): Done\n");
	return nullptr;
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

	swap_ctx_p->global_time = time(nullptr);
	swap_ctx_p->swap_time = swap_ctx_p->global_time;
}
