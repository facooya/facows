/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include "factype.h"
#include "facerr.h"
#include "types.h"
#include "net.h"
#include "file.h"
#include "fws.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include <errno.h>

#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <nftables/libnftables.h>

constexpr u64 nft_arr_cap = 1024;

static s32 _fws_80_run(struct fws_data_ctx *data_ctx_p);
static s32 _fws_443_run(struct fws_data_ctx *data_ctx_p);

void fws_child_run(struct fws_child_ctx *child_ctx_p) {
	SSL_CTX *ssl_ctx_p = nullptr;
	struct fws_nft *nft_arr_p = nullptr;
	struct fws_data_ctx *http_data_ctx_p = nullptr;
	struct fws_data_ctx *https_data_ctx_p = nullptr;
	struct fws_data_ctx *timer_data_ctx_p = nullptr;
	s32 fws_epfd = -1;
	s32 timer_fd = -1;
	s32 server_http_fd = -1;
	s32 server_https_fd = -1;
	s32 client_http_fd = -1;
	s32 client_fd = -1;
	s32 ret = 0;

	nft_arr_p = calloc(nft_arr_cap, sizeof(struct fws_nft));
	if (nft_arr_p == nullptr) {
		FAC_ERR("%s\n", strerror(errno));
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
		ret = 1;
		goto out;
	}
	server_https_fd = net_server_init(child_ctx_p->conf_p->https_port);
	if (server_https_fd < 0) {
		ret = 1;
		goto out;
	}

	static constexpr char www_data_str[] = "www-data";
	static constexpr char apache_str[] = "apache";
	static constexpr char http_str[] = "http";
	static constexpr char nobody_str[] = "nobody";
	static const char *uname_str_arr[] = {www_data_str, apache_str, http_str, nobody_str};
	struct passwd *passwd_p = nullptr;
	constexpr u64 uname_arr_cnt = sizeof(uname_str_arr) / sizeof(uname_str_arr[0]);
	bool is_uname_found = false;
	for (u64 i=0; i<uname_arr_cnt; i++) {
		passwd_p = getpwnam(uname_str_arr[i]);
		if (passwd_p != nullptr) {
			is_uname_found = true;
			break;
		}
	}
	if (!is_uname_found) {
		FAC_ERR("user not found: %s, %s, %s, %s\n", www_data_str, apache_str, http_str, nobody_str);
		ret = 1;
		goto out;
	}

	ret = setgid(passwd_p->pw_gid);
	if (ret != 0) {
		FAC_ERR("%s\n", strerror(errno));
		ret = 1;
		goto out;
	}
	ret = setuid(passwd_p->pw_uid);
	if (ret != 0) {
		FAC_ERR("%s\n", strerror(errno));
		ret = 1;
		goto out;
	}

	if (child_ctx_p->pipe_read_fd >= 0) {
		close(child_ctx_p->pipe_read_fd);
		child_ctx_p->pipe_read_fd = -1;
	}

	timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK|TFD_CLOEXEC);
	if (timer_fd < 0) {
		FAC_ERR("%s\n", strerror(errno));
		ret = 1;
		goto out;
	}

	struct itimerspec nft_swap_timer = {};
	nft_swap_timer.it_interval.tv_sec = child_ctx_p->conf_p->lim_swap_time;
	nft_swap_timer.it_value.tv_sec = child_ctx_p->conf_p->lim_swap_time;

	ret = timerfd_settime(timer_fd, 0, &nft_swap_timer, nullptr);
	if (ret < 0) {
		FAC_ERR("%s\n", strerror(errno));
		ret = 1;
		goto out;
	}

	constexpr u32 max_event = 32;
	struct epoll_event fws_ctl = {};
	struct epoll_event fws_event[max_event] = {};
	fws_epfd = epoll_create1(0);
	if (fws_epfd < 0) {
		FAC_ERR("%s\n", strerror(errno));
		ret = 1;
		goto out;
	}

	http_data_ctx_p = calloc(1, sizeof(struct fws_data_ctx));
	if (http_data_ctx_p == nullptr) {
		FAC_ERR("%s\n", strerror(errno));
		ret = 1;
		goto out;
	}
	http_data_ctx_p->conf_p = child_ctx_p->conf_p;
	http_data_ctx_p->ssl_ctx_opq_p = nullptr;
	http_data_ctx_p->fd = server_http_fd;
	fws_ctl.events = EPOLLIN;
	fws_ctl.data.ptr = http_data_ctx_p;
	ret = epoll_ctl(fws_epfd, EPOLL_CTL_ADD, server_http_fd, &fws_ctl);
	if (ret < 0) {
		FAC_ERR("%s\n", strerror(errno));
		ret = 1;
		goto out;
	}

	https_data_ctx_p = calloc(1, sizeof(struct fws_data_ctx));
	if (https_data_ctx_p == nullptr) {
		FAC_ERR("%s\n", strerror(errno));
		ret = 1;
		goto out;
	}
	https_data_ctx_p->fd = server_https_fd;
	fws_ctl.events = EPOLLIN;
	fws_ctl.data.ptr = https_data_ctx_p;
	ret = epoll_ctl(fws_epfd, EPOLL_CTL_ADD, server_https_fd, &fws_ctl);
	if (ret < 0) {
		FAC_ERR("%s\n", strerror(errno));
		ret = 1;
		goto out;
	}

	timer_data_ctx_p = calloc(1, sizeof(struct fws_data_ctx));
	if (timer_data_ctx_p == nullptr) {
		FAC_ERR("%s\n", strerror(errno));
		ret = 1;
		goto out;
	}
	timer_data_ctx_p->fd = timer_fd;
	fws_ctl.events = EPOLLIN;
	fws_ctl.data.ptr = timer_data_ctx_p;
	ret = epoll_ctl(fws_epfd, EPOLL_CTL_ADD, timer_fd, &fws_ctl);
	if (ret < 0) {
		FAC_ERR("%s\n", strerror(errno));
		ret = 1;
		goto out;
	}

	_Atomic s32 *sig_flag_p = (_Atomic s32 *) child_ctx_p->sig_flag_opq_p;
	printf("Facows start\n");
	while (true) {
		errno = 0;
		s32 event_n = epoll_wait(fws_epfd, fws_event, max_event, -1);
		bool sig_cond = (*sig_flag_p == SIGINT) || (*sig_flag_p == SIGTERM);
		if (event_n < 0 || sig_cond) {
			break;
		}

		for (s32 i=0; i<event_n; i++) {
			struct sockaddr_in6 client_addr = {};
			u32 client_addr_len = (u32)sizeof(client_addr);
			struct fws_data_ctx *data_ctx_p = fws_event[i].data.ptr;
			if (data_ctx_p->fd == server_http_fd) {
				/* SECTION: Server 80 */
				client_http_fd = accept4(server_http_fd, (struct sockaddr*)&client_addr,
						&client_addr_len, SOCK_NONBLOCK|SOCK_CLOEXEC);
				if (client_http_fd < 0) {
					if (errno == EAGAIN) {
						break;
					}
					FAC_ERR("%s: %d\n", strerror(errno), client_http_fd);
					break;
				}

				struct fws_data_ctx *ctl_data_ctx_p = calloc(1, sizeof(struct fws_data_ctx));
				if (ctl_data_ctx_p == nullptr) {
					FAC_ERR("%s\n", strerror(errno));
					ret = 1;
					goto out;
				}
				ctl_data_ctx_p->conf_p = child_ctx_p->conf_p;
				ctl_data_ctx_p->fd = client_http_fd;
				ctl_data_ctx_p->ssl_ctx_opq_p = nullptr;

				fws_ctl.events = EPOLLIN;
				fws_ctl.data.ptr = ctl_data_ctx_p;
				ret = epoll_ctl(fws_epfd, EPOLL_CTL_ADD, client_http_fd, &fws_ctl);
				if (ret < 0) {
					FAC_ERR("%s\n", strerror(errno));
					close(client_http_fd);
					client_http_fd = -1;
					free(ctl_data_ctx_p);
					ctl_data_ctx_p = nullptr;
					break;
				}
				continue;

			} else if (data_ctx_p->fd == server_https_fd) {
				/* SECTION: Server 443 */
				client_fd = accept4(server_https_fd, (struct sockaddr*)&client_addr,
						&client_addr_len, SOCK_NONBLOCK|SOCK_CLOEXEC);
				if (client_fd < 0) {
					if (errno == EAGAIN) {
						break;
					}
					FAC_ERR("%s: %d\n", strerror(errno), client_fd);
					break;
				}
				int one = 1;
				ret = setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, &one, (u32)sizeof(one));
				if (ret < 0) {
					FAC_ERR("%s\n", strerror(errno));
					ret = 1;
					goto out;
				}

				struct fws_data_ctx *ctl_data_ctx_p = calloc(1, sizeof(struct fws_data_ctx));
				if (ctl_data_ctx_p == nullptr) {
					FAC_ERR("%s\n", strerror(errno));
					ret = 1;
					goto out;
				}
				memcpy(ctl_data_ctx_p->client_ip_buf, client_addr.sin6_addr.s6_addr,
						sizeof(client_addr.sin6_addr.s6_addr));
				ctl_data_ctx_p->write_fd = child_ctx_p->pipe_write_fd;
				ctl_data_ctx_p->nft_arr_p = nft_arr_p;
				ctl_data_ctx_p->sig_flag_opq_p = (s32*)sig_flag_p;
				ctl_data_ctx_p->conf_p = child_ctx_p->conf_p;
				ctl_data_ctx_p->fd = client_fd;
				ctl_data_ctx_p->ssl_ctx_opq_p = (u8*)ssl_ctx_p;
				ctl_data_ctx_p->epfd = fws_epfd;
				ctl_data_ctx_p->ctl_opq_p = (u8*)&fws_ctl;

				fws_ctl.events = EPOLLIN;
				fws_ctl.data.ptr = ctl_data_ctx_p;
				ret = epoll_ctl(fws_epfd, EPOLL_CTL_ADD, client_fd, &fws_ctl);
				if (ret < 0) {
					close(client_fd);
					client_fd = -1;
					free(ctl_data_ctx_p);
					ctl_data_ctx_p = nullptr;
					break;
				}
				continue;

			} else if (data_ctx_p->fd == timer_fd) {
				/* SECTION: Timer */
				u64 timer_event_free = 0;
				ret = read(timer_fd, &timer_event_free, sizeof(timer_event_free));
				if (ret < 0) {
					if (errno == EAGAIN) {
						break;
					}
					FAC_ERR("%s\n", strerror(errno));
					break;
				}
				memset(nft_arr_p, 0, sizeof(struct fws_nft)*nft_arr_cap);
				continue;
			}

			/* SECTION: Client */
			if (data_ctx_p->ssl_ctx_opq_p == nullptr) {
				client_http_fd = -1;
				ret = _fws_80_run(data_ctx_p);
			} else {
				client_fd = -1;
				ret = _fws_443_run(data_ctx_p);
			}
		}
	}

	ret = 0;
out:
	SSL_CTX_free(ssl_ctx_p);
	ssl_ctx_p = nullptr;
	free(nft_arr_p);
	nft_arr_p = nullptr;
	free(http_data_ctx_p);
	http_data_ctx_p = nullptr;
	free(https_data_ctx_p);
	https_data_ctx_p = nullptr;
	free(timer_data_ctx_p);
	timer_data_ctx_p = nullptr;

	if (client_http_fd >= 0) {
		close(client_http_fd);
		client_http_fd = -1;
	}
	if (client_fd >= 0) {
		close(client_fd);
		client_fd = -1;
	}

	if (timer_fd >= 0) {
		close(timer_fd);
		timer_fd = -1;
	}
	if (server_http_fd >= 0) {
		close(server_http_fd);
		server_http_fd = -1;
	}
	if (server_https_fd >= 0) {
		close(server_https_fd);
		server_https_fd = -1;
	}
	if (fws_epfd >= 0) {
		close(fws_epfd);
		fws_epfd = -1;
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
	struct nft_ctx *nft_ctx = nullptr;
	s32 log_fd = -1;
	s32 ep_fd = -1;
	s32 ret = -1;

	if (parent_ctx_p->pipe_write_fd >= 0) {
		close(parent_ctx_p->pipe_write_fd);
		parent_ctx_p->pipe_write_fd = -1;
	}

	nft_ctx = nft_ctx_new(NFT_CTX_DEFAULT);
	if (nft_ctx == nullptr) {
		FAC_ERR("%s\n", strerror(errno));
		ret = -1;
		goto out;
	}

	static constexpr u32 web_log_n = sizeof(((struct fws_conf*)nullptr)->web_log);
	char log_path_buf[256] = {};
	char *p = log_path_buf;
	memcpy(p, parent_ctx_p->conf_p->web_log, strnlen(parent_ctx_p->conf_p->web_log, web_log_n));
	p += strnlen(parent_ctx_p->conf_p->web_log, web_log_n);
	static constexpr char log_file_str[] = "/facows.log";
	memcpy(p, log_file_str, sizeof(log_file_str)-1);
	p += sizeof(log_file_str) - 1;
	*p = '\0';

	log_fd = open(log_path_buf, (O_WRONLY|O_APPEND|O_CREAT), 0640);
	if (log_fd < 0) {
		FAC_ERR("%s\n", strerror(errno));
		ret = -1;
		goto out;
	}

	struct epoll_event ep_ctl = {};
	struct epoll_event ep_event = {};
	ep_fd = epoll_create1(0);
	ep_ctl.events = EPOLLIN;
	ep_ctl.data.fd = parent_ctx_p->pipe_read_fd;
	ret = epoll_ctl(ep_fd, EPOLL_CTL_ADD, parent_ctx_p->pipe_read_fd, &ep_ctl);
	if (ret < 0) {
		FAC_ERR("%s\n", strerror(errno));
		ret = -1;
		goto out;
	}

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
			FAC_ERR("%s\n", strerror(errno));
			ret = -1;
			goto out;
		}

		if (ep_event.events & (EPOLLIN|EPOLLHUP)) {
			char read_buf[8192] = {};
			s32 read_flag = 0;
			s32 read_acc = 0;
			while (true) {
				s32 ret = read(ep_event.data.fd, read_buf, sizeof(read_buf)-1);
				if (ret <= 0) {
					if (ret == 0) {
						read_flag = 2;
						break;
					}
					if (errno == EAGAIN) {
						break;
					}
					FAC_ERR("%s, read_acc: %d\n", strerror(errno), read_acc);
					if (ep_event.events & EPOLLHUP) {
						FAC_ERR("EPOLLHUP\n");
						read_flag = 2;
						break;
					}
					read_flag = 1;
					continue;
				}
				read_acc += ret;
			}
			if (read_flag == 1) {
				continue;
			} else if (read_flag == 2) {
				break;
			}
			read_buf[read_acc] = '\0';

			bool is_continue = false;
			const char *p = read_buf;
			while (read_acc > 0) {
				u64 n = strnlen(p, (u64)read_acc);
				if (n == (u64)read_acc) {
					FAC_ERR(FAC_ERR_LEN);
					is_continue = true;
					break;
				}

				if (*p == '1') {
					net_nft_dos_ban(parent_ctx_p->conf_p, nft_ctx, p+1, parent_ctx_p->conf_p->ban_time);
				} else if (*p == '2') {
					ret = write(log_fd, p+1, n-1);
					if (ret < 0) {
						FAC_ERR("%s\n", strerror(errno));
					}
					fdatasync(log_fd);
				} else {
					FAC_ERR("unknown header: %s\n", p);
					is_continue = true;
					break;
				}

				p += (n + 1);
				read_acc -= (n + 1);
			}
			if (is_continue) {
				continue;
			}

		} else {
			FAC_ERR("not EPOLLIN or EPOLLHUP, event: %u\n", ep_event.events);
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
	if (ret < 0) {
		FAC_ERR("%s\n", strerror(errno));
		ret = -1;
		goto out;
	}
	if (parent_ctx_p->conf_p->use_nft) {
		ret = net_nft_fini(parent_ctx_p->conf_p);
		if (ret < 0) {
			ret = -1;
			goto out;
		}
	}

	ret = 0;
out:
	if (nft_ctx != nullptr) {
		nft_ctx_free(nft_ctx);
		nft_ctx = nullptr;
	}
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

	struct timeval sock_tv = {};
	sock_tv.tv_sec = 2;
	sock_tv.tv_usec = 0;
	ret = setsockopt(data_ctx_p->fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&sock_tv, sizeof(sock_tv));
	if (ret < 0) {
		FAC_ERR("%s\n", strerror(errno));
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
	SSL *ssl = nullptr;
	s32 ret = -1;
	enum ssl_stat {SSL_STATUS_NEW, SSL_STATUS_INIT, SSL_STATUS_ACCEPT,
		SSL_STATUS_WANT_READ, SSL_STATUS_WANT_WRITE};
	constexpr u32 logSSL = 0;
	constexpr u32 logKTLS = 1;
	constexpr u32 logRead = 2;
	constexpr u32 logReqParse = 3;
	constexpr u32 logErrSSL = 4;
	constexpr u32 logErrSyscall = 5;

	const u8 *client_ip_buf = data_ctx_p->client_ip_buf;
	char ip_buf[INET6_ADDRSTRLEN] = {};
	inet_ntop(AF_INET6, client_ip_buf, ip_buf, INET6_ADDRSTRLEN);

	s64 raw_time = {};
	struct tm *fws_time = nullptr;
	raw_time = time(nullptr);
	if (raw_time == (s64)-1) {
		FAC_ERR("%s\n", strerror(errno));
		ret = -1;
		goto out;
	}
	fws_time = gmtime(&raw_time);
	if (fws_time == nullptr) {
		FAC_ERR("%s\n", strerror(errno));
		ret = -1;
		goto out;
	}
	char time_buf[16] = {};
	u64 strftime_ret = strftime(time_buf, sizeof(time_buf), "%Y%m%d%H%M%S", fws_time);
	if (strftime_ret == 0) {
		FAC_ERR(FAC_ERR_LEN);
		ret = -1;
		goto out;
	}

	char log_buf[1024] = {};
	memset(log_buf, 0, sizeof(log_buf));
	s32 log_acc = snprintf(log_buf, sizeof(log_buf), "%d%s %s", 2, ip_buf, time_buf);
	if (log_acc < 0) {
		FAC_ERR("output error\n");
		ret = -1;
		goto out;
	} else if ((u64)log_acc >= sizeof(log_buf)) {
		FAC_ERR(FAC_ERR_LEN);
		ret = -1;
		goto out;
	}

	char err_buf[256] = {};
	u64 err_code = 0;
	u32 log_flag = 0;
	if (data_ctx_p->ssl_status == SSL_STATUS_NEW) {
		SSL_CTX *ssl_ctx_p = (SSL_CTX *) data_ctx_p->ssl_ctx_opq_p;
		ERR_clear_error();
		ssl = SSL_new(ssl_ctx_p);
		if (ssl == nullptr) {
			err_code = ERR_get_error();
			ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
			FAC_ERR("%s\n", err_buf);
			log_flag |= (1 << logSSL);
			ret = -1;
			goto out;
		}
	
		ERR_clear_error();
		ret = SSL_set_fd(ssl, data_ctx_p->fd);
		if (ret == 0) {
			err_code = ERR_get_error();
			ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
			FAC_ERR("%s\n", err_buf);
			log_flag |= (1 << logSSL);
			ret = -1;
			goto out;
		}
		data_ctx_p->ssl_opq_p = (u8 *) ssl;
	} else {
		ssl = (SSL *) data_ctx_p->ssl_opq_p;
	}

	if (data_ctx_p->ssl_status != SSL_STATUS_ACCEPT) {
		struct epoll_event ctl = {};
		ERR_clear_error();
		ret = SSL_accept(ssl);
		if (ret <= 0) {
			s32 ssl_err_code = SSL_get_error(ssl, ret);
			if (ssl_err_code == SSL_ERROR_WANT_READ) {
				ctl.events = EPOLLIN;
				data_ctx_p->ssl_status = SSL_STATUS_WANT_READ;
				ctl.data.ptr = data_ctx_p;
				ret = epoll_ctl(data_ctx_p->epfd, EPOLL_CTL_MOD, data_ctx_p->fd, &ctl);
				if (ret < 0) {
					FAC_ERR("%s\n", strerror(errno));
					ret = -1;
					goto out;
				}
				return ssl_err_code;

			} else if (ssl_err_code == SSL_ERROR_WANT_WRITE) {
				ctl.events = EPOLLOUT;
				data_ctx_p->ssl_status = SSL_STATUS_WANT_WRITE;
				ctl.data.ptr = data_ctx_p;
				ret = epoll_ctl(data_ctx_p->epfd, EPOLL_CTL_MOD, data_ctx_p->fd, &ctl);
				if (ret < 0) {
					FAC_ERR("%s\n", strerror(errno));
					ret = -1;
					goto out;
				}
				return ssl_err_code;
			}

			log_flag |= (1 << logSSL);
			if (ssl_err_code == SSL_ERROR_SSL) {
				log_flag |= (1 << logErrSSL);
			} else if (ssl_err_code == SSL_ERROR_SYSCALL) {
				log_flag |= (1 << logErrSyscall);
			}
			data_ctx_p->ssl_status = SSL_STATUS_INIT;
			ret = -1;
			goto out;
		}
		ctl.events = EPOLLIN;
		data_ctx_p->ssl_status = SSL_STATUS_ACCEPT;
		ctl.data.ptr = data_ctx_p;
		ret = epoll_ctl(data_ctx_p->epfd, EPOLL_CTL_MOD, data_ctx_p->fd, &ctl);
		if (ret < 0) {
			FAC_ERR("%s\n", strerror(errno));
			ret = -1;
			goto out;
		}
	}

	const struct fws_conf *conf_p = data_ctx_p->conf_p;
	if (conf_p->use_ktls) {
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
	}

	struct fws_http_req http_req = {};
	while (true) {
		if (data_ctx_p->want_write == 1) {
			goto write;
		}
		ret = net_443_read(data_ctx_p);
		if (ret < 0) {
			data_ctx_p->want_write = 0;
			data_ctx_p->file_len = 0;
			log_flag |= (1 << logRead);
			ret = -1;
			goto out;
		} else if (ret == 0) {
			ret = 1;
			goto out;
		}

		ret = net_http_req_parse(data_ctx_p->req_buf, &http_req, conf_p->domain, sizeof(conf_p->domain));
		if (ret != 0) {
			log_flag |= (1 << logReqParse);
			ret = -1;
			goto out;
		}

		/* webroot = webroot + subdomain */
		char web_root_buf[256] = {};
		char *web_root_buf_p = web_root_buf;
		u64 conf_web_root_len = strnlen(conf_p->web_root, sizeof(conf_p->web_root));
		if (conf_web_root_len == sizeof(conf_p->web_root)) {
			FAC_ERR(FAC_ERR_LEN);
			ret = -1;
			goto out;
		}
		memcpy(web_root_buf_p, conf_p->web_root, conf_web_root_len);
		web_root_buf_p += conf_web_root_len;
		*web_root_buf_p = '\0';
		if (http_req.subdomain[0] != '\0') {
			*web_root_buf_p = '/';
			web_root_buf_p++;
			u64 req_subdomain_len = strnlen(http_req.subdomain, sizeof(http_req.subdomain));
			if (req_subdomain_len == sizeof(http_req.subdomain)) {
				FAC_ERR(FAC_ERR_LEN);
				ret = -1;
				goto out;
			}
			memcpy(web_root_buf_p, http_req.subdomain, req_subdomain_len);
			web_root_buf_p += req_subdomain_len;
			*web_root_buf_p = '\0';
		}

		struct fws_file file = {};
		s32 status_code = file_parse(&file, &http_req, web_root_buf, sizeof(web_root_buf));
		if (status_code == 301) {
			net_http_path_redir(&http_req, conf_p, &file, data_ctx_p);
			ret = -1;
			goto out;
		} else if (status_code < 0) {
			ret = -1;
			goto out;
		}

		bool is_html = false;
		u64 path_n = strnlen(file.path, sizeof(file.path));
		if (path_n == sizeof(file.path)) {
			FAC_ERR(FAC_ERR_LEN);
			ret = -1;
			goto out;
		}
		static const char html_ext_str[] = ".html";
		char *path_p = file.path + path_n - (sizeof(html_ext_str) - 1);
		ret = memcmp(path_p, html_ext_str, sizeof(html_ext_str));
		if (ret == 0) {
			is_html = true;
		}
		memcpy(data_ctx_p->file_path, file.path, path_n+1);

		/* get nft_i */
		struct fws_nft *nft_arr = data_ctx_p->nft_arr_p;
		u32 nft_i = 0;
		for (u64 i=0; i<nft_arr_cap; i++) {
			s32 ip_cmp = memcmp(nft_arr[i].ip_buf, client_ip_buf, 16);
			if (ip_cmp == 0) {
				nft_i = i;
				break;
			}

			static constexpr char empty_ip_buf[16] = {};
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
				char nft_buf[INET6_ADDRSTRLEN+1] = {};
				s32 nft_n = snprintf(nft_buf, sizeof(nft_buf)-1, "%d%s", 1, ip_buf);
				if ((u32)nft_n >= sizeof(nft_buf)) {
					FAC_ERR(FAC_ERR_LEN);
					ret = -1;
					goto out;
				}
				nft_buf[nft_n] = '\0';
				ret = write(data_ctx_p->write_fd, nft_buf, nft_n+1);
				if (ret < 0) {
					FAC_ERR("%s\n", strerror(errno));
				}
			}

			status_code = 429;
			ret = net_443_err_write(data_ctx_p, status_code);
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

		if (status_code != 0) {
			ret = net_443_err_write(data_ctx_p, status_code);
			if (ret < 0) {
				ret = -1;
				goto out;
			}

		} else {
			struct fws_http_res http_res = {};
			s32 res_ret = net_http_res_build(conf_p, fws_time,  &http_req, &http_res,
					file.path, sizeof(file.path));

			if (http_req.origin[0] != '\0') {
				http_res.is_origin_self = net_http_origin_self_check(&http_req, conf_p);
			}
			if (conf_p->use_hsts) {
				http_res.hsts_max_age = conf_p->hsts_max_age;
			}
			ret = net_443_res_write(data_ctx_p, &http_res, file.size, &http_req);
			if (ret != 0) {
				ret = -1;
				goto out;
			}
			if (res_ret == 304) {
				ret = 0;
				goto out;
			}
write:
			data_ctx_p->want_write = 0;
			ret = net_443_file_write(data_ctx_p, data_ctx_p->file_path);
			if (ret == 1) {
				data_ctx_p->want_write = 1;
				ret = 1;
				goto out;
			}
		}
	}

	ret = 0;
out:
	if (data_ctx_p->ssl_status == SSL_STATUS_ACCEPT) {
		if ((u64)log_acc > sizeof(log_buf)-1) {
			FAC_ERR("log fail to record\n");
		} else {
			log_acc += snprintf(log_buf+log_acc, sizeof(log_buf)-log_acc, "%02u %s %s %s %s %s %s %s\n",
					log_flag, http_req.version, http_req.method, http_req.subdomain,
					http_req.uri, http_req.lang, http_req.os, http_req.browser);
		}

		if ((u64)log_acc > sizeof(log_buf)-1) {
			FAC_ERR("log fail to record\n");
		} else {
			log_buf[log_acc] = '\0';
			const s32 write_ret = write(data_ctx_p->write_fd, log_buf, log_acc+1);
			if (write_ret < 0) {
				FAC_ERR("%s\n", strerror(errno));
			}
		}
	}

	if (ret <= 0) {
		epoll_ctl(data_ctx_p->epfd, EPOLL_CTL_DEL, data_ctx_p->fd, nullptr);

		if (data_ctx_p->ssl_status == SSL_STATUS_ACCEPT) {
			SSL_shutdown(ssl);
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
