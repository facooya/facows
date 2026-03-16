/* SPDX-License-Identifier: MIT
 *
 * Copyright 2026 Facooya and Fanone Facooya
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <signal.h>
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <ctype.h>

#define CONF_FILE "/etc/facows/facows.conf"

#define HTTP_METHOD_SIZE 16
#define HTTP_PATH_SIZE 512
#define HTTP_VERSION_SIZE 16
#define REQ_HEADER_KEYWORD_MAX 64
#define PATH_SIZE 512
#define SUB_DOMAIN_SIZE 16
#define REQ_HEADER_LINE_MAX 512
#define REQ_UA_TYPE_MAX 16
#define CONF_KEY_MAX 16

#define ERROR_BAD_REQUEST 400
#define ERROR_FILE_NOT_FOUND 404
#define ERROR_HEADER_LARGE 431
#define ERROR_INTERNAL_SERVER 500
#define ERROR_NOT_IMPLEMENTED 501

struct Configure {
	short port;
	char domain[64];
	char web_root[64];
	char web_log[64];
	char ssl_cert[128];
	char ssl_key[128];
};

int facows_write_conf_str(char *file_buf, char *config, size_t config_str_size) {
	char *start;
	char *end;
	ptrdiff_t n;

	start = memchr(file_buf, ' ', CONF_KEY_MAX);
	if (start == NULL) {
		// conf err
		return 1;
	}

	while (*start == ' ') {
		start++;
	}

	if (*(start) != '"') {
		// conf err
		return 1;
	}

	start++;
	end = memchr(start, '"', config_str_size);
	if (end == NULL) {
		// conf err
		return 1;
	}

	n = end - start;
	strncpy(config, start, n);
	config[n] = '\0';
	return 0;
}

int facows_parse_conf(char *path, struct Configure *config) {
	char *key[] = {"PORT", "DOMAIN", "WEB_ROOT", "WEB_LOG", "SSL_CERT", "SSL_KEY"};
	FILE *conf_file = fopen(path, "r");
	char file_buf[4096];
	while (fgets(file_buf, sizeof(file_buf), conf_file)) {
		if (file_buf[0] == '#') {
			continue;
		}
		for (int i=0; i<sizeof(key)/sizeof(key[0]); i++) {
			if (strstr(file_buf, key[i]) != NULL) {
				switch (i) {
					case 0:
						char *start = memchr(file_buf, ' ', CONF_KEY_MAX);
						if (start == NULL) {
							// conf err
							return 1;
						}
						while (*start == ' ') {
							start++;
						}
						config->port = (short) atoi(start);
						break;
					case 1:
						if (facows_write_conf_str(file_buf, config->domain, sizeof(config->domain)) != 0) {
							return 1;
						}
						break;
					case 2:
						if (facows_write_conf_str(file_buf, config->web_root, sizeof(config->web_root))) {
							return 1;
						}
						break;
					case 3:
						if (facows_write_conf_str(file_buf, config->web_log, sizeof(config->web_log))) {
							return 1;
						}
						break;
					case 4:
						if (facows_write_conf_str(file_buf, config->ssl_cert, sizeof(config->ssl_cert))) {
							return 1;
						}
						break;
					case 5:
						if (facows_write_conf_str(file_buf, config->ssl_key, sizeof(config->ssl_key))) {
							return 1;
						}
						break;
				}
				break;
			}
		}
	}
	fclose(conf_file);
	return 0;
}

int ssl_init(SSL_CTX **ssl_ctx, struct Configure config) {
	SSL_library_init();
	const SSL_METHOD *ssl_method;
	ssl_method = TLS_server_method();
	*ssl_ctx = SSL_CTX_new(ssl_method);
	if (SSL_CTX_use_certificate_file(*ssl_ctx, config.ssl_cert, SSL_FILETYPE_PEM) <= 0) {
		printf("SSL ERROR certificate\n");
		return 1;
	}
	if (SSL_CTX_use_PrivateKey_file(*ssl_ctx, config.ssl_key, SSL_FILETYPE_PEM) <= 0) {
		printf("SSL ERROR private key\n");
		return 1;
	}
	return 0;
}

int socket_init_server(int *server_sock, short port) {
	struct sockaddr_in6 server_addr;
	int opt = 1;

	*server_sock = socket(AF_INET6, SOCK_STREAM, 0);
	setsockopt(*server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin6_family = AF_INET6;
	server_addr.sin6_addr = in6addr_any;
	server_addr.sin6_port = htons(port);

	bind(*server_sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
	listen(*server_sock, 128);
	return 0;
}

void err_exit(SSL *ssl, int client_sock) {
	SSL_free(ssl);
	close(client_sock);
	exit(1);
}

int request_read(SSL *ssl, char *buf, int buf_size) {
	int total_read_size = 0;
	while (1) {
		int read_ret = SSL_read(ssl, buf+total_read_size, buf_size-total_read_size-1);
		if (read_ret <= 0) {
			int err_code = SSL_get_error(ssl, read_ret);
			if (err_code == SSL_ERROR_WANT_READ) {
				continue;
			} else if (err_code == SSL_ERROR_ZERO_RETURN) {
				return 400; // Bad Request
			}
			return 500; // Internal Server Error
		}

		total_read_size += read_ret;
		buf[total_read_size] = '\0';

		if (strstr(buf, "\r\n\r\n")) {
			break;
		}

		if (total_read_size >= 4095) {
			return 431; // Request Header Fields Too Large
		}
	}
	return 0;
}

int request_parse_line(char *target_line, char *method, char *path, char *version) {
	// { method
	char *start = target_line;
	char *end = memchr(start, ' ', HTTP_METHOD_SIZE);
	if (end == NULL) {
		// err_log
		return 1;
	}
	size_t size = end - start;
	if (size >= HTTP_METHOD_SIZE) {
		// err_log
		return 1;
	}
	strncpy(method, start, size);
	method[size] = '\0';
	// }

	// { path
	start += size + 1;
	end = memchr(start, ' ', HTTP_PATH_SIZE);
	if (end == NULL) {
		// err log
		return 1;
	}
	size = end - start;
	if (size >= HTTP_PATH_SIZE) {
		// err log
		return 1;
	}
	strncpy(path, start, size);
	path[size] = '\0';
	// }

	// { version
	start += size + 1;
	end = memchr(start, '\r', HTTP_VERSION_SIZE);
	if (end == NULL) {
		// err log
		return 1;
	}
	size = end - start;
	if (size >= HTTP_VERSION_SIZE) {
		// err log
		return 1;
	}
	strncpy(version, start, size);
	version[size] = '\0';
	// }

	if (strncmp(method, "GET", strlen(method)) != 0) {
		// attack_log
		return 1; // 405 Method Not Allowed
	}
	if (strncmp(version, "HTTP/1.1", strlen(version)) != 0) {
		// warn_log
		return 1;
	}
	return 0;
}

int http_build_path(char *path, char *http_path, char *web_root) {
	char v_path[PATH_SIZE];
	strcpy(v_path, web_root);
	strcat(v_path, http_path);
	realpath(v_path, path);

	if (strlen(path) > PATH_SIZE-1) {
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

int request_parse_header(char *req_buf, char *log, char *domain) {
	char tmp_log[2048];
	char *tmp_log_start = tmp_log;
	char keyword[][REQ_HEADER_KEYWORD_MAX] = {"host", "user-agent", "accept-language"};
	char *start = req_buf;
	char *end = memmem(start, REQ_HEADER_LINE_MAX, "\r\n", 2);
	if (end == NULL) {
		// err log
		return 1;
	}
	start = end + 2;

	// { tok line
	char *parse_start[3];
	char *parse_end[3];
	int parse_size[3] = {0};
	int keyword_i = 0;
	int total_log_size = 0;

	for (int i=0; i<(sizeof(parse_start)/sizeof(*parse_start)); i++) {
		parse_start[i] = start;
		parse_end[i] = start;
	}

	while (1) {
		if (strncmp(start, "\r\n", 2) == 0) {
			break;
		}

		char *keyword_end = memchr(start, ':', REQ_HEADER_KEYWORD_MAX);
		if (keyword_end == NULL) {
			// attack log
			return 1;
		}

		char *value_end;
		for (int i=0; i<(sizeof(keyword)/REQ_HEADER_KEYWORD_MAX); i++) {
			if (strncasecmp(start, keyword[i], strlen(keyword[i])) == 0) {
				value_end = memmem(start, 512, "\r\n", 2);
				if (value_end == NULL) {
					// attack log
					return 1;
				}
				int n = value_end - start;
				parse_start[keyword_i] = tmp_log_start;
				parse_end[keyword_i] = tmp_log_start + n;
				parse_size[keyword_i] = n;
				keyword_i++;

				strncpy(tmp_log_start, start, n);
				total_log_size += n + 1;
				tmp_log_start += n + 1;
				tmp_log[total_log_size-1] = '\n';
				break;
			}
		}

		value_end = memmem(start, 512, "\r\n", 2);
		if (value_end == NULL) {
			// err log
			return 1;
		}
		start = value_end + 2;
	}
	tmp_log[total_log_size] = '\0';
	// }

	// { normalize
	for (int i=0; i<strlen(tmp_log); i++) {
		tmp_log[i] = tolower(tmp_log[i]);
	}
	// }

	// {{ parse
	// { host
	start = tmp_log;
	keyword_i = -1;
	for (int i=0; i<(sizeof(keyword)/REQ_HEADER_KEYWORD_MAX); i++) {
		if (strncmp(parse_start[i], keyword[0], strlen(keyword[0])) == 0) {
			keyword_i = i;
			break;
		}
	}

	if (keyword_i == -1) {
		// err log
		return 1;
	}
	start = parse_start[keyword_i];
	end = memchr(start, ':', REQ_HEADER_KEYWORD_MAX);
	if (end == NULL) {
		// err log
		return 1;
	}

	int size = end - start;
	start += size + 1;

	while (*start == ' ') {
		start++;
	}

	end = memmem(start, 64, "\n", 1);
	if (end == NULL) {
		// err log
		return 1;
	}
	size = end - start;
	char *target = memmem(start, size, domain, strlen(domain));

	if (target == NULL) {
		// err log
		return 1;
	}

	size = target - start;
	if (size == 0) {
		strcat(log, "www");
	}

	strncat(log, start, size-1);
	strcat(log, " ");
	// }
	// { accept language
	start = tmp_log;
	keyword_i = -1;
	for (int i=0; i<(sizeof(keyword)/REQ_HEADER_KEYWORD_MAX); i++) {
		if (strncmp(parse_start[i], keyword[2], strlen(keyword[2])) == 0) {
			keyword_i = i;
			break;
		}
	}

	if (keyword_i != -1) {
		start = parse_start[keyword_i];
		end = memchr(start, ':', REQ_HEADER_KEYWORD_MAX);
		if (end == NULL) {
			return 1;
		}
		size = end - start;
		start += size + 1;
		while (*start == ' ') {
			start++;
		}

		end = start;
		while (1) {
			if (*end == ',') {
				break;
			} else if (*end == ';') {
				break;
			} else if (*end == '\n') {
				break;
			}
			end++;
		}

		size = end - start;
		strncat(log, start, size);
	} else {
		strcat(log, "- ");
	}
	// }
	// { user agent
	char os_type[][REQ_UA_TYPE_MAX] = {"android", "windows", "iphone", "ipad", "macintoch", "linux"};
	char browser_type[][REQ_UA_TYPE_MAX] = {"firefox", "edg", "chrome", "safari"};
	start = tmp_log;
	keyword_i = -1;
	for (int i=0; i<(sizeof(keyword)/REQ_HEADER_KEYWORD_MAX); i++) {
		if (strncmp(parse_start[i], keyword[1], strlen(keyword[1])) == 0) {
			keyword_i = i;
			break;
		}
	}

	if (keyword_i != -1) {

	} else {
		strcat(log, "- ");
	}
	// }
	// }}

	return 0;
}

int respone_build_path(char *path, int *size) {
	struct stat st;
	if (stat(path, &st) != 0) {
		char html_str[] = ".html";
		strcat(path, html_str);
		if (stat(path, &st) != 0) {
			// warn log
			return 404;
		}
	}
	*size = st.st_size;

	char index_str[] = "index.html";
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

int respone_send_status(SSL *ssl, char *path, int file_size) {
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

int respone_send_file(SSL *ssl, char *path) {
	int fd = open(path, O_RDONLY);
	char file_buf[4096];
	ssize_t read_bytes;
	while (read_bytes = read(fd, file_buf, sizeof(file_buf))) {
		if (SSL_write(ssl, file_buf, read_bytes) <= 0) {
			return 1;
		}
	}
	close(fd);
	return 0;
}

int main() {
	// { init
	struct Configure config;
	if (facows_parse_conf(CONF_FILE, &config) != 0) {
		// conf err
		return 0;
	}

	char request_buf[4096];
	char log[1024];
	signal(SIGCHLD, SIG_IGN);

	SSL_CTX *ssl_ctx;
	ssl_init(&ssl_ctx, config);

	int server_sock;
	socket_init_server(&server_sock, config.port);

	int client_sock;
	struct sockaddr_storage client_addr;
	socklen_t client_addr_size = sizeof(client_addr);
	// }

	while (1) {
		client_sock = accept(server_sock, (struct sockaddr*)&client_addr, &client_addr_size);
		pid_t pid = fork();

		if (pid == 0) {
			// { init
			close(server_sock);
			SSL *ssl = SSL_new(ssl_ctx);
			SSL_set_fd(ssl, client_sock);
			if (SSL_accept(ssl) <= 0) {
				err_exit(ssl, client_sock);
			}
			// }

			// { ip
			char ip_buf[INET6_ADDRSTRLEN];
			if (client_addr.ss_family == AF_INET) {
				struct sockaddr_in *ipv4 = (struct sockaddr_in *) &client_addr;
				inet_ntop(client_addr.ss_family, &(ipv4->sin_addr), ip_buf, sizeof(ip_buf));
			} else if (client_addr.ss_family == AF_INET6) {
				struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *) &client_addr;
				inet_ntop(client_addr.ss_family, &(ipv6->sin6_addr), ip_buf, sizeof(ip_buf));
			} else {
				err_exit(ssl, client_sock);
			}
			printf("IP: %s\n", ip_buf);
			// }

			while (1) {
				// { request_read()
				if (request_read(ssl, request_buf, sizeof(request_buf)) != 0) {
					err_exit(ssl, client_sock);
				}
				// }

				// { requset_parse_line()
				char http_method[HTTP_METHOD_SIZE];
				char http_path[HTTP_PATH_SIZE];
				char http_version[HTTP_VERSION_SIZE];
				if (request_parse_line(request_buf, http_method, http_path, http_version) != 0) {
					err_exit(ssl, client_sock);
				}
				// }

				// { http_build_path()
				char path[512];
				if (http_build_path(path, http_path, config.web_root) != 0) {
					err_exit(ssl, client_sock);
				}
				// }

				// { request_parse_header()
				if (request_parse_header(request_buf, log, config.domain) != 0) {
					err_exit(ssl, client_sock);
				}
				// }

				int file_size = 0;
				int status_code = respone_build_path(path, &file_size);
				if (status_code == 404) {
					char status[1024] = {0};
					char v_path[512];
					long file_404_size = 0;
					char path_tmp[] = "/404.html";
					struct stat st_tmp;
					strncpy(v_path, config.web_root, sizeof(config.web_root));
					strcat(v_path, path_tmp);
					realpath(v_path, path);
					stat(path, &st_tmp);
					file_404_size = st_tmp.st_size;

					snprintf(status, sizeof(status), "HTTP/1.1 404 File Not Found\r\nContent-Type: text/html\r\nContent-Length: %ld\r\n\r\n", file_404_size);
					SSL_write(ssl, status, strlen(status));
					respone_send_file(ssl, path);

					SSL_free(ssl);
					close(client_sock);
					exit(0);
				}

				if (respone_send_status(ssl, path, file_size) != 0) {
					// warn log
					err_exit(ssl, client_sock);
				}
				respone_send_file(ssl, path);
			}

			SSL_shutdown(ssl);
			SSL_free(ssl);
			close(client_sock);
			exit(0);

		} else if (pid > 0) {
			close(client_sock);
		} else {
			close(client_sock);
		}
	}

	close(server_sock);
	return 0;
}
