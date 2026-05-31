# SPDX-License-Identifier: MIT
#
# Copyright 2026 Facooya and Fanone Facooya

SAN_A = address,undefined
SAN_T = thread,undefined

CC = gcc
CFLAGS_C2O = -Wall -Wextra -Werror -O0 -g -fstack-protector-all -fsanitize=$(SAN_T) -std=c11 -D_GNU_SOURCE
CFLAGS_O2B = -g -fstack-protector-all -fsanitize=$(SAN_T)

SRCS = \
lib/fac_utils.c \
\
src/facows.c \
src/fws.c \
\
src/net.c \
src/net_80.c \
src/net_443.c \
src/net_http.c \
src/net_nft.c \
\
src/file.c \
src/file_conf.c

OBJS = $(SRCS:%.c=build/%.o)
DEPS = $(OBJS:.o=.d)

all: build/facows

build/facows: $(OBJS)
	$(CC) $(CFLAGS_O2B) -pthread -o $@ $^ -lssl -lcrypto -lnftables

build/%.o: %.c | build/
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS_C2O) -MMD -MP -Isrc -Iinclude -Ilib -c $< -o $@

build/:
	mkdir -p $@

install:
	mkdir -p /var/www/facows
	mkdir -p /etc/facows
	mkdir -p /usr/share/facows

	cp build/facows /usr/local/bin/

	cp etc/facows.service /etc/systemd/system/
	systemctl daemon-reload

	if [ -f /etc/facows/facows.conf ]; \
		then cp etc/facows.conf /etc/facows/facows.conf.dist; \
		else cp etc/facows.conf /etc/facows/; fi

	if [ -f /usr/share/facows/error_page.html ]; \
		then cp share/error_page.html /usr/share/facows/error_page.html.dist; \
		else cp share/error_page.html /usr/share/facows/; fi

-include $(DEPS)

clean:
	find build/ -name "*.o" -delete
	find build/ -name "*.d" -delete
	find build/ -name "facows" -delete
	find build/ -type d -empty -delete
