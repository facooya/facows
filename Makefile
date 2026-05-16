# SPDX-License-Identifier: MIT
#
# Copyright 2026 Facooya and Fanone Facooya

SRCS = \
src/facows.c \
lib/fac_utils.c \
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

all: build/facows

build/facows: $(OBJS)
	gcc -flto -fanalyzer -fstack-protector-all -fsanitize=thread,undefined -pthread -o $@ $^ -lssl -lcrypto -lnftables

build/%.o: %.c | build/
	mkdir -p $(dir $@)
	gcc -Wall -Wextra -flto -fanalyzer -fstack-protector-all -fsanitize=thread,undefined -Isrc -Iinclude -Ilib -c $< -o $@

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

clean:
	find build/ -name "*.o" -delete
	find build/ -type d -empty -delete

clean_all: clean
	find build/ -name "facows" -delete
	find build/ -type d -empty -delete
