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
src/net_tc.c \
\
src/file.c \
src/file_conf.c

OBJS = $(SRCS:%.c=build/%.o)

all: build/facows

build/facows: $(OBJS)
	gcc -pthread -o $@ $^ -lssl -lcrypto -lnftables -lkmod

build/%.o: %.c | build/
	mkdir -p $(dir $@)
	gcc -Isrc -Iinclude -Ilib -c $< -o $@

build/:
	mkdir -p $@

clean:
	find build/ -name "*.o" -delete
	find build/ -type d -empty -delete

clean_all: clean
	find build/ -name "facows" -delete
	find build/ -type d -empty -delete
