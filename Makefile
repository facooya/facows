# SPDX-License-Identifier: MIT
#
# Copyright 2026 Facooya and Fanone Facooya

SRCS = \
lib/utils.c \
src/net.c \
src/net_80.c \
src/net_443.c \
src/net_http.c \
src/net_nft.c \
src/net_tc.c \
src/conf.c \
src/file.c \
src/facows.c

OBJS = $(SRCS:%.c=build/%.o)

all: build/facows

build/facows: $(OBJS)
	gcc -pthread -o $@ $^ -lssl -lcrypto

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
