# SPDX-License-Identifier: MIT
#
# Copyright 2026 Facooya and Fanone Facooya

SRCS = \
lib/utils.c \
src/conf.c \
src/net.c \
src/net_80.c \
src/net_443.c \
src/http.c \
src/file.c \
src/nft.c \
src/tc.c \
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
