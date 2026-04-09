# SPDX-License-Identifier: MIT
#
# Copyright 2026 Facooya and Fanone Facooya

all: | ./build/
	gcc -Isrc -c ./src/utils.c -o ./build/utils.o
	gcc -Isrc -c ./src/conf.c -o ./build/conf.o
	gcc -Isrc -c ./src/net.c -o ./build/net.o
	gcc -Isrc -c ./src/http.c -o ./build/http.o
	gcc -Isrc -c ./src/file.c -o ./build/file.o
	gcc -Isrc -c ./src/nft.c -o ./build/nft.o
	gcc -Isrc -c ./src/tc.c -o ./build/tc.o
	gcc -Isrc -c ./src/facows.c -o ./build/facows.o
	gcc -Isrc -pthread -o ./build/facows ./build/facows.o ./build/conf.o ./build/net.o ./build/http.o ./build/file.o ./build/utils.o ./build/nft.o ./build/tc.o -lssl -lcrypto

./build/:
	mkdir -p $@
