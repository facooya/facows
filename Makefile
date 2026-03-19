# SPDX-License-Identifier: MIT
#
# Copyright 2026 Facooya and Fanone Facooya

all: | ./build/
	gcc -Iinc -c ./inc/conf.c -o ./build/conf.o
	gcc -Iinc -c ./inc/net.c -o ./build/net.o
	gcc -Iinc -c ./facows.c -o ./build/facows.o
	gcc -Iinc -o ./build/facows ./build/facows.o ./build/conf.o ./build/net.o -lssl -lcrypto

./build/:
	mkdir -p $@
