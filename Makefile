all:
	mkdir -p ./build
	gcc -o ./build/facows facows.c -lssl -lcrypto
