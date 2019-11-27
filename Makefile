CC=gcc
CFLAGS=-Wall -Wextra -g -std=gnu99

.PHONY: all clean
all: daemon transportdaemon client server 

daemon: daemon.c
	$(CC) $(CFLAGS) $^ -o $@ 
	sudo setcap CAP_NET_RAW=ep $@

transportdaemon: transportdaemon.c
	$(CC) $(CFLAGS) $^ -o $@ 

client: client.c
	$(CC) $(CFLAGS) $^ -o $@ 

server: server.c
	$(CC) $(CFLAGS) $^ -o $@ 

clean:
	rm -vf daemon transportdaemon client server
