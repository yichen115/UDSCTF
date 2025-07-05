CC=gcc
CFLAGS=-Wall -O2 -fno-pie -no-pie -Wl,-Ttext=0x40000000
OBJS=uds_server.o iso14229.o

all: uds_server

uds_server: uds_server.o iso14229.o
	$(CC) $(CFLAGS) -o uds_server uds_server.o iso14229.o

uds_server.o: uds_server.c iso14229.h
	$(CC) $(CFLAGS) -c uds_server.c

iso14229.o: iso14229.c iso14229.h
	$(CC) $(CFLAGS) -c iso14229.c

clean:
	rm -f *.o uds_server 