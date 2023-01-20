CC = gcc
CFLAGS = -Wall -g -fPIC
# build
build: sniffer spoofer snifferAndSpoofer

all: clean build


clean:
	rm -f *.o sniffer spoofer snifferAndSpoofer


sniffer: sniffer.o
	$(CC) $(CFLAGS) $^ -o $@ -lpcap

spoofer: spoofer.o
	$(CC) $(CFLAGS) $^ -o $@ -lpcap

snifferAndSpoofer : snifferAndSpoofer.o
		$(CC) $(CFLAGS) $^ -o $@ -lpcap


%.o:%.c
	$(CC) $(CFLAGS) -c $^ -o $@





