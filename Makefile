CC = gcc
CFLAGS = -Wall -g -fPIC
# build
build: sniffer spoofer gateway snifferAndSpoofer

all: clean build


clean:
	rm -f *.o sniffer spoofer gateway snifferAndSpoofer

gateway:
	gcc -o gateway gateway.c -Wall -g -fPIC -lpcap

sniffer: sniffer.o
	$(CC) $(CFLAGS) $^ -o $@ -lpcap

spoofer: spoofer.o
	$(CC) $(CFLAGS) $^ -o $@ -lpcap

snifferAndSpoofer : snifferAndSpoofer.o
		$(CC) $(CFLAGS) $^ -o $@ -lpcap


%.o:%.c
	$(CC) $(CFLAGS) -c $^ -o $@


clean:
	rm -f *.o sniffer spoofer gateway snifferAndSpoofer




