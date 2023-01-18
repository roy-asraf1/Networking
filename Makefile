CC = gcc
CFLAGS = -Wall -g -fPIC

all: sniffer spoofer gateway


gateway:
	gcc -o gateway gateway.c -Wall -g -fPIC -lpcap

sniffer: sniffer.o
	$(CC) $(CFLAGS) $^ -o $@ -lpcap

spoofer: spoofer.o
	$(CC) $(CFLAGS) $^ -o $@ -lpcap


#------- o files-------
%.o:%.c
	$(CC) $(CFLAGS) -c $^ -o $@
#------------------------------

clean:
	rm -f *.o sniffer spoofer gateway
