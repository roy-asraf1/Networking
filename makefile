FLAGS = -Wall -g
CC = gcc
all: sniffer spoofing


sniffer: 
	$(CC) $(FLAGS) sniffer.c -o sniffer -lpcap

spoofing:
	$(CC) $(FLAGS) spoofing.c -o spoofing

clean:
	rm -f *.o *.a *.so sniffer spoofing