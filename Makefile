CC = gcc
CFLAGS = -Wall -g -fPIC



gateway:
	gcc -o gateway gateway.c -Wall -g -fPIC -lpcap

sniffer: sniffer.o
	$(CC) $(CFLAGS) $^ -o $@ -lpcap

spoofer: spoofer.o
	$(CC) $(CFLAGS) $^ -o $@ -lpcap

snifferAndSpoofer : snifferAndSpoofer.o
		$(CC) $(CFLAGS) $^ -o $@ -lpcap



#------- o files-------
%.o:%.c
	$(CC) $(CFLAGS) -c $^ -o $@
#------------------------------

clean:
	rm -f *.o sniffer spoofer gateway snifferAndSpoofer


docker-build:
	docker-compose build

docker-up:
	docker-compose up -d

docker-rebuild:
	docker-compose build
	docker-compose up -d

# build
build: sniffer spoofer gateway snifferAndSpoofer

all: clean build

# testing
test-example:
	sudo docker-compose exec attacker ./sniffer

test-example-2:
	sudo docker-compose exec attacker ./spoofer arg-a arg-b
