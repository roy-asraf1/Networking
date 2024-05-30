CC = gcc
CFLAGS =  -g

.PHONY: all clean

# build
clean:
	rm -f *.o partA partB watchdog

all: ping safe_ping watchdog

rebuild: clean all

# apps
ping: ping.o
	$(CC) $(CFLAGS) $< -o partA

safe_ping: safe_ping.o
	$(CC) $(CFLAGS) $< -o partB

watchdog: watchdog.o
	$(CC) $(CFLAGS) watchdog.c -o watchdog

# units
%.o: %.c
	$(CC) $(CFLAGS) -c $<
