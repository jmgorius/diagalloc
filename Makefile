.POSIX:
.SUFFIXES:

CC = clang
CFLAGS = -Wall -Wextra -fPIC -g
LDFLAGS = -shared
LDLIBS = -ldl

.PHONY: all clean

all: logalloc.so

clean:
	rm -f logalloc.so

logalloc.so: logalloc.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)
