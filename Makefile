.POSIX:
.SUFFIXES:

CC = clang
CFLAGS = -Wall -Wextra -fPIC -g
LDFLAGS = -shared
LDLIBS = -ldl

.PHONY: all clean

all: failalloc.so logalloc.so

clean:
	rm -f failalloc.so logalloc.so

failalloc.so: failalloc.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

logalloc.so: logalloc.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)
