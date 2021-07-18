# diagalloc - Memory allocation diagnostics and testing

A set of dynamic libraries to be used with `LD_PRELOAD` to monitor and test
memory allocations.

# Building

To build the code in this repository, run
```console
$ make
```

# Usage

This repository provides a set of shared libraries that need to be used in
conjunction with `LD_PRELOAD` to override common memory allocation functions.
The following gives a brief description of each library.

## logalloc.so

The `logalloc.so` library logs all allocations to the standard error output
stream. It indicates the name of the called function, the value of the
parameters as well as the returned value.

For example,
```console
$ LD_PRELOAD=./logalloc.so ls >/dev/null
```
produces the following log.
```
0x7fac4c6cac90 malloc(5) -> 0x563c73aaf2a0
0x7fac4c6c51dc free(0x563c73aaf2a0)
...
0x7fac4c713d55 free(0x563c73ab6540)
```

## failalloc.so

The `failalloc.so` library can be used to randomly fail allocations with a
configurable failure rate. The latter is set through the `FAILALLOC_THRESHOLD`
environment variable.

For example,
```console
$ FAILALLOC_THRESHOLD=0.25 LD_PRELOAD=./failalloc.so ls >/dev/null
```
can produce
```
Failing malloc(5), called from 0x7f2bed422c90
Failing malloc(4096), called from 0x7f2bed45d564
Failing realloc((nil), 1600), called from 0x7f2bed42236e
Failing malloc(104), called from 0x7f2bed42297d
Failing malloc(34), called from 0x7f2bed41ed7f
Failing malloc(56), called from 0x55b6cdb03c9a
ls: memory exhausted
```

**Note:** `failalloc.so`'s behavior is not deterministic by nature.
