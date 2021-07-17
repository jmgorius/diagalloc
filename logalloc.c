#define _GNU_SOURCE // For RTLD_NEXT
#include <dlfcn.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define C_GREY(s) "\033[90m" s "\033[0m"

// This variable is used to avoid recursively calling into the hooked version of
// malloc if the latter uses functions that call malloc internally
static __thread int no_hook = 0;

static void *(*actual_malloc)(size_t size);
static void *(*actual_calloc)(size_t nmemb, size_t size);
static void (*actual_free)(void *ptr);
static void *(*actual_realloc)(void *ptr, size_t size);

static void *(*tmp_malloc)(size_t size);
static void *(*tmp_calloc)(size_t nmemb, size_t size);
static void (*tmp_free)(void *ptr);
static void *(*tmp_realloc)(void *ptr, size_t size);

// We need to provide an initial malloc implementation as in some cases (e.g.,
// when linked with pthread) the program may allocate memory in dlsym
static void *init_malloc(size_t size) {
  static char buffer[2048];
  static unsigned pos = 0;
  void *result = buffer + pos;
  pos += size;
  return result;
}

static void *init_calloc(size_t nmemb, size_t size) {
  if (nmemb == 0 || size == 0)
    return 0;
  char *result = init_malloc(nmemb * size);
  if (result)
    memset(result, 0, nmemb * size);
  return result;
}

static void init_free(__attribute__((__unused__)) void *ptr) {}

__attribute__((__constructor__)) static void init(void) {
  actual_calloc = init_calloc;
  actual_malloc = init_malloc;
  actual_free = init_free;
  actual_realloc = 0;

#define HOOK(fn)                                                               \
  if (!(tmp_##fn = dlsym(RTLD_NEXT, #fn))) {                                   \
    fprintf(stderr, "Failed to hook '" #fn "'\n");                             \
    exit(1);                                                                   \
  }                                                                            \
  actual_##fn = tmp_##fn

  HOOK(malloc);
  HOOK(calloc);
  HOOK(free);
  HOOK(realloc);

#undef HOOK
}

struct call_info {
  enum {
    MALLOC_CALL,
    CALLOC_CALL,
    FREE_CALL,
    REALLOC_CALL,
  } type;
  union {
    struct {
      size_t size;
      void *result;
    } malloc;
    struct {
      size_t nmemb;
      size_t size;
      void *result;
    } calloc;
    struct {
      void *ptr;
    } free;
    struct {
      void *ptr;
      size_t size;
      void *result;
    } realloc;
  };
};

static void call(struct call_info *info) {
  no_hook = 1;

  void *return_addr =
      __builtin_extract_return_addr(__builtin_return_address(0));

  switch (info->type) {
  case MALLOC_CALL:
    fprintf(stderr, C_GREY("%p") " malloc(%zu) -> ", return_addr,
            info->malloc.size);
    info->malloc.result = (*actual_malloc)(info->malloc.size);
    fprintf(stderr, "%p\n", info->malloc.result);
    break;
  case CALLOC_CALL:
    fprintf(stderr, C_GREY("%p") " calloc(%zu, %zu) -> ", return_addr,
            info->calloc.nmemb, info->calloc.size);
    info->calloc.result =
        (*actual_calloc)(info->calloc.nmemb, info->calloc.size);
    fprintf(stderr, "%p\n", info->calloc.result);
    break;
  case FREE_CALL:
    fprintf(stderr, C_GREY("%p") " free(%p)\n", return_addr, info->free.ptr);
    break;
  case REALLOC_CALL:
    fprintf(stderr, C_GREY("%p") " realloc(%p, %zu) -> ", return_addr,
            info->realloc.ptr, info->realloc.size);
    info->realloc.result =
        (*actual_realloc)(info->realloc.ptr, info->realloc.size);
    fprintf(stderr, "%p\n", info->realloc.result);
    break;
  }

  no_hook = 0;
}

void *malloc(size_t size) {
  if (no_hook)
    return (*actual_malloc)(size);

  struct call_info info = {.type = MALLOC_CALL, .malloc.size = size};
  call(&info);
  return info.malloc.result;
}

void *calloc(size_t nmemb, size_t size) {
  if (no_hook)
    return (*actual_calloc)(nmemb, size);

  struct call_info info = {
      .type = CALLOC_CALL, .calloc.nmemb = nmemb, .calloc.size = size};
  call(&info);
  return info.calloc.result;
}

void free(void *ptr) {
  if (no_hook)
    return (*actual_free)(ptr);

  struct call_info info = {.type = FREE_CALL, .free.ptr = ptr};
  call(&info);
}

void *realloc(void *ptr, size_t size) {
  if (no_hook)
    return (*actual_realloc)(ptr, size);

  struct call_info info = {
      .type = REALLOC_CALL, .realloc.ptr = ptr, .realloc.size = size};
  call(&info);
  return info.realloc.result;
}
