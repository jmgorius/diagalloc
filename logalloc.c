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
static void *(*actual_memalign)(size_t alignment, size_t size);
static void *(*actual_pvalloc)(size_t size);
static int (*actual_posix_memalign)(void **memptr, size_t alignment,
                                    size_t size);
static void *(*actual_aligned_alloc)(size_t alignment, size_t size);
static void *(*actual_valloc)(size_t size);

static void *(*tmp_malloc)(size_t size);
static void *(*tmp_calloc)(size_t nmemb, size_t size);
static void (*tmp_free)(void *ptr);
static void *(*tmp_realloc)(void *ptr, size_t size);
static void *(*tmp_memalign)(size_t alignment, size_t size);
static void *(*tmp_pvalloc)(size_t size);
static int (*tmp_posix_memalign)(void **memptr, size_t alignment, size_t size);
static void *(*tmp_aligned_alloc)(size_t alignment, size_t size);
static void *(*tmp_valloc)(size_t size);

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
  actual_memalign = 0;
  actual_pvalloc = 0;
  actual_posix_memalign = 0;
  actual_aligned_alloc = 0;

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
  HOOK(memalign);
  HOOK(pvalloc);
  HOOK(posix_memalign);
  HOOK(aligned_alloc);
  HOOK(valloc);

#undef HOOK
}

struct call_info {
  enum {
    MALLOC_CALL,
    CALLOC_CALL,
    FREE_CALL,
    REALLOC_CALL,
    MEMALIGN_CALL,
    PVALLOC_CALL,
    POSIX_MEMALIGN_CALL,
    ALIGNED_ALLOC_CALL,
    VALLOC_CALL,
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
    struct {
      size_t alignment;
      size_t size;
      void *result;
    } memalign;
    struct {
      size_t size;
      void *result;
    } pvalloc;
    struct {
      void **memptr;
      size_t alignment;
      size_t size;
      int result;
    } posix_memalign;
    struct {
      size_t alignment;
      size_t size;
      void *result;
    } aligned_alloc;
    struct {
      size_t size;
      void *result;
    } valloc;
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
  case MEMALIGN_CALL:
    fprintf(stderr, C_GREY("%p") " memalign(%zu, %zu) -> ", return_addr,
            info->memalign.alignment, info->memalign.alignment);
    info->memalign.result =
        (*actual_memalign)(info->memalign.alignment, info->memalign.size);
    fprintf(stderr, "%p\n", info->memalign.result);
    break;
  case PVALLOC_CALL:
    fprintf(stderr, C_GREY("%p") " pvalloc(%zu) -> ", return_addr,
            info->pvalloc.size);
    info->pvalloc.result = (*actual_pvalloc)(info->pvalloc.size);
    fprintf(stderr, "%p\n", info->pvalloc.result);
    break;
  case POSIX_MEMALIGN_CALL:
    fprintf(stderr, C_GREY("%p") " posix_memalign(%p, %zu, %zu) -> ",
            return_addr, info->posix_memalign.memptr,
            info->posix_memalign.alignment, info->posix_memalign.size);
    info->posix_memalign.result = (*actual_posix_memalign)(
        info->posix_memalign.memptr, info->posix_memalign.alignment,
        info->posix_memalign.size);
    fprintf(stderr, "%d [%p]\n", info->posix_memalign.result,
            *info->posix_memalign.memptr);
    break;
  case ALIGNED_ALLOC_CALL:
    fprintf(stderr, C_GREY("%p") " aligned_alloc(%zu, %zu) -> ", return_addr,
            info->aligned_alloc.alignment, info->aligned_alloc.size);
    info->aligned_alloc.result = (*actual_aligned_alloc)(
        info->aligned_alloc.alignment, info->aligned_alloc.size);
    fprintf(stderr, "%p\n", info->aligned_alloc.result);
    break;
  case VALLOC_CALL:
    fprintf(stderr, C_GREY("%p") " valloc(%zu) -> ", return_addr,
            info->valloc.size);
    info->valloc.result = (*actual_valloc)(info->valloc.size);
    fprintf(stderr, "%p\n", info->valloc.result);
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

void *memalign(size_t alignment, size_t size) {
  if (no_hook)
    return (*actual_memalign)(alignment, size);

  struct call_info info = {.type = MEMALIGN_CALL,
                           .memalign.alignment = alignment,
                           .memalign.size = size};
  call(&info);
  return info.memalign.result;
}

void *pvalloc(size_t size) {
  if (no_hook)
    return (*actual_pvalloc)(size);

  struct call_info info = {.type = PVALLOC_CALL, .pvalloc.size = size};
  call(&info);
  return info.pvalloc.result;
}

int posix_memalign(void **memptr, size_t alignment, size_t size) {
  if (no_hook)
    return (*actual_posix_memalign)(memptr, alignment, size);

  struct call_info info = {.type = POSIX_MEMALIGN_CALL,
                           .posix_memalign.memptr = memptr,
                           .posix_memalign.alignment = alignment,
                           .posix_memalign.size = size};
  call(&info);
  return info.posix_memalign.result;
}

void *aligned_alloc(size_t alignment, size_t size) {
  if (no_hook)
    return (*actual_aligned_alloc)(alignment, size);

  struct call_info info = {.type = ALIGNED_ALLOC_CALL,
                           .aligned_alloc.alignment = alignment,
                           .aligned_alloc.size = size};
  call(&info);
  return info.aligned_alloc.result;
}

void *valloc(size_t size) {
  if (no_hook)
    return (*actual_valloc)(size);

  struct call_info info = {.type = VALLOC_CALL, .valloc.size = size};
  call(&info);
  return info.valloc.result;
}
