#define _GNU_SOURCE // For RTLD_NEXT

#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define C_GREY(s) "\033[90m" s "\033[0m"

// This variable is used to avoid recursively calling into the hooked version of
// malloc if the latter uses functions that call malloc internally
static __thread int no_hook = 0;

// We need to provide an initial malloc implementation as in some cases (e.g.,
// when linked with pthread) the program may allocate memory in initialization
// code
#define INIT_MALLOC_BUFFER_SIZE (1 << 20)
static char init_malloc_buffer[INIT_MALLOC_BUFFER_SIZE];
static void *init_malloc(size_t size) {
  static unsigned pos = 0;
  void *result = init_malloc_buffer + pos;
  pos += size;
  // Round up to satisfy alignment requirements
  pos = (pos + alignof(max_align_t)) - (pos % alignof(max_align_t));
  if (pos >= INIT_MALLOC_BUFFER_SIZE)
    result = 0;
  return result;
}

static bool is_init_memory(uintptr_t ptr) {
  return (uintptr_t)init_malloc_buffer <= ptr &&
         ptr <= (uintptr_t)init_malloc_buffer + INIT_MALLOC_BUFFER_SIZE;
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

static void *init_realloc(void *ptr, size_t size) {
  if (!ptr)
    return init_malloc(size);

  if (size == 0) {
    init_free(ptr);
    return 0;
  }

  void *result = init_malloc(size);
  // We can copy size bytes since we are inside the temporary malloc buffer and
  // we own all memory there
  memcpy(result, ptr, size);
  init_free(ptr);
  return result;
}

static int init_posix_memalign(void **memptr, size_t alignment, size_t size) {
  void *result = 0;
  do {
    result = init_malloc(1);
  } while (((uintptr_t)result & ~(alignment - 1)) != (uintptr_t)result);
  init_malloc(size - 1);
  *memptr = result;
  return 0;
}

static void *(*actual_malloc)(size_t size) = init_malloc;
static void *(*actual_calloc)(size_t nmemb, size_t size) = init_calloc;
static void (*actual_free)(void *ptr) = init_free;
static void *(*actual_realloc)(void *ptr, size_t size) = init_realloc;
static void *(*actual_memalign)(size_t alignment, size_t size);
static void *(*actual_pvalloc)(size_t size);
static int (*actual_posix_memalign)(void **memptr, size_t alignment,
                                    size_t size) = init_posix_memalign;
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

static double fail_threshold = 0.0;

static uint64_t rng_state;

// Splitmix64 random number generator
static uint64_t randu64(void) {
  uint64_t z = (rng_state += 0x9e3779b97f4a7c15);
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
  z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
  return z ^ (z >> 31);
}

static double randf(void) { return (randu64() >> 11) * 0x1.0p-53; }

__attribute__((__constructor__)) static void init(void) {
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

  // Get allocation failure threshold from the environment, if it is set
  const char *threshold = getenv("FAILALLOC_THRESHOLD");
  if (threshold)
    fail_threshold = strtod(threshold, 0);

  // Seed the random number generator
  rng_state = time(0);
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
  void *return_addr;
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

  double r = randf();

  switch (info->type) {
  case MALLOC_CALL:
    if (r < fail_threshold) {
      fprintf(stderr, "Failing malloc(%zu), called from %p\n",
              info->malloc.size, info->return_addr);
      info->malloc.result = 0;
    } else
      info->malloc.result = (*actual_malloc)(info->malloc.size);
    break;
  case CALLOC_CALL:
    if (r < fail_threshold) {
      fprintf(stderr, "Failing calloc(%zu, %zu), called from %p\n",
              info->calloc.nmemb, info->calloc.size, info->return_addr);
      info->calloc.result = 0;
    } else
      info->calloc.result =
          (*actual_calloc)(info->calloc.nmemb, info->calloc.size);
    break;
  case FREE_CALL:
    (*actual_free)(info->free.ptr);
    break;
  case REALLOC_CALL:
    if (r < fail_threshold) {
      fprintf(stderr, "Failing realloc(%p, %zu), called from %p\n",
              info->realloc.ptr, info->realloc.size, info->return_addr);
      info->realloc.result = 0;
    } else
      info->realloc.result =
          (*actual_realloc)(info->realloc.ptr, info->realloc.size);
    break;
  case MEMALIGN_CALL:
    if (r < fail_threshold) {
      fprintf(stderr, "Failing memalign(%zu, %zu), called from %p\n",
              info->memalign.alignment, info->memalign.alignment,
              info->return_addr);
      info->memalign.result = 0;
    } else
      info->memalign.result =
          (*actual_memalign)(info->memalign.alignment, info->memalign.size);
    break;
  case PVALLOC_CALL:
    if (r < fail_threshold) {
      fprintf(stderr, "Failing pvalloc(%zu), called from %p\n",
              info->pvalloc.size, info->return_addr);
      info->pvalloc.result = 0;
    } else
      info->pvalloc.result = (*actual_pvalloc)(info->pvalloc.size);
    break;
  case POSIX_MEMALIGN_CALL:
    if (r < fail_threshold) {
      fprintf(stderr, "Failing posix_memalign(%p, %zu, %zu), called from %p\n",
              info->posix_memalign.memptr, info->posix_memalign.alignment,
              info->posix_memalign.size, info->return_addr);
      info->posix_memalign.result = ENOMEM;
    } else
      info->posix_memalign.result = (*actual_posix_memalign)(
          info->posix_memalign.memptr, info->posix_memalign.alignment,
          info->posix_memalign.size);
    break;
  case ALIGNED_ALLOC_CALL:
    if (r < fail_threshold) {
      fprintf(stderr, "Failing aligned_alloc(%zu, %zu), called from %p\n",
              info->aligned_alloc.alignment, info->aligned_alloc.size,
              info->return_addr);
      info->aligned_alloc.result = 0;
    } else
      info->aligned_alloc.result = (*actual_aligned_alloc)(
          info->aligned_alloc.alignment, info->aligned_alloc.size);
    break;
  case VALLOC_CALL:
    if (r < fail_threshold) {
      fprintf(stderr, "Failing valloc(%zu), called from %p\n",
              info->valloc.size, info->return_addr);
      info->valloc.result = 0;
    } else
      info->valloc.result = (*actual_valloc)(info->valloc.size);
    break;
  }

  no_hook = 0;
}

#define CALLER_ADDRESS                                                         \
  __builtin_extract_return_addr(__builtin_return_address(0))

void *malloc(size_t size) {
  if (no_hook)
    return (*actual_malloc)(size);

  struct call_info info = {
      .type = MALLOC_CALL, .return_addr = CALLER_ADDRESS, .malloc.size = size};
  call(&info);
  return info.malloc.result;
}

void *calloc(size_t nmemb, size_t size) {
  if (no_hook)
    return (*actual_calloc)(nmemb, size);

  struct call_info info = {.type = CALLOC_CALL,
                           .return_addr = CALLER_ADDRESS,
                           .calloc.nmemb = nmemb,
                           .calloc.size = size};
  call(&info);
  return info.calloc.result;
}

void free(void *ptr) {
  if (is_init_memory((uintptr_t)ptr))
    return;

  if (no_hook)
    return (*actual_free)(ptr);

  struct call_info info = {
      .type = FREE_CALL, .return_addr = CALLER_ADDRESS, .free.ptr = ptr};
  call(&info);
}

void *realloc(void *ptr, size_t size) {
  if (is_init_memory((uintptr_t)ptr)) {
    size_t size_to_copy = (uintptr_t)init_malloc_buffer +
                          INIT_MALLOC_BUFFER_SIZE - (uintptr_t)ptr;
    if (size < size_to_copy)
      size_to_copy = size;
    void *result = malloc(size);
    memcpy(result, ptr, size_to_copy);
    return result;
  }

  if (no_hook)
    return (*actual_realloc)(ptr, size);

  struct call_info info = {.type = REALLOC_CALL,
                           .return_addr = CALLER_ADDRESS,
                           .realloc.ptr = ptr,
                           .realloc.size = size};
  call(&info);
  return info.realloc.result;
}

void *memalign(size_t alignment, size_t size) {
  if (no_hook)
    return (*actual_memalign)(alignment, size);

  struct call_info info = {.type = MEMALIGN_CALL,
                           .return_addr = CALLER_ADDRESS,
                           .memalign.alignment = alignment,
                           .memalign.size = size};
  call(&info);
  return info.memalign.result;
}

void *pvalloc(size_t size) {
  if (no_hook)
    return (*actual_pvalloc)(size);

  struct call_info info = {.type = PVALLOC_CALL,
                           .return_addr = CALLER_ADDRESS,
                           .pvalloc.size = size};
  call(&info);
  return info.pvalloc.result;
}

int posix_memalign(void **memptr, size_t alignment, size_t size) {
  if (no_hook)
    return (*actual_posix_memalign)(memptr, alignment, size);

  struct call_info info = {.type = POSIX_MEMALIGN_CALL,
                           .return_addr = CALLER_ADDRESS,
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
                           .return_addr = CALLER_ADDRESS,
                           .aligned_alloc.alignment = alignment,
                           .aligned_alloc.size = size};
  call(&info);
  return info.aligned_alloc.result;
}

void *valloc(size_t size) {
  if (no_hook)
    return (*actual_valloc)(size);

  struct call_info info = {
      .type = VALLOC_CALL, .return_addr = CALLER_ADDRESS, .valloc.size = size};
  call(&info);
  return info.valloc.result;
}
