// Counts durability syscalls in a process; prints totals at exit.
// Build: cc -dynamiclib -o synccount.dylib synccount.c (macOS, DYLD_INSERT_LIBRARIES).
#include <fcntl.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#define INTERPOSE(replacement, replacee)                                             \
    __attribute__((used)) static struct {                                            \
        const void *r;                                                               \
        const void *e;                                                               \
    } interpose_##replacee __attribute__((section("__DATA,__interpose"))) = {        \
        (const void *)(uintptr_t)&replacement, (const void *)(uintptr_t)&replacee};

static atomic_long full, barrier, plain_fsync;

static int counted_fcntl(int fd, int cmd, ...) {
    va_list ap;
    va_start(ap, cmd);
    void *arg = va_arg(ap, void *);
    va_end(ap);
    if (cmd == F_FULLFSYNC) atomic_fetch_add(&full, 1);
    if (cmd == F_BARRIERFSYNC) atomic_fetch_add(&barrier, 1);
    return fcntl(fd, cmd, arg);
}

static int counted_fsync(int fd) {
    atomic_fetch_add(&plain_fsync, 1);
    return fsync(fd);
}

INTERPOSE(counted_fcntl, fcntl)
INTERPOSE(counted_fsync, fsync)

__attribute__((destructor)) static void report(void) {
    fprintf(stderr, "[sync] full=%ld barrier=%ld fsync=%ld\n", atomic_load(&full),
            atomic_load(&barrier), atomic_load(&plain_fsync));
}
