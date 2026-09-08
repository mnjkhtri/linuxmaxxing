/* SPDX-License-Identifier: GPL-2.0 */
#ifndef LAB_OBSERVER_RUNTIME_H
#define LAB_OBSERVER_RUNTIME_H
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>

/* Control has its own inherited descriptor. Standalone use keeps diagnostics visible. */
static inline void lab_control(const char *format, ...)
{
    const char *value = getenv("LAB_CONTROL_FD");
    int fd = value ? atoi(value) : STDERR_FILENO;
    va_list args;
    va_start(args, format);
    vdprintf(fd, format, args);
    va_end(args);
}

/* The controller stops the workload before requesting shutdown of the observer. */
static inline int lab_poll(struct ring_buffer *ring, volatile sig_atomic_t *stop)
{
    int result;
    while (!*stop) {
        result = ring_buffer__poll(ring, 100);
        if (result < 0 && result != -EINTR)
            return result;
    }
    unsigned int drains = 0;
    do {
        result = ring_buffer__consume(ring);
        if (++drains > 10000)
            return -ETIMEDOUT;
    } while (result > 0);
    return result;
}

static inline int lab_health(unsigned long long dropped, unsigned long long failures)
{
    fprintf(stderr, "collector health: dropped=%llu failures=%llu\n", dropped, failures);
    lab_control("LX_HEALTH dropped=%llu failures=%llu\n", dropped, failures);
    return dropped || failures ? -EIO : 0;
}
#endif
