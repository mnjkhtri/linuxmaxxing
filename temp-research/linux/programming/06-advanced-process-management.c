#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <errno.h>        /* errno for syscall failures */
#include <fcntl.h>        /* open(), O_RDONLY */
#include <sched.h>        /* sched_yield(), sched_get/setscheduler(), sched_get/setaffinity(), sched_getcpu(), cpu_set_t, SCHED_* */
#include <stdio.h>        /* printf(), fprintf(), snprintf() */
#include <stdlib.h>       /* EXIT_SUCCESS */
#include <string.h>       /* strerror() */
#include <sys/resource.h> /* getpriority(), setpriority(), getrlimit(), setrlimit(), RLIMIT_*, struct rlimit */
#include <sys/types.h>    /* pid_t */
#include <sys/wait.h>     /* wait() */
#include <time.h>         /* clock_gettime(), CLOCK_MONOTONIC */
#include <unistd.h>       /* getpid(), close(), read(), write(), pipe() */

/*
    Small Linux advanced process-management demonstrations.

    The examples cover:
      - sched_yield(): yield vs no-yield iteration count comparison
      - nice values: CPU share difference between nice=0 and nice=19
      - sched_getaffinity(), sched_setaffinity(), sched_getcpu()
      - sched_getscheduler(), sched_setscheduler(), sched_get_priority_min/max()
      - getrlimit(), setrlimit(): demonstrate a limit being enforced
*/

static void pipe_write(int fd, const void *buf, size_t len)
{
    ssize_t n = write(fd, buf, len);
    if (n != (ssize_t)len)
        fprintf(stderr, "pipe_write: short write\n");
}

static void pipe_read(int fd, void *buf, size_t len)
{
    ssize_t n = read(fd, buf, len);
    if (n != (ssize_t)len)
        fprintf(stderr, "pipe_read: short read\n");
}

/* Pin the calling process to CPU 0 so competing processes share one core. */
static void pin_to_cpu0(void)
{
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(0, &set);
    if (sched_setaffinity(0, sizeof(set), &set) == -1)
        fprintf(stderr, "pin_to_cpu0: sched_setaffinity failed: %s\n", strerror(errno));
}

/* Return milliseconds elapsed since start. */
static long long ms_since(struct timespec *start)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - start->tv_sec) * 1000LL +
           (now.tv_nsec - start->tv_nsec) / 1000000LL;
}

/*
    Demo 1: sched_yield() reduces work done.

    Two children compete on CPU 0 for 200ms. One calls sched_yield() every
    iteration, surrendering its timeslice each time. The lower iteration count
    of the yielding child proves it gave up CPU time to the other.
*/
static void demo_sched_yield(void)
{
    printf("\n------ 1. Yielding: sched_yield() ------\n");
    pin_to_cpu0();

    int pfd[2];
    if (pipe(pfd) == -1)
    {
        fprintf(stderr, "yield: pipe failed: %s\n", strerror(errno));
        return;
    }

    for (int do_yield = 0; do_yield <= 1; ++do_yield)
    {
        pid_t child = fork();
        if (child < 0)
        {
            fprintf(stderr, "yield: fork failed: %s\n", strerror(errno));
            continue;
        }
        if (child == 0)
        {
            close(pfd[0]);
            struct timespec start;
            clock_gettime(CLOCK_MONOTONIC, &start);
            long long count = 0;
            while (ms_since(&start) < 100)
            {
                ++count;
                if (do_yield)
                    sched_yield();
            }
            pipe_write(pfd[1], &do_yield, sizeof(do_yield));
            pipe_write(pfd[1], &count, sizeof(count));
            close(pfd[1]);
            _exit(0);
        }
    }
    close(pfd[1]);

    wait(NULL);
    wait(NULL);

    for (int i = 0; i < 2; ++i)
    {
        int flag;
        long long count;
        pipe_read(pfd[0], &flag, sizeof(flag));
        pipe_read(pfd[0], &count, sizeof(count));
        printf("yield: %-14s %lld iterations in 100ms\n",
               flag ? "with yield:" : "no yield:", count);
    }
    close(pfd[0]);
}

/*
    Demo 2: nice values change CPU share under CFS.

    Two children compete on CPU 0 for 300ms. One runs at nice=0, the other
    at nice=19. CFS gives the lower-nice process a larger CPU proportion,
    which shows up directly as more iterations completed.
*/
static void demo_priority(void)
{
    printf("\n------ 2. Priority: nice values under CFS ------\n");
    pin_to_cpu0();

    int pfd[2];
    if (pipe(pfd) == -1)
    {
        fprintf(stderr, "priority: pipe failed: %s\n", strerror(errno));
        return;
    }

    int nice_vals[] = {0, 10};
    for (int i = 0; i < 2; ++i)
    {
        pid_t child = fork();
        if (child < 0)
        {
            fprintf(stderr, "priority: fork failed: %s\n", strerror(errno));
            continue;
        }
        if (child == 0)
        {
            close(pfd[0]);
            setpriority(PRIO_PROCESS, 0, nice_vals[i]);
            struct timespec start;
            clock_gettime(CLOCK_MONOTONIC, &start);
            long long count = 0;
            while (ms_since(&start) < 100)
                ++count;
            int nv = nice_vals[i];
            pipe_write(pfd[1], &nv, sizeof(nv));
            pipe_write(pfd[1], &count, sizeof(count));
            close(pfd[1]);
            _exit(0);
        }
    }
    close(pfd[1]);

    wait(NULL);
    wait(NULL);

    for (int i = 0; i < 2; ++i)
    {
        int nv;
        long long count;
        pipe_read(pfd[0], &nv, sizeof(nv));
        pipe_read(pfd[0], &count, sizeof(count));
        printf("priority: nice=%2d  %lld iterations in 100ms\n", nv, count);
    }
    close(pfd[0]);
}

/*
    Demo 3: CPU affinity verified with sched_getcpu().

    sched_getcpu() reports which CPU the process is currently running on.
    After pinning to CPU 0, the reported CPU should be 0.
*/
static void demo_affinity(void)
{
    printf("\n------ 3. Affinity: sched_getaffinity(), sched_setaffinity(), sched_getcpu() ------\n");

    cpu_set_t original;
    CPU_ZERO(&original);
    if (sched_getaffinity(0, sizeof(original), &original) == -1)
    {
        fprintf(stderr, "affinity: sched_getaffinity failed: %s\n", strerror(errno));
        return;
    }

    printf("affinity: allowed CPUs: ");
    for (int i = 0; i < CPU_SETSIZE; ++i)
        if (CPU_ISSET(i, &original))
            printf("%d ", i);
    printf("\n");
    printf("affinity: currently on CPU %d\n", sched_getcpu());

    cpu_set_t pinned;
    CPU_ZERO(&pinned);
    CPU_SET(0, &pinned);
    if (sched_setaffinity(0, sizeof(pinned), &pinned) == -1)
    {
        fprintf(stderr, "affinity: sched_setaffinity failed: %s\n", strerror(errno));
        return;
    }
    printf("affinity: pinned to CPU 0, now on CPU %d\n", sched_getcpu());

    if (sched_setaffinity(0, sizeof(original), &original) == -1)
        fprintf(stderr, "affinity: failed to restore affinity: %s\n", strerror(errno));
    else
        printf("affinity: restored original affinity\n");
}

/*
    Demo 4: scheduling policies and priority ranges.

    SCHED_OTHER has static priority 0 and uses nice values.
    Real-time policies (SCHED_FIFO, SCHED_RR) have static priorities 1-99
    and always preempt any SCHED_OTHER process.
    Switching to a real-time policy requires CAP_SYS_NICE.
*/
static void demo_scheduling_policy(void)
{
    printf("\n------ 4. Scheduling policy: sched_getscheduler(), sched_setscheduler() ------\n");

    int policy = sched_getscheduler(0);
    if (policy == -1)
    {
        fprintf(stderr, "policy: sched_getscheduler failed: %s\n", strerror(errno));
        return;
    }

    const char *name =
        policy == SCHED_OTHER ? "SCHED_OTHER" :
        policy == SCHED_FIFO  ? "SCHED_FIFO"  :
        policy == SCHED_RR    ? "SCHED_RR"    :
        policy == SCHED_BATCH ? "SCHED_BATCH" : "unknown";

    printf("policy: current policy = %s\n", name);
    printf("policy: SCHED_OTHER priority range = %d to %d (uses nice values instead)\n",
           sched_get_priority_min(SCHED_OTHER), sched_get_priority_max(SCHED_OTHER));
    printf("policy: SCHED_FIFO  priority range = %d to %d\n",
           sched_get_priority_min(SCHED_FIFO), sched_get_priority_max(SCHED_FIFO));
    printf("policy: SCHED_RR    priority range = %d to %d\n",
           sched_get_priority_min(SCHED_RR), sched_get_priority_max(SCHED_RR));

    struct sched_param param;
    param.sched_priority = 1;
    if (sched_setscheduler(0, SCHED_RR, &param) == -1)
    {
        printf("policy: sched_setscheduler(SCHED_RR) denied (requires CAP_SYS_NICE): %s\n",
               strerror(errno));
    }
    else
    {
        printf("policy: switched to SCHED_RR priority=1 — now preempts all SCHED_OTHER processes\n");
        param.sched_priority = 0;
        sched_setscheduler(0, SCHED_OTHER, &param);
        printf("policy: restored SCHED_OTHER\n");
    }
}

/*
    Demo 5: resource limits enforced by the kernel.

    Prints key limits, then lowers RLIMIT_NOFILE to a small value and opens
    files in a loop until the kernel rejects the open() call, proving the
    limit is actively enforced.
*/
static void print_rlimit(const char *name, int resource)
{
    struct rlimit rl;
    if (getrlimit(resource, &rl) == -1)
    {
        fprintf(stderr, "rlimit: getrlimit(%s) failed: %s\n", name, strerror(errno));
        return;
    }
    char soft[24], hard[24];
    if (rl.rlim_cur == RLIM_INFINITY) snprintf(soft, sizeof(soft), "unlimited");
    else snprintf(soft, sizeof(soft), "%llu", (unsigned long long)rl.rlim_cur);
    if (rl.rlim_max == RLIM_INFINITY) snprintf(hard, sizeof(hard), "unlimited");
    else snprintf(hard, sizeof(hard), "%llu", (unsigned long long)rl.rlim_max);
    printf("rlimit: %-20s soft=%-14s hard=%s\n", name, soft, hard);
}

static void demo_resource_limits(void)
{
    printf("\n------ 5. Resource limits: getrlimit(), setrlimit() ------\n");

    print_rlimit("RLIMIT_AS",      RLIMIT_AS);
    print_rlimit("RLIMIT_CORE",    RLIMIT_CORE);
    print_rlimit("RLIMIT_CPU",     RLIMIT_CPU);
    print_rlimit("RLIMIT_NOFILE",  RLIMIT_NOFILE);
    print_rlimit("RLIMIT_NPROC",   RLIMIT_NPROC);
    print_rlimit("RLIMIT_STACK",   RLIMIT_STACK);

    /* Lower the soft fd limit to 8 and open files until the kernel rejects. */
    struct rlimit nofile;
    if (getrlimit(RLIMIT_NOFILE, &nofile) == -1)
    {
        fprintf(stderr, "rlimit: getrlimit failed: %s\n", strerror(errno));
        return;
    }

    rlim_t original = nofile.rlim_cur;
    nofile.rlim_cur = 8;
    if (setrlimit(RLIMIT_NOFILE, &nofile) == -1)
    {
        fprintf(stderr, "rlimit: setrlimit failed: %s\n", strerror(errno));
        return;
    }
    printf("rlimit: lowered RLIMIT_NOFILE soft limit to %llu\n",
           (unsigned long long)nofile.rlim_cur);

    int fds[16];
    int opened = 0;
    for (int i = 0; i < 16; ++i)
    {
        fds[i] = open("/dev/null", O_RDONLY);
        if (fds[i] == -1)
        {
            printf("rlimit: open() rejected at attempt %d: %s\n", i + 1, strerror(errno));
            break;
        }
        opened++;
    }
    printf("rlimit: successfully opened %d file(s) before hitting the limit\n", opened);

    for (int i = 0; i < opened; ++i)
        close(fds[i]);

    nofile.rlim_cur = original;
    if (setrlimit(RLIMIT_NOFILE, &nofile) == -1)
        fprintf(stderr, "rlimit: failed to restore limit: %s\n", strerror(errno));
    else
        printf("rlimit: restored RLIMIT_NOFILE soft limit to %llu\n",
               (unsigned long long)original);
}

int main(void)
{
    printf("Starting advanced process-management demonstrations.\n");

    demo_sched_yield();
    demo_priority();
    demo_affinity();
    demo_scheduling_policy();
    demo_resource_limits();

    printf("\nAll advanced process-management demonstrations completed.\n");
    return EXIT_SUCCESS;
}
