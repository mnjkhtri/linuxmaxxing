#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/*
    Small Linux time management demonstrations.

    The examples cover:
      - POSIX clocks: CLOCK_REALTIME, CLOCK_MONOTONIC, CLOCK_PROCESS_CPUTIME_ID
      - Time conversion: time_t -> struct tm -> formatted string, mktime, difftime
      - Wall time vs CPU time: sleep advances wall only; work advances both
      - Interval timers: setitimer(), SIGALRM
*/

static long long ms_diff(struct timespec *a, struct timespec *b)
{
    return (b->tv_sec - a->tv_sec) * 1000LL +
           (b->tv_nsec - a->tv_nsec) / 1000000LL;
}

/*
    Demo 1: POSIX clocks.

    CLOCK_REALTIME is wall time — settable, subject to NTP adjustment.
    CLOCK_MONOTONIC is uptime — strictly increasing, immune to clock changes.
    CLOCK_PROCESS_CPUTIME_ID counts only time the CPU spent in this process.
    clock_getres() reports each clock's resolution (typically 1 ns on Linux).
*/
static void demo_clocks(void)
{
    printf("\n------ 1. POSIX clocks ------\n");

    struct timespec ts, res;
    char tbuf[32];

    clock_gettime(CLOCK_REALTIME, &ts);
    clock_getres(CLOCK_REALTIME, &res);
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", localtime(&ts.tv_sec));
    printf("clock: CLOCK_REALTIME           %s  res=%ldns\n", tbuf, res.tv_nsec);

    clock_gettime(CLOCK_MONOTONIC, &ts);
    clock_getres(CLOCK_MONOTONIC, &res);
    printf("clock: CLOCK_MONOTONIC          %llds %ldms since boot  res=%ldns\n",
           (long long)ts.tv_sec, ts.tv_nsec / 1000000L, res.tv_nsec);

    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ts);
    clock_getres(CLOCK_PROCESS_CPUTIME_ID, &res);
    printf("clock: CLOCK_PROCESS_CPUTIME_ID %lld.%06ldms CPU time  res=%ldns\n",
           (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000,
           ts.tv_nsec % 1000000, res.tv_nsec);

    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    printf("clock: CLOCK_THREAD_CPUTIME_ID  %lldns thread CPU time\n",
           (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec);
}

/*
    Demo 2: time conversion.

    time() returns seconds since the Unix epoch (1970-01-01 00:00:00 UTC).
    gmtime() and localtime() break that into a struct tm.
    strftime() formats it as a string.
    mktime() converts a local struct tm back to a time_t.
    difftime() subtracts two time_t values.
*/
static void demo_conversion(void)
{
    printf("\n------ 2. Time conversion: epoch, struct tm, strftime ------\n");

    time_t now = time(NULL);
    printf("time: epoch  = %lld\n", (long long)now);

    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", gmtime(&now));
    printf("time: UTC    = %s\n", buf);

    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S %Z", localtime(&now));
    printf("time: local  = %s\n", buf);

    /* mktime: build a specific point in time and get its epoch value */
    struct tm t = {0};
    t.tm_year = 100; /* 2000 */
    t.tm_mon = 0;    /* January */
    t.tm_mday = 1;
    time_t y2k = mktime(&t);
    printf("time: mktime(2000-01-01) = %lld\n", (long long)y2k);

    printf("time: difftime(now, y2k) = %.0f seconds  (%.1f years)\n",
           difftime(now, y2k), difftime(now, y2k) / (365.25 * 86400));
}

/*
    Demo 3: wall time vs CPU time.

    nanosleep() suspends the process — wall clock advances but the CPU is free to run other processes, so CPU time barely moves.
    A busy loop keeps the CPU fully occupied — both clocks advance together.
*/
static void demo_wall_vs_cpu(void)
{
    printf("\n------ 3. Wall time vs CPU time ------\n");

    struct timespec w0, w1, c0, c1;

    /* sleep: wall advances, CPU does not */
    clock_gettime(CLOCK_MONOTONIC, &w0);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &c0);
    struct timespec req = {0, 100000000}; /* 100ms */
    nanosleep(&req, NULL);
    clock_gettime(CLOCK_MONOTONIC, &w1);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &c1);
    printf("timing: nanosleep(100ms)  wall=%lldms  cpu=%lldms\n",
           ms_diff(&w0, &w1), ms_diff(&c0, &c1));

    /* busy work: both advance */
    clock_gettime(CLOCK_MONOTONIC, &w0);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &c0);
    volatile long long x = 0;
    struct timespec now;
    do
    {
        for (int i = 0; i < 10000; ++i)
            ++x;
        clock_gettime(CLOCK_MONOTONIC, &now);
    } while (ms_diff(&w0, &now) < 100);
    clock_gettime(CLOCK_MONOTONIC, &w1);
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &c1);
    printf("timing: busy loop  100ms  wall=%lldms  cpu=%lldms\n",
           ms_diff(&w0, &w1), ms_diff(&c0, &c1));
}

/*
    Demo 4: interval timer.

    setitimer(ITIMER_REAL) sends SIGALRM repeatedly at a fixed interval.
    The it_value field sets the initial delay; it_interval sets the repeat period.
    Passing a zeroed struct to setitimer() disarms the timer.
*/
static volatile sig_atomic_t alarm_count = 0;

static void alarm_handler(int signo)
{
    (void)signo;
    ++alarm_count;
}

static void demo_timer(void)
{
    printf("\n------ 4. Interval timer: setitimer(), SIGALRM ------\n");

    struct sigaction sa = {0};
    sa.sa_handler = alarm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGALRM, &sa, NULL);

    struct itimerval itv = {0};
    itv.it_value.tv_usec = 50000;    /* first fire: 50ms */
    itv.it_interval.tv_usec = 50000; /* repeat:     50ms */
    setitimer(ITIMER_REAL, &itv, NULL);
    printf("timer: armed at 50ms intervals\n");

    while (alarm_count < 3)
        pause();

    memset(&itv, 0, sizeof(itv));
    setitimer(ITIMER_REAL, &itv, NULL);
    printf("timer: received %d SIGALRM firings, disarmed\n", (int)alarm_count);

    sa.sa_handler = SIG_DFL;
    sigaction(SIGALRM, &sa, NULL);
}

int main(void)
{
    printf("Starting time management demonstrations.\n");

    demo_clocks();
    demo_conversion();
    demo_wall_vs_cpu();
    demo_timer();

    printf("\nAll time management demonstrations completed.\n");
    return EXIT_SUCCESS;
}
