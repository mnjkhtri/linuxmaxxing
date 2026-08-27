#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/*
    Small Linux threading demonstrations.

    The examples cover:
      - pthread_create(), pthread_join(), pthread_self(), pthread_equal()
      - Race conditions: lost updates from unsynchronized shared memory
      - Mutexes: mutual exclusion restores correct counts
      - Parallelism: CPU-bound speedup across multiple threads
*/

#define THREADS 4
#define ITERATIONS 1000000
#define WORK_N 400000000LL

static long long ms_since(struct timespec *start)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - start->tv_sec) * 1000LL +
           (now.tv_nsec - start->tv_nsec) / 1000000LL;
}

/*
    Demo 1: Thread lifecycle.

    Four workers are created, each printing its own TID and argument index.
    The main thread joins each one and retrieves its integer return value.
    pthread_equal() confirms the main TID differs from the worker TIDs.
*/
static void *lifecycle_fn(void *arg)
{
    int n = *(int *)arg;
    printf("lifecycle: worker %d  tid=%lu\n", n, (unsigned long)pthread_self());
    return (void *)(long)(n * 10);
}

static void demo_lifecycle(void)
{
    printf("\n------ 1. Thread lifecycle: create, join, self, equal ------\n");

    pthread_t tids[4];
    int args[4];

    for (int i = 0; i < 4; ++i)
    {
        args[i] = i;
        if (pthread_create(&tids[i], NULL, lifecycle_fn, &args[i]) != 0)
        {
            fprintf(stderr, "lifecycle: pthread_create failed\n");
            return;
        }
    }

    for (int i = 0; i < 4; ++i)
    {
        void *retval;
        pthread_join(tids[i], &retval);
        printf("lifecycle: worker %d returned %ld\n", i, (long)retval);
    }

    pthread_t self = pthread_self();
    printf("lifecycle: main tid=%lu\n", (unsigned long)self);
    printf("lifecycle: tid[0] == main? %s\n",
           pthread_equal(tids[0], self) ? "yes" : "no");
}

/*
    Demo 2: Race condition.

    THREADS threads each increment a shared counter ITERATIONS times with no synchronization.
    Because ++counter is a non-atomic load-add-store sequence,
    concurrent threads overwrite each other's increments and updates are lost.
*/
static volatile long long race_counter;

static void *race_fn(void *arg)
{
    (void)arg;
    for (long long i = 0; i < ITERATIONS; ++i)
        ++race_counter;
    return NULL;
}

static void demo_race(void)
{
    printf("\n------ 2. Race condition: unsynchronized counter ------\n");

    race_counter = 0;
    pthread_t tids[THREADS];

    for (int i = 0; i < THREADS; ++i)
        pthread_create(&tids[i], NULL, race_fn, NULL);
    for (int i = 0; i < THREADS; ++i)
        pthread_join(tids[i], NULL);

    long long expected = (long long)THREADS * ITERATIONS;
    printf("race: expected=%lld  got=%lld  lost=%lld\n",
           expected, race_counter, expected - race_counter);
}

/*
    Demo 3: Mutex.

    Same counter and workload as the race demo.
    Each increment is wrapped in a lock/unlock pair so only one thread can execute the critical region at a time.
    No updates are lost.
*/
static long long mutex_counter;
static pthread_mutex_t mutex_lock = PTHREAD_MUTEX_INITIALIZER;

static void *mutex_fn(void *arg)
{
    (void)arg;
    for (long long i = 0; i < ITERATIONS; ++i)
    {
        pthread_mutex_lock(&mutex_lock);
        ++mutex_counter;
        pthread_mutex_unlock(&mutex_lock);
    }
    return NULL;
}

static void demo_mutex(void)
{
    printf("\n------ 3. Mutex: synchronized counter ------\n");

    mutex_counter = 0;
    pthread_t tids[THREADS];

    for (int i = 0; i < THREADS; ++i)
        pthread_create(&tids[i], NULL, mutex_fn, NULL);
    for (int i = 0; i < THREADS; ++i)
        pthread_join(tids[i], NULL);

    long long expected = (long long)THREADS * ITERATIONS;
    printf("mutex: expected=%lld  got=%lld  %s\n",
           expected, mutex_counter,
           mutex_counter == expected ? "correct" : "WRONG");
}

/*
    Demo 4: Parallelism speedup.

    A sum over WORK_N integers is first computed single-threaded, then split evenly across THREADS threads.
    On a machine with enough cores the multi-threaded run completes in roughly 1/THREADS of the time.
*/
struct slice
{
    long long start, end, result;
};

static void *sum_fn(void *arg)
{
    struct slice *s = arg;
    long long sum = 0;
    for (long long i = s->start; i < s->end; ++i)
        sum += i;
    s->result = sum;
    return NULL;
}

static void demo_parallelism(void)
{
    printf("\n------ 4. Parallelism: CPU-bound work across %d threads ------\n", THREADS);

    struct timespec t0;

    /* volatile prevents the compiler from folding this into a closed-form formula */
    static volatile long long work_n = WORK_N;
    long long n = work_n;

    clock_gettime(CLOCK_MONOTONIC, &t0);
    long long single = 0;
    for (long long i = 0; i < n; ++i)
        single += i;
    long long single_ms = ms_since(&t0);
    printf("parallel: single-thread  sum=%lld  %lldms\n", single, single_ms);

    pthread_t tids[THREADS];
    struct slice slices[THREADS];
    long long chunk = WORK_N / THREADS;

    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < THREADS; ++i)
    {
        slices[i].start = (long long)i * chunk;
        slices[i].end = (i == THREADS - 1) ? WORK_N : (long long)(i + 1) * chunk;
        slices[i].result = 0;
        pthread_create(&tids[i], NULL, sum_fn, &slices[i]);
    }
    long long multi = 0;
    for (int i = 0; i < THREADS; ++i)
    {
        pthread_join(tids[i], NULL);
        multi += slices[i].result;
    }
    long long multi_ms = ms_since(&t0);

    printf("parallel: %d threads     sum=%lld  %lldms",
           THREADS, multi, multi_ms);
    if (single_ms > 0 && multi_ms > 0)
        printf("  (%.1fx speedup)", (double)single_ms / (double)multi_ms);
    printf("\n");
}

int main(void)
{
    printf("Starting threading demonstrations.\n");

    demo_lifecycle();
    demo_race();
    demo_mutex();
    demo_parallelism();

    printf("\nAll threading demonstrations completed.\n");
    return EXIT_SUCCESS;
}
