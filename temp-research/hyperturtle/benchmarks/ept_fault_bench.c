/*
 * ept_fault_bench.c — EPT fault latency microbenchmark
 *
 * Reproduces Fig 9a / Table 2 from HyperTurtle (ATC'25).
 * mmaps 1GiB of anonymous memory, then touches each 4KiB page
 * sequentially, measuring the latency of each page fault via rdtsc.
 *
 * Output: per-fault latency stats (avg, median, 99p) in microseconds.
 *
 * Build:  gcc -O2 -o ept_fault_bench ept_fault_bench.c -lm
 * Run:    ./ept_fault_bench [size_in_MiB]   (default: 1024 MiB)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

#define PAGE_SIZE 4096
#define DEFAULT_SIZE_MIB 1024

static inline uint64_t rdtsc(void) {
    uint32_t lo, hi;
    __asm__ __volatile__ ("lfence; rdtsc; lfence" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static double get_tsc_freq(void) {
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    uint64_t tsc0 = rdtsc();

    /* Spin for ~100ms to calibrate */
    volatile uint64_t dummy = 0;
    for (int i = 0; i < 50000000; i++) dummy += i;

    clock_gettime(CLOCK_MONOTONIC, &t1);
    uint64_t tsc1 = rdtsc();

    double elapsed_ns = (t1.tv_sec - t0.tv_sec) * 1e9 + (t1.tv_nsec - t0.tv_nsec);
    return (double)(tsc1 - tsc0) / elapsed_ns * 1e3; /* MHz */
}

static int cmp_u64(const void *a, const void *b) {
    uint64_t va = *(const uint64_t *)a;
    uint64_t vb = *(const uint64_t *)b;
    return (va > vb) - (va < vb);
}

int main(int argc, char **argv) {
    size_t size_mib = DEFAULT_SIZE_MIB;
    const char *label = "unknown";
    if (argc > 1) size_mib = atol(argv[1]);
    if (argc > 2) label = argv[2];

    size_t size = size_mib * 1024UL * 1024UL;
    size_t n_pages = size / PAGE_SIZE;

    fprintf(stderr, "EPT fault latency benchmark\n");
    fprintf(stderr, "  Region: %zu MiB (%zu pages)\n", size_mib, n_pages);

    /* Calibrate TSC */
    double tsc_mhz = get_tsc_freq();
    fprintf(stderr, "  TSC freq: %.2f MHz\n", tsc_mhz);
    double tsc_per_us = tsc_mhz;

    /* Allocate latency array */
    uint64_t *latencies = malloc(n_pages * sizeof(uint64_t));
    if (!latencies) { perror("malloc latencies"); return 1; }

    /* mmap anonymous region — pages not yet faulted */
    char *region = mmap(NULL, size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) { perror("mmap"); return 1; }

    /* Ensure no pages are pre-faulted by advising the kernel */
    madvise(region, size, MADV_DONTNEED);

    fprintf(stderr, "  Measuring %zu page faults...\n", n_pages);

    /* Touch each page, measure fault latency */
    for (size_t i = 0; i < n_pages; i++) {
        uint64_t t0 = rdtsc();
        /* Volatile write to force the fault */
        *(volatile char *)(region + i * PAGE_SIZE) = (char)i;
        uint64_t t1 = rdtsc();
        latencies[i] = t1 - t0;
    }

    /* Compute stats */
    qsort(latencies, n_pages, sizeof(uint64_t), cmp_u64);

    uint64_t total = 0;
    for (size_t i = 0; i < n_pages; i++) total += latencies[i];

    double avg_us = (double)total / n_pages / tsc_per_us;
    double median_us = (double)latencies[n_pages / 2] / tsc_per_us;
    double p99_us = (double)latencies[(size_t)(n_pages * 0.99)] / tsc_per_us;
    double p999_us = (double)latencies[(size_t)(n_pages * 0.999)] / tsc_per_us;
    double min_us = (double)latencies[0] / tsc_per_us;
    double max_us = (double)latencies[n_pages - 1] / tsc_per_us;

    printf("=== EPT Fault Latency Results ===\n");
    printf("Pages faulted:  %zu\n", n_pages);
    printf("Average:        %.2f us\n", avg_us);
    printf("Median:         %.2f us\n", median_us);
    printf("99th %%ile:      %.2f us\n", p99_us);
    printf("99.9th %%ile:    %.2f us\n", p999_us);
    printf("Min:            %.2f us\n", min_us);
    printf("Max:            %.2f us\n", max_us);

    /* Also dump raw CSV for analysis */
    const char *outdir = getenv("RESULTS_DIR");
    if (!outdir) outdir = "/home/ubuntu/shared_folder/benchmarks/results";
    char fname[512];
    snprintf(fname, sizeof(fname), "%s/ept_fault_latencies_%s_%zuMiB.csv", outdir, label, size_mib);
    FILE *f = fopen(fname, "w");
    if (f) {
        fprintf(f, "page_index,latency_cycles,latency_us\n");
        /* Unsorted — re-read in original order would be better,
           but sorted is fine for stats. Output sorted. */
        for (size_t i = 0; i < n_pages; i++) {
            fprintf(f, "%zu,%lu,%.3f\n", i, latencies[i],
                    (double)latencies[i] / tsc_per_us);
        }
        fclose(f);
        fprintf(stderr, "Raw data saved to %s\n", fname);
    }

    munmap(region, size);
    free(latencies);
    return 0;
}
