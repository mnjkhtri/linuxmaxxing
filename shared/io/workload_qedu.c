#define _GNU_SOURCE

#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include "json_writer.h"

#define QEDU_PATH "/dev/qedu"
#define SYSFS_PATH "/sys/class/misc/qedu/timeout_ms"
#define DEBUGFS_PATH "/sys/kernel/debug/qedu/status"
#define DMA_BYTES 512
#define FACTORIAL_INPUT 10
#define FACTORIAL_RESULT "3628800\n"
#define FACTORIAL_RESULT_BYTES 8

enum phase_fact_kind
{
	PHASE_FACT_STR,
	PHASE_FACT_U64,
};

struct phase_fact
{
	const char *key;
	enum phase_fact_kind kind;
	union
	{
		const char *str;
		unsigned long long num;
	};
};

#define FACT_STR(k, v) ((struct phase_fact){ .key = (k), .kind = PHASE_FACT_STR, .str = (v) })
#define FACT_U64(k, v) ((struct phase_fact){ .key = (k), .kind = PHASE_FACT_U64, .num = (v) })

static unsigned int phase_seq_counter;

static void emit_phase(const char *phase_name, const char *category,
		       const char *action, const struct phase_fact *facts, size_t fact_count)
{
	unsigned int seq = ++phase_seq_counter;
	struct json_writer jw;
	struct timespec now;
	unsigned long long time_ns;
	size_t i;

	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
	{
		perror("clock_gettime");
		exit(EXIT_FAILURE);
	}
	time_ns = (unsigned long long)now.tv_sec * 1000000000ULL +
		  (unsigned long long)now.tv_nsec;

	json_writer_init(&jw, stdout);
	json_object_begin(&jw);
	json_u32(&jw, "schema_version", 1);
	json_string(&jw, "experiment", "io");
	json_string(&jw, "kind", "phase");
	json_string(&jw, "source", "workload");
	json_u32(&jw, "seq", seq);
	json_u64(&jw, "time_ns", time_ns);
	json_object_begin_field(&jw, "event_info");
	json_string(&jw, "phase", phase_name);
	json_string(&jw, "category", category);
	json_string(&jw, "action", action);
	for (i = 0; i < fact_count; i++)
	{
		if (facts[i].kind == PHASE_FACT_STR)
			json_string(&jw, facts[i].key, facts[i].str);
		else
			json_u64(&jw, facts[i].key, facts[i].num);
	}
	json_object_end(&jw);
	json_object_begin_field(&jw, "context");
	json_u32(&jw, "pid", (uint32_t)getpid());
	json_object_end(&jw);
	json_object_end(&jw);
	json_newline(&jw);
	if (!json_writer_ok(&jw) || fflush(stdout) != 0)
	{
		fprintf(stderr, "workload: phase record write failed\n");
		exit(EXIT_FAILURE);
	}
}

static void read_interface(const char *path)
{
	char buffer[256];
	int fd = open(path, O_RDONLY);
	if (fd < 0 || read(fd, buffer, sizeof(buffer)) < 0)
	{
		perror(path);
		exit(EXIT_FAILURE);
	}
	close(fd);
}

static void write_interface(const char *path, const char *value)
{
	int fd = open(path, O_WRONLY);
	size_t length = strlen(value);
	if (fd < 0 || write(fd, value, length) != (ssize_t)length)
	{
		perror(path);
		exit(EXIT_FAILURE);
	}
	close(fd);
}

int main(int argc, char **argv)
{
	char factorial_result[16];
	char dma_payload[DMA_BYTES];
	char dma_result[DMA_BYTES];
	ssize_t result_size;
	int qedu_fd;

	if (prctl(PR_SET_NAME, "qedu_workload", 0, 0, 0) != 0)
	{
		perror("prctl");
		return EXIT_FAILURE;
	}

	/* run.sh resumes us after it installs PID-specific trace filters. */
	if (argc == 2 && strcmp(argv[1], "--trace-wait") == 0)
		raise(SIGSTOP);

	emit_phase("run", "io", "begin",
		   (const struct phase_fact[]){ FACT_STR("device", QEDU_PATH) }, 1);

	emit_phase("sysfs", "syscall", "begin",
		   (const struct phase_fact[]){ FACT_STR("attribute", "timeout_ms") }, 1);
	write_interface(SYSFS_PATH, "1200\n");
	read_interface(SYSFS_PATH);
	emit_phase("sysfs", "syscall", "end",
		   (const struct phase_fact[]){ FACT_STR("attribute", "timeout_ms") }, 1);

	emit_phase("debugfs", "syscall", "begin",
		   (const struct phase_fact[]){ FACT_STR("file", "status") }, 1);
	read_interface(DEBUGFS_PATH);
	emit_phase("debugfs", "syscall", "end",
		   (const struct phase_fact[]){ FACT_STR("file", "status") }, 1);

	/* Integer input selects the factorial engine and completes through one IRQ. */
	emit_phase("factorial", "mmio", "begin",
		   (const struct phase_fact[]){ FACT_U64("input", FACTORIAL_INPUT) }, 1);
	qedu_fd = open(QEDU_PATH, O_RDWR);
	if (qedu_fd < 0 || write(qedu_fd, "10\n", 3) != 3)
	{
		perror("factorial write");
		return EXIT_FAILURE;
	}
	result_size = read(qedu_fd, factorial_result, sizeof(factorial_result));
	close(qedu_fd);
	if (result_size != FACTORIAL_RESULT_BYTES ||
	    memcmp(factorial_result, FACTORIAL_RESULT, FACTORIAL_RESULT_BYTES) != 0)
	{
		fprintf(stderr, "unexpected factorial result\n");
		return EXIT_FAILURE;
	}
	emit_phase("factorial", "mmio", "end",
		   (const struct phase_fact[]){ FACT_U64("input", FACTORIAL_INPUT),
						FACT_U64("result", 3628800ULL),
						FACT_U64("bytes", FACTORIAL_RESULT_BYTES) },
		   3);

	/* A 512-byte non-integer payload takes the RAM -> EDU -> RAM DMA path. */
	memset(dma_payload, 'x', sizeof(dma_payload));
	emit_phase("dma_echo", "dma", "begin",
		   (const struct phase_fact[]){ FACT_U64("bytes", DMA_BYTES) }, 1);
	qedu_fd = open(QEDU_PATH, O_RDWR);
	if (qedu_fd < 0 || write(qedu_fd, dma_payload, sizeof(dma_payload)) != sizeof(dma_payload))
	{
		perror("DMA write");
		return EXIT_FAILURE;
	}
	result_size = read(qedu_fd, dma_result, sizeof(dma_result));
	close(qedu_fd);
	if (result_size != sizeof(dma_result) ||
	    memcmp(dma_payload, dma_result, sizeof(dma_payload)) != 0)
	{
		fprintf(stderr, "DMA echo mismatch\n");
		return EXIT_FAILURE;
	}
	emit_phase("dma_echo", "dma", "end",
		   (const struct phase_fact[]){ FACT_U64("bytes", DMA_BYTES),
						FACT_U64("read_calls", 1) },
		   2);
	emit_phase("run", "io", "end", NULL, 0);

	return EXIT_SUCCESS;
}
