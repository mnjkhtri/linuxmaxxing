#define _GNU_SOURCE

#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <unistd.h>

#define QEDU_PATH "/dev/qedu"
#define TRACE_MARKER_PATH "/sys/kernel/tracing/trace_marker"
#define SYSFS_PATH "/sys/class/misc/qedu/timeout_ms"
#define DEBUGFS_PATH "/sys/kernel/debug/qedu/status"
#define DMA_BYTES 512

static void mark_phase(int marker_fd, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	if (vdprintf(marker_fd, format, args) < 0) {
		perror("write trace marker");
		exit(EXIT_FAILURE);
	}
	va_end(args);
}

static void read_interface(const char *path)
{
	char buffer[256];
	int fd = open(path, O_RDONLY);
	if (fd < 0 || read(fd, buffer, sizeof(buffer)) < 0) {
		perror(path);
		exit(EXIT_FAILURE);
	}
	close(fd);
}

static void write_interface(const char *path, const char *value)
{
	int fd = open(path, O_WRONLY);
	size_t length = strlen(value);
	if (fd < 0 || write(fd, value, length) != (ssize_t)length) {
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
	int marker_fd;
	int qedu_fd;

	if (prctl(PR_SET_NAME, "qedu_workload", 0, 0, 0) != 0) {
		perror("prctl");
		return EXIT_FAILURE;
	}

	/* run.sh resumes us after it installs PID-specific trace filters. */
	if (argc == 2 && strcmp(argv[1], "--trace-wait") == 0)
		raise(SIGSTOP);

	marker_fd = open(TRACE_MARKER_PATH, O_WRONLY);
	if (marker_fd < 0) {
		perror("open trace_marker");
		return EXIT_FAILURE;
	}

	mark_phase(marker_fd, "QEDU_PHASE sequence=1 phase=run action=begin pid=%d device=/dev/qedu\n", getpid());

	mark_phase(marker_fd, "QEDU_PHASE sequence=2 phase=sysfs action=begin pid=%d attribute=timeout_ms\n", getpid());
	write_interface(SYSFS_PATH, "1200\n");
	read_interface(SYSFS_PATH);
	mark_phase(marker_fd, "QEDU_PHASE sequence=3 phase=sysfs action=end pid=%d attribute=timeout_ms\n", getpid());

	mark_phase(marker_fd, "QEDU_PHASE sequence=4 phase=debugfs action=begin pid=%d file=status\n", getpid());
	read_interface(DEBUGFS_PATH);
	mark_phase(marker_fd, "QEDU_PHASE sequence=5 phase=debugfs action=end pid=%d file=status\n", getpid());

	/* Integer input selects the factorial engine and completes through one IRQ. */
	mark_phase(marker_fd, "QEDU_PHASE sequence=6 phase=factorial action=begin pid=%d input=10\n", getpid());
	qedu_fd = open(QEDU_PATH, O_RDWR);
	if (qedu_fd < 0 || write(qedu_fd, "10\n", 3) != 3) {
		perror("factorial write");
		return EXIT_FAILURE;
	}
	result_size = read(qedu_fd, factorial_result, sizeof(factorial_result));
	close(qedu_fd);
	if (result_size != 8 || memcmp(factorial_result, "3628800\n", 8) != 0) {
		fprintf(stderr, "unexpected factorial result\n");
		return EXIT_FAILURE;
	}
	mark_phase(marker_fd, "QEDU_PHASE sequence=7 phase=factorial action=end pid=%d input=10 result=3628800 bytes=8\n", getpid());

	/* A 512-byte non-integer payload takes the RAM -> EDU -> RAM DMA path. */
	memset(dma_payload, 'x', sizeof(dma_payload));
	mark_phase(marker_fd, "QEDU_PHASE sequence=8 phase=dma_echo action=begin pid=%d bytes=512\n", getpid());
	qedu_fd = open(QEDU_PATH, O_RDWR);
	if (qedu_fd < 0 || write(qedu_fd, dma_payload, sizeof(dma_payload)) != sizeof(dma_payload)) {
		perror("DMA write");
		return EXIT_FAILURE;
	}
	result_size = read(qedu_fd, dma_result, sizeof(dma_result));
	close(qedu_fd);
	if (result_size != sizeof(dma_result) || memcmp(dma_payload, dma_result, sizeof(dma_payload)) != 0) {
		fprintf(stderr, "DMA echo mismatch\n");
		return EXIT_FAILURE;
	}
	mark_phase(marker_fd, "QEDU_PHASE sequence=9 phase=dma_echo action=end pid=%d bytes=512 read_calls=1\n", getpid());
	mark_phase(marker_fd, "QEDU_PHASE sequence=10 phase=run action=end pid=%d\n", getpid());

	close(marker_fd);
	return EXIT_SUCCESS;
}
