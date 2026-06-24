#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define MiB (1024UL * 1024UL)

static void *shared_address_space_thread(void *arg)
{
	unsigned char *p = arg;
	size_t i;

	for (i = 0; i < 8 * MiB; i += 4096)
		p[i] = (unsigned char)(i >> 12);
	return NULL;
}

int main(void)
{
	size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
	size_t len = 64 * MiB;
	unsigned char *anon;
	unsigned char *file_map;
	void *ptrs[4096];
	char template[] = "/tmp/koops-mm-XXXXXX";
	size_t i;
	pthread_t thread;
	pid_t child;
	int fd;

	printf("memory workload starting page_size=%zu anon=%zuMiB\n", page_size, len / MiB);
	fflush(stdout);

	printf("phase=anon_mmap_reserve\n");
	fflush(stdout);
	anon = mmap(NULL, len, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (anon == MAP_FAILED) {
		perror("mmap(anon)");
		return 1;
	}

	printf("phase=anon_fault_touch\n");
	fflush(stdout);
	for (i = 0; i < len; i += page_size)
		anon[i] = (unsigned char)(i >> 12);

	printf("phase=mprotect_split\n");
	fflush(stdout);
	if (mprotect(anon + 16 * MiB, 16 * MiB, PROT_READ) != 0)
		perror("mprotect(read)");
	if (mprotect(anon + 16 * MiB, 16 * MiB, PROT_READ | PROT_WRITE) != 0)
		perror("mprotect(write)");

	printf("phase=munmap_middle_split\n");
	fflush(stdout);
	if (munmap(anon + 32 * MiB, 8 * MiB) != 0)
		perror("munmap(middle)");

	printf("phase=malloc_churn\n");
	fflush(stdout);
	memset(ptrs, 0, sizeof(ptrs));
	for (i = 0; i < 4096; i++) {
		size_t size = 16 + ((i * 37) % 8192);

		ptrs[i] = malloc(size);
		if (ptrs[i])
			memset(ptrs[i], (int)i, size);
	}
	for (i = 0; i < 4096; i += 2) {
		free(ptrs[i]);
		ptrs[i] = NULL;
	}
	for (i = 1; i < 4096; i += 2)
		free(ptrs[i]);

	printf("phase=thread_shared_vm\n");
	fflush(stdout);
	if (pthread_create(&thread, NULL, shared_address_space_thread, anon) != 0) {
		perror("pthread_create");
	} else {
		pthread_join(thread, NULL);
	}

	printf("phase=fork_cow\n");
	fflush(stdout);
	child = fork();
	if (child < 0) {
		perror("fork");
	} else if (child == 0) {
		for (i = 0; i < 16 * MiB; i += page_size)
			anon[i] = (unsigned char)(i >> 12);
		_exit(0);
	} else {
		waitpid(child, NULL, 0);
	}

	printf("phase=file_backed_mmap\n");
	fflush(stdout);
	fd = mkstemp(template);
	if (fd < 0) {
		perror("mkstemp");
	} else {
		unlink(template);
		if (ftruncate(fd, (off_t)(8 * MiB)) != 0) {
			perror("ftruncate");
		} else {
			file_map = mmap(NULL, 8 * MiB, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
			if (file_map == MAP_FAILED) {
				perror("mmap(file)");
			} else {
				for (i = 0; i < 8 * MiB; i += page_size)
					file_map[i] = (unsigned char)(i >> 12);
				msync(file_map, 8 * MiB, MS_SYNC);
				munmap(file_map, 8 * MiB);
			}
		}
		close(fd);
	}

	printf("phase=cleanup\n");
	fflush(stdout);
	munmap(anon, 32 * MiB);
	munmap(anon + 40 * MiB, 24 * MiB);

	printf("memory workload complete\n");
	return 0;
}
