#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define MiB (1024UL * 1024UL)
#define KERNEL_OBJECT_BATCH 48

static int marker_fd = -1;

static void write_trace_marker(const char *marker, size_t length)
{
	ssize_t written;

	if (marker_fd < 0 || !length)
		return;
	written = write(marker_fd, marker, length);
	(void)written;
}

static void phase(const char *name)
{
	char marker[128];
	int length;

	printf("phase=%s\n", name);
	fflush(stdout);
	length = snprintf(marker, sizeof(marker), "mm_phase=%s\n", name);
	if (length > 0)
		write_trace_marker(marker, (size_t)length);
}

static void program_step(const char *name, const char *operation, int line,
						 size_t current, size_t total, const char *function)
{
	char marker[256];
	int length;

	length = snprintf(marker, sizeof(marker),
					  "mm_step=%s file=exercise_memory_management.c line=%d "
					  "func=%s op=%s current=%zu total=%zu\n",
					  name, line, function, operation, current, total);
	if (length > 0 && (size_t)length < sizeof(marker))
		write_trace_marker(marker, (size_t)length);
}

#define PROGRAM_STEP(name, operation) \
	program_step((name), (operation), __LINE__, 0, 0, __func__)
#define PROGRAM_PROGRESS(name, operation, current, total) \
	program_step((name), (operation), __LINE__, (current), (total), __func__)

static void *shared_address_space_thread(void *arg)
{
	unsigned char *p = arg;
	size_t i;

	for (i = 0; i < 8 * MiB; i += 4096)
	{
		if (((i / 4096) % 256) == 0)
			PROGRAM_PROGRESS("thread_shared_write", "xor_shared_anonymous_page",
							 i / 4096, (8 * MiB) / 4096);
		p[i] ^= (unsigned char)(i >> 12);
	}
	return NULL;
}

static void kernel_object_churn(void)
{
	int pipes[KERNEL_OBJECT_BATCH][2];
	int sockets[KERNEL_OBJECT_BATCH][2];
	int events[KERNEL_OBJECT_BATCH];
	int epolls[KERNEL_OBJECT_BATCH];
	struct epoll_event event = {.events = EPOLLIN, .data.u64 = 0x6d6d};
	uint64_t one = 1;
	int i;

	memset(pipes, -1, sizeof(pipes));
	memset(sockets, -1, sizeof(sockets));
	for (i = 0; i < KERNEL_OBJECT_BATCH; i++)
	{
		if ((i % 8) == 0)
			PROGRAM_PROGRESS("kernel_object_create", "pipe_socket_eventfd_epoll",
							 (size_t)i, KERNEL_OBJECT_BATCH);
		events[i] = -1;
		epolls[i] = -1;
		if (pipe2(pipes[i], O_CLOEXEC) != 0)
			continue;
		if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0,
					   sockets[i]) != 0)
			continue;
		events[i] = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
		epolls[i] = epoll_create1(EPOLL_CLOEXEC);
		if (events[i] >= 0)
		{
			ssize_t written = write(events[i], &one, sizeof(one));
			(void)written;
		}
		if (epolls[i] >= 0 && events[i] >= 0)
			(void)epoll_ctl(epolls[i], EPOLL_CTL_ADD, events[i], &event);
	}
	for (i = KERNEL_OBJECT_BATCH - 1; i >= 0; i--)
	{
		if ((i % 8) == 7)
			PROGRAM_PROGRESS("kernel_object_destroy", "close_kernel_objects",
							 (size_t)(KERNEL_OBJECT_BATCH - 1 - i),
							 KERNEL_OBJECT_BATCH);
		if (epolls[i] >= 0)
			close(epolls[i]);
		if (events[i] >= 0)
			close(events[i]);
		if (sockets[i][0] >= 0)
			close(sockets[i][0]);
		if (sockets[i][1] >= 0)
			close(sockets[i][1]);
		if (pipes[i][0] >= 0)
			close(pipes[i][0]);
		if (pipes[i][1] >= 0)
			close(pipes[i][1]);
	}
}

int main(void)
{
	const char *file_dir = getenv("KOOPS_MM_FILE_DIR");
	size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
	size_t len = 64 * MiB;
	unsigned char *anon, *remapped, *thp, *thp_mapping, *file_map, *private_map;
	volatile unsigned long checksum = 0;
	void *ptrs[4096];
	char template[256];
	size_t i;
	pthread_t thread;
	pid_t child;
	int fd;

	marker_fd = open("/sys/kernel/tracing/trace_marker", O_WRONLY | O_CLOEXEC);
	if (!file_dir || !*file_dir)
		file_dir = "/var/tmp";
	if (snprintf(template, sizeof(template), "%s/koops-mm-XXXXXX", file_dir) >=
		(int)sizeof(template))
	{
		fprintf(stderr, "KOOPS_MM_FILE_DIR path is too long\n");
		return 1;
	}

	printf("memory workload starting page_size=%zu anon=%zuMiB\n",
		   page_size, len / MiB);
	fflush(stdout);

	/* PROGRAM ZONE: reserve and populate anonymous virtual memory. */
	phase("anon_mmap_reserve");
	PROGRAM_STEP("anon_mmap_reserve", "mmap_private_anonymous_64MiB");
	anon = mmap(NULL, len, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (anon == MAP_FAILED)
	{
		perror("mmap(anon)");
		return 1;
	}

	phase("anon_read_fault_zero_page");
	for (i = 0; i < 8 * MiB; i += page_size)
	{
		if (((i / page_size) % 256) == 0)
			PROGRAM_PROGRESS("anon_read_fault_zero_page", "read_anonymous_page",
						 i / page_size, (8 * MiB) / page_size);
		checksum += anon[i];
	}

	phase("anon_write_fault");
	for (i = 0; i < len; i += page_size)
	{
		if (((i / page_size) % 256) == 0)
			PROGRAM_PROGRESS("anon_write_fault", "write_anonymous_page",
						 i / page_size, len / page_size);
		anon[i] = (unsigned char)(i >> 12);
	}

	/* PROGRAM ZONE: reshape VMA boundaries and permissions. */
	phase("mprotect_vma_split_merge");
	PROGRAM_STEP("mprotect_read", "mprotect_middle_read_only");
	if (mprotect(anon + 16 * MiB, 16 * MiB, PROT_READ) != 0)
		perror("mprotect(read)");
	PROGRAM_STEP("mprotect_write", "mprotect_middle_read_write");
	if (mprotect(anon + 16 * MiB, 16 * MiB, PROT_READ | PROT_WRITE) != 0)
		perror("mprotect(write)");

	phase("munmap_middle_vma_split");
	PROGRAM_STEP("munmap_middle", "unmap_middle_8MiB");
	if (munmap(anon + 32 * MiB, 8 * MiB) != 0)
		perror("munmap(middle)");

	phase("mremap_grow_move_shrink");
	PROGRAM_STEP("mremap_source", "mmap_remap_source_4MiB");
	remapped = mmap(NULL, 4 * MiB, PROT_READ | PROT_WRITE,
					MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (remapped != MAP_FAILED)
	{
		PROGRAM_STEP("mremap_prefault", "memset_source_4MiB");
		memset(remapped, 0x4d, 4 * MiB);
		PROGRAM_STEP("mremap_grow", "mremap_4MiB_to_12MiB_maymove");
		remapped = mremap(remapped, 4 * MiB, 12 * MiB, MREMAP_MAYMOVE);
		if (remapped == MAP_FAILED)
		{
			perror("mremap(grow)");
		}
		else
		{
			PROGRAM_STEP("mremap_grown_touch", "memset_new_8MiB");
			memset(remapped + 4 * MiB, 0x52, 8 * MiB);
			PROGRAM_STEP("mremap_shrink", "mremap_12MiB_to_6MiB");
			remapped = mremap(remapped, 12 * MiB, 6 * MiB, 0);
			if (remapped == MAP_FAILED)
				perror("mremap(shrink)");
			else
			{
				PROGRAM_STEP("mremap_cleanup", "munmap_remapped_6MiB");
				munmap(remapped, 6 * MiB);
			}
		}
	}

	/* PROGRAM ZONE: discard/pageout resident pages, then refault them. */
	phase("madvise_dontneed_refault");
	PROGRAM_STEP("madvise_dontneed", "discard_anonymous_8MiB");
	if (madvise(anon + 8 * MiB, 8 * MiB, MADV_DONTNEED) != 0)
		perror("madvise(DONTNEED)");
	for (i = 8 * MiB; i < 16 * MiB; i += page_size)
	{
		if ((((i - 8 * MiB) / page_size) % 256) == 0)
			PROGRAM_PROGRESS("dontneed_refault", "write_discarded_anonymous_page",
						 (i - 8 * MiB) / page_size, (8 * MiB) / page_size);
		anon[i] = (unsigned char)(i >> 12);
	}
#ifdef MADV_PAGEOUT
	phase("madvise_pageout_refault");
	PROGRAM_STEP("madvise_pageout", "request_anonymous_pageout_8MiB");
	if (madvise(anon + 16 * MiB, 8 * MiB, MADV_PAGEOUT) == 0)
	{
		for (i = 16 * MiB; i < 24 * MiB; i += page_size)
		{
			if ((((i - 16 * MiB) / page_size) % 256) == 0)
				PROGRAM_PROGRESS("pageout_refault", "read_paged_out_anonymous_page",
							 (i - 16 * MiB) / page_size,
							 (8 * MiB) / page_size);
			checksum += anon[i];
		}
	}
#endif

	/* PROGRAM ZONE: populate base pages, then collapse and split THP memory. */
	phase("thp_fault_collapse_split");
	PROGRAM_STEP("thp_mmap", "mmap_aligned_hugepage_candidate_16MiB");
	thp_mapping = mmap(NULL, 18 * MiB, PROT_READ | PROT_WRITE,
					 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (thp_mapping != MAP_FAILED)
	{
		int collapse_result;
		char collapse_operation[64];

		thp = (unsigned char *)(((uintptr_t)thp_mapping + 2 * MiB - 1) &
							~(uintptr_t)(2 * MiB - 1));
		PROGRAM_STEP("thp_advise", "madvise_nohugepage_before_faults");
		if (madvise(thp, 16 * MiB, MADV_NOHUGEPAGE) != 0)
			perror("madvise(NOHUGEPAGE)");
		for (i = 0; i < 16 * MiB; i += page_size)
		{
			if (((i / page_size) % 256) == 0)
				PROGRAM_PROGRESS("thp_fault", "populate_base_page_candidate",
							 i / page_size, (16 * MiB) / page_size);
			thp[i] = (unsigned char)(i >> 12);
		}
		PROGRAM_STEP("thp_advise", "madvise_hugepage_after_base_faults");
		if (madvise(thp, 16 * MiB, MADV_HUGEPAGE) != 0)
			perror("madvise(HUGEPAGE)");
#ifdef MADV_COLLAPSE
		PROGRAM_STEP("thp_collapse", "madvise_collapse_begin");
		errno = 0;
		collapse_result = madvise(thp, 16 * MiB, MADV_COLLAPSE);
		if (collapse_result == 0)
			snprintf(collapse_operation, sizeof(collapse_operation),
					 "madvise_collapse_succeeded");
		else
			snprintf(collapse_operation, sizeof(collapse_operation),
					 "madvise_collapse_failed_errno_%d", errno);
		program_step("thp_collapse", collapse_operation, __LINE__, 0, 0,
					 __func__);
#endif
		PROGRAM_STEP("thp_split_read", "mprotect_single_page_read_only");
		(void)mprotect(thp + 4 * MiB, page_size, PROT_READ);
		PROGRAM_STEP("thp_split_write", "mprotect_single_page_read_write");
		(void)mprotect(thp + 4 * MiB, page_size, PROT_READ | PROT_WRITE);
		PROGRAM_STEP("thp_unmap", "munmap_hugepage_candidate");
		munmap(thp_mapping, 18 * MiB);
	}

	/* PROGRAM ZONE: exercise userspace and kernel object allocators. */
	phase("userspace_allocator_churn");
	PROGRAM_STEP("malloc_prepare", "clear_pointer_table");
	memset(ptrs, 0, sizeof(ptrs));
	for (i = 0; i < 4096; i++)
	{
		size_t size = 16 + ((i * 37) % 8192);

		if ((i % 512) == 0)
			PROGRAM_PROGRESS("malloc_churn", "malloc_and_memset",
						 i, 4096);
		ptrs[i] = malloc(size);
		if (ptrs[i])
			memset(ptrs[i], (int)i, size);
	}
	for (i = 0; i < 4096; i += 2)
	{
		if ((i % 512) == 0)
			PROGRAM_PROGRESS("malloc_free_even", "free_even_allocations",
						 i / 2, 2048);
		free(ptrs[i]);
		ptrs[i] = NULL;
	}
	for (i = 1; i < 4096; i += 2)
	{
		if (((i - 1) % 512) == 0)
			PROGRAM_PROGRESS("malloc_free_odd", "free_odd_allocations",
						 (i - 1) / 2, 2048);
		free(ptrs[i]);
	}

	phase("kernel_object_churn");
	PROGRAM_STEP("kernel_object_churn", "create_and_close_kernel_objects");
	kernel_object_churn();

	/* PROGRAM ZONE: mutate one mm from a second thread. */
	phase("thread_shared_mm");
	PROGRAM_STEP("thread_create", "pthread_create_shared_mm_writer");
	if (pthread_create(&thread, NULL, shared_address_space_thread, anon) != 0)
		perror("pthread_create");
	else
	{
		PROGRAM_STEP("thread_join", "pthread_join_shared_mm_writer");
		pthread_join(thread, NULL);
	}

	/* PROGRAM ZONE: fork and force private copy-on-write pages. */
	phase("fork_copy_on_write");
	PROGRAM_STEP("fork_cow", "fork_child_for_cow");
	child = fork();
	if (child < 0)
	{
		perror("fork");
	}
	else if (child == 0)
	{
		for (i = 0; i < 16 * MiB; i += page_size)
		{
			if (((i / page_size) % 256) == 0)
				PROGRAM_PROGRESS("fork_cow_child", "xor_private_cow_page",
							 i / page_size, (16 * MiB) / page_size);
			anon[i] ^= 0xa5;
		}
		_exit(0);
	}
	else
	{
		PROGRAM_STEP("fork_cow_wait", "wait_for_cow_child");
		waitpid(child, NULL, 0);
	}

	/* PROGRAM ZONE: shared file faults, dirtying, and synchronous writeback. */
	phase("file_shared_dirty_writeback");
	PROGRAM_STEP("file_create", "mkstemp_backing_file");
	fd = mkstemp(template);
	if (fd < 0)
	{
		perror("mkstemp");
	}
	else
	{
		PROGRAM_STEP("file_unlink", "unlink_open_backing_file");
		unlink(template);
		PROGRAM_STEP("file_resize", "ftruncate_backing_file_16MiB");
		if (ftruncate(fd, (off_t)(16 * MiB)) != 0)
		{
			perror("ftruncate");
		}
		else
		{
			PROGRAM_STEP("file_shared_mmap", "mmap_shared_file_16MiB");
			file_map = mmap(NULL, 16 * MiB, PROT_READ | PROT_WRITE,
							MAP_SHARED, fd, 0);
			if (file_map == MAP_FAILED)
			{
				perror("mmap(file shared)");
			}
			else
			{
				for (i = 0; i < 16 * MiB; i += page_size)
				{
					if (((i / page_size) % 256) == 0)
						PROGRAM_PROGRESS("file_shared_dirty", "write_shared_file_page",
								 i / page_size, (16 * MiB) / page_size);
					file_map[i] = (unsigned char)(i >> 12);
				}
				PROGRAM_STEP("file_msync", "msync_shared_mapping_sync");
				(void)msync(file_map, 16 * MiB, MS_SYNC);
				PROGRAM_STEP("file_fsync", "fsync_backing_file");
				(void)fsync(fd);
				PROGRAM_STEP("file_shared_unmap", "munmap_shared_file");
				munmap(file_map, 16 * MiB);
			}

			/* PROGRAM ZONE: private file mapping copy-on-write. */
			phase("file_private_cow");
			PROGRAM_STEP("file_private_mmap", "mmap_private_file_16MiB");
			private_map = mmap(NULL, 16 * MiB, PROT_READ | PROT_WRITE,
							   MAP_PRIVATE, fd, 0);
			if (private_map != MAP_FAILED)
			{
				for (i = 0; i < 4 * MiB; i += page_size)
				{
					if (((i / page_size) % 256) == 0)
						PROGRAM_PROGRESS("file_private_cow", "xor_private_file_page",
								 i / page_size, (4 * MiB) / page_size);
					private_map[i] ^= 0x3c;
				}
				PROGRAM_STEP("file_private_unmap", "munmap_private_file");
				munmap(private_map, 16 * MiB);
			}

			/* PROGRAM ZONE: evict, readahead, and refault file-cache pages. */
			phase("file_cache_drop_refault");
			PROGRAM_STEP("file_cache_drop", "fadvise_dontneed_16MiB");
			(void)posix_fadvise(fd, 0, 16 * MiB, POSIX_FADV_DONTNEED);
			PROGRAM_STEP("file_readahead", "fadvise_willneed_16MiB");
			(void)posix_fadvise(fd, 0, 16 * MiB, POSIX_FADV_WILLNEED);
			PROGRAM_STEP("file_refault_mmap", "mmap_shared_file_read_only");
			file_map = mmap(NULL, 16 * MiB, PROT_READ, MAP_SHARED, fd, 0);
			if (file_map != MAP_FAILED)
			{
				for (i = 0; i < 16 * MiB; i += page_size)
				{
					if (((i / page_size) % 256) == 0)
						PROGRAM_PROGRESS("file_cache_refault", "read_file_page_after_drop",
								 i / page_size, (16 * MiB) / page_size);
					checksum += file_map[i];
				}
				PROGRAM_STEP("file_refault_unmap", "munmap_refault_mapping");
				munmap(file_map, 16 * MiB);
			}
		}
		PROGRAM_STEP("file_close", "close_backing_file");
		close(fd);
	}

	/* PROGRAM ZONE: tear down the workload-owned address space. */
	phase("address_space_teardown");
	PROGRAM_STEP("teardown_lower", "munmap_anonymous_lower_32MiB");
	munmap(anon, 32 * MiB);
	PROGRAM_STEP("teardown_upper", "munmap_anonymous_upper_24MiB");
	munmap(anon + 40 * MiB, 24 * MiB);

	phase("complete");
	PROGRAM_STEP("complete", "workload_complete");
	if (marker_fd >= 0)
		close(marker_fd);
	printf("memory workload complete checksum=%lu\n", checksum);
	return 0;
}
