/*
 * This does not attempt every Linux MM feature—NUMA migration, memory cgroups, mlock, hugeTLB, DAX, direct I/O, userfaultfd, KSM, and OOM behavior are separate subjects.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/wait.h>
#include <unistd.h>

#define MiB (1024UL * 1024UL)
#define ANON_LENGTH (8 * MiB)
#define SHARED_ANON_LENGTH (8 * MiB)
#define FILE_LENGTH (8 * MiB)
#define THP_LENGTH (8 * MiB)

static int marker_fd = -1;

static void write_trace_marker(const char *marker, size_t length)
{
	if (marker_fd < 0 || !length)
		return;
	ssize_t written = write(marker_fd, marker, length);
	(void)written;
}

static void phase(const char *name)
{
	char marker[128];
	printf("phase=%s\n", name);
	fflush(stdout);
	int length = snprintf(marker, sizeof(marker), "mm_phase=%s\n", name);
	if (length > 0)
		write_trace_marker(marker, (size_t)length);
}

static void mapping_state(const char *mapping, const char *action, void *address, size_t length, const char *protection, const char *backing)
{
	printf("mapping=%s action=%s address=%p length=%zu protection=%s backing=%s\n", mapping, action, address, length, protection, backing);
	fflush(stdout);

	char marker[256];
	int marker_length = snprintf(marker, sizeof(marker), "mm_mapping=%s action=%s address=%p length=%zu protection=%s backing=%s\n", mapping, action, address, length, protection, backing);
	if (marker_length > 0 && (size_t)marker_length < sizeof(marker))
		write_trace_marker(marker, (size_t)marker_length);
}

#define PHASE(name) phase((name))

struct fault_counts
{
	long minor;
	long major;
};

static struct fault_counts read_fault_counts(void)
{
	struct rusage usage;
	if (getrusage(RUSAGE_SELF, &usage) != 0)
		return (struct fault_counts){0, 0};
	return (struct fault_counts){usage.ru_minflt, usage.ru_majflt};
}

static void report_fault_delta(const char *name, struct fault_counts initial_faults)
{
	struct fault_counts after = read_fault_counts();
	long minor = after.minor - initial_faults.minor;
	long major = after.major - initial_faults.major;
	printf("faults=%s minor=%ld major=%ld\n", name, minor, major);
	fflush(stdout);

	char marker[192];
	int marker_length = snprintf(marker, sizeof(marker), "mm_faults=%s minor=%ld major=%ld\n", name, minor, major);
	if (marker_length > 0 && (size_t)marker_length < sizeof(marker))
		write_trace_marker(marker, (size_t)marker_length);
}

static int wait_for_signal(pid_t child, int expected, const char *name)
{
	int status;
	if (waitpid(child, &status, 0) < 0)
	{
		perror("waitpid");
		return -1;
	}

	int observed = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
	(void)name;
	return observed == expected ? 0 : -1;
}

/*
 * Exercise private anonymous demand paging, COW, VMA changes, discard, and swap-backed pageout.
 */
static int exercise_private_anonymous_memory(size_t page_size, volatile unsigned long *checksum)
{
	int result = 0;

	/* Reserve address space; mmap itself does not populate physical pages. */
	PHASE("anonymous private: reserve virtual address space");
	unsigned char *anon = mmap(NULL, ANON_LENGTH, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (anon == MAP_FAILED)
	{
		perror("mmap(private anonymous)");
		return -1;
	}
	mapping_state("private_anon", "map", anon, ANON_LENGTH, "rw", "anonymous");

	/* Untouched reads fault through read-only zero-page mappings. */
	PHASE("anonymous private: read untouched pages through the zero page");
	struct fault_counts initial_faults = read_fault_counts();
	for (size_t i = 0; i < 1 * MiB; i += page_size)
		*checksum += anon[i];
	report_fault_delta("private_anon_zero_page_faults", initial_faults);

	/* First writes replace zero-page PTEs and allocate private anonymous pages. */
	PHASE("anonymous private: write and allocate private pages");
	initial_faults = read_fault_counts();
	for (size_t i = 0; i < ANON_LENGTH; i += page_size)
		anon[i] = (unsigned char)(i / page_size);
	report_fault_delta("private_anon_write_faults", initial_faults);

	/* fork shares MAP_PRIVATE pages only until either process writes and gets a COW copy. */
	PHASE("anonymous private: fork and copy on write");
	unsigned char parent_value = anon[0];
	pid_t child = fork();
	if (child == 0)
	{
		/* One write per page forces COW without rewriting every byte. */
		for (size_t i = 0; i < 2 * MiB; i += page_size)
			anon[i] ^= 0xa5;
		_exit(0);
	}
	if (child < 0)
	{
		perror("fork(private COW)");
		result = -1;
	}
	else
	{
		int status;
		waitpid(child, &status, 0);
		int isolated = WIFEXITED(status) && WEXITSTATUS(status) == 0 && anon[0] == parent_value;
		if (!isolated)
			result = -1;
	}

	/* A write to a read-only VMA is a protection fault, not a demand fault. */
	PHASE("anonymous private: make pages read only and reject a write");
	if (mprotect(anon + 2 * MiB, 2 * MiB, PROT_READ) != 0)
	{
		perror("mprotect(read-only)");
		result = -1;
	}
	else
	{
		mapping_state("private_anon", "protect", anon + 2 * MiB, 2 * MiB, "r", "anonymous");
		child = fork();
		if (child == 0)
		{
			*(volatile unsigned char *)(anon + 2 * MiB) = 0xff;
			_exit(0);
		}
		if (child < 0 || wait_for_signal(child, SIGSEGV, "private_anon_write_protection") != 0)
			result = -1;
		PHASE("anonymous private: restore write permission and merge VMAs");
		if (mprotect(anon + 2 * MiB, 2 * MiB, PROT_READ | PROT_WRITE) != 0)
			result = -1;
		else
			mapping_state("private_anon", "protect", anon + 2 * MiB, 2 * MiB, "rw", "anonymous");
	}

	/* Removing the middle creates two VMAs separated by an unmapped hole. */
	PHASE("anonymous private: unmap the middle and create a VMA hole");
	if (munmap(anon + 4 * MiB, 1 * MiB) != 0)
	{
		perror("munmap(private hole)");
		result = -1;
	}
	else
	{
		mapping_state("private_anon", "unmap_hole", anon + 4 * MiB, 1 * MiB, "none", "anonymous");
	}

	/* Resize the final part of this same mapping; no unrelated mmap is needed. */
	PHASE("anonymous private: grow and possibly move the mapping tail");
	unsigned char *tail = anon + 7 * MiB;
	mapping_state("private_anon_tail", "select", tail, 1 * MiB, "rw", "anonymous");
	errno = 0;
	unsigned char *remapped = mremap(tail, 1 * MiB, 3 * MiB, MREMAP_MAYMOVE);
	if (remapped == MAP_FAILED)
	{
		perror("mremap(grow)");
		result = -1;
	}
	else
	{
		mapping_state("private_anon_tail", "grow", remapped, 3 * MiB, "rw", "anonymous");
		memset(remapped + 1 * MiB, 0x52, 2 * MiB);
		PHASE("anonymous private: shrink the remapped tail");
		errno = 0;
		unsigned char *shrunk = mremap(remapped, 3 * MiB, 2 * MiB, 0);
		if (shrunk == MAP_FAILED)
		{
			perror("mremap(shrink)");
			munmap(remapped, 3 * MiB);
			result = -1;
		}
		else
		{
			mapping_state("private_anon_tail", "shrink", shrunk, 2 * MiB, "rw", "anonymous");
			munmap(shrunk, 2 * MiB);
			mapping_state("private_anon", "unmap_tail", shrunk, 2 * MiB, "none", "anonymous");
		}
	}

	/* MADV_DONTNEED discards private pages; writes allocate fresh zeroed pages. */
	PHASE("anonymous private: discard pages and fault them back");
	errno = 0;
	int discarded = madvise(anon + 1 * MiB, 1 * MiB, MADV_DONTNEED);
	if (discarded != 0)
		result = -1;
	initial_faults = read_fault_counts();
	for (size_t i = 1 * MiB; i < 2 * MiB; i += page_size)
		anon[i] = (unsigned char)(i / page_size);
	report_fault_delta("private_anon_discard_refaults", initial_faults);

	/* With active swap, pageout installs swap entries and reads fault them back. */
	PHASE("anonymous private: page out to swap and fault back");
	struct sysinfo memory;
	if (sysinfo(&memory) == 0 && memory.totalswap != 0)
	{
		if (madvise(anon + 2 * MiB, 1 * MiB, MADV_PAGEOUT) != 0)
		{
			perror("madvise(private pageout)");
			result = -1;
		}
		else
		{
			initial_faults = read_fault_counts();
			for (size_t i = 2 * MiB; i < 3 * MiB; i += page_size)
				*checksum += anon[i];
			report_fault_delta("private_anon_swapin_faults", initial_faults);
		}
	}
	PHASE("anonymous private: unmap surviving ranges");
	munmap(anon, 4 * MiB);
	munmap(anon + 5 * MiB, 2 * MiB);
	mapping_state("private_anon", "unmap", anon, ANON_LENGTH, "none", "anonymous");
	return result;
}

/* Exercise shmem-backed anonymous pages shared across fork and swap. */
static int exercise_shared_anonymous_memory(size_t page_size, volatile unsigned long *checksum)
{
	int result = 0;

	/* Unlike forked MAP_PRIVATE memory, MAP_SHARED anonymous memory stays shared through shmem. */
	PHASE("anonymous shared: map shmem backed pages and fault them in");
	unsigned char *shared = mmap(NULL, SHARED_ANON_LENGTH, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (shared == MAP_FAILED)
	{
		perror("mmap(shared anonymous)");
		return -1;
	}
	mapping_state("shared_anon", "map", shared, SHARED_ANON_LENGTH, "rw", "shmem");

	struct fault_counts initial_faults = read_fault_counts();
	for (size_t i = 0; i < SHARED_ANON_LENGTH; i += page_size)
		*checksum += shared[i];
	report_fault_delta("shared_anon_demand_faults", initial_faults);

	/* Child writes update the same shmem folios, so the parent sees them. */
	PHASE("anonymous shared: fork and observe shared writes");
	pid_t child = fork();
	if (child == 0)
	{
		for (size_t i = 0; i < 4 * MiB; i += page_size)
			shared[i] = (unsigned char)(0x80 ^ (i / page_size));
		_exit(0);
	}
	if (child < 0)
	{
		perror("fork(shared anonymous)");
		result = -1;
	}
	else
	{
		int status;
		waitpid(child, &status, 0);
		int visible = WIFEXITED(status) && WEXITSTATUS(status) == 0;
	for (size_t i = 0; visible && i < 4 * MiB; i += page_size)
			visible = shared[i] ==
					  (unsigned char)(0x80 ^ (i / page_size));
		if (!visible)
			result = -1;
	}

	PHASE("anonymous shared: page out to swap and fault back");
	struct sysinfo shared_memory;
	if (sysinfo(&shared_memory) == 0 && shared_memory.totalswap != 0)
	{
		if (madvise(shared, 4 * MiB, MADV_PAGEOUT) != 0)
		{
			perror("madvise(shared pageout)");
			result = -1;
		}
		else
		{
			initial_faults = read_fault_counts();
			for (size_t i = 0; i < 4 * MiB; i += page_size)
				*checksum += shared[i];
			report_fault_delta("shared_anon_swapin_faults", initial_faults);
		}
	}
	PHASE("anonymous shared: unmap shared memory");
	munmap(shared, SHARED_ANON_LENGTH);
	mapping_state("shared_anon", "unmap", shared, SHARED_ANON_LENGTH, "none", "shmem");
	return result;
}

/*
 * Exercise one real file through both MAP_SHARED and MAP_PRIVATE.
 * The phases distinguish page-cache residency, PTE refaults, coherence, persistence, private COW, permission failures, and invalidated file offsets.
 */
static int exercise_file_backed_memory(size_t page_size, volatile unsigned long *checksum)
{
	char path[] = "/var/tmp/koops-mm-XXXXXX";

	PHASE("file backed: seed disk blocks and drop the page cache");
	int fd = mkstemp(path);
	if (fd < 0)
	{
		perror("mkstemp");
		return -1;
	}
	int result = 0;
	if (ftruncate(fd, FILE_LENGTH) != 0)
	{
		perror("ftruncate(seed)");
		close(fd);
		unlink(path);
		return -1;
	}

	for (size_t i = 0; i < FILE_LENGTH; i += page_size)
	{
		unsigned char value = (unsigned char)(i / page_size);
		if (pwrite(fd, &value, 1, (off_t)i) != 1)
		{
			perror("pwrite(seed)");
			close(fd);
			unlink(path);
			return -1;
		}
	}
	int seed_sync = fsync(fd);
	int seed_drop = posix_fadvise(fd, 0, FILE_LENGTH, POSIX_FADV_DONTNEED);
	if (seed_sync != 0 || seed_drop != 0)
		result = -1;

	int read_only_fd = open(path, O_RDONLY | O_CLOEXEC);
	if (read_only_fd < 0)
	{
		perror("open(read-only backing)");
		result = -1;
	}
	else
	{
	}
	unlink(path);

	/* A cold mapping starts without resident cache folios and may require I/O. */
	PHASE("file shared: cold page cache faults");
	unsigned char *cold = mmap(NULL, FILE_LENGTH, PROT_READ, MAP_SHARED, fd, 0);
	if (cold == MAP_FAILED)
	{
		perror("mmap(cold shared)");
		if (read_only_fd >= 0)
			close(read_only_fd);
		close(fd);
		return -1;
	}
	mapping_state("shared_file", "map", cold, FILE_LENGTH, "r", "page_cache");
	struct fault_counts initial_faults = read_fault_counts();
	for (size_t i = 0; i < FILE_LENGTH; i += page_size)
		*checksum += cold[i];
	report_fault_delta("file_shared_cold_faults", initial_faults);

	/* Dropping PTEs while retaining cache produces warm minor refaults. */
	PHASE("file shared: drop PTEs and refault warm cache");
	errno = 0;
	int dropped_ptes = madvise(cold, FILE_LENGTH, MADV_DONTNEED);
	if (dropped_ptes != 0)
		result = -1;
	initial_faults = read_fault_counts();
	for (size_t i = 0; i < FILE_LENGTH; i += page_size)
		*checksum += cold[i];
	report_fault_delta("file_shared_warm_faults", initial_faults);

	/* A present read-only PTE rejects writes with a protection SIGSEGV. */
	PHASE("file shared: reject a write through a read only mapping");
	pid_t child = fork();
	if (child == 0)
	{
		*(volatile unsigned char *)cold = 0xff;
		_exit(0);
	}
	if (child < 0 || wait_for_signal(child, SIGSEGV, "file_read_only_write") != 0)
		result = -1;

	/* A read-only fd cannot create a writable shared mapping at all. */
	PHASE("file shared: reject writable mmap from a read only fd");
	if (read_only_fd >= 0)
	{
		errno = 0;
		void *invalid = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, read_only_fd, 0);
		int rejected = invalid == MAP_FAILED && errno == EACCES;
		if (invalid != MAP_FAILED)
			munmap(invalid, page_size);
		if (!rejected)
			result = -1;
	}
	munmap(cold, FILE_LENGTH);
	mapping_state("shared_file", "unmap", cold, FILE_LENGTH, "none", "page_cache");

	/* Two MAP_SHARED VMAs resolve to the same dirty page-cache folios. */
	PHASE("file shared: share dirty page cache folios between mappings");
	unsigned char *shared_a = mmap(NULL, FILE_LENGTH, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	unsigned char *shared_b = mmap(NULL, FILE_LENGTH, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (shared_a == MAP_FAILED || shared_b == MAP_FAILED)
	{
		perror("mmap(shared pair)");
		if (shared_a != MAP_FAILED)
			munmap(shared_a, FILE_LENGTH);
		if (shared_b != MAP_FAILED)
			munmap(shared_b, FILE_LENGTH);
		if (read_only_fd >= 0)
			close(read_only_fd);
		close(fd);
		return -1;
	}
	mapping_state("shared_file_a", "map", shared_a, FILE_LENGTH, "rw", "page_cache");
	mapping_state("shared_file_b", "map", shared_b, FILE_LENGTH, "rw", "page_cache");

	for (size_t i = 0; i < 4 * MiB; i += page_size)
		shared_a[i] = (unsigned char)(0x5a ^ (i / page_size));
	int coherent = 1;
	for (size_t i = 0; coherent && i < 4 * MiB; i += page_size)
		coherent = shared_b[i] ==
				   (unsigned char)(0x5a ^ (i / page_size));
	if (!coherent)
		result = -1;

	/* Coherence is immediate; persistence is a separate writeback operation. */
	PHASE("file shared: write dirty cache folios back to disk");
	int synced = msync(shared_a, 4 * MiB, MS_SYNC) == 0 && fsync(fd) == 0;
	if (!synced)
		result = -1;
	munmap(shared_a, FILE_LENGTH);
	munmap(shared_b, FILE_LENGTH);
	mapping_state("shared_file", "unmap", shared_a, FILE_LENGTH, "none", "page_cache");
	int persistence_drop = posix_fadvise(fd, 0, FILE_LENGTH, POSIX_FADV_DONTNEED);
	if (persistence_drop != 0)
		result = -1;

	int persistent = 1;
	for (size_t i = 0; persistent && i < 4 * MiB; i += page_size)
	{
		unsigned char value;
		persistent = pread(fd, &value, 1, (off_t)i) == 1 &&
					 value == (unsigned char)(0x5a ^ (i / page_size));
	}
	if (!persistent)
		result = -1;

	/* MAP_PRIVATE reads file folios, then writes replace PTEs with anon COW. */
	PHASE("file private: read page cache then copy on write");
	unsigned char *shared_view = mmap(NULL, FILE_LENGTH, PROT_READ, MAP_SHARED, fd, 0);
	unsigned char *private_view = mmap(NULL, FILE_LENGTH, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (shared_view == MAP_FAILED || private_view == MAP_FAILED)
	{
		perror("mmap(private comparison)");
		result = -1;
	}
	else
	{
		mapping_state("shared_file", "map", shared_view, FILE_LENGTH, "r", "page_cache");
		mapping_state("private_file", "map", private_view, FILE_LENGTH, "rw", "file_then_anon_cow");
		initial_faults = read_fault_counts();
		for (size_t i = 0; i < FILE_LENGTH; i += page_size)
			*checksum += private_view[i];
		report_fault_delta("file_private_initial_faults", initial_faults);

		for (size_t i = 0; i < 4 * MiB; i += page_size)
			private_view[i] ^= 0x3c;
		mapping_state("private_file", "cow", private_view, 4 * MiB, "rw", "anonymous_cow");

		int isolated = 1;
		for (size_t i = 0; isolated && i < 4 * MiB; i += page_size)
		{
			unsigned char file_value = (unsigned char)(0x5a ^ (i / page_size));
			isolated = shared_view[i] == file_value && private_view[i] == (unsigned char)(file_value ^ 0x3c);
		}
		if (!isolated)
			result = -1;

		PHASE("file private: page out private COW pages and fault back");
		struct sysinfo memory;
		if (sysinfo(&memory) == 0 && memory.totalswap != 0)
		{
			if (madvise(private_view, 4 * MiB, MADV_PAGEOUT) != 0)
			{
				perror("madvise(private file pageout)");
				result = -1;
			}
			else
			{
				initial_faults = read_fault_counts();
				for (size_t i = 0; i < 4 * MiB; i += page_size)
					*checksum += private_view[i];
				report_fault_delta("file_private_cow_swapin_faults", initial_faults);
			}
		}
	}

	/* Truncation invalidates the final mapped page; accessing it raises SIGBUS. */
	PHASE("file backed: truncate the file and raise SIGBUS");
	if (shared_view != MAP_FAILED && ftruncate(fd, FILE_LENGTH - page_size) == 0)
	{
		child = fork();
		if (child == 0)
		{
			volatile unsigned char value = shared_view[FILE_LENGTH - page_size];
			(void)value;
			_exit(0);
		}
		if (child < 0 || wait_for_signal(child, SIGBUS, "file_truncate_access") != 0)
			result = -1;
	}
	else
	{
		perror("ftruncate(SIGBUS)");
		result = -1;
	}

	if (shared_view != MAP_FAILED)
	{
		munmap(shared_view, FILE_LENGTH);
		mapping_state("shared_file", "unmap", shared_view, FILE_LENGTH, "none", "page_cache");
	}
	if (private_view != MAP_FAILED)
	{
		munmap(private_view, FILE_LENGTH);
		mapping_state("private_file", "unmap", private_view, FILE_LENGTH, "none", "file_then_anon_cow");
	}
	if (read_only_fd >= 0)
		close(read_only_fd);
	close(fd);
	return result;
}

/* Keep THP independent so it cannot obscure the base-page exercises above. */
static int exercise_transparent_huge_pages(size_t page_size)
{
	PHASE("transparent huge pages: populate base pages");
	unsigned char *mapping = mmap(NULL, THP_LENGTH + 2 * MiB, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mapping == MAP_FAILED)
	{
		perror("mmap(transparent huge pages)");
		return -1;
	}

	/* Find a 2 MiB-aligned 8 MiB range inside the 10 MiB allocation. */
	unsigned char *thp = (unsigned char *)(((uintptr_t)mapping + 2 * MiB - 1) & ~(uintptr_t)(2 * MiB - 1));
	mapping_state("thp", "map", thp, THP_LENGTH, "rw", "anonymous");
	if (madvise(thp, THP_LENGTH, MADV_NOHUGEPAGE) != 0)
	{
		perror("madvise(MADV_NOHUGEPAGE)");
		munmap(mapping, THP_LENGTH + 2 * MiB);
		return -1;
	}
	for (size_t i = 0; i < THP_LENGTH; i += page_size)
		thp[i] = (unsigned char)(i / page_size);

	PHASE("transparent huge pages: collapse base pages into huge pages");
	if (madvise(thp, THP_LENGTH, MADV_HUGEPAGE) != 0 || madvise(thp, THP_LENGTH, MADV_COLLAPSE) != 0)
	{
		perror("madvise(transparent huge pages)");
		munmap(mapping, THP_LENGTH + 2 * MiB);
		return -1;
	}
	mapping_state("thp", "collapse", thp, THP_LENGTH, "rw", "transparent_huge_page");

	PHASE("transparent huge pages: split with single page protection");
	if (mprotect(thp + 4 * MiB, page_size, PROT_READ) != 0)
	{
		perror("mprotect(split transparent huge page)");
		munmap(mapping, THP_LENGTH + 2 * MiB);
		return -1;
	}
	mapping_state("thp", "split", thp + 4 * MiB, page_size, "r", "anonymous");
	mprotect(thp + 4 * MiB, page_size, PROT_READ | PROT_WRITE);

	PHASE("transparent huge pages: unmap");
	munmap(mapping, THP_LENGTH + 2 * MiB);
	mapping_state("thp", "unmap", thp, THP_LENGTH, "none", "anonymous");
	return 0;
}

int main(void)
{
	marker_fd = open("/sys/kernel/tracing/trace_marker", O_WRONLY | O_CLOEXEC);

	long configured_page_size = sysconf(_SC_PAGESIZE);
	if (configured_page_size <= 0)
	{
		perror("sysconf(_SC_PAGESIZE)");
		return 1;
	}
	size_t page_size = (size_t)configured_page_size;
	printf("memory workload starting page_size=%zu\n", page_size);

	volatile unsigned long checksum = 0;
	int result = exercise_file_backed_memory(page_size, &checksum);
	if (exercise_private_anonymous_memory(page_size, &checksum) != 0)
		result = -1;
	if (exercise_shared_anonymous_memory(page_size, &checksum) != 0)
		result = -1;
	if (exercise_transparent_huge_pages(page_size) != 0)
		result = -1;

	PHASE("complete");
	if (marker_fd >= 0)
		close(marker_fd);
	printf("memory workload complete checksum=%lu result=%s\n", checksum, result == 0 ? "pass" : "fail");
	return result == 0 ? 0 : 1;
}
