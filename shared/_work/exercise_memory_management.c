/*
 * This does not attempt every Linux MM feature—NUMA migration, memory cgroups, mlock, hugeTLB, DAX, direct I/O, userfaultfd, KSM, and OOM behavior are separate subjects.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <sys/wait.h>
#include <unistd.h>

#define KiB 1024UL
#define MiB (1024UL * KiB)
#define ANON_LENGTH (2 * MiB)
#define ANON_EIGHTH_LENGTH (ANON_LENGTH / 8)
#define ANON_QUARTER_LENGTH (ANON_LENGTH / 4)
#define ANON_HALF_LENGTH (ANON_LENGTH / 2)
#define ANON_PROTECT_START ANON_QUARTER_LENGTH
#define ANON_PROTECT_LENGTH ANON_QUARTER_LENGTH
#define ANON_HOLE_START ANON_HALF_LENGTH
#define ANON_HOLE_LENGTH ANON_EIGHTH_LENGTH
#define ANON_TAIL_OLD_LENGTH ANON_EIGHTH_LENGTH
#define ANON_TAIL_GROWN_LENGTH (ANON_QUARTER_LENGTH + ANON_EIGHTH_LENGTH)
#define ANON_TAIL_FINAL_LENGTH ANON_QUARTER_LENGTH
#define ANON_TAIL_OFFSET (ANON_LENGTH - ANON_TAIL_OLD_LENGTH)
#define ANON_DISCARD_START ANON_EIGHTH_LENGTH
#define ANON_DISCARD_LENGTH ANON_EIGHTH_LENGTH
#define ANON_PAGEOUT_START ANON_QUARTER_LENGTH
#define ANON_PAGEOUT_LENGTH ANON_EIGHTH_LENGTH
#define SHARED_ANON_LENGTH (2 * MiB)
#define SHARED_ANON_HALF_LENGTH (SHARED_ANON_LENGTH / 2)
#define FILE_LENGTH (2 * MiB)
#define FILE_HALF_LENGTH (FILE_LENGTH / 2)
#define THP_LENGTH (2 * MiB)
#define THP_ALIGNMENT (2 * MiB)
#define THP_MAPPING_LENGTH (THP_LENGTH + THP_ALIGNMENT)
#define THP_SPLIT_OFFSET (THP_LENGTH / 2)

__attribute__((noinline, used, visibility("default"))) void phase_boundary(void)
{
	/* Explicit uprobe target: snapshots are taken after a phase line is printed. */
	asm volatile("" ::: "memory");
}

__attribute__((noinline, used, visibility("default"))) void phase(const char *name)
{
	static const char *active_phase;

	/* Publish the preceding phase at this boundary, after its work completed. */
	if (active_phase)
	{
		struct timespec now;
		clock_gettime(CLOCK_MONOTONIC, &now);
		unsigned long long time_ns = (unsigned long long)now.tv_sec * 1000000000ULL + (unsigned long long)now.tv_nsec;
		printf("{\"type\":\"phase\",\"time_ns\":%llu,\"name\":\"%s\"}\n", time_ns, active_phase);
		fflush(stdout);
		phase_boundary();
	}
	active_phase = name;
}

static size_t kb_count(size_t bytes)
{
	return bytes / KiB;
}

static void phasef(const char *format, ...)
{
	static char messages[2][256];
	static unsigned int slot;
	va_list args;

	slot = (slot + 1) & 1;
	va_start(args, format);
	vsnprintf(messages[slot], sizeof(messages[slot]), format, args);
	va_end(args);
	phase(messages[slot]);
}

#define PHASE(...) phasef(__VA_ARGS__)

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
 * Exercise one real file through both MAP_SHARED and MAP_PRIVATE.
 * The phases distinguish page-cache residency, PTE refaults, coherence, persistence, private COW, permission failures, and invalidated file offsets.
 */
static int exercise_file_backed_memory(size_t page_size, volatile unsigned long *checksum)
{
	char path[] = "/var/tmp/koops-mm-XXXXXX";

	/* Seed deterministic disk contents, then drop cache so the first file faults are cold. */
	PHASE("file backed: created a %zu KB file, wrote one byte per page, synced it, and evicted cached pages", kb_count(FILE_LENGTH));
	int fd = mkstemp(path);
	if (fd < 0)
	{
		perror("mkstemp");
		return -1;
	}
	int result = 0;
	pid_t child;
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
	unlink(path);

	/* A cold mapping starts without resident cache folios and may require I/O. */
	PHASE("file shared: mmap installed one %zu KB read-only MAP_SHARED VMA without faulting file pages", kb_count(FILE_LENGTH));
	unsigned char *cold = mmap(NULL, FILE_LENGTH, PROT_READ, MAP_SHARED, fd, 0);
	if (cold == MAP_FAILED)
	{
		perror("mmap(cold shared)");
		if (read_only_fd >= 0)
			close(read_only_fd);
		close(fd);
		return -1;
	}

	/* Cold reads connect the VMA to page-cache folios and install file PTEs. */
	PHASE("file shared: cold reads populated page cache and read-only PTEs across %zu KB", kb_count(FILE_LENGTH));
	for (size_t i = 0; i < FILE_LENGTH; i += page_size)
		*checksum += cold[i];

	/* Dropping PTEs while retaining cache produces warm minor refaults. */
	PHASE("file shared: MADV_DONTNEED removed PTEs for the %zu KB VMA while address_space cached pages remained", kb_count(FILE_LENGTH));
	errno = 0;
	int dropped_ptes = madvise(cold, FILE_LENGTH, MADV_DONTNEED);
	if (dropped_ptes != 0)
		result = -1;

	/* Cached folios remain, so refaults rebuild PTEs without disk I/O. */
	PHASE("file shared: warm reads rebuilt %zu KB of PTEs from cached folios", kb_count(FILE_LENGTH));
	for (size_t i = 0; i < FILE_LENGTH; i += page_size)
		*checksum += cold[i];

	/* Removing the VMA does not evict its clean pages from address_space. */
	PHASE("file shared: munmap removed the %zu KB cold read-only VMA while clean pages remained in the page cache", kb_count(FILE_LENGTH));
	munmap(cold, FILE_LENGTH);

	/* Two MAP_SHARED VMAs resolve to the same dirty page-cache folios. */
	PHASE("file shared: two writable %zu KB MAP_SHARED VMAs mapped the same inode and address_space", kb_count(FILE_LENGTH));
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

	/* MAP_SHARED writes dirty page-cache folios, not private anonymous pages. */
	PHASE("file shared: writes through shared_a dirty %zu KB of shared page-cache folios", kb_count(FILE_HALF_LENGTH));
	for (size_t i = 0; i < FILE_HALF_LENGTH; i += page_size)
		shared_a[i] = (unsigned char)(0x5a ^ (i / page_size));

	/* The second shared VMA sees the same dirty cache folios immediately. */
	PHASE("file shared: reads through shared_b observe the same %zu KB dirty folios", kb_count(FILE_HALF_LENGTH));
	int coherent = 1;
	for (size_t i = 0; coherent && i < FILE_HALF_LENGTH; i += page_size)
		coherent = shared_b[i] == (unsigned char)(0x5a ^ (i / page_size));
	if (!coherent)
		result = -1;

	/* Coherence is immediate; persistence is a separate writeback operation. */
	PHASE("file shared: msync and fsync wrote back %zu KB of dirty cache pages while both shared VMAs remained mapped", kb_count(FILE_HALF_LENGTH));
	int synced = msync(shared_a, FILE_HALF_LENGTH, MS_SYNC) == 0 && fsync(fd) == 0;
	if (!synced)
		result = -1;

	/* Unmap one alias while the inode and second shared VMA remain alive. */
	PHASE("file shared: munmap(shared_a) removes the first VMA while shared_b remains mapped");
	munmap(shared_a, FILE_LENGTH);

	/* Remove the final shared alias after writeback has completed. */
	PHASE("file shared: munmap(shared_b) removes the remaining shared VMA");
	munmap(shared_b, FILE_LENGTH);

	/* Ask the kernel to drop clean cache so the private-file section starts clear. */
	PHASE("file shared: cache eviction requested after both shared VMAs were removed");
	int persistence_drop = posix_fadvise(fd, 0, FILE_LENGTH, POSIX_FADV_DONTNEED);
	if (persistence_drop != 0)
		result = -1;

	/* MAP_PRIVATE reads file folios, then writes replace PTEs with anon COW. */
	PHASE("file private: mmap installed %zu KB read-only MAP_SHARED and writable MAP_PRIVATE views of the same inode", kb_count(FILE_LENGTH));
	unsigned char *shared_view = mmap(NULL, FILE_LENGTH, PROT_READ, MAP_SHARED, fd, 0);
	unsigned char *private_view = mmap(NULL, FILE_LENGTH, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
	if (shared_view == MAP_FAILED || private_view == MAP_FAILED)
	{
		perror("mmap(private comparison)");
		result = -1;
	}
	else
	{
		/* MAP_PRIVATE reads still use page-cache folios until the mapping writes. */
		PHASE("file private: reads faulted %zu KB MAP_PRIVATE pages from page cache", kb_count(FILE_LENGTH));
		for (size_t i = 0; i < FILE_LENGTH; i += page_size)
			*checksum += private_view[i];

		/* First MAP_PRIVATE writes replace file PTEs with private anonymous pages. */
		PHASE("file private: writes COWed %zu KB into anonymous pages", kb_count(FILE_HALF_LENGTH));
		for (size_t i = 0; i < FILE_HALF_LENGTH; i += page_size)
			private_view[i] ^= 0x3c;

		/* After COW, the VMA remains file-backed but dirty PTEs point at anon pages. */
		PHASE("file private: COW complete; private PTEs target anon pages");
		int isolated = 1;
		for (size_t i = 0; isolated && i < FILE_HALF_LENGTH; i += page_size)
		{
			unsigned char file_value = (unsigned char)(0x5a ^ (i / page_size));
			isolated = shared_view[i] == file_value && private_view[i] == (unsigned char)(file_value ^ 0x3c);
		}
		if (!isolated)
			result = -1;

		/* Private COW pages behave like anonymous memory when pageout targets them. */
		PHASE("file private: MADV_PAGEOUT requested swapout for %zu KB of COW pages", kb_count(FILE_HALF_LENGTH));
		struct sysinfo memory;
		if (sysinfo(&memory) == 0 && memory.totalswap != 0)
		{
			if (madvise(private_view, FILE_HALF_LENGTH, MADV_PAGEOUT) != 0)
			{
				perror("madvise(private file pageout)");
				result = -1;
			}
			else
			{
				/* Reading the private COW range faults swapped/nonresident pages back in. */
				PHASE("file private: reads refaulted %zu KB of paged-out COW pages", kb_count(FILE_HALF_LENGTH));
				for (size_t i = 0; i < FILE_HALF_LENGTH; i += page_size)
					*checksum += private_view[i];
			}
		}
	}

	/* Truncation invalidates the final mapped page; accessing it raises SIGBUS. */
	PHASE("file private: truncation invalidated the final mapped file page, access raised SIGBUS, and remaining file VMAs were unmapped");
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
		munmap(shared_view, FILE_LENGTH);
	if (private_view != MAP_FAILED)
		munmap(private_view, FILE_LENGTH);

	if (read_only_fd >= 0)
		close(read_only_fd);
	close(fd);
	return result;
}

/*
 * Exercise private anonymous demand paging, COW, VMA changes, discard, and swap-backed pageout.
 */
static int exercise_private_anonymous_memory(size_t page_size, volatile unsigned long *checksum)
{
	int result = 0;

	/* Reserve address space; mmap itself does not populate physical pages. */
	PHASE("anonymous private: mmap created one %zu KB read-write MAP_PRIVATE anonymous VMA", kb_count(ANON_LENGTH));
	unsigned char *anon = mmap(NULL, ANON_LENGTH, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (anon == MAP_FAILED)
	{
		perror("mmap(private anonymous)");
		return -1;
	}

	/* Untouched reads fault through read-only zero-page mappings. */
	PHASE("anonymous private: read %zu KB untouched range; PTEs point to shared zero page, RSS unchanged", kb_count(ANON_EIGHTH_LENGTH));
	for (size_t i = 0; i < ANON_EIGHTH_LENGTH; i += page_size)
		*checksum += anon[i];

	/* First writes replace zero-page PTEs and allocate private anonymous pages. */
	PHASE("anonymous private: wrote %zu KB; zero-page PTEs became private anon PFNs", kb_count(ANON_LENGTH));
	for (size_t i = 0; i < ANON_LENGTH; i += page_size)
		anon[i] = (unsigned char)(i / page_size);

	/* fork shares MAP_PRIVATE pages only until either process writes and gets a COW copy. */
	PHASE("anonymous private: child wrote %zu KB after fork; parent kept original COW PFNs", kb_count(ANON_QUARTER_LENGTH));
	unsigned char parent_value = anon[0];
	pid_t child = fork();
	if (child == 0)
	{
		/* One write per page forces COW without rewriting every byte. */
		for (size_t i = 0; i < ANON_QUARTER_LENGTH; i += page_size)
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
	PHASE("anonymous private: mprotect made middle %zu KB read-only; VMA split into three", kb_count(ANON_PROTECT_LENGTH));
	if (mprotect(anon + ANON_PROTECT_START, ANON_PROTECT_LENGTH, PROT_READ) != 0)
	{
		perror("mprotect(read-only)");
		result = -1;
	}
	else
	{
		/* Verify that VMA permission changes are enforced by a protection fault. */
		PHASE("anonymous private: write to read-only middle VMA raised protection SIGSEGV");
		child = fork();
		if (child == 0)
		{
			*(volatile unsigned char *)(anon + ANON_PROTECT_START) = 0xff;
			_exit(0);
		}
		if (child < 0 || wait_for_signal(child, SIGSEGV, "private_anon_write_protection") != 0)
			result = -1;
		/* Restoring identical permissions lets the kernel merge compatible VMAs. */
		PHASE("anonymous private: mprotect restored write permission; compatible VMAs merged");
		if (mprotect(anon + ANON_PROTECT_START, ANON_PROTECT_LENGTH, PROT_READ | PROT_WRITE) != 0)
			result = -1;
	}

	/* Removing the middle creates two VMAs separated by an unmapped hole. */
	PHASE("anonymous private: munmap removed middle %zu KB; address space now has a hole", kb_count(ANON_HOLE_LENGTH));
	if (munmap(anon + ANON_HOLE_START, ANON_HOLE_LENGTH) != 0)
	{
		perror("munmap(private hole)");
		result = -1;
	}

	/* Resize the final part of this same mapping; no unrelated mmap is needed. */
	PHASE("anonymous private: mremap grew tail %zu→%zu KB; VMA may move", kb_count(ANON_TAIL_OLD_LENGTH), kb_count(ANON_TAIL_GROWN_LENGTH));
	unsigned char *tail = anon + ANON_TAIL_OFFSET;
	errno = 0;
	unsigned char *remapped = mremap(tail, ANON_TAIL_OLD_LENGTH, ANON_TAIL_GROWN_LENGTH, MREMAP_MAYMOVE);
	if (remapped == MAP_FAILED)
	{
		perror("mremap(grow)");
		result = -1;
	}
	else
	{
		/* Touching the expanded tail turns new virtual space into real anon pages. */
		PHASE("anonymous private: wrote new %zu KB tail; fresh private anon PFNs appeared", kb_count(ANON_TAIL_GROWN_LENGTH - ANON_TAIL_OLD_LENGTH));
		memset(remapped + ANON_TAIL_OLD_LENGTH, 0x52, ANON_TAIL_GROWN_LENGTH - ANON_TAIL_OLD_LENGTH);

		/* Shrinking keeps the remaining prefix mapped and releases the right end. */
		PHASE("anonymous private: mremap shrank tail %zu→%zu KB; right end unmapped", kb_count(ANON_TAIL_GROWN_LENGTH), kb_count(ANON_TAIL_FINAL_LENGTH));
		errno = 0;
		unsigned char *shrunk = mremap(remapped, ANON_TAIL_GROWN_LENGTH, ANON_TAIL_FINAL_LENGTH, 0);
		if (shrunk == MAP_FAILED)
		{
			perror("mremap(shrink)");
			munmap(remapped, ANON_TAIL_GROWN_LENGTH);
			result = -1;
		}
		else
		{
			/* Clean up the remapped tail so the later anon ranges are easier to read. */
			PHASE("anonymous private: munmap removed the remaining remapped tail VMA");
			munmap(shrunk, ANON_TAIL_FINAL_LENGTH);
		}
	}

	/* MADV_DONTNEED discards private pages and leaves the VMA in place. */
	PHASE("anonymous private: MADV_DONTNEED dropped %zu KB of anon PTEs", kb_count(ANON_DISCARD_LENGTH));
	errno = 0;
	int discarded = madvise(anon + ANON_DISCARD_START, ANON_DISCARD_LENGTH, MADV_DONTNEED);
	if (discarded != 0)
		result = -1;

	/* Writes after DONTNEED allocate fresh zeroed private anon pages. */
	PHASE("anonymous private: writes refaulted %zu KB as fresh zeroed anon pages", kb_count(ANON_DISCARD_LENGTH));
	for (size_t i = ANON_DISCARD_START; i < ANON_DISCARD_START + ANON_DISCARD_LENGTH; i += page_size)
		anon[i] = (unsigned char)(i / page_size);

	/* With active swap, pageout can replace present anon PTEs with swap entries. */
	PHASE("anonymous private: MADV_PAGEOUT requested swapout for %zu KB anon pages", kb_count(ANON_PAGEOUT_LENGTH));
	struct sysinfo memory;
	if (sysinfo(&memory) == 0 && memory.totalswap != 0)
	{
		if (madvise(anon + ANON_PAGEOUT_START, ANON_PAGEOUT_LENGTH, MADV_PAGEOUT) != 0)
		{
			perror("madvise(private pageout)");
			result = -1;
		}
		else
		{
			/* Reading the paged-out anon range faults swap/nonresident pages back in. */
			PHASE("anonymous private: reads refaulted %zu KB of paged-out anon pages", kb_count(ANON_PAGEOUT_LENGTH));
			for (size_t i = ANON_PAGEOUT_START; i < ANON_PAGEOUT_START + ANON_PAGEOUT_LENGTH; i += page_size)
				*checksum += anon[i];
		}
	}

	/* Remove the remaining pieces after the split/remap/discard sequence. */
	PHASE("anonymous private: munmap removed all remaining private-anon VMA ranges");
	munmap(anon, ANON_HOLE_START);
	munmap(anon + ANON_HOLE_START + ANON_HOLE_LENGTH, ANON_TAIL_OFFSET - (ANON_HOLE_START + ANON_HOLE_LENGTH));
	return result;
}

/* Exercise shmem-backed anonymous pages shared across fork and swap. */
static int exercise_shared_anonymous_memory(size_t page_size, volatile unsigned long *checksum)
{
	int result = 0;

	/* Unlike forked MAP_PRIVATE memory, MAP_SHARED anonymous memory stays shared through shmem. */
	PHASE("anonymous shared: mmap created one %zu KB read-write MAP_SHARED anonymous shmem VMA", kb_count(SHARED_ANON_LENGTH));
	unsigned char *shared = mmap(NULL, SHARED_ANON_LENGTH, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (shared == MAP_FAILED)
	{
		perror("mmap(shared anonymous)");
		return -1;
	}

	/* First access allocates shmem-backed pages rather than private anon pages. */
	PHASE("anonymous shared: reads faulted all %zu KB through shmem-backed shared pages", kb_count(SHARED_ANON_LENGTH));
	for (size_t i = 0; i < SHARED_ANON_LENGTH; i += page_size)
		*checksum += shared[i];

	/* Child writes update the same shmem folios, so the parent sees them. */
	PHASE("anonymous shared: child writes updated %zu KB of shared shmem pages visible to the parent", kb_count(SHARED_ANON_HALF_LENGTH));
	pid_t child = fork();
	if (child == 0)
	{
		for (size_t i = 0; i < SHARED_ANON_HALF_LENGTH; i += page_size)
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
		for (size_t i = 0; visible && i < SHARED_ANON_HALF_LENGTH; i += page_size)
			visible = shared[i] ==
					  (unsigned char)(0x80 ^ (i / page_size));
		if (!visible)
			result = -1;
	}

	/* Shared-anon pageout uses shmem/swap machinery while preserving contents. */
	PHASE("anonymous shared: MADV_PAGEOUT requested swapout for %zu KB shmem pages", kb_count(SHARED_ANON_HALF_LENGTH));
	struct sysinfo shared_memory;
	if (sysinfo(&shared_memory) == 0 && shared_memory.totalswap != 0)
	{
		if (madvise(shared, SHARED_ANON_HALF_LENGTH, MADV_PAGEOUT) != 0)
		{
			perror("madvise(shared pageout)");
			result = -1;
		}
		else
		{
			/* Reading the shared-anon range faults shmem/swap-backed pages back in. */
			PHASE("anonymous shared: reads refaulted %zu KB of paged-out shmem pages", kb_count(SHARED_ANON_HALF_LENGTH));
			for (size_t i = 0; i < SHARED_ANON_HALF_LENGTH; i += page_size)
				*checksum += shared[i];
		}
	}

	/* Removing the only shared-anon VMA drops this process view of the shmem object. */
	PHASE("anonymous shared: munmap removed the shared-anonymous shmem VMA");
	munmap(shared, SHARED_ANON_LENGTH);
	return result;
}

/* Keep THP independent so it cannot obscure the base-page exercises above. */
static int exercise_transparent_huge_pages(size_t page_size)
{
	/* Reserve padding, keep only the aligned 2 MiB VMA, and discard the padding. */
	PHASE("transparent huge pages: mmap kept one aligned %zu KB THP-sized VMA", kb_count(THP_LENGTH));
	unsigned char *mapping = mmap(NULL, THP_MAPPING_LENGTH, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mapping == MAP_FAILED)
	{
		perror("mmap(transparent huge pages)");
		return -1;
	}

	unsigned char *thp = (unsigned char *)(((uintptr_t)mapping + THP_ALIGNMENT - 1) & ~(uintptr_t)(THP_ALIGNMENT - 1));
	size_t prefix = (size_t)(thp - mapping);
	size_t suffix = THP_MAPPING_LENGTH - prefix - THP_LENGTH;
	if (prefix && munmap(mapping, prefix) != 0)
	{
		perror("munmap(thp prefix)");
		munmap(mapping, THP_MAPPING_LENGTH);
		return -1;
	}
	if (suffix && munmap(thp + THP_LENGTH, suffix) != 0)
	{
		perror("munmap(thp suffix)");
		munmap(thp, THP_LENGTH + suffix);
		return -1;
	}

	/* Keep first faults as base pages so collapse has a visible before/after. */
	PHASE("transparent huge pages: MADV_NOHUGEPAGE kept %zu KB in base-page mode", kb_count(THP_LENGTH));
	if (madvise(thp, THP_LENGTH, MADV_NOHUGEPAGE) != 0)
	{
		perror("madvise(MADV_NOHUGEPAGE)");
		munmap(thp, THP_LENGTH);
		return -1;
	}

	/* First writes populate exactly 512 base-page slots before collapse. */
	PHASE("transparent huge pages: writes populated %zu KB as %zu KiB PTEs", kb_count(THP_LENGTH), page_size / 1024);
	for (size_t i = 0; i < THP_LENGTH; i += page_size)
		thp[i] = (unsigned char)(i / page_size);

	/* Collapse the 512 base-page PTEs into one PMD-level THP mapping. */
	PHASE("transparent huge pages: MADV_COLLAPSE replaced 512 PTEs with one huge PMD");
	if (madvise(thp, THP_LENGTH, MADV_HUGEPAGE) != 0 || madvise(thp, THP_LENGTH, MADV_COLLAPSE) != 0)
	{
		perror("madvise(transparent huge pages)");
		munmap(thp, THP_LENGTH);
		return -1;
	}

	/* A 4 KiB permission change forces a huge-PMD split around that page. */
	PHASE("transparent huge pages: mprotect split one %zu KiB page from a THP", page_size / 1024);
	if (mprotect(thp + THP_SPLIT_OFFSET, page_size, PROT_READ) != 0)
	{
		perror("mprotect(split transparent huge page)");
		munmap(thp, THP_LENGTH);
		return -1;
	}

	/* Matching permissions allow adjacent VMAs to merge, but PTEs stay split. */
	PHASE("transparent huge pages: write permission restored VMA merge while PTEs stayed split");
	if (mprotect(thp + THP_SPLIT_OFFSET, page_size, PROT_READ | PROT_WRITE) != 0)
	{
		perror("mprotect(restore transparent huge page)");
		munmap(thp, THP_LENGTH);
		return -1;
	}

	/* Explicit collapse is needed to rebuild the huge PMD after mprotect split it. */
	PHASE("transparent huge pages: MADV_COLLAPSE rebuilt one huge PMD after split");
	if (madvise(thp, THP_LENGTH, MADV_COLLAPSE) != 0)
	{
		perror("madvise(recollapse transparent huge page)");
		munmap(thp, THP_LENGTH);
		return -1;
	}

	/* Tear down the aligned THP-sized VMA. */
	PHASE("transparent huge pages: munmap removed the aligned %zu KB THP VMA", kb_count(THP_LENGTH));
	munmap(thp, THP_LENGTH);
	return 0;
}

int main(void)
{
	long configured_page_size = sysconf(_SC_PAGESIZE);
	if (configured_page_size <= 0)
	{
		perror("sysconf(_SC_PAGESIZE)");
		return 1;
	}
	size_t page_size = (size_t)configured_page_size;

	volatile unsigned long checksum = 0;
	int result = exercise_file_backed_memory(page_size, &checksum);
	if (exercise_private_anonymous_memory(page_size, &checksum) != 0)
		result = -1;
	if (exercise_shared_anonymous_memory(page_size, &checksum) != 0)
		result = -1;
	if (exercise_transparent_huge_pages(page_size) != 0)
		result = -1;

	/* Final boundary lets the observer capture the fully cleaned-up address space. */
	PHASE("complete: file, private-anon, shared-anon, and THP mappings cleaned up");
	phase(NULL);
	printf("{\"type\":\"result\",\"status\":\"%s\",\"checksum\":%lu}\n", result == 0 ? "pass" : "fail", checksum);
	return result == 0 ? 0 : 1;
}
