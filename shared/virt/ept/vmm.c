#include <linux/kvm.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#define GUEST_MEM_SIZE 0x8000
#define HUGE_MEM_SIZE 0x200000
#define THP_MAPPING_SIZE (HUGE_MEM_SIZE * 2)
#define HUGE_GPA 0x200000
#define HUGE_GFN_2ND (HUGE_GPA / 0x1000 + 1) /* GFN 513, GPA 0x201000: command-5 probe page. */
#define GUEST_PAGE_SIZE 0x1000
#define DATA_GPA 0x7000
#define DATA_GFN (DATA_GPA / GUEST_PAGE_SIZE)
#define CONTROL_PORT 0xe9

static int set_memory_region(int vm, uint32_t slot, uint64_t guest_phys_addr, uint8_t *memory, size_t size, uint32_t flags)
{
	struct kvm_userspace_memory_region region = {
		.slot = slot,
		.flags = flags,
		.guest_phys_addr = guest_phys_addr,
		.memory_size = size,
		.userspace_addr = (uint64_t)memory,
	};

	return ioctl(vm, KVM_SET_USER_MEMORY_REGION, &region);
}

/* The Command-4 huge slot backing, kept alive so Command 5 can re-register the same mapping with dirty logging. */
static uint8_t *huge_mem;

int main(void)
{
	const size_t guest_mem_size = GUEST_MEM_SIZE;

	int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);
	if (kvm < 0)
	{
		perror("open /dev/kvm");
		return 1;
	}

	/* KVM_GET_API_VERSION checks that this kernel speaks the stable KVM userspace ABI. */
	int api_version = ioctl(kvm, KVM_GET_API_VERSION, 0);
	if (api_version < 0)
	{
		perror("KVM_GET_API_VERSION");
		return 1;
	}
	if (api_version != 12)
	{
		fprintf(stderr, "unexpected KVM API version: %d\n", api_version);
		return 1;
	}
	/* KVM_CREATE_VM creates one VM object; its fd is used for VM-wide ioctls. */
	int vm = ioctl(kvm, KVM_CREATE_VM, 0);
	if (vm < 0)
	{
		perror("KVM_CREATE_VM");
		return 1;
	}

	/* Allocate normal userspace RAM; KVM runs against memory we provide and register below. */
	uint8_t *guest_mem = mmap(NULL, guest_mem_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (guest_mem == MAP_FAILED)
	{
		perror("mmap guest memory");
		return 1;
	}
	uint8_t *replacement_mem = mmap(NULL, guest_mem_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (replacement_mem == MAP_FAILED)
	{
		perror("mmap replacement guest memory");
		return 1;
	}
	uint8_t *active_mem = guest_mem;

	/* Load the tiny real-mode program at guest physical address 0x0000. */
	FILE *guest = fopen("build/guest.bin", "rb");
	if (!guest)
	{
		perror("fopen guest.bin");
		return 1;
	}
	size_t guest_size = fread(guest_mem, 1, guest_mem_size, guest);
	if (ferror(guest))
	{
		perror("fread guest.bin");
		return 1;
	}
	fclose(guest);
	(void)guest_size;

	/* KVM_SET_USER_MEMORY_REGION maps eight guest pages, GFN 0 through GFN 7. */
	if (set_memory_region(vm, 0, 0, active_mem, guest_mem_size, 0) < 0)
	{
		perror("KVM_SET_USER_MEMORY_REGION");
		return 1;
	}

	/* KVM_CREATE_VCPU creates one virtual CPU; its fd controls vCPU state and KVM_RUN. */
	int vcpu = ioctl(vm, KVM_CREATE_VCPU, 0);
	if (vcpu < 0)
	{
		perror("KVM_CREATE_VCPU");
		return 1;
	}

	/* KVM_GET_VCPU_MMAP_SIZE tells us how large the shared struct kvm_run page is. */
	int run_size = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, 0);
	if (run_size < 0)
	{
		perror("KVM_GET_VCPU_MMAP_SIZE");
		return 1;
	}

	struct kvm_run *run = mmap(NULL, (size_t)run_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpu, 0);
	if (run == MAP_FAILED)
	{
		perror("mmap struct kvm_run");
		return 1;
	}

	/* KVM_GET_SREGS reads special registers; we only change CS for real-mode address 0. */
	struct kvm_sregs sregs;
	if (ioctl(vcpu, KVM_GET_SREGS, &sregs) < 0)
	{
		perror("KVM_GET_SREGS");
		return 1;
	}
	sregs.cs.selector = 0;
	sregs.cs.base = 0;

	/* KVM_SET_SREGS writes the adjusted code segment back to KVM. */
	if (ioctl(vcpu, KVM_SET_SREGS, &sregs) < 0)
	{
		perror("KVM_SET_SREGS");
		return 1;
	}

	/* KVM_SET_REGS starts execution at CS:IP 0000:0000 with reserved RFLAGS set. */
	struct kvm_regs regs = {
		.rip = 0,
		.rflags = 0x2,
	};
	if (ioctl(vcpu, KVM_SET_REGS, &regs) < 0)
	{
		perror("KVM_SET_REGS");
		return 1;
	}

	/* Re-enter the vCPU after each userspace-visible KVM exit until the guest halts. */
	for (;;)
	{
		/* KVM_RUN enters the guest and returns when KVM must report an exit to userspace. */
		if (ioctl(vcpu, KVM_RUN, 0) < 0)
		{
			perror("KVM_RUN");
			return 1;
		}

		/* Handle guest IN/OUT instructions that KVM forwards to userspace. */
		if (run->exit_reason == KVM_EXIT_IO)
		{
			/* Locate the transferred bytes inside the shared struct kvm_run mapping. */
			uint8_t *data = (uint8_t *)run + run->io.data_offset;

			/* Port 0xe9 carries synchronization requests from this toy guest. */
			if (run->io.direction == KVM_EXIT_IO_OUT && run->io.port == CONTROL_PORT)
			{
				/* Command 1 discards the host page backing guest data GFN 7. */
				if (data[0] == 1)
				{
					/* The host-MM invalidation makes KVM remove the corresponding EPT mapping. */
					if (madvise(active_mem + DATA_GPA, 0x1000, MADV_DONTNEED) < 0)
					{
						perror("madvise(MADV_DONTNEED)");
						return 1;
					}
				}

				/* Command 2 replaces the entire KVM memory slot with new host memory. */
				else if (data[0] == 2)
				{
					/* Preserve code and GFN 7 while leaving the unused GFN 1-6 gap untouched. */
					memcpy(replacement_mem, active_mem, guest_size);
					memcpy(replacement_mem + DATA_GPA, active_mem + DATA_GPA, GUEST_PAGE_SIZE);

					/* Delete slot 0, then recreate it over the replacement host mapping. */
					if (set_memory_region(vm, 0, 0, NULL, 0, 0) < 0 ||
						set_memory_region(vm, 0, 0, replacement_mem, guest_mem_size, 0) < 0)
					{
						perror("replace KVM memory region");
						return 1;
					}
					/* Use the replacement mapping for subsequent host-side guest-memory operations. */
					active_mem = replacement_mem;
				}

				/* Command 3 keeps the mapping but resets dirty tracking for data GFN 7. */
				else if (data[0] == 3)
				{
					unsigned long clear_bitmap = 1UL << DATA_GFN;
					struct kvm_clear_dirty_log clear = {
						.slot = 0,
						.num_pages = guest_mem_size / GUEST_PAGE_SIZE,
						.first_page = 0,
						.dirty_bitmap = &clear_bitmap,
					};

					/* Enable dirty tracking, then clear only data GFN 7's dirty state. */
					if (set_memory_region(vm, 0, 0, active_mem, guest_mem_size, KVM_MEM_LOG_DIRTY_PAGES) < 0)
					{
						perror("enable KVM dirty logging");
						return 1;
					}
					/* KVM clears EPT D (or write-protects without A/D), then invalidates cached translations. */
					if (ioctl(vm, KVM_CLEAR_DIRTY_LOG, &clear) < 0)
					{
						perror("KVM_CLEAR_DIRTY_LOG");
						return 1;
					}
				}

				/* Command 4 adds one aligned 2 MiB THP-backed data slot at GPA 0x200000. */
				else if (data[0] == 4)
				{
					uint8_t *mapping = mmap(NULL, THP_MAPPING_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

					if (mapping == MAP_FAILED)
					{
						perror("mmap THP candidate");
						return 1;
					}
					huge_mem = (uint8_t *)(((uintptr_t)mapping + HUGE_MEM_SIZE - 1) & ~(uintptr_t)(HUGE_MEM_SIZE - 1));
					size_t prefix = (size_t)(huge_mem - mapping);
					size_t suffix = THP_MAPPING_SIZE - prefix - HUGE_MEM_SIZE;

					/* Keep only one 2 MiB-aligned anonymous VMA. */
					if ((prefix && munmap(mapping, prefix) < 0) ||
						(suffix && munmap(huge_mem + HUGE_MEM_SIZE, suffix) < 0))
					{
						perror("align THP candidate");
						return 1;
					}
					/* Ask for THP backing; base pages remain a valid observable fallback. */
					if (madvise(huge_mem, HUGE_MEM_SIZE, MADV_HUGEPAGE) < 0)
						perror("warning: madvise(MADV_HUGEPAGE)");
					for (size_t offset = 0; offset < HUGE_MEM_SIZE; offset += GUEST_PAGE_SIZE)
						huge_mem[offset] = (uint8_t)(offset / GUEST_PAGE_SIZE);
					/* Slot 0 keeps executable code; slot 1 is data-only so KVM can use an L2 leaf. */
					if (set_memory_region(vm, 1, HUGE_GPA, huge_mem, HUGE_MEM_SIZE, 0) < 0)
					{
						perror("install 2 MiB KVM memory region");
						return 1;
					}
				}

				/*
				 * Command 5 enables fine-grained dirty tracking on the existing huge slot.
				 * The same slot, GPA, HVA, and size stay; only the flags change to KVM_MEM_LOG_DIRTY_PAGES.
				 * Eager write-protection splits the level-2 huge leaf into level-1 4 KiB leaves on TDP-MMU kernels.
				 * The EPT observer reports whatever structure the kernel actually produces, not an assumed one.
				 */
				else if (data[0] == 5)
				{
					if (!huge_mem)
					{
						fprintf(stderr, "command 5 before a command 4 huge slot\n");
						return 1;
					}
					if (set_memory_region(vm, 1, HUGE_GPA, huge_mem, HUGE_MEM_SIZE, KVM_MEM_LOG_DIRTY_PAGES) < 0)
					{
						perror("enable dirty logging on 2 MiB slot");
						return 1;
					}
				}

				/* EPT workload controls remain guest I/O. */
			}

			/* Port 0x82 closes the run after the EPT workload has finished. */
			else if (run->io.direction == KVM_EXIT_IO_OUT && run->io.port == 0x82)
			{
				break;
			}

			/* Complete an IN instruction by placing the emulated device value in kvm_run. */
			else if (run->io.direction == KVM_EXIT_IO_IN)
			{
				data[0] = 0x11;
				(void)run->io.port;
			}
			continue;
		}

		/* Report guest accesses to GPAs that KVM routes to userspace as MMIO. */
		if (run->exit_reason == KVM_EXIT_MMIO)
		{
			continue;
		}

		/* HLT is the guest's timeout fallback when a wait never completes, never a success signal. */
		if (run->exit_reason == KVM_EXIT_HLT)
		{
			fprintf(stderr, "guest halted unexpectedly; a wait timed out\n");
			return 1;
		}

		/* Any unhandled exit means the toy VMM cannot safely resume the guest. */
		fprintf(stderr, "unexpected KVM exit reason: %u\n", run->exit_reason);
		return 1;
	}

	fprintf(stderr, "guest finished via port 0x82\n");
	return 0;
}
