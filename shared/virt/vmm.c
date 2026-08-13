#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

#define GUEST_MEM_SIZE 0x4000
#define DATA_GPA 0x2000
#define CONTROL_PORT 0xe9

static int set_memory_region(int vm, uint8_t *memory, size_t size)
{
	struct kvm_userspace_memory_region region = {
		.slot = 0,
		.flags = 0,
		.guest_phys_addr = 0,
		.memory_size = size,
		.userspace_addr = (uint64_t)memory,
	};

	return ioctl(vm, KVM_SET_USER_MEMORY_REGION, &region);
}

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
	printf("loaded guest.bin: %zu bytes\n", guest_size);

	/* KVM_SET_USER_MEMORY_REGION maps guest physical 0x0000 to our userspace page. */
	if (set_memory_region(vm, active_mem, guest_mem_size) < 0)
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
				/* Command 1 discards the host page backing guest data GFN 2. */
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
					/* Preserve guest bytes so execution can continue from the replacement mapping. */
					memcpy(replacement_mem, active_mem, guest_mem_size);

					/* Delete slot 0, then recreate it over the replacement host mapping. */
					if (set_memory_region(vm, NULL, 0) < 0 ||
						set_memory_region(vm, replacement_mem, guest_mem_size) < 0)
					{
						perror("replace KVM memory region");
						return 1;
					}
					/* Use the replacement mapping for subsequent host-side guest-memory operations. */
					active_mem = replacement_mem;
				}
				printf("userspace handled guest control command %u\n", data[0]);
			}

			/* Complete an IN instruction by placing the emulated device value in kvm_run. */
			else if (run->io.direction == KVM_EXIT_IO_IN)
			{
				data[0] = 0x11;
				printf("userspace received KVM_EXIT_IO IN port=0x%x value=0x%02x\n", run->io.port, data[0]);
			}
			/* Log ordinary OUT instructions that are not synchronization requests. */
			else
				printf("userspace received KVM_EXIT_IO OUT port=0x%x value=0x%02x\n", run->io.port, data[0]);
			continue;
		}

		/* Report guest accesses to GPAs that KVM routes to userspace as MMIO. */
		if (run->exit_reason == KVM_EXIT_MMIO)
		{
			printf("userspace received KVM_EXIT_MMIO addr=0x%llx len=%u write=%u data=0x%02x\n", (unsigned long long)run->mmio.phys_addr, run->mmio.len, run->mmio.is_write, run->mmio.data[0]);
			continue;
		}

		/* HLT is the guest's intentional completion signal for this experiment. */
		if (run->exit_reason == KVM_EXIT_HLT)
		{
			printf("userspace received KVM_EXIT_HLT\n");
			break;
		}

		/* Any unhandled exit means the toy VMM cannot safely resume the guest. */
		printf("unexpected KVM exit reason: %u\n", run->exit_reason);
		return 1;
	}

	return 0;
}
