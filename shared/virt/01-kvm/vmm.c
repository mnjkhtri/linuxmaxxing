#include <linux/kvm.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

int main(void)
{
	const size_t guest_mem_size = 0x1000;

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

	/* Load the tiny real-mode program at guest physical address 0x0000. */
	FILE *guest = fopen("guest.bin", "rb");
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
	struct kvm_userspace_memory_region mem = {
		.slot = 0,
		.flags = 0,
		.guest_phys_addr = 0,
		.memory_size = guest_mem_size,
		.userspace_addr = (uint64_t)guest_mem,
	};
	if (ioctl(vm, KVM_SET_USER_MEMORY_REGION, &mem) < 0)
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

	for (;;)
	{
		/* KVM_RUN enters the guest and returns when KVM must report an exit to userspace. */
		if (ioctl(vcpu, KVM_RUN, 0) < 0)
		{
			perror("KVM_RUN");
			return 1;
		}

		if (run->exit_reason == KVM_EXIT_IO)
		{
			uint8_t *data = (uint8_t *)run + run->io.data_offset;
			if (run->io.direction == KVM_EXIT_IO_OUT)
			{
				printf("userspace received KVM_EXIT_IO OUT port=0x%x value=0x%02x '%c'\n", run->io.port, data[0], data[0]);
			}
			else
			{
				data[0] = 0x11;
				printf("userspace received KVM_EXIT_IO IN port=0x%x value=0x%02x\n", run->io.port, data[0]);
			}
			continue;
		}

		if (run->exit_reason == KVM_EXIT_MMIO)
		{
			printf("userspace received KVM_EXIT_MMIO addr=0x%llx len=%u write=%u data=0x%02x\n", (unsigned long long)run->mmio.phys_addr, run->mmio.len, run->mmio.is_write, run->mmio.data[0]);
			continue;
		}

		if (run->exit_reason == KVM_EXIT_HLT)
		{
			printf("userspace received KVM_EXIT_HLT\n");
			break;
		}

		printf("unexpected KVM exit reason: %u\n", run->exit_reason);
		return 1;
	}

	return 0;
}
