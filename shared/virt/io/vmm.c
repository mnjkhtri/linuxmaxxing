// SPDX-License-Identifier: GPL-2.0
/*
 * Toy VMM for the IO-virtualization experiment.
 *
 * One VM, one vCPU, flat 32-bit protected-mode guest with paging off (GVA == GPA), one guest-RAM slot, and one tiny MMIO virtual device.
 * The guest programs its own virtual LAPIC/IOAPIC and drives the device; this VMM provides the device model and the interrupt transports.
 *
 * Two explicit interrupt-delivery paths (never conflated):
 *   legacy commands (CMD_IRQ_ONLY, CMD_DMA_TO_DEVICE, CMD_DMA_FROM_DEVICE):
 *     KVM_IRQ_LINE -> virtual IOAPIC -> virtual LAPIC -> guest IDT vector DEVICE_VECTOR
 *   MSI command (CMD_MSI_ONLY):
 *     KVM_SIGNAL_MSI with an architectural MSI message -> virtual LAPIC -> guest IDT vector MSI_VECTOR
 *     (the MSI message includes its own routing/delivery; no GSI and no IOAPIC participate)
 *
 * Main path for each operation:
 *   guest writes COMMAND over MMIO
 *     -> KVM_EXIT_MMIO
 *       -> device_mmio_write() -> device_execute_command()
 *         -> device_dma_transfer() (virtual DMA into guest RAM)
 *       -> legacy: device_raise_legacy_irq() (KVM_IRQ_LINE assert + deassert)
 *                    or MSI: device_signal_msi() (KVM_SIGNAL_MSI)
 *         -> KVM virtual IOAPIC/LAPIC -> guest IDT -> ISR
 *
 * NOTE: this is deliberately VIRTUAL DMA, not physical PCI bus-master DMA.
 * "Device -> guest memory" is a copy between the device's internal buffer and the registered KVM memory-slot backing (host userspace RAM).
 * No real device and no IOMMU is involved.
 */

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

#include "device.h"

#define GUEST_MEM_SIZE 0x20000 /* 128 KiB flat guest RAM (code, IDT, stack, buffers) */
#define GUEST_PAGE_SIZE 0x1000

/*
 * Toy device model: a small set of named MMIO registers plus device-internal storage.
 * MMIO writes update these fields; writing REG_COMMAND starts the operation.  Whatever is not a register lives in the buffer below.
 */
struct toy_device
{
	uint32_t command;					/* REG_COMMAND  last command written by the guest */
	uint32_t status;					/* REG_STATUS   STATUS_BUSY / STATUS_DONE / STATUS_ERROR */
	uint32_t dma_gpa;					/* REG_DMA_GPA  DMA target guest physical address */
	uint32_t result;					/* REG_RESULT   device result / checksum */
	uint8_t buffer[DEVICE_BUFFER_SIZE]; /* device-internal DMA target/source buffer */
};

/* Register the guest physical memory region this VMM supplies. */
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

/* Simple sum-of-bytes checksum left in REG_RESULT. */
static uint32_t bytesum(const uint8_t *data, size_t len)
{
	uint32_t sum = 0;

	for (size_t i = 0; i < len; i++)
		sum = (sum + data[i]) & 0xffffffffu;
	return sum;
}

/* Fill the device buffer with the deterministic device pattern the guest expects. */
static void refill_device_pattern(struct toy_device *dev)
{
	for (size_t i = 0; i < DEVICE_BUFFER_SIZE; i++)
		dev->buffer[i] = (uint8_t)(DEVICE_PATTERN_BASE + i);
}

/*
 * The real DMA operation.  __attribute__((noinline)) and kept unstripped so the eBPF observer's uprobe can attach here and see the transfer parameters as normal ABI arguments.
 * This is an actual part of the device implementation, not a synthetic instrumentation shim.
 * Virtual DMA: copies between the toy device's internal buffer and the host userspace memory backing the guest's GPA.
 * Every guest-supplied address is validated before use; a bad request never touches arbitrary VMM memory.
 */
__attribute__((noinline)) int device_dma_transfer(struct toy_device *dev, uint8_t *guest_mem_base, uint64_t guest_mem_size, uint32_t dir, uint64_t gpa, uint32_t len)
{
	if (!dev || !guest_mem_base)
		return -1;
	/* Range validation: non-empty, within device buffer, and wholly in guest RAM. */
	if (len == 0 || len > DEVICE_BUFFER_SIZE)
		return -1;
	if (gpa + len < gpa || gpa + len > guest_mem_size)
		return -1;

	if (dir == CMD_DMA_TO_DEVICE)
	{
		memcpy(dev->buffer, guest_mem_base + gpa, len);
		dev->result = bytesum(dev->buffer, len);
	}
	else if (dir == CMD_DMA_FROM_DEVICE)
	{
		memcpy(guest_mem_base + gpa, dev->buffer, len);
		dev->result = bytesum(dev->buffer, len);
	}
	else
		return -1;
	return 0;
}

/*
 * One legacy edge on DEVICE_GSI through KVM_IRQ_LINE: assert then deassert.
 * The in-kernel irqchip (virtual IOAPIC + LAPIC) delivers vector DEVICE_VECTOR.
 * This path is used for the legacy interrupt (Phase B), the pending case (Phase C), and DMA completion (Phase E).
 */
static void device_raise_legacy_irq(int vm)
{
	struct kvm_irq_level level = {.irq = DEVICE_GSI, .level = 1};

	if (ioctl(vm, KVM_IRQ_LINE, &level) < 0)
		perror("KVM_IRQ_LINE assert");
	level.level = 0;
	if (ioctl(vm, KVM_IRQ_LINE, &level) < 0)
		perror("KVM_IRQ_LINE deassert");
}

/*
 * Deliver one architectural x86 MSI message for this single-vCPU xAPIC setup.
 * The message targets LAPIC ID 0 in physical destination mode with fixed edge-triggered delivery of MSI_VECTOR.
 * The MSI address and data encode the routing/delivery themselves, so the LAPIC accepts vector 0x41 directly and the IOAPIC is bypassed.
 * Address encoding (xAPIC MSI base at 0xFEE00000): bits[31:20] carry the destination APIC ID shifted by 20, bit 3 sets logical/physical destination mode (cleared = physical).
 * Data encoding: bits[7:0] hold the vector, bits[10:8] the delivery mode (000 = fixed), and bit 15 the trigger mode (0 = edge).
 */
static void device_signal_msi(int vm)
{
	struct kvm_msi msi = {0};

	msi.address_lo = 0xfee00000u | (0u << 20);                       /* Physical mode, destination APIC ID 0. */
	msi.address_hi = 0;
	msi.data = MSI_VECTOR | (0u << 8) | (0u << 15);                  /* Fixed (000), edge, vector 0x41. */

	if (ioctl(vm, KVM_SIGNAL_MSI, &msi) <= 0)
	{
		/* KVM_SIGNAL_MSI returns >0 delivered, 0 guest-blocked, -1 error; none of those is success here. */
		perror("KVM_SIGNAL_MSI");
		fprintf(stderr, "MSI delivery failed for Phase D.\n");
		exit(1);
	}
}

/*
 * Execute a command synchronously, then signal completion through STATUS + the matching interrupt transport.
 * CMD_MSI_ONLY is the only MSI command; every other successful command uses the legacy KVM_IRQ_LINE edge.
 */
static void device_execute_command(int vm, struct toy_device *dev, uint8_t *guest_mem, uint64_t guest_mem_size)
{
	int ret = -1;

	dev->status = STATUS_BUSY;
	switch (dev->command)
	{
	case CMD_IRQ_ONLY:
	case CMD_MSI_ONLY:
		ret = 0; /* pure interrupt delivery; no I/O data changes */
		break;
	case CMD_DMA_TO_DEVICE:
		ret = device_dma_transfer(dev, guest_mem, guest_mem_size, dev->command, dev->dma_gpa, DMA_XFER_SIZE);
		break;
	case CMD_DMA_FROM_DEVICE:
		ret = device_dma_transfer(dev, guest_mem, guest_mem_size, dev->command, dev->dma_gpa, DMA_XFER_SIZE);
		break;
	default:
		break;
	}

	dev->status = ret == 0 ? STATUS_DONE : STATUS_ERROR;

	/* Only a successful operation raises the completion interrupt; a failed copy must not look done. */
	if (ret != 0)
		return;
	if (dev->command == CMD_MSI_ONLY)
		device_signal_msi(vm);
	else
		device_raise_legacy_irq(vm);
}

/* MMIO read: synthesize the register value in the guest's data buffer. */
static void device_mmio_read(struct toy_device *dev, uint32_t offset, uint8_t *data)
{
	uint32_t value = 0;

	switch (offset)
	{
	case REG_COMMAND:
		value = dev->command;
		break;
	case REG_STATUS:
		value = dev->status;
		break;
	case REG_DMA_GPA:
		value = dev->dma_gpa;
		break;
	case REG_RESULT:
		value = dev->result;
		break;
	default:
		if (offset >= REG_BUFFER && offset < REG_BUFFER + DEVICE_BUFFER_SIZE)
		{
			/* The readback window exposes the device buffer so the guest can verify DMA_TO bytes. */
			memcpy(data, &dev->buffer[offset - REG_BUFFER], sizeof(value));
			return;
		}
		break;
	}
	memcpy(data, &value, sizeof(value));
}

/* MMIO write: update device state, executing when COMMAND is written. */
static void device_mmio_write(int vm, struct toy_device *dev, uint32_t offset, uint8_t *data, uint8_t *guest_mem, uint64_t guest_mem_size)
{
	uint32_t value;

	memcpy(&value, data, sizeof(value));
	switch (offset)
	{
	case REG_DMA_GPA:
		dev->dma_gpa = value;
		break;
	case REG_COMMAND:
		dev->command = value;
		device_execute_command(vm, dev, guest_mem, guest_mem_size);
		break;
	case REG_IRQ_ACK:
		dev->status &= ~STATUS_DONE; /* optional ack: clear DONE for the next operation */
		break;
	default:
		break;
	}
}

int main(void)
{
	struct toy_device dev = {0};

	/* Pre-fill the device buffer with the distinct device pattern so DMA_TO readback proves the copy. */
	refill_device_pattern(&dev);

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

	/*
	 * Phase D depends on KVM_SIGNAL_MSI, so the capability must be present before the run starts.
	 * If this kernel cannot signal MSI, fail loudly and explain rather than silently falling back to KVM_IRQ_LINE.
	 */
	if (ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_SIGNAL_MSI) <= 0)
	{
		fprintf(stderr, "KVM_CAP_SIGNAL_MSI is not supported by this kernel; the MSI Phase D cannot be demonstrated.\n");
		return 1;
	}

	/* KVM_CREATE_VM creates one VM object; its fd is used for VM-wide ioctls. */
	int vm = ioctl(kvm, KVM_CREATE_VM, 0);
	if (vm < 0)
	{
		perror("KVM_CREATE_VM");
		return 1;
	}

	/*
	 * In-kernel irqchip: KVM emulates the legacy PIC plus the virtual IOAPIC and gives each vCPU a local APIC.
	 * Must be created before the vCPU so the vCPU gets its LAPIC.
	 * The guest then programs these virtual devices itself; the VMM never injects vectors directly.
	 * The irqchip is also required for the KVM_SIGNAL_MSI path used in Phase D.
	 */
	if (ioctl(vm, KVM_CREATE_IRQCHIP, 0) < 0)
	{
		perror("KVM_CREATE_IRQCHIP");
		return 1;
	}

	/* Allocate guest RAM; KVM runs against memory we provide and register below. */
	uint8_t *guest_mem = mmap(NULL, GUEST_MEM_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (guest_mem == MAP_FAILED)
	{
		perror("mmap guest memory");
		return 1;
	}

	/* Load the guest image at guest physical address 0x0000. */
	FILE *guest = fopen("build/guest.bin", "rb");
	if (!guest)
	{
		perror("fopen build/guest.bin");
		return 1;
	}
	size_t guest_size = fread(guest_mem, 1, GUEST_MEM_SIZE, guest);
	if (ferror(guest))
	{
		perror("fread guest.bin");
		return 1;
	}
	fclose(guest);
	(void)guest_size;

	if (set_memory_region(vm, 0, 0, guest_mem, GUEST_MEM_SIZE, 0) < 0)
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

	/* Re-enter the vCPU after each userspace-visible exit until the guest finishes. */
	for (;;)
	{
		if (ioctl(vcpu, KVM_RUN, 0) < 0)
		{
			perror("KVM_RUN");
			return 1;
		}

		/* Guest MMIO to the toy device window -> device model. */
		if (run->exit_reason == KVM_EXIT_MMIO)
		{
			uint64_t base = (uint64_t)run->mmio.phys_addr;
			uint8_t *data = run->mmio.data;

			if (base >= DEVICE_MMIO_BASE && base < DEVICE_MMIO_BASE + DEVICE_MMIO_SIZE)
			{
				uint32_t offset = (uint32_t)(base - DEVICE_MMIO_BASE);

				if (run->mmio.is_write)
					device_mmio_write(vm, &dev, offset, data, guest_mem, GUEST_MEM_SIZE);
				else
					device_mmio_read(&dev, offset, data);
			}
			continue;
		}

		/* PIO is marker-only in this experiment (0xe9 markers, 0x82 done). */
		if (run->exit_reason == KVM_EXIT_IO)
		{
			if (run->io.direction == KVM_EXIT_IO_OUT && run->io.port == DONE_PORT)
				break;
			continue;
		}

		/* HLT is the guest's timeout fallback when an interrupt is never delivered, never a success signal. */
		if (run->exit_reason == KVM_EXIT_HLT)
		{
			fprintf(stderr, "guest halted unexpectedly; interrupt delivery likely failed\n");
			return 1;
		}

		fprintf(stderr, "unexpected KVM exit reason: %u\n", run->exit_reason);
		return 1;
	}

	fprintf(stderr, "guest finished via DONE_PORT\n");
	return 0;
}
