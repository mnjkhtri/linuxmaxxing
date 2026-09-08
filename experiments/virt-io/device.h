// SPDX-License-Identifier: GPL-2.0
/*
 * Shared IO-virtualization device contract.
 *
 * This is deliberately VIRTUAL DMA, not physical PCI bus-master DMA.
 * From the guest's perspective a virtual device talks to guest physical memory;
 * From the host's perspective the VMM device model copies through the registered KVM memory-slot backing.
 * No real device or IOMMU is involved.
 *
 * Constants here are kept in sync with the toy device model in vmm.c, the guest assembly in guest.S (mirrored as asm equates), and the observers/UI.
 */

#ifndef DEVICE_H
#define DEVICE_H

/* Toy MMIO device lives outside guest RAM. */
#define DEVICE_MMIO_BASE 0x10000000u

/* Device register offsets (absolute MMIO addresses are BASE + offset). */
#define REG_COMMAND   0x00u
#define REG_STATUS    0x04u
#define REG_DMA_GPA   0x08u
#define REG_RESULT    0x10u
#define REG_IRQ_ACK   0x14u
#define REG_BUFFER    0x18u /* Readback window into the device buffer; proves DMA_TO really landed. */

/* The device buffer's own fill byte; distinct from the guest's 0..63 source so DMA changes readback. */
#define DEVICE_PATTERN_BASE 0x40u

/* Total MMIO address window, registers plus the device-buffer readback. */
#define DEVICE_MMIO_SIZE (REG_BUFFER + DEVICE_BUFFER_SIZE)

/* Device commands written to REG_COMMAND. */
#define CMD_IRQ_ONLY 1u
#define CMD_DMA_TO_DEVICE 2u
#define CMD_DMA_FROM_DEVICE 3u
#define CMD_MSI_ONLY 4u /* A single MSI message delivered through KVM_SIGNAL_MSI, bypassing the IOAPIC. */

/* STATUS bits read from REG_STATUS. */
#define STATUS_BUSY 0x01u
#define STATUS_DONE 0x02u
#define STATUS_ERROR 0x04u

/*
 * Interrupt routing: one legacy edge-triggered GSI into the in-kernel irqchip.
 * DEVICE_GSI / DEVICE_VECTOR stay on the legacy KVM_IRQ_LINE -> IOAPIC -> LAPIC path for Phases B, C and E.
 * MSI_VECTOR is a distinct vector delivered only by the MSI message in Phase D (no GSI, no IOAPIC).
 */
#define DEVICE_GSI 4u
#define DEVICE_VECTOR 0x40u
#define MSI_VECTOR 0x41u

/* Device internal buffer bounds. */
#define DEVICE_BUFFER_SIZE 256u
#define DMA_XFER_SIZE 64u

/* Userspace device state observed by the VMM uprobes. */
struct toy_device
{
	unsigned int command;
	unsigned int status;
	unsigned int dma_gpa;
	unsigned int result;
	unsigned char buffer[DEVICE_BUFFER_SIZE];
};

/* Completion / phase-marker PIO ports (markers only; PIO is not the subject). */
#define MARKER_PORT 0xe9u
#define DONE_PORT 0x82u

/* Phase markers written through MARKER_PORT. */
#define MARKER_APIC_READY 0x11u
#define MARKER_IRQ_PENDING_IF0 0x12u
#define MARKER_MSI 0x13u /* Sync point: MSI already delivered (vector 0x41), guest ISR may have run. */

#endif /* DEVICE_H */
