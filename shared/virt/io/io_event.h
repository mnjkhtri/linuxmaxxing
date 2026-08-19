/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Ring-buffer ABI shared between the BPF side (io.bpf.c) and the userspace loader (io.c).
 * This is the binary format only: the loader serializes it into the canonical NDJSON envelope.
 *
 * One interrupt-virtualization boundary snapshot, grouped into three semantic facts:
 *
 *   time_ns    CLOCK_MONOTONIC (bpf_ktime_get_ns()), comparable with the tracefs instance clock (mono)
 *   event_info which KVM intercept or device operation produced this snapshot
 *   context    where and as whom the probe executed (the VMM thread)
 *   state      the observed interrupt controller and the uprobed virtual-DMA operation
 *
 * The header intentionally contains no JSON vocabulary and no JSON representation choices.
 * Events are integers here, pointers are raw u64 here, and availability flags are 0/1 here.
 * The loader converts those into readable names, "0x..."/null, and booleans for the public schema.
 * It must compile in both BPF (-target bpf) and normal userspace builds.
 * Device constants come from device.h so the BPF side, the loader, and the VMM share one contract.
 */
#ifndef IO_EVENT_H
#define IO_EVENT_H

#include "device.h"

/* The KVM intercept or device operation that produced this snapshot; the loader owns the readable names. */
enum io_event_type
{
	IO_EVENT_KVM_ENTRY = 0,
	IO_EVENT_KVM_EXIT = 1,
	IO_EVENT_KVM_USERSPACE_EXIT = 2,
	IO_EVENT_KVM_IOAPIC_SET_IRQ = 3,
	IO_EVENT_KVM_APIC_ACCEPT_IRQ = 4,
	IO_EVENT_KVM_INJ_VIRQ = 5,
	IO_EVENT_KVM_EOI = 6,
	IO_EVENT_KVM_APIC = 7,
	IO_EVENT_DEVICE_DMA_TRANSFER = 8,
	IO_EVENT_KVM_MSI_SET_IRQ = 9,
	IO_EVENT_COUNT = 10,
};

/* Which boundary this snapshot belongs to. */
struct vio_event_info
{
	unsigned int event; /* enum io_event_type. */
};

/* Where and as whom the probe executed: the VMM thread driving the vCPU. */
struct vio_context
{
	unsigned int pid; /* TGID of the probing task. */
	unsigned int tid; /* TID of the probing task. */
	unsigned int cpu; /* CPU on which the probe callback executed. */
	char comm[16];	  /* Task name of the probing task. */
};

/* Best-effort LAPIC/IOAPIC sample taken at the boundary. */
struct vio_controller
{
	unsigned long long rte;			 /* IOAPIC redirection entry for DEVICE_GSI (64 bits). */
	unsigned char irr;				 /* LAPIC IRR bit for the sampled vector. */
	unsigned char isr;				 /* LAPIC ISR bit for the sampled vector. */
	unsigned int vector;			 /* Vector the IRR/ISR bits were sampled for. */
	unsigned char vector_sampled;	 /* 1 when a real vector was sampled, 0 when none was available. */
};

/* An observed architectural MSI message; only present when the MSI tracepoint fired. */
struct vio_msi
{
	unsigned char present;			 /* 1 when kvm_msi_set_irq produced this observation. */
	unsigned long long address;		 /* Raw MSI address (xAPIC base plus destination fields). */
	unsigned long long data;		 /* Raw MSI data (delivery mode, trigger, vector). */
};

/* The uprobed virtual-DMA operation; only the fields that vary are recorded. */
struct vio_dma
{
	unsigned long long gpa; /* Guest physical address targeted. */
	unsigned int dir;		/* CMD_DMA_TO_DEVICE / CMD_DMA_FROM_DEVICE. */
};

/* The interrupt-controller and virtual-DMA state observed after the boundary. */
struct vio_state
{
	unsigned long long vcpu;	  /* struct kvm_vcpu * that owns this snapshot. */
	unsigned long long kvm;		  /* Owning struct kvm * for this vCPU. */
	unsigned long long apic;	  /* struct kvm_lapic *, when this tracepoint exposes one. */
	unsigned long long ioapic;	  /* struct kvm_ioapic *, when this tracepoint exposes one. */
	struct vio_controller controller;
	struct vio_msi msi;
	struct vio_dma dma;
};

struct vio_event
{
	unsigned long long time_ns;
	struct vio_event_info event_info;
	struct vio_context context;
	struct vio_state state;
};

#endif /* IO_EVENT_H */
