/* Checkpoint 4 guest: one shared-memory entropy request with level-triggered completion notification. */
/* The guest enters flat 32-bit protected mode with paging disabled, so GVA equals GPA. */
/* It performs only aligned 32-bit accesses to the virtio-mmio register window. */
/* The interrupt wakes the driver, while the used ring remains the authoritative completion state. */
#include "virtio.h"

.set LAPIC_BASE, 0xfee00000
.set LAPIC_EOI, 0x00b0
.set LAPIC_TPR, 0x0080
.set LAPIC_SVR, 0x00f0
.set IOAPIC_BASE, 0xfec00000
.set IOAPIC_SEL, 0x00
.set IOAPIC_WIN, 0x10
.set KERNEL_CS, 0x08

/* This macro writes one complete 32-bit interrupt gate into the guest IDT area. */
.macro BUILD_IDT_GATE handler, vector
	movl $\handler, %ebx
	movl $VIRTIO_IDT_GPA, %edi
	addl $(\vector * 8), %edi
	movw %bx, 0(%edi)
	movw $KERNEL_CS, 2(%edi)
	movb $0, 4(%edi)
	movb $0x8e, 5(%edi)
	movl %ebx, %eax
	shrl $16, %eax
	movw %ax, 6(%edi)
.endm

.code16
.global _start

_start:
	cli
	lgdt gdt_descriptor
	movl %cr0, %eax
	orl $1, %eax
	movl %eax, %cr0
	ljmpl $0x08, $protected_mode

.code32
protected_mode:
	/* Flat code and data segments make every guest virtual address equal its guest physical address. */
	movw $0x10, %ax
	movw %ax, %ds
	movw %ax, %es
	movw %ax, %ss
	movl $VIRTIO_GUEST_STACK_TOP, %esp

	/* Discover one modern virtio-rng device. */
	movl VIRTIO_MMIO_BASE + VIRTIO_MMIO_MAGIC_VALUE, %eax
	cmpl $VIRTIO_MAGIC_VALUE, %eax
	jne fail_magic

	movl VIRTIO_MMIO_BASE + VIRTIO_MMIO_VERSION, %eax
	cmpl $VIRTIO_VERSION_MODERN, %eax
	jne fail_version

	movl VIRTIO_MMIO_BASE + VIRTIO_MMIO_DEVICE_ID, %eax
	cmpl $VIRTIO_DEVICE_ID_ENTROPY, %eax
	jne fail_device_id

	movl VIRTIO_MMIO_BASE + VIRTIO_MMIO_VENDOR_ID, %eax
	testl %eax, %eax
	jz fail_vendor_id

	/* Writing zero performs the only device reset defined in this checkpoint. */
	movl $0, VIRTIO_MMIO_BASE + VIRTIO_MMIO_STATUS
	/* Reading Status back confirms the guest-visible status returned to zero. */
	movl VIRTIO_MMIO_BASE + VIRTIO_MMIO_STATUS, %eax
	testl %eax, %eax
	jnz fail_reset

	/* ACKNOWLEDGE tells the device that the guest recognized it as a valid virtio device. */
	movl $VIRTIO_STATUS_ACKNOWLEDGE, VIRTIO_MMIO_BASE + VIRTIO_MMIO_STATUS
	movl VIRTIO_MMIO_BASE + VIRTIO_MMIO_STATUS, %eax
	cmpl $VIRTIO_STATUS_ACKNOWLEDGE, %eax
	jne fail_acknowledge

	/* DRIVER tells the device that the guest knows how to drive this device type. */
	movl $(VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER), VIRTIO_MMIO_BASE + VIRTIO_MMIO_STATUS
	movl VIRTIO_MMIO_BASE + VIRTIO_MMIO_STATUS, %eax
	cmpl $(VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER), %eax
	jne fail_driver

	/* Selector zero exposes global feature bits 0 through 31, and this device offers none of them. */
	movl $0, VIRTIO_MMIO_BASE + VIRTIO_MMIO_DEVICE_FEATURES_SEL
	movl VIRTIO_MMIO_BASE + VIRTIO_MMIO_DEVICE_FEATURES, %eax
	testl %eax, %eax
	jnz fail_device_features_0

	/* Selector one exposes global feature bits 32 through 63, so bit zero of this word represents VIRTIO_F_VERSION_1. */
	movl $VIRTIO_VERSION_1_WORD, VIRTIO_MMIO_BASE + VIRTIO_MMIO_DEVICE_FEATURES_SEL
	movl VIRTIO_MMIO_BASE + VIRTIO_MMIO_DEVICE_FEATURES, %eax
	cmpl $VIRTIO_VERSION_1_WORD_MASK, %eax
	jne fail_device_features_1

	/* The driver mirrors the accepted feature set through the matching pair of selector and data registers. */
	movl $0, VIRTIO_MMIO_BASE + VIRTIO_MMIO_DRIVER_FEATURES_SEL
	movl $0, VIRTIO_MMIO_BASE + VIRTIO_MMIO_DRIVER_FEATURES
	movl $VIRTIO_VERSION_1_WORD, VIRTIO_MMIO_BASE + VIRTIO_MMIO_DRIVER_FEATURES_SEL
	movl $VIRTIO_VERSION_1_WORD_MASK, VIRTIO_MMIO_BASE + VIRTIO_MMIO_DRIVER_FEATURES

	/* FEATURES_OK asks the device to validate the exact feature words written above. */
	movl $VIRTIO_STATUS_CHECKPOINT1, VIRTIO_MMIO_BASE + VIRTIO_MMIO_STATUS
	/* A modern driver must read Status back because the device may clear FEATURES_OK when negotiation is invalid. */
	movl VIRTIO_MMIO_BASE + VIRTIO_MMIO_STATUS, %eax
	cmpl $VIRTIO_STATUS_CHECKPOINT1, %eax
	jne fail_features_ok
	testl $VIRTIO_STATUS_FEATURES_OK, %eax
	jz fail_features_ok
	testl $VIRTIO_STATUS_DRIVER_OK, %eax
	jnz fail_driver_ok

	/* FEATURES_OK means the guest and device agree on protocol features, but the queue does not exist yet. */
	movl $VIRTQ_INDEX, VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_SEL
	movl VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_READY, %eax
	testl %eax, %eax
	jnz fail_queue_initial_ready
	movl VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_SIZE_MAX, %eax
	cmpl $VIRTQ_SIZE, %eax
	jne fail_queue_size_max

	/* Selecting queue one demonstrates that this device exposes no second queue. */
	movl $1, VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_SEL
	movl VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_SIZE_MAX, %eax
	testl %eax, %eax
	jnz fail_unsupported_queue
	movl $VIRTQ_INDEX, VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_SEL

	/* The guest owns queue memory and explicitly clears each dedicated page before publishing its GPA. */
	cld
	xorl %eax, %eax
	movl $DESC_GPA, %edi
	movl $(VIRTQ_PAGE_SIZE / 4), %ecx
	rep stosl
	movl $AVAIL_GPA, %edi
	movl $(VIRTQ_PAGE_SIZE / 4), %ecx
	rep stosl
	movl $USED_GPA, %edi
	movl $(VIRTQ_PAGE_SIZE / 4), %ecx
	rep stosl

	/* QueueSize and the three 64-bit GPAs fully describe the split queue to the device. */
	movl $VIRTQ_SIZE, VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_SIZE
	movl $DESC_GPA, VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_DESC_LOW
	movl $0, VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_DESC_HIGH
	movl $AVAIL_GPA, VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_DRIVER_LOW
	movl $0, VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_DRIVER_HIGH
	movl $USED_GPA, VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_DEVICE_LOW
	movl $0, VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_DEVICE_HIGH

	/* QueueReady means this specific queue is fully configured and may no longer be mutated. */
	movl $1, VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_READY
	movl VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_READY, %eax
	cmpl $1, %eax
	jne fail_queue_ready

	/* DRIVER_OK means all driver setup is complete and the device may now operate. */
	movl $VIRTIO_STATUS_CHECKPOINT2, VIRTIO_MMIO_BASE + VIRTIO_MMIO_STATUS
	movl VIRTIO_MMIO_BASE + VIRTIO_MMIO_STATUS, %eax
	cmpl $VIRTIO_STATUS_CHECKPOINT2, %eax
	jne fail_final_status

	/* Interrupt setup is added only after the unchanged Checkpoint 1 through 3 initialization reaches DRIVER_OK. */
	call setup_interrupts
	movl VIRTIO_MMIO_BASE + VIRTIO_MMIO_INTERRUPT_STATUS, %eax
	testl %eax, %eax
	jnz fail_initial_interrupt_status
	sti

	/* The sentinel makes the future device write easy to inspect, but success never depends on its value changing. */
	movl $RNG_BUFFER_GPA, %edi
	movl $0xa5a5a5a5, %eax
	movl $(RNG_REQUEST_LEN / 4), %ecx
	rep stosl

	/* The guest prepares direct writable descriptor zero while retaining ownership of it. */
	movl $RNG_BUFFER_GPA, DESC_GPA + VIRTQ_DESC_ADDR_OFFSET
	movl $0, DESC_GPA + VIRTQ_DESC_ADDR_OFFSET + 4
	movl $RNG_REQUEST_LEN, DESC_GPA + VIRTQ_DESC_LEN_OFFSET
	movw $VIRTQ_DESC_F_WRITE, DESC_GPA + VIRTQ_DESC_FLAGS_OFFSET
	movw $0, DESC_GPA + VIRTQ_DESC_NEXT_OFFSET

	/* The available-ring entry names descriptor zero, but avail.idx remains zero so the device does not own it yet. */
	movw $0, AVAIL_GPA + VIRTQ_AVAIL_FLAGS_OFFSET
	movw $0, AVAIL_GPA + VIRTQ_AVAIL_IDX_OFFSET
	movw $0, AVAIL_GPA + VIRTQ_AVAIL_RING_OFFSET
	/* This fence makes the descriptor and ring entry visible before avail.idx publishes device ownership. */
	mfence
	movw $1, AVAIL_GPA + VIRTQ_AVAIL_IDX_OFFSET
	/* This fence orders avail.idx publication before the QueueNotify MMIO doorbell. */
	mfence
	movl $VIRTQ_INDEX, VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_NOTIFY

	/* The interrupt is only a bounded wakeup condition, so irq_count is not treated as completion data. */
	movl $VIRTIO_IRQ_WAIT_LIMIT, %ecx
wait_for_interrupt:
	cmpl $1, VIRTIO_IRQ_COUNT_GPA
	je interrupt_serviced
	cmpl $-1, VIRTIO_IRQ_COUNT_GPA
	je fail_unexpected_interrupt
	decl %ecx
	jnz wait_for_interrupt
	jmp fail_interrupt_timeout

interrupt_serviced:
	/* The ISR has acknowledged the source, so InterruptStatus and the level-triggered GSI must now be clear. */
	movl VIRTIO_MMIO_BASE + VIRTIO_MMIO_INTERRUPT_STATUS, %eax
	testl %eax, %eax
	jnz fail_interrupt_not_cleared
	/* Notification has completed, but the used ring is still the authoritative completion record. */
	movzwl USED_GPA + VIRTQ_USED_IDX_OFFSET, %eax
	cmpl $1, %eax
	jne fail_used_idx
	/* This acquire fence keeps used-element and output-buffer reads after reading the published used.idx. */
	lfence
	cmpl $0, USED_GPA + VIRTQ_USED_RING_OFFSET + VIRTQ_USED_ELEM_ID_OFFSET
	jne fail_used_id
	cmpl $RNG_REQUEST_LEN, USED_GPA + VIRTQ_USED_RING_OFFSET + VIRTQ_USED_ELEM_LEN_OFFSET
	jne fail_used_len

	/* Port 0x82 is the explicit success signal used by the tiny VIRT guests. */
	movb $0, %al
	outb %al, $VIRTIO_TEST_SUCCESS_PORT
	hlt

/* The guest programs only the IDT gate, LAPIC state, and one level-triggered IOAPIC route needed by virtio. */
setup_interrupts:
	pushl %eax
	pushl %ebx
	pushl %edi
	movl $0, VIRTIO_IRQ_COUNT_GPA
	movl $0, VIRTIO_IRQ_STATUS_GPA
	BUILD_IDT_GATE virtio_isr, VIRTIO_VECTOR
	lidt idt_descriptor
	/* Masking the legacy PIC ensures GSI 4 is delivered only through the programmed IOAPIC route. */
	movb $0xff, %al
	outb %al, $0x21
	outb %al, $0xa1
	/* TPR zero admits the interrupt, and SVR bit eight software-enables the local APIC. */
	movl $0, LAPIC_BASE + LAPIC_TPR
	movl $(0x100 | 0xff), LAPIC_BASE + LAPIC_SVR
	/* The IOAPIC entry routes active-high level-triggered GSI 4 to vector 0x40 on LAPIC ID zero. */
	movl $(0x10 + VIRTIO_GSI * 2), IOAPIC_BASE + IOAPIC_SEL
	movl $(VIRTIO_VECTOR | (1 << 15)), IOAPIC_BASE + IOAPIC_WIN
	movl $(0x10 + VIRTIO_GSI * 2 + 1), IOAPIC_BASE + IOAPIC_SEL
	movl $0, IOAPIC_BASE + IOAPIC_WIN
	popl %edi
	popl %ebx
	popl %eax
	ret

/* The ISR acknowledges the virtio source before LAPIC EOI and leaves used-ring inspection to the main driver path. */
virtio_isr:
	pusha
	movl VIRTIO_MMIO_BASE + VIRTIO_MMIO_INTERRUPT_STATUS, %eax
	movl %eax, VIRTIO_IRQ_STATUS_GPA
	testl $VIRTIO_MMIO_INT_VRING, %eax
	jz unexpected_isr
	movl $VIRTIO_MMIO_INT_VRING, VIRTIO_MMIO_BASE + VIRTIO_MMIO_INTERRUPT_ACK
	incl VIRTIO_IRQ_COUNT_GPA
	jmp isr_eoi
unexpected_isr:
	movl $-1, VIRTIO_IRQ_COUNT_GPA
isr_eoi:
	movl $0, LAPIC_BASE + LAPIC_EOI
	popa
	iret

fail_magic:
	movb $1, %al
	jmp guest_failure
fail_version:
	movb $2, %al
	jmp guest_failure
fail_device_id:
	movb $3, %al
	jmp guest_failure
fail_vendor_id:
	movb $4, %al
	jmp guest_failure
fail_reset:
	movb $5, %al
	jmp guest_failure
fail_acknowledge:
	movb $6, %al
	jmp guest_failure
fail_driver:
	movb $7, %al
	jmp guest_failure
fail_device_features_0:
	movb $8, %al
	jmp guest_failure
fail_device_features_1:
	movb $9, %al
	jmp guest_failure
fail_features_ok:
	movb $10, %al
	jmp guest_failure
fail_driver_ok:
	movb $11, %al
	jmp guest_failure
fail_queue_initial_ready:
	movb $12, %al
	jmp guest_failure
fail_queue_size_max:
	movb $13, %al
	jmp guest_failure
fail_unsupported_queue:
	movb $14, %al
	jmp guest_failure
fail_queue_ready:
	movb $15, %al
	jmp guest_failure
fail_final_status:
	movb $16, %al
	jmp guest_failure
fail_interrupt_timeout:
	movb $17, %al
	jmp guest_failure
fail_used_id:
	movb $18, %al
	jmp guest_failure
fail_used_len:
	movb $19, %al
	jmp guest_failure
fail_initial_interrupt_status:
	movb $20, %al
	jmp guest_failure
fail_unexpected_interrupt:
	movb $21, %al
	jmp guest_failure
fail_interrupt_not_cleared:
	movb $22, %al
	jmp guest_failure
fail_used_idx:
	movb $23, %al

guest_failure:
	outb %al, $VIRTIO_TEST_FAILURE_PORT
	hlt

.align 8
gdt:
	.quad 0x0000000000000000
	.quad 0x00cf9a000000ffff
	.quad 0x00cf92000000ffff
gdt_end:
gdt_descriptor:
	.word gdt_end - gdt - 1
	.long gdt

idt_descriptor:
	.word (VIRTIO_VECTOR + 1) * 8 - 1
	.long VIRTIO_IDT_GPA
