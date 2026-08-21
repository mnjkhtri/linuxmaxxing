/* This tiny driver uses flat 32-bit protected mode with paging disabled, so GVA equals GPA. */
/* Every virtio-mmio access is aligned, 32-bit, and little-endian. */
#include "virtio.h"

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
	movw $0x10, %ax
	movw %ax, %ds
	movw %ax, %es
	movw %ax, %ss
	movl $VIRTIO_GUEST_STACK_TOP, %esp

	/* -------------------------------------------------- */
	/* PHASE A — VIRTIO DEVICE BRING-UP */
	/* Goal: the guest and device agree that they speak modern virtio. */
	/* -------------------------------------------------- */
	movl VIRTIO_MMIO_BASE + VIRTIO_MMIO_MAGIC_VALUE, %eax
	cmpl $VIRTIO_MAGIC_VALUE, %eax
	jne fail_identity
	movl VIRTIO_MMIO_BASE + VIRTIO_MMIO_VERSION, %eax
	cmpl $VIRTIO_VERSION_MODERN, %eax
	jne fail_identity
	movl VIRTIO_MMIO_BASE + VIRTIO_MMIO_DEVICE_ID, %eax
	cmpl $VIRTIO_DEVICE_ID_ENTROPY, %eax
	jne fail_identity
	movl VIRTIO_MMIO_BASE + VIRTIO_MMIO_VENDOR_ID, %eax
	testl %eax, %eax
	jz fail_identity

	/* Status zero resets mutable device-side state before initialization begins. */
	movl $0, VIRTIO_MMIO_BASE + VIRTIO_MMIO_STATUS
	movl VIRTIO_MMIO_BASE + VIRTIO_MMIO_STATUS, %eax
	testl %eax, %eax
	jnz fail_status
	movl $VIRTIO_STATUS_ACKNOWLEDGE, VIRTIO_MMIO_BASE + VIRTIO_MMIO_STATUS
	movl $(VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER), VIRTIO_MMIO_BASE + VIRTIO_MMIO_STATUS

	/* Feature word one bit zero is global feature bit 32, VIRTIO_F_VERSION_1. */
	movl $0, VIRTIO_MMIO_BASE + VIRTIO_MMIO_DEVICE_FEATURES_SEL
	movl VIRTIO_MMIO_BASE + VIRTIO_MMIO_DEVICE_FEATURES, %eax
	testl %eax, %eax
	jnz fail_features
	movl $VIRTIO_F_VERSION_1_WORD, VIRTIO_MMIO_BASE + VIRTIO_MMIO_DEVICE_FEATURES_SEL
	movl VIRTIO_MMIO_BASE + VIRTIO_MMIO_DEVICE_FEATURES, %eax
	cmpl $VIRTIO_F_VERSION_1_MASK, %eax
	jne fail_features

	movl $0, VIRTIO_MMIO_BASE + VIRTIO_MMIO_DRIVER_FEATURES_SEL
	movl $0, VIRTIO_MMIO_BASE + VIRTIO_MMIO_DRIVER_FEATURES
	movl $VIRTIO_F_VERSION_1_WORD, VIRTIO_MMIO_BASE + VIRTIO_MMIO_DRIVER_FEATURES_SEL
	movl $VIRTIO_F_VERSION_1_MASK, VIRTIO_MMIO_BASE + VIRTIO_MMIO_DRIVER_FEATURES
	movl $VIRTIO_STATUS_FEATURES_ACCEPTED, VIRTIO_MMIO_BASE + VIRTIO_MMIO_STATUS
	/* The readback matters because a device clears FEATURES_OK when it rejects the negotiated set. */
	movl VIRTIO_MMIO_BASE + VIRTIO_MMIO_STATUS, %eax
	cmpl $VIRTIO_STATUS_FEATURES_ACCEPTED, %eax
	jne fail_features

	/* -------------------------------------------------- */
	/* PHASE B — CONFIGURE ONE SPLIT VIRTQUEUE */
	/* Goal: tell the device where the three shared-memory queue regions live. */
	/* -------------------------------------------------- */
	movl $VIRTIO_RNG_QUEUE_INDEX, VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_SEL
	movl VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_READY, %eax
	testl %eax, %eax
	jnz fail_queue
	movl VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_SIZE_MAX, %eax
	cmpl $VIRTQ_SIZE, %eax
	jne fail_queue

	/* Queue memory belongs to the guest, so the guest explicitly initializes it before sharing its GPAs. */
	cld
	xorl %eax, %eax
	movl $VIRTQ_DESC_GPA, %edi
	movl $(VIRTQ_PAGE_SIZE / 4), %ecx
	rep stosl
	movl $VIRTQ_AVAIL_GPA, %edi
	movl $(VIRTQ_PAGE_SIZE / 4), %ecx
	rep stosl
	movl $VIRTQ_USED_GPA, %edi
	movl $(VIRTQ_PAGE_SIZE / 4), %ecx
	rep stosl

	movl $VIRTQ_SIZE, VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_SIZE
	movl $VIRTQ_DESC_GPA, VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_DESC_LOW
	movl $0, VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_DESC_HIGH
	movl $VIRTQ_AVAIL_GPA, VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_DRIVER_LOW
	movl $0, VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_DRIVER_HIGH
	movl $VIRTQ_USED_GPA, VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_DEVICE_LOW
	movl $0, VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_DEVICE_HIGH
	movl $1, VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_READY
	movl VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_READY, %eax
	cmpl $1, %eax
	jne fail_queue

	/* FEATURES_OK means the protocol is agreed, QueueReady means this queue exists, and DRIVER_OK makes the device operational. */
	movl $VIRTIO_STATUS_OPERATIONAL, VIRTIO_MMIO_BASE + VIRTIO_MMIO_STATUS
	movl VIRTIO_MMIO_BASE + VIRTIO_MMIO_STATUS, %eax
	cmpl $VIRTIO_STATUS_OPERATIONAL, %eax
	jne fail_driver_ok

	/* -------------------------------------------------- */
	/* PHASE C — PARAVIRTUALIZED I/O THROUGH THE VIRTQUEUE */
	/* Goal: requests live in shared RAM; QueueNotify only tells the backend that the queue has new work. */
	/* -------------------------------------------------- */
	/* First, one request demonstrates the basic descriptor to available ring to notification to used ring path. */
	/* Descriptor zero describes 32 device-writable bytes, but the guest still owns the descriptor while preparing it. */
	movl $VIRTIO_RNG_BUFFER_GPA, VIRTQ_DESC_GPA + VIRTQ_DESC_ADDR_OFFSET
	movl $0, VIRTQ_DESC_GPA + VIRTQ_DESC_ADDR_OFFSET + 4
	movl $VIRTIO_RNG_REQUEST_LEN, VIRTQ_DESC_GPA + VIRTQ_DESC_LEN_OFFSET
	movw $VIRTQ_DESC_F_WRITE, VIRTQ_DESC_GPA + VIRTQ_DESC_FLAGS_OFFSET
	movw $0, VIRTQ_DESC_GPA + VIRTQ_DESC_NEXT_OFFSET

	/* The ring now points to descriptor zero, but avail.idx is still zero and the device must not consume it. */
	movw $0, VIRTQ_AVAIL_GPA + VIRTQ_AVAIL_FLAGS_OFFSET
	movw $0, VIRTQ_AVAIL_GPA + VIRTQ_AVAIL_IDX_OFFSET
	movw $0, VIRTQ_AVAIL_GPA + VIRTQ_AVAIL_RING_OFFSET
	/* This fence makes the descriptor and ring entry visible before avail.idx publishes device ownership. */
	mfence
	movw $1, VIRTQ_AVAIL_GPA + VIRTQ_AVAIL_IDX_OFFSET
	/* This fence orders shared-memory publication before the MMIO doorbell. */
	mfence
	/* QueueNotify contains only the queue index; the request GPA, length, and direction are already in shared RAM. */
	movl $VIRTIO_RNG_QUEUE_INDEX, VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_NOTIFY

	/* Completion is shared-memory state, so the guest waits with a bounded poll of used.idx. */
	movl $VIRTIO_POLL_LIMIT, %ecx
poll_used_idx:
	movzwl VIRTQ_USED_GPA + VIRTQ_USED_IDX_OFFSET, %eax
	cmpl $1, %eax
	je completion_published
	decl %ecx
	jnz poll_used_idx
	jmp fail_timeout

completion_published:
	/* This acquire fence keeps used-element and output-buffer reads after observing the device's used.idx publication. */
	lfence
	cmpl $0, VIRTQ_USED_GPA + VIRTQ_USED_RING_OFFSET + VIRTQ_USED_ELEM_ID_OFFSET
	jne fail_completion
	cmpl $VIRTIO_RNG_REQUEST_LEN, VIRTQ_USED_GPA + VIRTQ_USED_RING_OFFSET + VIRTQ_USED_ELEM_LEN_OFFSET
	jne fail_completion

	/* Next, four requests are batched before ringing the same doorbell once. */
	/* These four descriptors physically exist while avail.idx remains one, so the device cannot consume them yet. */
	movl $(VIRTIO_RNG_BUFFER_GPA + 1 * VIRTIO_RNG_BUFFER_STRIDE), VIRTQ_DESC_GPA + 1 * VIRTQ_DESC_SIZE + VIRTQ_DESC_ADDR_OFFSET
	movl $0, VIRTQ_DESC_GPA + 1 * VIRTQ_DESC_SIZE + VIRTQ_DESC_ADDR_OFFSET + 4
	movl $VIRTIO_RNG_REQUEST_LEN, VIRTQ_DESC_GPA + 1 * VIRTQ_DESC_SIZE + VIRTQ_DESC_LEN_OFFSET
	movw $VIRTQ_DESC_F_WRITE, VIRTQ_DESC_GPA + 1 * VIRTQ_DESC_SIZE + VIRTQ_DESC_FLAGS_OFFSET
	movw $0, VIRTQ_DESC_GPA + 1 * VIRTQ_DESC_SIZE + VIRTQ_DESC_NEXT_OFFSET

	movl $(VIRTIO_RNG_BUFFER_GPA + 2 * VIRTIO_RNG_BUFFER_STRIDE), VIRTQ_DESC_GPA + 2 * VIRTQ_DESC_SIZE + VIRTQ_DESC_ADDR_OFFSET
	movl $0, VIRTQ_DESC_GPA + 2 * VIRTQ_DESC_SIZE + VIRTQ_DESC_ADDR_OFFSET + 4
	movl $VIRTIO_RNG_REQUEST_LEN, VIRTQ_DESC_GPA + 2 * VIRTQ_DESC_SIZE + VIRTQ_DESC_LEN_OFFSET
	movw $VIRTQ_DESC_F_WRITE, VIRTQ_DESC_GPA + 2 * VIRTQ_DESC_SIZE + VIRTQ_DESC_FLAGS_OFFSET
	movw $0, VIRTQ_DESC_GPA + 2 * VIRTQ_DESC_SIZE + VIRTQ_DESC_NEXT_OFFSET

	movl $(VIRTIO_RNG_BUFFER_GPA + 3 * VIRTIO_RNG_BUFFER_STRIDE), VIRTQ_DESC_GPA + 3 * VIRTQ_DESC_SIZE + VIRTQ_DESC_ADDR_OFFSET
	movl $0, VIRTQ_DESC_GPA + 3 * VIRTQ_DESC_SIZE + VIRTQ_DESC_ADDR_OFFSET + 4
	movl $VIRTIO_RNG_REQUEST_LEN, VIRTQ_DESC_GPA + 3 * VIRTQ_DESC_SIZE + VIRTQ_DESC_LEN_OFFSET
	movw $VIRTQ_DESC_F_WRITE, VIRTQ_DESC_GPA + 3 * VIRTQ_DESC_SIZE + VIRTQ_DESC_FLAGS_OFFSET
	movw $0, VIRTQ_DESC_GPA + 3 * VIRTQ_DESC_SIZE + VIRTQ_DESC_NEXT_OFFSET

	movl $(VIRTIO_RNG_BUFFER_GPA + 4 * VIRTIO_RNG_BUFFER_STRIDE), VIRTQ_DESC_GPA + 4 * VIRTQ_DESC_SIZE + VIRTQ_DESC_ADDR_OFFSET
	movl $0, VIRTQ_DESC_GPA + 4 * VIRTQ_DESC_SIZE + VIRTQ_DESC_ADDR_OFFSET + 4
	movl $VIRTIO_RNG_REQUEST_LEN, VIRTQ_DESC_GPA + 4 * VIRTQ_DESC_SIZE + VIRTQ_DESC_LEN_OFFSET
	movw $VIRTQ_DESC_F_WRITE, VIRTQ_DESC_GPA + 4 * VIRTQ_DESC_SIZE + VIRTQ_DESC_FLAGS_OFFSET
	movw $0, VIRTQ_DESC_GPA + 4 * VIRTQ_DESC_SIZE + VIRTQ_DESC_NEXT_OFFSET

	/* Ring slots and descriptor IDs are separate concepts even though this controlled example maps one to one. */
	movw $1, VIRTQ_AVAIL_GPA + VIRTQ_AVAIL_RING_OFFSET + 1 * 2
	movw $2, VIRTQ_AVAIL_GPA + VIRTQ_AVAIL_RING_OFFSET + 2 * 2
	movw $3, VIRTQ_AVAIL_GPA + VIRTQ_AVAIL_RING_OFFSET + 3 * 2
	movw $4, VIRTQ_AVAIL_GPA + VIRTQ_AVAIL_RING_OFFSET + 4 * 2
	cmpw $1, VIRTQ_AVAIL_GPA + VIRTQ_AVAIL_IDX_OFFSET
	jne fail_queue
	/* One publication changes pending work from zero to four: avail.idx becomes five while last_avail_idx is one. */
	mfence
	movw $VIRTIO_RNG_REQUEST_COUNT, VIRTQ_AVAIL_GPA + VIRTQ_AVAIL_IDX_OFFSET
	mfence
	/* One QueueNotify announces all four newly published entries rather than describing any one request. */
	movl $VIRTIO_RNG_QUEUE_INDEX, VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_NOTIFY

	movl $VIRTIO_POLL_LIMIT, %ecx
poll_batch_used_idx:
	movzwl VIRTQ_USED_GPA + VIRTQ_USED_IDX_OFFSET, %eax
	cmpl $VIRTIO_RNG_REQUEST_COUNT, %eax
	je batch_completion_published
	decl %ecx
	jnz poll_batch_used_idx
	jmp fail_timeout

batch_completion_published:
	/* This acquire fence keeps all four used-element reads after observing used.idx equal five. */
	lfence
	cmpl $1, VIRTQ_USED_GPA + VIRTQ_USED_RING_OFFSET + 1 * VIRTQ_USED_ELEM_SIZE + VIRTQ_USED_ELEM_ID_OFFSET
	jne fail_completion
	cmpl $VIRTIO_RNG_REQUEST_LEN, VIRTQ_USED_GPA + VIRTQ_USED_RING_OFFSET + 1 * VIRTQ_USED_ELEM_SIZE + VIRTQ_USED_ELEM_LEN_OFFSET
	jne fail_completion
	cmpl $2, VIRTQ_USED_GPA + VIRTQ_USED_RING_OFFSET + 2 * VIRTQ_USED_ELEM_SIZE + VIRTQ_USED_ELEM_ID_OFFSET
	jne fail_completion
	cmpl $VIRTIO_RNG_REQUEST_LEN, VIRTQ_USED_GPA + VIRTQ_USED_RING_OFFSET + 2 * VIRTQ_USED_ELEM_SIZE + VIRTQ_USED_ELEM_LEN_OFFSET
	jne fail_completion
	cmpl $3, VIRTQ_USED_GPA + VIRTQ_USED_RING_OFFSET + 3 * VIRTQ_USED_ELEM_SIZE + VIRTQ_USED_ELEM_ID_OFFSET
	jne fail_completion
	cmpl $VIRTIO_RNG_REQUEST_LEN, VIRTQ_USED_GPA + VIRTQ_USED_RING_OFFSET + 3 * VIRTQ_USED_ELEM_SIZE + VIRTQ_USED_ELEM_LEN_OFFSET
	jne fail_completion
	cmpl $4, VIRTQ_USED_GPA + VIRTQ_USED_RING_OFFSET + 4 * VIRTQ_USED_ELEM_SIZE + VIRTQ_USED_ELEM_ID_OFFSET
	jne fail_completion
	cmpl $VIRTIO_RNG_REQUEST_LEN, VIRTQ_USED_GPA + VIRTQ_USED_RING_OFFSET + 4 * VIRTQ_USED_ELEM_SIZE + VIRTQ_USED_ELEM_LEN_OFFSET
	jne fail_completion

	/* -------------------------------------------------- */
	/* PHASE D — IOEVENTFD DOORBELL */
	/* -------------------------------------------------- */
	/* Requests still live in shared RAM; only the QueueNotify delivery path changes. */
	movl $(VIRTIO_RNG_BUFFER_GPA + VIRTIO_IOEVENTFD_DESC_INDEX * VIRTIO_RNG_BUFFER_STRIDE), VIRTQ_DESC_GPA + VIRTIO_IOEVENTFD_DESC_INDEX * VIRTQ_DESC_SIZE + VIRTQ_DESC_ADDR_OFFSET
	movl $0, VIRTQ_DESC_GPA + VIRTIO_IOEVENTFD_DESC_INDEX * VIRTQ_DESC_SIZE + VIRTQ_DESC_ADDR_OFFSET + 4
	movl $VIRTIO_RNG_REQUEST_LEN, VIRTQ_DESC_GPA + VIRTIO_IOEVENTFD_DESC_INDEX * VIRTQ_DESC_SIZE + VIRTQ_DESC_LEN_OFFSET
	movw $VIRTQ_DESC_F_WRITE, VIRTQ_DESC_GPA + VIRTIO_IOEVENTFD_DESC_INDEX * VIRTQ_DESC_SIZE + VIRTQ_DESC_FLAGS_OFFSET
	movw $0, VIRTQ_DESC_GPA + VIRTIO_IOEVENTFD_DESC_INDEX * VIRTQ_DESC_SIZE + VIRTQ_DESC_NEXT_OFFSET
	movw $VIRTIO_IOEVENTFD_DESC_INDEX, VIRTQ_AVAIL_GPA + VIRTQ_AVAIL_RING_OFFSET + VIRTIO_IOEVENTFD_DESC_INDEX * 2
	cmpw $VIRTIO_RNG_REQUEST_COUNT, VIRTQ_AVAIL_GPA + VIRTQ_AVAIL_IDX_OFFSET
	jne fail_queue

	/* avail.idx remains five while descriptor 5 and available slot 5 are prepared and guest-owned. */
	mfence
	movw $VIRTIO_TOTAL_REQUEST_COUNT, VIRTQ_AVAIL_GPA + VIRTQ_AVAIL_IDX_OFFSET
	/* This fence orders publication before the QueueNotify write handled by KVM_IOEVENTFD. */
	mfence
	movl $VIRTIO_RNG_QUEUE_INDEX, VIRTIO_MMIO_BASE + VIRTIO_MMIO_QUEUE_NOTIFY

	movl $VIRTIO_POLL_LIMIT, %ecx
.Lpoll_ioeventfd_completion:
	cmpw $VIRTIO_TOTAL_REQUEST_COUNT, VIRTQ_USED_GPA + VIRTQ_USED_IDX_OFFSET
	je .Lioeventfd_complete
	decl %ecx
	jnz .Lpoll_ioeventfd_completion
	jmp fail_timeout
.Lioeventfd_complete:
	/* The acquire fence keeps completion reads after observing used.idx reach six. */
	lfence
	cmpl $VIRTIO_IOEVENTFD_DESC_INDEX, VIRTQ_USED_GPA + VIRTQ_USED_RING_OFFSET + VIRTIO_IOEVENTFD_DESC_INDEX * VIRTQ_USED_ELEM_SIZE + VIRTQ_USED_ELEM_ID_OFFSET
	jne fail_completion
	cmpl $VIRTIO_RNG_REQUEST_LEN, VIRTQ_USED_GPA + VIRTQ_USED_RING_OFFSET + VIRTIO_IOEVENTFD_DESC_INDEX * VIRTQ_USED_ELEM_SIZE + VIRTQ_USED_ELEM_LEN_OFFSET
	jne fail_completion

	/* The VMM treats this port write as explicit success and exits before the following fault instruction. */
	movb $0, %al
	outb %al, $VIRTIO_TEST_SUCCESS_PORT
	ud2

fail_identity:
	movb $1, %al
	jmp guest_failure
fail_status:
	movb $2, %al
	jmp guest_failure
fail_features:
	movb $3, %al
	jmp guest_failure
fail_queue:
	movb $4, %al
	jmp guest_failure
fail_driver_ok:
	movb $5, %al
	jmp guest_failure
fail_timeout:
	movb $6, %al
	jmp guest_failure
fail_completion:
	movb $7, %al

guest_failure:
	outb %al, $VIRTIO_TEST_FAILURE_PORT
	ud2

.align 8
gdt:
	.quad 0x0000000000000000
	.quad 0x00cf9a000000ffff
	.quad 0x00cf92000000ffff
gdt_end:
gdt_descriptor:
	.word gdt_end - gdt - 1
	.long gdt
