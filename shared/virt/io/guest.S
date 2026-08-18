/*
 * Guest for the IO-virtualization experiment.
 *
 * Starts in real mode, enters flat 32-bit protected mode with paging disabled
 * (GVA == GPA), then teaches interrupt virtualization over a tiny MMIO virtual
 * device.  Phase markers go through the 0xe9 control port (PIO is only a marker,
 * not the subject); port 0x82 terminates the run.
 *
 * Layout and interrupt objects are reserved at fixed GPAs with .org so the
 * assembler both documents and pre-fills them:
 *
 *   0x0000  code + GDT + IDT
 *   0x4000  irq_count
 *   0x6000  DMA source buffer (pre-filled 0..63)
 *   0x6800  DMA expected device pattern (pre-filled 0x40..0x7f)
 *   0x7000  DMA destination buffer
 *
 * Phases:
 *   A  APIC ready  -- install IDT, configure LAPIC + IOAPIC RTE(4), marker, sti
 *   B  normal IRQ  -- CMD_IRQ_ONLY, full IOAPIC -> LAPIC -> inject -> ISR -> EOI
 *   C  pending while IF=0 -- cli, CMD_IRQ_ONLY, sync marker, sti;nop, deliver
 *   D  DMA_TO_DEVICE / DMA_FROM_DEVICE
 *   D verifies every DMA byte: DMA_TO reads the device buffer back, DMA_FROM compares the destination.
 *   Any verification failure halts permanently, and the VMM reports that halt as a failed run.
 *   Only byte-exact DMA reaches port 0x82, the VMM's sole success signal.
 *
 * Constants must stay in sync with device.h.
 */

/* ---- device contract (mirrors device.h) ---- */
.set DEVICE_MMIO_BASE, 0x10000000     /* virtual device's MMIO window (outside guest RAM) */
.set REG_COMMAND,   0x00              /* write a CMD_* here to start an operation */
.set REG_STATUS,    0x04              /* read BUSY/DONE/ERROR */
.set REG_DMA_GPA,   0x08              /* DMA target guest physical address */
.set REG_RESULT,    0x10              /* device result/checksum */
.set REG_IRQ_ACK,   0x14              /* optional device acknowledgment */
.set REG_BUFFER,    0x18              /* readback window into the device buffer */

.set DEVICE_PATTERN_BASE, 0x40        /* device's own buffer fill; distinct from guest source 0..63 */

.set CMD_IRQ_ONLY,        1           /* no I/O data; proves pure interrupt delivery */
.set CMD_DMA_TO_DEVICE,   2           /* guest RAM -> device internal buffer */
.set CMD_DMA_FROM_DEVICE, 3           /* device internal buffer -> guest RAM */

.set DEVICE_GSI,    4                 /* global system interrupt this device raises */
.set DEVICE_VECTOR, 0x40              /* interrupt vector routed into the guest IDT */

.set DMA_XFER_SIZE, 64                /* tiny deterministic transfer size */

.set MARKER_PORT, 0xe9                /* outb phase markers (PIO as marker only) */
.set DONE_PORT,   0x82                /* outb terminates the VMM run */
.set MARKER_APIC_READY,      0x11     /* phase A complete: LAPIC+IOAPIC programmed */
.set MARKER_IRQ_PENDING_IF0, 0x12     /* phase C: IRQ raised while guest IF=0 */

/* ---- arch MMIO regions (virtual LAPIC / IOAPIC) ---- */
.set LAPIC_BASE,  0xfee00000          /* architectural local APIC MMIO page */
.set LAPIC_EOI,   0x00b0              /* writing here signals ISR completion */
.set LAPIC_TPR,   0x0080              /* task priority: 0 lets all interrupts deliver */
.set LAPIC_SVR,   0x00f0              /* spurious vector reg: bit 8 software-enables APIC */
.set IOAPIC_BASE, 0xfec00000          /* architectural I/O APIC MMIO region */
.set IOAPIC_SEL,  0x00                /* IOREGSEL: register index */
.set IOAPIC_WIN,  0x10                /* IOWIN: register value */

/* ---- guest memory layout ---- */
.set IDT_BASE,  0x1000                /* 256-entry IDT (gate 0x40 built at runtime) */
.set STACK_TOP, 0x0e00                /* stack top; grows down, stays below IDT */
.set IRQ_COUNT, 0x4000                /* u32 bumped by the ISR; phases key off it */
.set DMA_SRC,   0x6000                /* DMA_TO source buffer */
.set DMA_EXPECT, 0x6800               /* expected device pattern for DMA_FROM verification */
.set DMA_DST,   0x7000                /* DMA_FROM destination buffer */

.set KERNEL_CS, 0x08                  /* GDT index 1: flat ring-0 32-bit code */
.set KERNEL_DS, 0x10                  /* GDT index 2: flat ring-0 32-bit data */

/*
 * Wait until the delivered ISR raises irq_count to \expect.
 * Each phase waits for its exact value (1,2,3,4) so the timeline can
 * unambiguously prove the interrupt actually ran.  If it never arrives,
 * \expect spins down to 0 and hlt guarantees the guest stops instead of hanging.
 */
.macro WAIT_IRQ_COUNT expect
	movl $400000, %ecx
1:	cmpl $\expect, irq_count
	je 2f
	loop 1b
	hlt
2:
.endm

.code16
.global _start

/* Enter flat 32-bit protected mode (same minimal ramp as the EPT guest). */
_start:
	cli                       /* no interrupts until the IDT/LAPIC/IOAPIC are ready */
	lgdt gdt_descriptor       /* load the flat ring-0 GDT */

	/* Set PE (protected mode enable) in CR0 ... */
	movl %cr0, %eax
	orl $1, %eax
	movl %eax, %cr0
	/* ... then jump through GDT index 1 so the CPU now runs 32-bit code. */
	ljmpl $KERNEL_CS, $protected_mode

.code32
protected_mode:
	/* Use the flat data segment for stack, data, and the reserved buffers. */
	movw $KERNEL_DS, %ax
	movw %ax, %ds
	movw %ax, %es
	movw %ax, %ss
	movl $STACK_TOP, %esp

	call setup_idt            /* guest builds and loads its own IDT */

	/* The 8259 PIC also receives GSI 4 and would preempt the IOAPIC with its own vector. */
	/* The guest masks every PIC line so only the IOAPIC route delivers the device interrupt. */
	movb $0xff, %al
	outb %al, $0x21          /* master PIC OCW1: mask all IRQs */
	outb %al, $0xa1          /* slave PIC OCW1: mask all IRQs */

	/*
	 * LAPIC setup (virtual LAPIC MMIO at 0xfee00000):
	 * TPR=0 admits every interrupt priority; SVR bit 8 software-enables the APIC and picks spurious vector 0x0f.
	 * The guest, not the VMM, configures its interrupt hardware.
	 */
	movl $0, %eax
	movl %eax, LAPIC_BASE + LAPIC_TPR
	movl $(0x100 + 0x0f), %eax
	movl %eax, LAPIC_BASE + LAPIC_SVR

	/*
	 * IOAPIC setup: program GSI DEVICE_GSI's redirection entry via the architectural IOREGSEL/IOWIN pair.
	 * Register index = 0x10 + 2*pin.
	 * Low dword: fixed delivery, vector 0x40, physical dest, edge, unmasked.
	 * High dword: destination LAPIC id 0.
	 */
	movl $(0x10 + DEVICE_GSI * 2), %eax
	movl %eax, IOAPIC_BASE + IOAPIC_SEL
	movl $DEVICE_VECTOR, %eax
	movl %eax, IOAPIC_BASE + IOAPIC_WIN
	movl $(0x10 + DEVICE_GSI * 2 + 1), %eax
	movl %eax, IOAPIC_BASE + IOAPIC_SEL
	movl $0, %eax
	movl %eax, IOAPIC_BASE + IOAPIC_WIN

	/* ---- Phase A: mark the APIC-ready baseline, then enable interrupts. ---- */
	movb $MARKER_APIC_READY, %al
	outb %al, $MARKER_PORT
	sti

	/* ---- Phase B: one normal IRQ_ONLY through the full IOAPIC->LAPIC chain. ---- */
	movl $CMD_IRQ_ONLY, DEVICE_MMIO_BASE + REG_COMMAND   /* VMM runs it, raises IRQ */
	WAIT_IRQ_COUNT 1

	/*
	 * ---- Phase C: interrupt pending while IF=0. ----
	 * cli makes the LAPIC *contain* the vector: IRR[0x40]=1, ISR[0x40]=0, and the ISR must not run.
	 * The marker forces a synchronization VM exit so the observer can sample that pending state deterministically.
	 * sti's one instruction shadow means 0x40 only delivers on the next instruction (nop).
	 */
	cli
	movl $CMD_IRQ_ONLY, DEVICE_MMIO_BASE + REG_COMMAND
	movb $MARKER_IRQ_PENDING_IF0, %al
	outb %al, $MARKER_PORT
	sti                            /* IF becomes 1 only after the next instruction */
	nop                            /* consume the STI shadow; 0x40 now injects */
	WAIT_IRQ_COUNT 2

	/* ---- Phase D: virtual DMA (device internal buffer <-> guest RAM). ---- */
	movl $DMA_SRC, DEVICE_MMIO_BASE + REG_DMA_GPA       /* source: guest RAM 0x6000 */
	movl $CMD_DMA_TO_DEVICE, DEVICE_MMIO_BASE + REG_COMMAND
	WAIT_IRQ_COUNT 3                                       /* guest saw completion IRQ */

	/* The device buffer must now read back the guest source exactly; a no-op copy fails here. */
	movl $0, %ecx
	movl $DMA_SRC, %esi
1:	movl (%esi), %ebx                              /* expected 32-bit slice of the source */
	movl $0, %eax
	movl DEVICE_MMIO_BASE + REG_BUFFER(,%ecx,4), %eax /* readback of the matching device slice */
	cmpl %ebx, %eax
	jne dma_failed
	addl $4, %esi
	incl %ecx
	cmpl $16, %ecx
	jb 1b

	movl $DMA_DST, DEVICE_MMIO_BASE + REG_DMA_GPA        /* dest: guest RAM 0x7000 */
	movl $CMD_DMA_FROM_DEVICE, DEVICE_MMIO_BASE + REG_COMMAND
	WAIT_IRQ_COUNT 4

	/* The destination must equal the expected device pattern byte for byte. */
	cld
	movl $DMA_EXPECT, %esi
	movl $DMA_DST, %edi
	movl $DMA_XFER_SIZE, %ecx
	repe cmpsb
	jne dma_failed

	/* ---- terminate the VMM run only after every DMA byte was verified ---- */
	movb $0, %al
	outb %al, $DONE_PORT
	hlt

/* A failed DMA proof halts forever; the VMM treats the unexpected HLT as a failed run. */
dma_failed:
	cli
	hlt

/*
 * Build the single 32-bit interrupt gate at IDT[0x40] and load the table.
 * Descriptor layout (8 bytes): offset[15:0] | selector | 0 | P/DPL/type | offset[31:16].
 * KERNEL_CS means the handler runs in ring-0 flat code; 0x8e = present, DPL=0, 32-bit interrupt gate.
 * Built at runtime because the handler address is only resolvable as a relocation, not as split data.
 */
setup_idt:
	pushl %edi
	pushl %eax
	pushl %ebx
	movl $irq_handler, %ebx
	movl $IDT_BASE, %edi
	addl $(DEVICE_VECTOR * 8), %edi   /* IDT[DEVICE_VECTOR] */
	movw %bx, 0(%edi)          /* handler offset[15:0] */
	movw $KERNEL_CS, 2(%edi)   /* segment selector = ring-0 code */
	movb $0x00, 4(%edi)        /* descriptor byte 4 reserved */
	movb $0x8e, 5(%edi)        /* present + DPL 0 + 32-bit interrupt gate */
	movl %ebx, %eax
	shrl $16, %eax
	movw %ax, 6(%edi)          /* handler offset[31:16] */
	lidt idt_descriptor
	popl %ebx
	popl %eax
	popl %edi
	ret

/* Guest ISR for vector 0x40: acknowledge, observe device, then architecturally EOI. */
irq_handler:
	pusha                                              /* preserve all guest GPRs */
	incl irq_count                                     /* phases key off this bump */
	movl DEVICE_MMIO_BASE + REG_STATUS, %eax           /* read device STATUS via MMIO */
	movl $1, %eax
	movl %eax, DEVICE_MMIO_BASE + REG_IRQ_ACK          /* optional device ack */
	movl $0, LAPIC_BASE + LAPIC_EOI                    /* EOI to virtual LAPIC */
	popa
	iret                                               /* return, restoring EFLAGS (IF) */

/* ================= data / tables ================= */
.align 8
gdt:
	.quad 0x0000000000000000            /* null */
	.quad 0x00cf9a000000ffff            /* ring-0 flat 32-bit code */
	.quad 0x00cf92000000ffff            /* ring-0 flat 32-bit data */
gdt_end:
gdt_descriptor:
	.word gdt_end - gdt - 1             /* 32-bit limit (index-based) */
	.long gdt                           /* base = 0 (loaded at GPA 0) */

idt_descriptor:
	.word (DEVICE_VECTOR * 8 + 8) - 1   /* limit: gate at index 0x40 */
	.long IDT_BASE                      /* base = 0x1000 */

/* IDT: gate at vector 0x40 is built at runtime into this reserved region. */
.org IDT_BASE
idt:
	.space DEVICE_VECTOR * 8 + 8, 0

/* IRQ bookkeeping: incremented by the ISR. */
.org IRQ_COUNT
irq_count:
	.long 0

/* DMA source: deterministic bytes 0..63 (pre-assembled, no runtime fill). */
.org DMA_SRC
dma_src:
	.set fill_i, 0
	.rept DMA_XFER_SIZE
		.byte fill_i
		.set fill_i, fill_i + 1
	.endr

/* Expected device pattern for DMA_FROM verification (mirrors DEVICE_PATTERN_BASE + i). */
.org DMA_EXPECT
dma_expect:
	.set fill_j, DEVICE_PATTERN_BASE
	.rept DMA_XFER_SIZE
		.byte fill_j
		.set fill_j, fill_j + 1
	.endr

/* DMA destination: filled by the VMM during DMA_FROM. */
.org DMA_DST
dma_dst:
	.space DMA_XFER_SIZE, 0
