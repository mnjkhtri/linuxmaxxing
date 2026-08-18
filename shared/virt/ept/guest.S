/*
 * The guest starts in real mode, enters flat 32-bit protected mode, then performs the EPT memory workload.
 * Each 0xe9 command asks the VMM to reshape the EPT (MADV_DONTNEED, slot replacement, dirty-log clear, one 2 MiB THP-backed slot, and its dirty-logging split);
 * writing GFN 7 / the huge slot between commands faults in and walks the EPT.  Port 0x82 ends the run.
 */
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
	movl $0x0ff0, %esp

	movl $0, %eax        	/* Select CPUID leaf 0. */
	cpuid                	/* VM exit handled by KVM in the kernel. */

	/* Normal guest arithmetic executes without a VM exit. */
	movw $0x1111, %ax
	movw $0x0001, %bx
	addw %bx, %ax        	/* AX becomes 0x1112. */

	movw %ax, 0x7000     	/* First GFN 7 write keeps data well away from code in GFN 0. */

	/* Command 1 makes the VMM MADV_DONTNEED GFN 7's host page. */
	movb $1, %al
	outb %al, $0xe9      	/* KVM_EXIT_IO transfers the command to userspace. */
	movw $0x2222, 0x7000 	/* Write GFN 7 again and rebuild its EPT mapping. */

	/* Command 2 makes the VMM replace the entire guest-memory slot. */
	movb $2, %al
	outb %al, $0xe9      	/* KVM_EXIT_IO transfers the command to userspace. */
	movw $0x3333, 0x7000 	/* Map GFN 7 through the replacement host memory. */

	/* Command 3 keeps GFN 7's PFN but clears its EPT dirty-tracking state. */
	movb $3, %al
	outb %al, $0xe9      	/* KVM invalidates the cached translation after clearing D (or write-protecting). */
	movw $0x4444, 0x7000 	/* Write sets EPT D again; hosts without EPT A/D instead take a write violation. */

	movw %ax, 0xa001     	/* GFN 10 is beyond RAM, with GFNs 8-9 left as a visible gap before MMIO. */

	/* Command 4 adds a data-only 2 MiB THP-backed slot at aligned GPA 0x200000. */
	movb $4, %al
	outb %al, $0xe9      	/* Slot 0 keeps code; slot 1 receives the huge host page. */
	movw $0x5555, 0x200000	/* Flat 32-bit addressing reaches the data-only huge slot. */

	/* Command 5 asks KVM to split the huge EPT mapping for dirty logging. */
	movb $5, %al
	outb %al, $0xe9      	/* VMM re-registers slot 1 with KVM_MEM_LOG_DIRTY_PAGES. */
	movw $0x6666, 0x201000	/* Second 4 KiB page inside the same 2 MiB range, after the split. */

	/* Close the capture after the EPT workload. */
	movb $0, %al
	outb %al, $0x82

	hlt

.align 8
gdt:
	.quad 0x0000000000000000	/* Null descriptor. */
	.quad 0x00cf9a000000ffff	/* Ring-0 flat 32-bit code segment. */
	.quad 0x00cf92000000ffff	/* Ring-0 flat 32-bit data segment. */
gdt_end:
gdt_descriptor:
	.word gdt_end - gdt - 1
	.long gdt
