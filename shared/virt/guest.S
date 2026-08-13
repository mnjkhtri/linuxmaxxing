/*
 * Tiny 16-bit guest for observing EPT changes.
 * AT&T syntax is source,destination; b/w/l mean 8/16/32 bits.
 * Guest paging is off, so GVA == GPA; Intel EPT still maps GPA to HPA.
 * RAM is 0x0000-0x3fff, and GFN 2 (GPA 0x2000) is the data page.
 */
.code16
.global _start

_start:
	movl $0, %eax        	/* Select CPUID leaf 0. */
	cpuid                	/* VM exit handled by KVM in the kernel. */

	/* Normal guest arithmetic executes without a VM exit. */
	movw $0x1111, %ax
	movw $0x0001, %bx
	addw %bx, %ax        	/* AX becomes 0x1112. */

	movw %ax, 0x2000     	/* First GFN 2 write makes KVM install its EPT leaf. */

	/* Command 1 makes the VMM MADV_DONTNEED GFN 2's host page. */
	movb $1, %al
	outb %al, $0xe9      	/* KVM_EXIT_IO transfers the command to userspace. */
	movw $0x2222, 0x2000 	/* Write GFN 2 again and rebuild its EPT mapping. */

	/* Command 2 makes the VMM replace the entire guest-memory slot. */
	movb $2, %al
	outb %al, $0xe9      	/* KVM_EXIT_IO transfers the command to userspace. */
	movw $0x3333, 0x2000 	/* Map GFN 2 through the replacement host memory. */

	movw %ax, 0x4001     	/* Outside registered RAM, so userspace gets KVM_EXIT_MMIO. */
	hlt                  	/* Finish the guest with KVM_EXIT_HLT. */
