.code16                 /* KVM starts this toy guest like 16-bit real-mode code. */
.global _start

_start:
	movl $0, %eax       /* CPUID is a CPU query that causes a VM exit. */
	cpuid               /* KVM handles this exit in the kernel and then resumes the guest. */

	movw $0x1111, %ax   /* These normal arithmetic instructions do not exit by themselves. */
	movw $0x0001, %bx
	addw %bx, %ax

	movw %ax, 0x0100    /* This writes inside the registered 4 KiB guest RAM. */
	movw %ax, 0x1001    /* This writes outside guest RAM, so KVM reports KVM_EXIT_MMIO. */

	/* movb $'A', %al      Port I/O exits to userspace because our VMM handles KVM_EXIT_IO. */
	/* outb %al, $0xe9     OUT sends the byte in AL to debug-style port 0xe9. */
	/* inb $0xe9, %al      IN asks userspace for a byte; vmm.c returns 0x55. */

	hlt                 /* HLT stops the toy guest and userspace receives KVM_EXIT_HLT. */
