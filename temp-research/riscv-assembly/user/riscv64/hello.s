.section .data
msg:
    .ascii "Hello from RISC-V!\n"

.section .text
.globl _start

_start:
    # write(1, msg, 19)
    li a0, 1            # file descriptor 1 (stdout)
    la a1, msg          # address of message
    li a2, 19           # length of message
    li a7, 64           # syscall number for write (64)
    ecall               # transfer control to kernel

    # exit(0)
    li a0, 0            # return code 0
    li a7, 93           # syscall number for exit (93)
    ecall
