.section .data
msg:
    .ascii "Hello from x86-64!\n"

.section .text
.globl _start

_start:
    # write(1, msg, 19)
    movq $1, %rax       # syscall number for write
    movq $1, %rdi       # file descriptor 1 (stdout)
    leaq msg(%rip), %rsi
    movq $19, %rdx      # length of message
    syscall

    # exit(0)
    movq $60, %rax      # syscall number for exit
    xorl %edi, %edi     # return code 0
    syscall

.section .note.GNU-stack,"",@progbits
