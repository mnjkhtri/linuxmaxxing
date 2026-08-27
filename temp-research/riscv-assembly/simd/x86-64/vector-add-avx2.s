# vector_add_avx2(const int *a, const int *b, int *out, long n)

.text
.globl vector_add_avx2
.type vector_add_avx2, @function

vector_add_avx2:
    # rdi = a
    # rsi = b
    # rdx = out
    # rcx = n

    xorl %eax, %eax              # i = 0

vector_loop:
    movq %rcx, %r8
    subq %rax, %r8
    cmpq $8, %r8
    jl   scalar_loop

    vmovdqu (%rdi,%rax,4), %ymm0
    vmovdqu (%rsi,%rax,4), %ymm1
    vpaddd %ymm1, %ymm0, %ymm0
    vmovdqu %ymm0, (%rdx,%rax,4)

    addq $8, %rax
    jmp  vector_loop

scalar_loop:
    cmpq %rcx, %rax
    jge  done

    movl (%rdi,%rax,4), %r8d
    addl (%rsi,%rax,4), %r8d
    movl %r8d, (%rdx,%rax,4)

    incq %rax
    jmp  scalar_loop

done:
    vzeroupper
    ret

.size vector_add_avx2, .-vector_add_avx2

.section .note.GNU-stack,"",@progbits
