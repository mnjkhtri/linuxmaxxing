# bubble_sort(long *array, long size)

.text
.globl bubble_sort
.type bubble_sort, @function

bubble_sort:
    # rdi = base address of array
    # rsi = size (N)

    movq %rsi, %r8       # r8 = N
    decq %r8             # r8 = limit for outer loop (N-1)
    xorl %r9d, %r9d      # r9 = i = 0

outer_loop:
    cmpq %r8, %r9        # if i >= N-1, exit
    jge  done
    xorl %r10d, %r10d    # r10 = j = 0

inner_loop:
    cmpq %r8, %r10       # if j >= N-1, go to next i
    jge  next_i

    # Address calculation: arr[j] and arr[j+1]
    leaq (%rdi,%r10,8), %r11

    movq 0(%r11), %rax   # rax = arr[j]
    movq 8(%r11), %rdx   # rdx = arr[j+1]

    cmpq %rdx, %rax
    jle  no_swap
    # Swap
    movq %rdx, 0(%r11)
    movq %rax, 8(%r11)

no_swap:
    incq %r10            # j++
    jmp  inner_loop

next_i:
    incq %r9             # i++
    jmp  outer_loop

done:
    ret

.size bubble_sort, .-bubble_sort

.section .note.GNU-stack,"",@progbits
