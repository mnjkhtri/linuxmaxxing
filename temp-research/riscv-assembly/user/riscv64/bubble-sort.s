# bubble_sort(long *array, long size)

.text
.globl bubble_sort

bubble_sort:
    # a0 = base address of array
    # a1 = size (N)

    addi t0, a1, -1     # t0 = limit for outer loop (N-1)
    li   t1, 0          # t1 = i = 0

outer_loop:
    bge  t1, t0, done   # if i >= N-1, exit
    li   t2, 0          # t2 = j = 0

inner_loop:
    bge  t2, t0, next_i # if j >= N-1, go to next i

    # Address calculation: arr[j] and arr[j+1]
    slli t3, t2, 3      # t3 = j * 8
    add  t4, a0, t3     # t4 = &arr[j]

    ld   t5, 0(t4)      # t5 = arr[j]
    ld   t6, 8(t4)      # t6 = arr[j+1]

    ble  t5, t6, no_swap
    # Swap
    sd   t6, 0(t4)
    sd   t5, 8(t4)

no_swap:
    addi t2, t2, 1      # j++
    j    inner_loop

next_i:
    addi t1, t1, 1      # i++
    j    outer_loop

done:
    ret                 # Return to caller
