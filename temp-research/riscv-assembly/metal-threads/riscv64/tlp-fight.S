.equ UART0, 0x10000000
.equ VIRT_TEST, 0x100000
.equ HART_COUNT, 4
.equ STACK_SIZE, 1024
.equ INCREMENTS, 100000
.equ EXPECTED, HART_COUNT * INCREMENTS

.section .text
.globl _start

_start:
    # 1. Give every hart its own stack.
    csrr t0, mhartid
    li   t1, HART_COUNT
    bgeu t0, t1, park

    la   sp, stack_space
    addi t2, t0, 1
    li   t1, STACK_SIZE
    mul  t1, t1, t2
    add  sp, sp, t1

    # 2. Every hart increments the same shared counter.
    la   a0, shared_counter
    li   t1, INCREMENTS

loop:
#ifdef USE_ATOMIC
    li   t2, 1
    amoadd.d zero, t2, (a0)
#else
    ld   t2, 0(a0)
    addi t2, t2, 1
    sd   t2, 0(a0)
#endif
    addi t1, t1, -1
    bnez t1, loop

    fence rw, rw

    # 3. Mark this hart as finished.
    la   t3, done_count
    li   t4, 1
    amoadd.d zero, t4, (t3)

    # 4. Hart 0 waits for everyone then reports.
    csrr t0, mhartid
    bnez t0, park

wait_done:
    ld   t5, 0(t3)
    li   t6, HART_COUNT
    bne  t5, t6, wait_done
    fence rw, rw

    # --- PRINT RESULTS VIA UART ---
#ifdef USE_ATOMIC
    la   a0, atomic_msg
#else
    la   a0, unsafe_msg
#endif
    call puts
    call newline

    la   a0, expected_msg
    call puts
    li   a0, EXPECTED
    call print_u64
    call newline

    la   a0, actual_msg
    call puts
    la   t0, shared_counter
    ld   a0, 0(t0)
    call print_u64
    call newline

    call qemu_exit_success

park:
    wfi
    j park

puts:
    li   t0, UART0
puts_loop:
    lbu  t1, 0(a0)
    beqz t1, puts_done
    sb   t1, 0(t0)
    addi a0, a0, 1
    j    puts_loop
puts_done:
    ret

newline:
    li   t0, UART0
    li   t1, '\n'
    sb   t1, 0(t0)
    ret

print_u64:
    addi sp, sp, -64
    mv   t0, sp
    li   t1, 0
    li   t2, 10
    bnez a0, print_digits
    li   t3, '0'
    sb   t3, 0(t0)
    li   t1, 1
    j    emit_digits
print_digits:
    remu t3, a0, t2
    divu a0, a0, t2
    addi t3, t3, '0'
    add  t4, t0, t1
    sb   t3, 0(t4)
    addi t1, t1, 1
    bnez a0, print_digits
emit_digits:
    li   t5, UART0
emit_loop:
    addi t1, t1, -1
    add  t4, t0, t1
    lbu  t3, 0(t4)
    sb   t3, 0(t5)
    bnez t1, emit_loop
    addi sp, sp, 64
    ret

qemu_exit_success:
    li   t0, VIRT_TEST
    li   t1, 0x5555
    sw   t1, 0(t0)
    ret

.section .rodata
unsafe_msg:   .asciz "Mode: Unsafe Load/Store"
atomic_msg:   .asciz "Mode: Atomic AMOADD"
expected_msg: .asciz "Expected: "
actual_msg:   .asciz "Actual:   "

.section .data
.balign 8
shared_counter: .dword 0
done_count:     .dword 0

.section .bss
.balign 16
stack_space:    .space HART_COUNT * STACK_SIZE
