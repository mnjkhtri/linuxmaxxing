# Assembly Examples

## User Programs

Sources are grouped by ISA under `user/<isa>/`.

| Program | RISC-V 64 | x86-64 | Notes |
| --- | --- | --- | --- |
| Hello | `riscv64/hello.s` | `x86-64/hello.s` | Standalone program |
| Bubble sort | `riscv64/bubble-sort.s` | `x86-64/bubble-sort.s` | Uses `main.c` with `USER` |

## SIMD Programs

Sources are grouped by ISA under `simd/<isa>/`.

| Program | RISC-V 64 | x86-64 | Notes |
| --- | --- | --- | --- |
| Vector add | - | `x86-64/vector-add-avx2.s` | AVX2, uses `main.c` with `SIMD` |

## Metal Threads Programs

Sources are grouped by ISA under `metal-threads/<isa>/`.

| Program | RISC-V 64 | x86-64 | Notes |
| --- | --- | --- | --- |
| TLP fight | `riscv64/tlp-fight.S` | - | Multi-hart bare metal, inspected with QEMU + GDB |

## Build

```sh
make
make simd
make metal-threads
```
