# Omitted generated and large files

The three research trees were migrated here without generated build outputs or files >=90 MiB. Those files were preserved, not deleted, under `../large-research-artifacts/` with their original relative paths. Recreate them with each project build or restore them from that directory if an old artifact is specifically needed.

## Files >=90 MiB

- `hyperturtle/cloudlab-copy/work/hyperturtle/ubuntu-l1.qcow2` — 13 GiB (QEMU image)
- `hyperturtle/tarz/ubuntu-l1.qcow2` — 12 GiB (QEMU image)
- `hyperturtle/tarz/hyperturtle-shallow.tar.gz` — 3.5 GiB (archive)
- `hyperturtle/cloudlab-copy/work/hyperturtle/hyperturtle-linux/vmlinux.o` — 1.6 GiB (kernel build output)
- `hyperturtle/cloudlab-copy/work/hyperturtle/redis_data/dump.rdb` — 1.0 GiB (database dump)
- `hyperturtle/cloudlab-copy/work/hyperturtle/hyperturtle-linux/vmlinux` — 592 MiB (kernel image)
- `hyperturtle/cloudlab-copy/work/hyperturtle/hyperturtle-linux/.tmp_vmlinux.btf` — 591 MiB (kernel build output)
- `hyperturtle/cloudlab-copy/work/hyperturtle/hyperturtle-linux/drivers/net/ethernet/mellanox/mlx5/core/mlx5_core.ko` — 103 MiB (kernel module)
- `hyperturtle/cloudlab-copy/work/hyperturtle/hyperturtle-linux/drivers/net/ethernet/mellanox/mlx5/core/mlx5_core.o` — 102 MiB (object file)

## Other omitted generated content

- QEMU build directory and generated firmware/binaries (including small PC BIOS ELF images)
- Linux/QEMU object files, archives, modules, dependency files, and `vmlinux*` outputs
- Python virtual environments and `__pycache__`/`.pyc` files
- ELF executables produced by the projects

## Twitter

- `twitter/venv/` — 171 MiB (reproducible Python virtual environment; preserved at `../large-research-artifacts/twitter/venv/`)
- `twitter/venv/lib/python3.12/site-packages/playwright/driver/node` — 117 MiB (generated Playwright driver)

## RISC-V assembly

- `riscv-assembly/build/` — generated build output; preserved at `../large-research-artifacts/riscv-assembly/build/`

- `hyperturtle/cloudlab-copy/` — 2.5 GiB disposable CloudLab working copy with cloned Linux/QEMU/libbpf trees; preserved at `../large-research-artifacts/hyperturtle/cloudlab-copy/`

- Additional generated hyperturtle binaries, nested `.git` metadata, editor swap files, and build logs from `benchmarks/` and `mutilate/` were preserved under `../large-research-artifacts/hyperturtle/source-generated/`.
