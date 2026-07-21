# External Kernel Modules

The module tools live in this directory. The combined module is built as `koops.ko`. Captures are written under `shared/_captures/`.

Build the modules against the configured custom kernel:

```bash
./build.sh
make -C shared/modules
```

Inside QEMU, load the combined study module and collect both outputs:

```bash
sh /mnt/host/modules/w.sh
mkdir -p /mnt/host/_captures
dmesg | grep -E "KOOPS_CORE|KOOPS_MM" > /mnt/host/_captures/modules-koops.txt
```
