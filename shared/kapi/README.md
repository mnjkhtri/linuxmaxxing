# External Kernel Modules

The module tools live in this directory. The combined module is built as `kapi.ko`. Captures are written under `shared/_captures/`.

Build the modules against the configured custom kernel:

```bash
./build.sh
make -C shared/kapi
```

Inside QEMU, load the combined study module and collect its structured `KAPI_EVT` records:

```bash
sh /mnt/host/kapi/run.sh
```

The runner writes the latest complete module run to `shared/_captures/kapi.txt`.
