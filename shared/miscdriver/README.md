# LLKD Misc Driver

`llkd_miscdrv.c` is a beginner-friendly Linux misc character driver. It does
not drive real hardware. Instead, it uses a small in-kernel string as the
backing device and exposes that state through several common kernel/userspace
interfaces:

- `/dev/llkd_miscdrv` for the real character-device data path;
- `/sys/class/misc/llkd_miscdrv/` for one-value-per-file device attributes;
- `/proc/llkd_miscdrv/` as a procfs comparison interface; and
- `/sys/kernel/debug/llkd_miscdrv/status` for a rich debug-only dump.

The point of this driver is to show lifecycle and API touch points. When you
know the names and order below, you can open the kernel docs or source and fill
in exact prototypes later.

## Topology

```text
Userspace
  echo hello > /dev/llkd_miscdrv
       |
       v
  write(2)
       |
       v
  write_miscdrv()
       |-- copy_from_user()
       |-- update ctx->oursecret
       `-- update ctx->rx

  cat /dev/llkd_miscdrv
       |
       v
  read(2)
       |
       v
  read_miscdrv()
       |-- copy_to_user()
       |-- advance file offset
       `-- update ctx->tx
```

The side interfaces expose the same private state:

```text
/sys/class/misc/llkd_miscdrv/config      read/write ctx->config
/sys/class/misc/llkd_miscdrv/tx          read ctx->tx
/sys/class/misc/llkd_miscdrv/rx          read ctx->rx
/sys/class/misc/llkd_miscdrv/secret_len  read ctx->secret_len

/proc/llkd_miscdrv/status                multi-line procfs status
/proc/llkd_miscdrv/config                read/write ctx->config

/sys/kernel/debug/llkd_miscdrv/status    rich debugfs diagnostic dump
```

## Private Context

Driver state is centered on one private structure:

```text
struct drv_ctx
  |-- struct device *dev
  |-- tx
  |-- rx
  |-- config
  |-- mutex lock
  |-- proc_dir
  |-- debugfs_dir
  |-- oursecret[MAXBYTES]
  `-- secret_len
```

Important fields:

| Field | Purpose |
|---|---|
| `dev` | The misc-created device object used for `dev_info()` and `dev_warn()` logging. |
| `tx` | Total bytes transmitted from the driver to userspace through `/dev` reads. |
| `rx` | Total bytes received from userspace through `/dev` writes. |
| `config` | Small tunable exposed through procfs and sysfs. |
| `lock` | Mutex protecting shared state. |
| `proc_dir` | Procfs directory handle for `/proc/llkd_miscdrv`. |
| `debugfs_dir` | Debugfs directory handle for `/sys/kernel/debug/llkd_miscdrv`. |
| `oursecret` | The stored string returned by `/dev/llkd_miscdrv` reads. |
| `secret_len` | Number of valid bytes in `oursecret`. |

`MAXBYTES` is `128`. If userspace uses the same limit, a real project should
put it in a shared UAPI header instead of duplicating it.

## Module Lifecycle

The module load path runs from `module_init()` into `llkd_misc_init()`.
Initialization happens in this order:

```text
misc_register()
    -> llkd_miscdev.this_device becomes valid
        -> devm_kzalloc() private ctx
            -> mutex_init()
            -> seed initial state
            -> sysfs_create_group()
                -> proc_mkdir()
                -> proc_create(status)
                -> proc_create(config)
                    -> debugfs_create_dir()
                    -> debugfs_create_file(status)
```

The unload path runs from `module_exit()` into `llkd_misc_exit()` and removes
things in reverse order:

```text
debugfs_remove_recursive()
    -> remove_proc_subtree()
        -> sysfs_remove_group()
            -> misc_deregister()
```

The same reverse-order idea appears in the init error labels. If procfs setup
fails, sysfs is removed and the misc device is deregistered. If debugfs setup
fails, debugfs is removed first, then procfs, sysfs, and the misc device.

## Misc Device Lifecycle

The misc framework creates the `/dev` character device with a small amount of
boilerplate:

```text
struct file_operations llkd_misc_fops
    -> open_miscdrv
    -> read_miscdrv
    -> write_miscdrv
    -> close_miscdrv

struct miscdevice llkd_miscdev
    -> MISC_DYNAMIC_MINOR
    -> name "llkd_miscdrv"
    -> mode 0666
    -> fops &llkd_misc_fops
```

Important API touch points:

| API | Role |
|---|---|
| `misc_register()` | Publishes the misc device and creates the kernel `struct device`. |
| `misc_deregister()` | Removes the misc device. |
| `MISC_DYNAMIC_MINOR` | Asks the kernel to allocate a free misc minor. |
| `struct miscdevice` | Describes the misc device name, mode, minor, and file operations. |
| `struct file_operations` | Dispatch table for `/dev` system calls. |
| `THIS_MODULE` | Pins the module while file operations run. |

After registration, the device appears as:

```text
/dev/llkd_miscdrv
/sys/class/misc/llkd_miscdrv
/sys/devices/virtual/misc/llkd_miscdrv
```

## `/dev` Data Path

`/dev/llkd_miscdrv` is the actual character-device I/O path.

Callbacks:

| Userspace action | Driver callback |
|---|---|
| `open("/dev/llkd_miscdrv")` | `open_miscdrv()` |
| `read(fd, ...)` | `read_miscdrv()` |
| `write(fd, ...)` | `write_miscdrv()` |
| `close(fd)` | `close_miscdrv()` |

### Open

`open_miscdrv()` currently only logs. In a larger driver, open often allocates
per-file state and stores it in `file->private_data`.

Touch points:

- `struct inode`
- `struct file`
- `file->private_data`
- `dev_info()`

### Write

`write_miscdrv()` accepts bytes from userspace and replaces `ctx->oursecret`.

Lifecycle:

```text
validate count
    -> allocate temporary kernel buffer with kvmalloc()
        -> clear it with memset()
            -> copy_from_user()
                -> mutex_lock()
                    -> strscpy() into ctx->oursecret
                    -> update ctx->secret_len
                    -> update ctx->rx
                -> mutex_unlock()
        -> kvfree()
```

Important touch points:

| API | Role |
|---|---|
| `copy_from_user()` | Safely copies bytes from a userspace pointer. |
| `kvmalloc()` | Allocates temporary kernel memory. |
| `kvfree()` | Frees memory allocated by `kvmalloc()`. |
| `memset()` | Clears the temporary buffer. |
| `strscpy()` | Copies into the fixed-size driver buffer with NUL termination. |
| `mutex_lock()` / `mutex_unlock()` | Protects shared driver state. |
| `get_task_comm()` / `current` | Logs the calling task name. |
| `dev_warn()` | Logs invalid write size or copy failure. |

The driver rejects writes `>= MAXBYTES` so one byte remains available for a
trailing NUL character.

### Read

`read_miscdrv()` copies the current stored string back to userspace.

Lifecycle:

```text
log calling task
    -> mutex_lock()
        -> check file offset for EOF
        -> clamp read size to remaining bytes
        -> copy_to_user()
        -> advance file offset
        -> update ctx->tx
    -> mutex_unlock()
```

Important touch points:

| API | Role |
|---|---|
| `copy_to_user()` | Safely copies bytes to a userspace pointer. |
| `loff_t *off` | File offset used so repeated reads eventually return EOF. |
| `min_t()` | Clamps requested count to remaining data. |
| `mutex_lock()` / `mutex_unlock()` | Protects shared state while reading. |

Returning `0` from `read()` means EOF. This is why `cat /dev/llkd_miscdrv`
terminates instead of looping forever.

### Release

`close_miscdrv()` currently only logs. If open allocated per-file state, release
would free it.

## Sysfs Attributes

Sysfs exposes simple attributes below the misc device:

```text
/sys/class/misc/llkd_miscdrv/config
/sys/class/misc/llkd_miscdrv/tx
/sys/class/misc/llkd_miscdrv/rx
/sys/class/misc/llkd_miscdrv/secret_len
```

Sysfs convention is one value per file. This makes shell scripts simple and
keeps each attribute stable.

Read/write config:

```text
cat config      -> config_show()
echo 7 > config -> config_store()
```

Read-only counters:

```text
cat tx          -> tx_show()
cat rx          -> rx_show()
cat secret_len  -> secret_len_show()
```

Important API touch points:

| API | Role |
|---|---|
| `DEVICE_ATTR_RW(config)` | Creates `dev_attr_config` from `config_show()` and `config_store()`. |
| `DEVICE_ATTR_RO(tx)` | Creates read-only `dev_attr_tx` from `tx_show()`. |
| `DEVICE_ATTR_RO(rx)` | Creates read-only `dev_attr_rx` from `rx_show()`. |
| `DEVICE_ATTR_RO(secret_len)` | Creates read-only `dev_attr_secret_len` from `secret_len_show()`. |
| `sysfs_emit()` | Formats output from a sysfs `show()` callback. |
| `kstrtoint()` | Parses text written to a sysfs `store()` callback. |
| `struct attribute_group` | Groups multiple sysfs attributes together. |
| `sysfs_create_group()` | Registers the sysfs files. |
| `sysfs_remove_group()` | Removes the sysfs files. |

The macro naming convention matters. `DEVICE_ATTR_RW(config)` expects functions
named `config_show()` and `config_store()`, and it creates `dev_attr_config`.
That generated object is what gets placed in the attribute group.

## Procfs Interface

Procfs is included as a teaching comparison. It creates:

```text
/proc/llkd_miscdrv/status
/proc/llkd_miscdrv/config
```

`status` is a multi-line status dump. `config` is a direct read/write scalar.
For new stable per-device interfaces, prefer sysfs attributes. Procfs remains
useful to learn because many kernel examples and older drivers use it.

### Procfs Status

Status uses the `seq_file` helpers:

```text
open status
    -> status_proc_open()
        -> single_open(status_proc_show)
read status
    -> seq_read()
        -> status_proc_show()
release status
    -> single_release()
```

Important touch points:

| API | Role |
|---|---|
| `proc_mkdir()` | Creates `/proc/llkd_miscdrv`. |
| `proc_create()` | Creates procfs files. |
| `struct proc_ops` | Procfs operation table on modern kernels. |
| `single_open()` | Connects one simple show function to a proc file. |
| `seq_printf()` | Prints into the seq_file/proc read buffer. |
| `seq_read()` | Copies seq_file output to userspace. |
| `seq_lseek()` | Provides seek support. |
| `single_release()` | Cleans up `single_open()`. |
| `remove_proc_subtree()` | Removes the procfs directory and files. |

### Procfs Config

Config uses direct callbacks instead of `seq_file` because it is just one
integer:

```text
cat /proc/llkd_miscdrv/config
    -> config_proc_read()

echo 7 > /proc/llkd_miscdrv/config
    -> config_proc_write()
```

Important touch points:

| API | Role |
|---|---|
| `scnprintf()` | Formats the integer into a small kernel buffer. |
| `simple_read_from_buffer()` | Handles copying that kernel buffer to userspace. |
| `kstrtoint_from_user()` | Parses an integer directly from userspace input. |

## Debugfs Interface

Debugfs is for developer diagnostics, not stable ABI. This driver creates:

```text
/sys/kernel/debug/llkd_miscdrv/status
```

If debugfs is not mounted:

```sh
mount -t debugfs none /sys/kernel/debug
```

The debugfs status file prints a richer report than sysfs should expose:

```text
llkd_miscdrv debug status
========================
module: llkd_miscdrv
devnode: /dev/llkd_miscdrv
misc_major: 10
misc_minor: ...
ctx: ...
device: ...

counters
--------
tx_bytes_to_user: ...
rx_bytes_from_user: ...

state
-----
config: ...
maxbytes: 128
secret_len: ...
secret_preview: ...
```

Important touch points:

| API | Role |
|---|---|
| `debugfs_create_dir()` | Creates `/sys/kernel/debug/llkd_miscdrv`. |
| `debugfs_create_file()` | Creates the debugfs `status` file. |
| `debugfs_remove_recursive()` | Removes the debugfs directory and files. |
| `struct file_operations` | Debugfs files still use normal file operations. |
| `single_open()` / `seq_read()` | Same simple rich-read pattern as procfs status. |
| `seq_puts()` / `seq_printf()` | Prints rich multi-line debug text. |

Do not put required userspace ABI in debugfs. Treat it as optional debug output.

## Locking

`ctx->lock` protects shared mutable state:

- `tx`
- `rx`
- `config`
- `oursecret`
- `secret_len`

The mutex is used because multiple processes can access the driver at the same
time through different paths:

```text
process A: echo hello > /dev/llkd_miscdrv
process B: cat /sys/class/misc/llkd_miscdrv/secret_len
process C: cat /sys/kernel/debug/llkd_miscdrv/status
```

Without locking, a reader could observe partially updated state.

## Logging

The driver uses device-scoped logging once `ctx->dev` exists:

| API | Role |
|---|---|
| `dev_info()` | Normal lifecycle and access logs. |
| `dev_warn()` | Recoverable warnings such as invalid size or copy failure. |
| `pr_fmt()` | Prefix format for `pr_*()` logs if they are added later. |

Useful dmesg checks:

```sh
dmesg | grep llkd_miscdrv
```

## Build and Run

Build against the repository's kernel output tree:

```sh
make -C shared/miscdriver
```

Boot QEMU, mount the host share, and load the driver:

```sh
sh /mnt/host/miscdriver/w.sh
```

Manual checks inside QEMU:

```sh
echo "hello driver" > /dev/llkd_miscdrv
cat /dev/llkd_miscdrv

cat /sys/class/misc/llkd_miscdrv/config
echo 42 > /sys/class/misc/llkd_miscdrv/config
cat /sys/class/misc/llkd_miscdrv/config
cat /sys/class/misc/llkd_miscdrv/tx
cat /sys/class/misc/llkd_miscdrv/rx
cat /sys/class/misc/llkd_miscdrv/secret_len

cat /proc/llkd_miscdrv/status
echo 99 > /proc/llkd_miscdrv/config
cat /proc/llkd_miscdrv/config

mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
cat /sys/kernel/debug/llkd_miscdrv/status
```

Unload explicitly when finished:

```sh
rmmod llkd_miscdrv
```

## Current Scope

This remains a teaching driver. Current limitations are intentional:

- one global `ctx`, so only one device instance is supported;
- one shared stored string, not per-open state;
- no ioctl interface;
- no poll/select support;
- no binary protocol;
- no UAPI header for `MAXBYTES`;
- world-readable/writable `/dev` mode for convenience; and
- debugfs exposes internal state and should not be treated as stable ABI.
