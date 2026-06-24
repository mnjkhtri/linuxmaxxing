# QEMU EDU PCI Driver

`qedu.c` is an educational Linux PCI driver for QEMU's EDU device (`1234:11e8`).
It demonstrates the major pieces of a real device driver in a small environment:

- PCI discovery and resource ownership
- BAR0 MMIO access
- shared interrupt handling
- coherent DMA
- wait queues and interrupt-driven completion
- a `/dev/qedu` userspace interface
- layered initialization and reverse-order cleanup

## Topology

```text
Userspace
  echo 10 > /dev/qedu       echo hello > /dev/qedu
           |                       |
           +------ write(2) -------+
                       |
                       v
                 qedu_write()
                 |-- integer input --> factorial engine
                 `-- other bytes ----> DMA RAM -> EDU -> RAM
                       |
                       v
                 qdev->dma_buf
                 qdev->result_size
                       |
                       v
                 qedu_read()
                       |
                       v
                 cat /dev/qedu
```

Kernel-side ownership is centered on one private structure:

```text
struct pci_dev
    |
    +-- driver_data -------------> struct qedu_dev
                                      |-- BAR0 mapping
                                      |-- coherent DMA buffer
                                      |-- DMA address
                                      |-- result size
                                      |-- mutex
                                      |-- wait queue
                                      |-- completion bits
                                      +-- miscdevice (/dev/qedu)
```

The `pci_set_drvdata()` attaches `qedu_dev` to the PCI device. PCI callbacks later
recover it with `pci_get_drvdata()`. The misc framework instead starts with a
pointer to the embedded `miscdevice`; `qedu_open()` uses `container_of()` to
recover the enclosing `qedu_dev` and stores that pointer in `file->private_data`.

## Driver Layers

The probe path initializes dependencies from the bottom up:

```text
qedu_alloc_device()
    -> qedu_pci_init()
        -> qedu_irq_init()
            -> qedu_dma_init()
                -> qedu_selftest()
                    -> qedu_chrdev_init()
```

Removal performs the reverse sequence:

```text
qedu_chrdev_exit()
    -> qedu_dma_exit()
        -> qedu_irq_exit()
            -> qedu_pci_exit()
                -> qedu_free_device()
```

Probe error labels use the same reverse ordering. Each label releases only the
layers that were successfully initialized before the failure.

## PCI and BAR0

QEMU exposes one 1 MiB MMIO BAR. The driver:

1. enables the PCI function with `pci_enable_device()`;
2. claims its BARs with `pci_request_regions()`;
3. maps BAR0 with `pci_iomap()`; and
4. stores the resulting kernel virtual address in `qdev->bar0`.

BAR0 is device memory, not ordinary RAM. Register access therefore uses MMIO
helpers such as `ioread32()`, `iowrite32()`, `readq()`, and `writeq()`.

Important register groups are:

| Area | Offsets | Purpose |
|---|---:|---|
| Core | `0x00`-`0x20` | identification, liveness, factorial, status |
| IRQ | `0x24`, `0x60`, `0x64` | status, software raise, acknowledge |
| DMA | `0x80`-`0x98` | source, destination, count, command |
| EDU buffer | `0x40000` | internal 4 KiB DMA target/source |

## Interrupt Flow

The driver requests a shared IRQ with `IRQF_SHARED`. The top-half handler must
first determine whether EDU raised the interrupt:

```text
read IRQ status
    -> zero: return IRQ_NONE
    -> nonzero: acknowledge reported bits
                 set software completion bits
                 wake interruptible waiters
                 return IRQ_HANDLED
```

Two hardware completion sources matter to jobs:

- `QEDU_IRQ_FACTORIAL` records factorial completion;
- `QEDU_IRQ_DMA` records DMA completion.

The handler uses `set_bit()` because `completed_events` is shared with process
context. It then calls `wake_up_interruptible()` on `job_wait`. The interrupt
handler never takes the userspace mutex and never sleeps.

## Wait Queue and Event Bits

A wait queue manages sleeping tasks but does not remember that an event
occurred. `completed_events` stores that condition. Both are therefore needed.

A job follows this pattern:

```text
clear stale event bit
    -> submit command with IRQ enabled
        -> sleep in wait_event_interruptible_timeout()
            -> IRQ handler sets event bit and wakes queue
                -> condition becomes true and job resumes
```

The timeout prevents failed or missing hardware from blocking a process
forever. A signal can interrupt the sleep, which propagates an error back to
the userspace system call.

Startup self-tests intentionally remain polling examples. Runtime jobs use IRQ
completion so the calling process sleeps instead of repeatedly reading MMIO.

## DMA Model

`dma_alloc_coherent()` returns two addresses for the same allocation:

```text
qdev->dma_buf       CPU/kernel virtual address
qdev->dma_handle    device-visible DMA address
```

The CPU reads and writes `dma_buf`. EDU receives `dma_handle` in its DMA
registers. They are not interchangeable.

`qedu_dma_init()` also:

- requests a 32-bit coherent DMA mask;
- enables PCI bus mastering; and
- allocates one 4096-byte coherent buffer.

A non-integer userspace write performs a full echo round trip:

```text
userspace bytes
    -> copy_from_user() into dma_buf
    -> DMA: guest RAM to EDU internal buffer
    -> clear dma_buf
    -> DMA: EDU internal buffer to guest RAM
    -> expose returned bytes through qedu_read()
```

Both directions request DMA completion interrupts and wait independently. The
event bit is cleared before each command so the second transfer cannot consume
the first transfer's completion.

## Factorial Jobs

For an integer write, `qedu_write()`:

1. parses the complete input with `kstrtou32()`;
2. clears the stale factorial event bit;
3. enables factorial completion interrupts;
4. writes the input to the factorial register;
5. sleeps until the IRQ handler records completion; and
6. formats the result as decimal text in `dma_buf`.

Example:

```sh
echo 10 > /dev/qedu
cat /dev/qedu
# 3628800
```

The newline added by `echo` is accepted by the integer parser.

## DMA Echo Jobs

If the complete input is not an unsigned integer, the driver treats it as
bytes to echo through DMA:

```sh
echo hello > /dev/qedu
cat /dev/qedu
# hello
```

The newline produced by `echo` is part of the DMA payload. Writes must be
smaller than `QEDU_DMA_SIZE`; one byte is reserved temporarily for a NUL
terminator used during integer parsing.

## Read and Write Interface

The misc device creates `/dev/qedu` with these callbacks:

- `qedu_open()` converts misc-device private data into `qedu_dev`;
- `qedu_write()` submits one synchronous factorial or DMA job;
- `qedu_read()` returns the most recently completed result; and
- `qedu_release()` currently has no per-open resources to release.

`simple_read_from_buffer()` implements bounded copies, partial reads, file
offset advancement, and end-of-file behavior. The driver stores the number of
valid bytes in `result_size`.

## Locking

`qdev->lock` serializes userspace reads and writes that share:

- the coherent DMA/result buffer;
- `result_size`; and
- the device's single factorial and DMA engines.

The mutex may remain held while process context sleeps on the wait queue. This
is safe because the IRQ handler does not acquire the mutex; it only records an
event and wakes the sleeping task.

Coherent DMA solves CPU/device cache-coherency requirements. It does not
serialize multiple CPU threads, which is why the mutex is still necessary.

## Self-Tests

Before publishing `/dev/qedu`, probe runs small hardware checks:

- identification and liveness MMIO;
- factorial computation using polling;
- software-raised IRQ handling; and
- a one-way RAM-to-EDU DMA smoke test using polling.

These tests deliberately demonstrate polling while runtime jobs demonstrate
interrupt-driven completion.

## Build and Run

Build against the repository's Linux 6.6.30 output tree:

```sh
make -C shared/pci
```

Boot QEMU and load the module inside the guest:

```sh
sh /mnt/host/pci/w.sh
```

Check the interface:

```sh
ls -l /dev/qedu
echo 10 > /dev/qedu
cat /dev/qedu
echo kernel-driver > /dev/qedu
cat /dev/qedu
```

Unload explicitly when finished:

```sh
rmmod qedu
```

## Current Scope

This remains an educational driver. Notable limitations include:

- one fixed misc-device name, so multiple EDU devices would conflict;
- one shared result per device rather than per-open results;
- synchronous userspace jobs, although completion is interrupt-driven;
- no MSI/MSI-X setup; the driver uses the assigned shared IRQ;
- no cancellation protocol for hardware after a timeout; and
- factorial results are limited by the EDU register's 32-bit behavior.
