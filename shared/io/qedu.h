/* SPDX-License-Identifier: GPL-2.0 */
#ifndef QEDU_H
#define QEDU_H

#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

/*
 * Private hardware contract shared by all qedu translation units.
 *
 * QEMU EDU exposes these register groups through BAR0:
 *
 *   0x00-0x20  identification, liveness, factorial, and device status
 *   0x24/0x60/0x64  IRQ status, software raise, and acknowledgement
 *   0x80-0x98  DMA source, destination, byte count, and command
 *   0x40000     EDU's internal 4 KiB DMA target/source buffer
 *
 * Offsets name locations inside MMIO device memory; callers must use the kernel MMIO accessors rather than treating qdev->bar0 as normal RAM.
 */

/* Core MMIO registers. */
#define QEDU_REG_ID 0x00
#define QEDU_REG_LIVENESS 0x04
#define QEDU_REG_FACTORIAL 0x08
#define QEDU_REG_STATUS 0x20

/* Factorial engine status bits in QEDU_REG_STATUS. */
#define QEDU_STATUS_FACTORIAL_BUSY 0x01
#define QEDU_STATUS_FACTORIAL_IRQ_ENABLE 0x80

/* Interrupt MMIO registers and source bits in QEDU_REG_IRQ_STATUS. */
#define QEDU_REG_IRQ_STATUS 0x24
#define QEDU_REG_IRQ_RAISE 0x60
#define QEDU_REG_IRQ_ACK 0x64
#define QEDU_IRQ_FACTORIAL 0x01
#define QEDU_IRQ_DMA 0x100

/* DMA MMIO registers. */
#define QEDU_REG_DMA_SRC 0x80
#define QEDU_REG_DMA_DST 0x88
#define QEDU_REG_DMA_CNT 0x90
#define QEDU_REG_DMA_CMD 0x98

/* DMA memory layout and command bits. */
#define QEDU_DMA_DEV_BUF 0x40000
#define QEDU_DMA_SIZE 4096
#define QEDU_DMA_CMD_START 0x01
#define QEDU_DMA_CMD_DIR 0x02
#define QEDU_DMA_CMD_IRQ 0x04

#define QEDU_DEFAULT_TIMEOUT_MS 1000 /* Initial timeout for each hardware job. */
#define QEDU_MAX_TIMEOUT_MS 60000	 /* Largest timeout accepted through sysfs. */

enum qedu_completion_event
{
	QEDU_EVENT_FACTORIAL,
	QEDU_EVENT_DMA,
};

enum qedu_dma_stage
{
	QEDU_DMA_IDLE,
	QEDU_DMA_TO_DEVICE,
	QEDU_DMA_FROM_DEVICE,
};

/* Stable numeric values carried by qedu trace events. */
enum qedu_io_engine
{
	QEDU_ENGINE_NONE,
	QEDU_ENGINE_FACTORIAL,
	QEDU_ENGINE_DMA,
};

enum qedu_cpu_buffer_operation
{
	QEDU_BUFFER_COPY_FROM_USER,
	QEDU_BUFFER_CLEAR_FOR_DMA_RETURN,
	QEDU_BUFFER_COPY_TO_USER,
};

enum qedu_file_operation
{
	QEDU_FILE_OPEN,
	QEDU_FILE_READ,
	QEDU_FILE_WRITE,
	QEDU_FILE_RELEASE,
};

enum qedu_file_phase
{
	QEDU_FILE_ENTER,
	QEDU_FILE_EXIT,
};

enum qedu_dma_stage_reason
{
	QEDU_STAGE_SUBMIT,
	QEDU_STAGE_ADVANCE_WORK,
	QEDU_STAGE_FINISH_WORK,
	QEDU_STAGE_SIGNAL,
	QEDU_STAGE_TIMEOUT,
};

enum qedu_dma_direction
{
	QEDU_DMA_DIR_TO_DEVICE,
	QEDU_DMA_DIR_FROM_DEVICE,
};

enum qedu_dma_address_space
{
	QEDU_ADDR_DMA,
	QEDU_ADDR_EDU_LOCAL,
};

enum qedu_dma_work_kind
{
	QEDU_WORK_NONE,
	QEDU_WORK_ADVANCE,
	QEDU_WORK_FINISH,
};

enum qedu_wait_phase
{
	QEDU_WAIT_BEGIN,
	QEDU_WAIT_END,
};

enum qedu_probe_stage
{
	QEDU_PROBE_BEGIN,
	QEDU_DEVICE_STATE_READY,
	QEDU_PCI_ENABLED,
	QEDU_BAR_REGIONS_CLAIMED,
	QEDU_BAR0_MAPPED,
	QEDU_IRQ_REGISTERED,
	QEDU_DMA_MASK_CONFIGURED,
	QEDU_BUS_MASTER_ENABLED,
	QEDU_DMA_BUFFER_READY,
	QEDU_WORKQUEUE_READY,
	QEDU_CHARDEV_PUBLISHED,
	QEDU_SYSFS_PUBLISHED,
	QEDU_DEBUGFS_PUBLISHED,
	QEDU_PROBE_READY,
};

/*
 * Per-device state shared by the PCI, character-device, IRQ, DMA, sysfs, and debugfs layers.
 */

struct attribute_group;
struct dentry;

struct qedu_dev
{
	struct pci_dev *pdev;				 /* Bound PCI function. */
	void __iomem *bar0;					 /* Kernel mapping of BAR0 MMIO. */
	void *dma_cpu_addr;					 /* CPU virtual address of the coherent guest-RAM buffer. */
	dma_addr_t dma_addr;				 /* Device DMA address of the same guest-RAM buffer. */
	size_t result_size;					 /* Valid bytes currently available to read(). */
	int tx;								 /* Bytes returned to userspace. */
	int rx;								 /* Bytes accepted from userspace. */
	unsigned int timeout_ms;			 /* Hardware completion wait timeout. */
	struct mutex lock;					 /* Serializes jobs and shared result state. */
	wait_queue_head_t job_wait;			 /* Waiters sleeping for completion IRQs. */
	unsigned long completed_events;		 /* Completion bits set by the IRQ handler. */
	struct workqueue_struct *dma_wq;	 /* Dedicated process-context bottom half for DMA completion. */
	struct work_struct dma_advance_work; /* First IRQ: start the return transfer. */
	struct work_struct dma_finish_work;	 /* Second IRQ: complete the echo and wake userspace. */
	atomic_t dma_stage;					 /* Current direction in the two-IRQ DMA echo state machine. */
	size_t dma_len;						 /* Byte count reused when the worker starts the return transfer. */
	atomic64_t next_io_id;				 /* Instrumentation sequence assigned to each write(2). */
	u64 active_io_id;					 /* Operation currently allowed to reach the IRQ handler. */
	u64 result_io_id;					 /* Operation that produced the readable result buffer. */
	enum qedu_io_engine active_engine;	 /* Hardware engine expected by the shared IRQ handler. */
	struct miscdevice miscdev;			 /* /dev/qedu and sysfs registration. */
	struct dentry *debugfs_dir;			 /* /sys/kernel/debug/qedu root. */
};

int qedu_chrdev_init(struct qedu_dev *qdev);
void qedu_chrdev_exit(struct qedu_dev *qdev);

const struct attribute_group **qedu_sysfs_groups(void);
void qedu_debugfs_init(struct qedu_dev *qdev);
void qedu_debugfs_exit(struct qedu_dev *qdev);

int qedu_irq_init(struct qedu_dev *qdev);
void qedu_irq_exit(struct qedu_dev *qdev);
void qedu_raise_test_irq(struct qedu_dev *qdev);

int qedu_dma_init(struct qedu_dev *qdev);
void qedu_dma_exit(struct qedu_dev *qdev);
int qedu_dma_smoke_test(struct qedu_dev *qdev);
int qedu_dma_echo_job(struct qedu_dev *qdev, size_t len, u64 io_id);
void qedu_dma_irq_complete(struct qedu_dev *qdev);

int qedu_factorial_job(struct qedu_dev *qdev, u32 input, u32 *result, u64 io_id);

#endif /* QEDU_H */
