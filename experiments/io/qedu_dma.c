// SPDX-License-Identifier: GPL-2.0
#include <linux/dma-mapping.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/delay.h>
#include <linux/string.h>

#include "qedu.h"
#include "qedu_trace.h"

/*
 * qedu_dma_init() prepares the device for DMA in three steps:
 *
 *   select a 32-bit DMA mask -> enable PCI bus mastering
 *                            -> allocate one 4096-byte coherent buffer
 *
 * dma_alloc_coherent() allocates a buffer backed by guest RAM and returns two addresses for that same RAM:
 *
 *   qdev->dma_cpu_addr       CPU/kernel virtual address
 *   qdev->dma_addr           device DMA/bus address
 *
 * The CPU uses dma_cpu_addr and the device uses dma_addr. Neither address refers to memory inside QEMU EDU.
 * QEDU_DMA_DEV_BUF names that separate device-internal buffer.
 *
 * A DMA transfer moves bytes between these two buffers:
 *   coherent buffer in guest RAM <-> QEDU_DMA_DEV_BUF inside the EDU device
 *
 * dma_cpu_addr and dma_addr belong to different address spaces and must not be used in place of each other.
 *
 * "Coherent" means CPU and device writes remain mutually visible without explicit cache maintenance.
 * It does not serialize CPU threads, so the character-device path still uses qdev->lock around the shared buffer.
 *
 * A transfer is submitted by writing source, destination, byte count, and command registers.
 * Runtime transfers request an IRQ. The hardirq handler acknowledges the
 * device and queues the appropriate DMA work item; the worker advances or completes the transfer.
 */

/*
 * DMA bottom half. It runs in qedu_dma's kworker process context, so the
 * hardirq only performs the time-critical acknowledge-and-queue handoff.
 *
 *   first IRQ  -> worker clears RAM and starts EDU -> RAM
 *   second IRQ -> worker records completion and wakes the writer
 *
 * The first worker deliberately sleeps for 20 ms before advancing DMA. This
 * is teaching code: workqueues run in schedulable process context, so a worker
 * may sleep. A hardirq, softirq, or tasklet callback cannot.
 */
static void qedu_dma_advance_work(struct work_struct *work)
{
	struct qedu_dev *qdev = container_of(work, struct qedu_dev, dma_advance_work);
	const char *device = pci_name(qdev->pdev);
	u64 io_id = READ_ONCE(qdev->active_io_id);
	int old_stage;

	old_stage = atomic_cmpxchg(&qdev->dma_stage, QEDU_DMA_TO_DEVICE,
							   QEDU_DMA_FROM_DEVICE);
	if (old_stage != QEDU_DMA_TO_DEVICE)
		return;

	Trace_qedu_dma_stage(device, io_id, old_stage, QEDU_DMA_FROM_DEVICE,
						 QEDU_STAGE_ADVANCE_WORK);
	pr_info("qedu: DMA worker sleeping before deferred processing\n");
	msleep(20);

	memset(qdev->dma_cpu_addr, 0, qdev->dma_len);
	Trace_qedu_cpu_buffer_io(device, io_id,
							 QEDU_BUFFER_CLEAR_FOR_DMA_RETURN, 0,
							 qdev->dma_len, qdev->dma_len);

	pr_info("qedu: DMA worker starting EDU -> RAM, bytes=%zu\n", qdev->dma_len);
	writeq(QEDU_DMA_DEV_BUF, qdev->bar0 + QEDU_REG_DMA_SRC);
	writeq(qdev->dma_addr, qdev->bar0 + QEDU_REG_DMA_DST);
	writeq(qdev->dma_len, qdev->bar0 + QEDU_REG_DMA_CNT);
	writeq(QEDU_DMA_CMD_START | QEDU_DMA_CMD_DIR | QEDU_DMA_CMD_IRQ,
		   qdev->bar0 + QEDU_REG_DMA_CMD);
	Trace_qedu_dma_submit(device, io_id, 1, QEDU_DMA_DIR_FROM_DEVICE,
						  QEDU_ADDR_EDU_LOCAL, QEDU_DMA_DEV_BUF,
						  QEDU_ADDR_DMA, (u64)qdev->dma_addr,
						  qdev->dma_len,
						  QEDU_DMA_CMD_START | QEDU_DMA_CMD_DIR |
							  QEDU_DMA_CMD_IRQ);
}

static void qedu_dma_finish_work(struct work_struct *work)
{
	struct qedu_dev *qdev = container_of(work, struct qedu_dev, dma_finish_work);
	const char *device = pci_name(qdev->pdev);
	u64 io_id = READ_ONCE(qdev->active_io_id);
	unsigned long bits_before;
	int old_stage;

	old_stage = atomic_cmpxchg(&qdev->dma_stage, QEDU_DMA_FROM_DEVICE,
							   QEDU_DMA_IDLE);
	if (old_stage != QEDU_DMA_FROM_DEVICE)
		return;

	Trace_qedu_dma_stage(device, io_id, old_stage, QEDU_DMA_IDLE,
						 QEDU_STAGE_FINISH_WORK);
	bits_before = READ_ONCE(qdev->completed_events);
	set_bit(QEDU_EVENT_DMA, &qdev->completed_events);
	Trace_qedu_completion_publish(device, io_id, QEDU_ENGINE_DMA,
								  QEDU_EVENT_DMA, bits_before,
								  READ_ONCE(qdev->completed_events));
	wake_up_interruptible(&qdev->job_wait);
	pr_info("qedu: DMA worker completed echo\n");
}

/* Called by the hardirq top half after it acknowledges a DMA completion. */
void qedu_dma_irq_complete(struct qedu_dev *qdev)
{
	const char *device = pci_name(qdev->pdev);
	struct work_struct *work = NULL;
	enum qedu_dma_work_kind work_kind = QEDU_WORK_NONE;
	u64 io_id = READ_ONCE(qdev->active_io_id);
	bool queued;
	int stage = atomic_read(&qdev->dma_stage);

	if (!qdev->dma_wq)
		return;

	if (stage == QEDU_DMA_TO_DEVICE)
	{
		work = &qdev->dma_advance_work;
		work_kind = QEDU_WORK_ADVANCE;
	}
	else if (stage == QEDU_DMA_FROM_DEVICE)
	{
		work = &qdev->dma_finish_work;
		work_kind = QEDU_WORK_FINISH;
	}
	else
	{
		return;
	}

	queued = queue_work(qdev->dma_wq, work);
	Trace_qedu_dma_work_queue(device, io_id, stage, work_kind,
							  (unsigned long)work, queued);
}

/* Verify the DMA engine at startup by polling one small RAM-to-EDU transfer. */
int qedu_dma_smoke_test(struct qedu_dev *qdev)
{
	static const u8 pattern[] = {0x11, 0x22, 0x33, 0x44};
	u64 dma_cmd;
	int ret;

	memcpy(qdev->dma_cpu_addr, pattern, sizeof(pattern));

	writeq(qdev->dma_addr, qdev->bar0 + QEDU_REG_DMA_SRC);
	writeq(QEDU_DMA_DEV_BUF, qdev->bar0 + QEDU_REG_DMA_DST);
	writeq(sizeof(pattern), qdev->bar0 + QEDU_REG_DMA_CNT);
	writeq(QEDU_DMA_CMD_START, qdev->bar0 + QEDU_REG_DMA_CMD);

	ret = readq_poll_timeout(qdev->bar0 + QEDU_REG_DMA_CMD, dma_cmd,
							 !(dma_cmd & QEDU_DMA_CMD_START),
							 10, 1000000);
	if (ret)
	{
		pr_err("qedu: DMA smoke test timed out\n");
		return ret;
	}

	pr_info("qedu: DMA smoke test completed\n");
	return 0;
}

/*
 * Echo the userspace data through the device in two DMA transfers:
 *
 *   copy_from_user() fills dma_cpu_addr
 *     -> DMA from guest RAM to the EDU internal buffer
 *       -> hardirq queues qedu_dma_advance_work
 *         -> worker clears RAM and starts EDU -> RAM
 *           -> second hardirq queues qedu_dma_finish_work
 *             -> worker records completion and wakes the writer
 *               -> qedu_read() returns the restored bytes
 *
 * The old final-completion bit is cleared before submission. Userspace waits
 * once while the two IRQ/worker pairs advance the internal DMA stage machine.
 *
 * wait_event_interruptible_timeout() returns a negative error for a signal, zero for a timeout, and a positive value when the completion bit becomes true.
 * The caller receives signal and timeout failures unchanged.
 */
int qedu_dma_echo_job(struct qedu_dev *qdev, size_t len, u64 io_id)
{
	const char *device = pci_name(qdev->pdev);
	long wait_ret;
	int old_stage;

	pr_info("qedu: DMA RAM -> EDU started, bytes=%zu\n", len);
	WRITE_ONCE(qdev->active_engine, QEDU_ENGINE_DMA);
	clear_bit(QEDU_EVENT_DMA, &qdev->completed_events);
	qdev->dma_len = len;
	old_stage = atomic_xchg(&qdev->dma_stage, QEDU_DMA_TO_DEVICE);
	Trace_qedu_dma_stage(device, io_id, old_stage, QEDU_DMA_TO_DEVICE,
						 QEDU_STAGE_SUBMIT);

	writeq(qdev->dma_addr, qdev->bar0 + QEDU_REG_DMA_SRC);
	writeq(QEDU_DMA_DEV_BUF, qdev->bar0 + QEDU_REG_DMA_DST);
	writeq(len, qdev->bar0 + QEDU_REG_DMA_CNT);
	writeq(QEDU_DMA_CMD_START | QEDU_DMA_CMD_IRQ,
		   qdev->bar0 + QEDU_REG_DMA_CMD);
	Trace_qedu_dma_submit(device, io_id, 0, QEDU_DMA_DIR_TO_DEVICE,
						  QEDU_ADDR_DMA, (u64)qdev->dma_addr,
						  QEDU_ADDR_EDU_LOCAL, QEDU_DMA_DEV_BUF, len,
						  QEDU_DMA_CMD_START | QEDU_DMA_CMD_IRQ);

	Trace_qedu_wait(device, io_id, QEDU_ENGINE_DMA, QEDU_WAIT_BEGIN,
					qdev->timeout_ms, 0, READ_ONCE(qdev->completed_events));
	wait_ret = wait_event_interruptible_timeout(
		qdev->job_wait,
		test_bit(QEDU_EVENT_DMA, &qdev->completed_events),
		msecs_to_jiffies(qdev->timeout_ms));
	Trace_qedu_wait(device, io_id, QEDU_ENGINE_DMA, QEDU_WAIT_END,
					qdev->timeout_ms, wait_ret,
					READ_ONCE(qdev->completed_events));

	if (wait_ret < 0)
	{
		old_stage = atomic_xchg(&qdev->dma_stage, QEDU_DMA_IDLE);
		Trace_qedu_dma_stage(device, io_id, old_stage, QEDU_DMA_IDLE,
							 QEDU_STAGE_SIGNAL);
		cancel_work_sync(&qdev->dma_advance_work);
		cancel_work_sync(&qdev->dma_finish_work);
		return wait_ret;
	}

	if (wait_ret == 0)
	{
		old_stage = atomic_xchg(&qdev->dma_stage, QEDU_DMA_IDLE);
		Trace_qedu_dma_stage(device, io_id, old_stage, QEDU_DMA_IDLE,
							 QEDU_STAGE_TIMEOUT);
		cancel_work_sync(&qdev->dma_advance_work);
		cancel_work_sync(&qdev->dma_finish_work);
		pr_err("qedu: DMA echo timed out\n");
		return -ETIMEDOUT;
	}

	pr_info("qedu: DMA echo completed by worker\n");
	return 0;
}

/* Set the DMA addressing limit, enable bus mastering, and allocate the buffer. */
int qedu_dma_init(struct qedu_dev *qdev)
{
	struct pci_dev *pdev = qdev->pdev;
	int ret;

	ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
	if (ret)
	{
		pr_err("qedu: 32-bit DMA not supported\n");
		return ret;
	}
	Trace_qedu_probe_stage(pci_name(pdev), QEDU_DMA_MASK_CONFIGURED, "dma_set_mask_and_coherent",
						   "coherent_dma_mask", DMA_BIT_MASK(32), 32, 0);
	pr_info("qedu: 32-bit DMA supported\n");

	pci_set_master(pdev);
	Trace_qedu_probe_stage(pci_name(pdev), QEDU_BUS_MASTER_ENABLED, "pci_set_master",
						   "pci_bus_master_bit", 0, 0, 0);

	qdev->dma_cpu_addr = dma_alloc_coherent(&pdev->dev, QEDU_DMA_SIZE, &qdev->dma_addr, GFP_KERNEL);
	if (!qdev->dma_cpu_addr)
	{
		pr_err("qedu: dma_alloc_coherent failed\n");
		pci_clear_master(pdev);
		return -ENOMEM;
	}

	Trace_qedu_probe_stage(pci_name(pdev), QEDU_DMA_BUFFER_READY, "dma_alloc_coherent",
						   "coherent_dma_buffer", (u64)qdev->dma_addr,
						   QEDU_DMA_SIZE, 0);

	INIT_WORK(&qdev->dma_advance_work, qedu_dma_advance_work);
	INIT_WORK(&qdev->dma_finish_work, qedu_dma_finish_work);
	atomic_set(&qdev->dma_stage, QEDU_DMA_IDLE);
	qdev->dma_wq = alloc_ordered_workqueue("qedu_dma", WQ_MEM_RECLAIM);
	if (!qdev->dma_wq)
	{
		dma_free_coherent(&pdev->dev, QEDU_DMA_SIZE, qdev->dma_cpu_addr, qdev->dma_addr);
		qdev->dma_cpu_addr = NULL;
		pci_clear_master(pdev);
		return -ENOMEM;
	}

	Trace_qedu_probe_stage(pci_name(pdev), QEDU_WORKQUEUE_READY, "alloc_ordered_workqueue",
						   "qedu_dma_ordered_workqueue",
						   (unsigned long)qdev->dma_wq, 0, 0);
	pr_info("qedu: DMA buffer allocated\n");
	pr_info("qedu: CPU address = %px\n", qdev->dma_cpu_addr);
	pr_info("qedu: DMA address = %pad\n", &qdev->dma_addr);

	return 0;
}

/* Release the coherent buffer, then stop the PCI function from bus mastering. */
void qedu_dma_exit(struct qedu_dev *qdev)
{
	atomic_set(&qdev->dma_stage, QEDU_DMA_IDLE);
	if (qdev->dma_wq)
	{
		cancel_work_sync(&qdev->dma_advance_work);
		cancel_work_sync(&qdev->dma_finish_work);
		destroy_workqueue(qdev->dma_wq);
		qdev->dma_wq = NULL;
	}

	if (qdev->dma_cpu_addr)
	{
		dma_free_coherent(&qdev->pdev->dev, QEDU_DMA_SIZE, qdev->dma_cpu_addr, qdev->dma_addr);
		qdev->dma_cpu_addr = NULL;
		qdev->dma_addr = 0;
		qdev->result_size = 0;
		pr_info("qedu: DMA buffer freed\n");
	}

	pci_clear_master(qdev->pdev);
}
