// SPDX-License-Identifier: GPL-2.0
#include <linux/interrupt.h>
#include <linux/io.h>

#include "qedu.h"

/*
 * QEMU EDU uses legacy INTx, which may share one Linux IRQ with other devices.
 * request_irq(..., IRQF_SHARED, ...) adds qedu to that IRQ's action chain:
 * the list of handlers Linux calls whenever the shared line is raised.
 * Each handler must check its own hardware to decide whether the IRQ is its.
 *
 * qedu_irq_handler() follows this flow:
 *
 *   read IRQ status
 *     -> zero:    qedu did not raise it, so return IRQ_NONE
 *     -> nonzero: acknowledge every reported source
 *                 record and wake factorial completion directly
 *                 queue DMA completion to the workqueue bottom half
 *                 return IRQ_HANDLED
 *
 * QEDU_IRQ_FACTORIAL and QEDU_IRQ_DMA are the two completion sources.
 * Factorial completion is recorded in completed_events with atomic set_bit().
 * DMA completion is handed to the worker, which records the final event.
 *
 * completed_events and job_wait have different jobs:
 *
 *   completed_events remembers which job is fully complete
 *   job_wait wakes sleeping tasks, but does not remember an event
 *
 * The direct factorial path therefore follows this sequence:
 *
 *   clear the old event bit
 *     -> submit an interrupt-enabled command
 *       -> wait_event_interruptible_timeout()
 *         -> this handler records the event and wakes job_wait
 *           -> the wait condition becomes true and the task continues
 *
 * This function runs as the hard-IRQ top half. It must not sleep or take
 * qdev->lock. Factorial stays as the minimal direct-wakeup example. DMA uses
 * qedu_dma_work so direction changes and final wakeup happen in process context.
 *
 * The timeout stops broken hardware from blocking a task forever. A signal
 * may interrupt the sleep; that error is returned to the userspace syscall.
 */

static irqreturn_t qedu_irq_handler(int irq, void *dev_id)
{
	struct qedu_dev *qdev = dev_id;
	u32 status;

	status = ioread32(qdev->bar0 + QEDU_REG_IRQ_STATUS);
	if (!status)
		return IRQ_NONE;

	iowrite32(status, qdev->bar0 + QEDU_REG_IRQ_ACK);

	if (status & QEDU_IRQ_FACTORIAL)
	{
		set_bit(QEDU_EVENT_FACTORIAL, &qdev->completed_events);
		wake_up_interruptible(&qdev->job_wait);
	}

	if (status & QEDU_IRQ_DMA)
		qedu_dma_irq_complete(qdev);

	pr_info("qedu: IRQ handled, status=0x%08x\n", status);
	return IRQ_HANDLED;
}

/* Ask the device to generate an interrupt without starting a real job. */
void qedu_raise_test_irq(struct qedu_dev *qdev)
{
	iowrite32(1, qdev->bar0 + QEDU_REG_IRQ_RAISE);
	pr_info("qedu: test IRQ raised\n");
}

/* Attach qedu's handler to the Linux IRQ assigned to this PCI device. */
int qedu_irq_init(struct qedu_dev *qdev)
{
	struct pci_dev *pdev = qdev->pdev;
	int ret;

	ret = request_irq(pdev->irq, qedu_irq_handler, IRQF_SHARED, "qedu", qdev);
	if (ret)
	{
		pr_err("qedu: request_irq failed: %d\n", ret);
		return ret;
	}

	pr_info("qedu: IRQ %d requested\n", pdev->irq);
	return 0;
}

/* Detach the same handler instance registered by qedu_irq_init(). */
void qedu_irq_exit(struct qedu_dev *qdev)
{
	free_irq(qdev->pdev->irq, qdev);
	pr_info("qedu: IRQ %d freed\n", qdev->pdev->irq);
}
