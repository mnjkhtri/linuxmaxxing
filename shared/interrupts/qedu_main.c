// SPDX-License-Identifier: GPL-2.0
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/slab.h>

#include "qedu.h"

static bool selftest;
module_param(selftest, bool, 0444);
MODULE_PARM_DESC(selftest, "Run probe-time MMIO, IRQ, and DMA self-tests");

/*
 * QEDU is an educational PCI driver for QEMU's EDU device (1234:11e8). One qedu.ko is linked from focused implementation units:
 *
 *   qedu_main.c    PCI binding, BAR ownership, probe/remove, and self-tests
 *   qedu_chrdev.c  /dev/qedu registration and file operations
 *   qedu_irq.c     shared IRQ acknowledgement and completion wakeups
 *   qedu_dma.c     coherent DMA allocation and IRQ-driven echo jobs
 *   qedu_sysfs.c   one-value configuration and statistics attributes
 *   qedu_debugfs.c developer-only multi-line diagnostic state
 *   qedu.h         private state, register definitions, and declarations
 *
 * Together they demonstrate PCI discovery and resource ownership, BAR MMIO, shared interrupts, coherent DMA, wait queues, a misc character device, and reverse-order cleanup.
 *
 * Build from the repository root:
 *   make -C shared/interrupts
 *
 * After booting the repository's QEMU guest, load and inspect it with:
 *
 *   sh /mnt/host/interrupts/run.sh
 *   ls -l /dev/qedu
 *   echo 10 > /dev/qedu
 *   cat /dev/qedu
 *   echo kernel-driver > /dev/qedu
 *   cat /dev/qedu
 *
 * run.sh leaves the module loaded so its interfaces remain inspectable. Use "rmmod qedu" when finished.
 *
 * The complete userspace data path is:
 *
 *   echo 10 > /dev/qedu       echo hello > /dev/qedu
 *            |                         |
 *            +-------- write(2) -------+
 *                         |
 *                    qedu_write()
 *                    |-- integer --> factorial engine
 *                    `-- bytes ----> DMA RAM -> EDU -> RAM
 *                         |
 *                 dma_cpu_addr + result_size
 *                         |
 *                    qedu_read()
 *                         |
 *                   cat /dev/qedu
 *
 */

/* Startup register self-test. */
static int qedu_test_registers(struct qedu_dev *qdev)
{
	u32 device_id;
	u32 live;
	u32 status;
	u32 fact;
	int ret;

	device_id = ioread32(qdev->bar0 + QEDU_REG_ID);
	pr_info("qedu: ID register = 0x%08x\n", device_id);

	iowrite32(0xdeadbeef, qdev->bar0 + QEDU_REG_LIVENESS);
	live = ioread32(qdev->bar0 + QEDU_REG_LIVENESS);
	pr_info("qedu: liveness readback = 0x%08x\n", live);

	iowrite32(10, qdev->bar0 + QEDU_REG_FACTORIAL);
	ret = readl_poll_timeout(qdev->bar0 + QEDU_REG_STATUS, status, !(status & QEDU_STATUS_FACTORIAL_BUSY), 10, 1000000);
	if (ret)
	{
		pr_err("qedu: factorial operation timed out\n");
		return ret;
	}

	fact = ioread32(qdev->bar0 + QEDU_REG_FACTORIAL);
	pr_info("qedu: factorial result = %u\n", fact);

	return 0;
}

/*
 * Run an integer job after qedu_write() has parsed the complete input:
 *
 *   clear stale factorial event
 *     -> enable factorial completion interrupts
 *       -> write the factorial input register
 *         -> sleep until the IRQ handler records completion
 *           -> read the result register
 *
 * qedu_write() then formats this 32-bit value as decimal text in dma_cpu_addr.
 */
int qedu_factorial_job(struct qedu_dev *qdev, u32 input, u32 *result)
{
	long wait_ret;

	pr_info("qedu: factorial job started, input=%u\n", input);

	clear_bit(QEDU_EVENT_FACTORIAL, &qdev->completed_events);
	iowrite32(QEDU_STATUS_FACTORIAL_IRQ_ENABLE, qdev->bar0 + QEDU_REG_STATUS);
	iowrite32(input, qdev->bar0 + QEDU_REG_FACTORIAL);

	wait_ret = wait_event_interruptible_timeout(
		qdev->job_wait,
		test_bit(QEDU_EVENT_FACTORIAL, &qdev->completed_events),
		msecs_to_jiffies(qdev->timeout_ms));

	if (wait_ret < 0)
		return wait_ret;

	if (wait_ret == 0)
	{
		pr_err("qedu: factorial job timed out\n");
		return -ETIMEDOUT;
	}

	*result = ioread32(qdev->bar0 + QEDU_REG_FACTORIAL);
	return 0;
}

/*
 * When selftest=1, identification/liveness MMIO and the factorial engine are
 * checked by polling. A software-raised IRQ then checks the registered handler,
 * and a one-way RAM-to-EDU transfer checks DMA. Normal module loads skip this
 * extra device activity so workload traces contain only the requested jobs.
 */
static int qedu_selftest(struct qedu_dev *qdev)
{
	int ret;

	pr_info("qedu: startup self-tests begin\n");

	ret = qedu_test_registers(qdev);
	if (ret)
		return ret;

	qedu_raise_test_irq(qdev);

	ret = qedu_dma_smoke_test(qdev);
	if (ret)
		return ret;

	pr_info("qedu: startup self-tests passed\n");
	return 0;
}

/*
 * Initialize the PCI resources used by this qedu_dev. Its job is to enable the PCI device, claim its BAR regions, inspect BAR0, and map BAR0 into the kernel virtual address space.
 *
 * Those steps happen in dependency order:
 *
 *   pci_enable_device() -> pci_request_regions() -> pci_iomap(BAR0)
 *
 * qdev->bar0 is a kernel virtual mapping of device memory, not ordinary RAM.
 * Register accesses must therefore use ioread32(), iowrite32(), readq(), and writeq() rather than direct pointer dereferences.
 * qedu_pci_exit() reverses this ownership by unmapping BAR0, releasing the regions, and disabling the function.
 */
static int qedu_pci_init(struct qedu_dev *qdev)
{
	struct pci_dev *pdev = qdev->pdev;
	resource_size_t bar0_start;
	resource_size_t bar0_len;
	int ret;

	ret = pci_enable_device(pdev);
	if (ret)
	{
		pr_err("qedu: failed to enable PCI device: %d\n", ret);
		return ret;
	}

	ret = pci_request_regions(pdev, "qedu");
	if (ret)
	{
		pr_err("qedu: pci_request_regions failed: %d\n", ret);
		goto err_disable;
	}

	bar0_start = pci_resource_start(pdev, 0);
	bar0_len = pci_resource_len(pdev, 0);
	pr_info("qedu: BAR0 start=%pa len=%pa\n", &bar0_start, &bar0_len);

	qdev->bar0 = pci_iomap(pdev, 0, 0);
	if (!qdev->bar0)
	{
		ret = -ENOMEM;
		pr_err("qedu: failed to map BAR0\n");
		goto err_regions;
	}

	pr_info("qedu: BAR0 mapped at %px\n", qdev->bar0);
	return 0;

err_regions:
	pci_release_regions(pdev);
err_disable:
	pci_disable_device(pdev);
	return ret;
}

static void qedu_pci_exit(struct qedu_dev *qdev)
{
	struct pci_dev *pdev = qdev->pdev;

	pci_iounmap(pdev, qdev->bar0);
	qdev->bar0 = NULL;
	pci_release_regions(pdev);
	pci_disable_device(pdev);
	pr_info("qedu: BAR0 unmapped, PCI regions released, device disabled\n");
}

/*
 * Allocate one private object for each successfully probed PCI function:
 *
 *   struct pci_dev
 *       `-- driver_data ----------> struct qedu_dev
 *                                      |-- BAR0 mapping
 *                                      |-- coherent DMA buffer + DMA address
 *                                      |-- result size and mutex
 *                                      |-- wait queue + completion bits
 *                                      `-- miscdevice (/dev/qedu)
 *
 * pci_set_drvdata() establishes this ownership link; remove recovers it with pci_get_drvdata().
 * The misc core reaches the same object through its embedded miscdevice, as documented beside qedu_open().
 */
static int qedu_alloc_device(struct pci_dev *pdev, struct qedu_dev **out)
{
	struct qedu_dev *qdev;

	qdev = devm_kzalloc(&pdev->dev, sizeof(*qdev), GFP_KERNEL);
	if (!qdev)
		return -ENOMEM;

	qdev->pdev = pdev;
	mutex_init(&qdev->lock);
	init_waitqueue_head(&qdev->job_wait);
	qdev->completed_events = 0;
	qdev->result_size = 0;
	qdev->timeout_ms = QEDU_DEFAULT_TIMEOUT_MS;
	pci_set_drvdata(pdev, qdev);
	*out = qdev;
	return 0;
}

static void qedu_free_device(struct qedu_dev *qdev)
{
	pci_set_drvdata(qdev->pdev, NULL);
}

/*
 * Layers are initialized from their prerequisites upward:
 *
 *   qedu_alloc_device()
 *     -> qedu_pci_init()
 *       -> qedu_irq_init()
 *         -> qedu_dma_init()
 *           -> qedu_selftest() when selftest=1
 *             -> qedu_chrdev_init()
 *               -> qedu_debugfs_init()
 *
 * Remove performs the exact reverse sequence. Probe's error labels follow that same ordering and release only layers initialized before the failure.
 */
static int qedu_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct qedu_dev *qdev;
	int ret;

	ret = qedu_alloc_device(pdev, &qdev);
	if (ret)
		return ret;

	ret = qedu_pci_init(qdev);
	if (ret)
		goto err_free;

	ret = qedu_irq_init(qdev);
	if (ret)
		goto err_pci;

	ret = qedu_dma_init(qdev);
	if (ret)
		goto err_irq;

	if (selftest)
	{
		ret = qedu_selftest(qdev);
		if (ret)
			goto err_irq_dma;
	}

	ret = qedu_chrdev_init(qdev);
	if (ret)
		goto err_irq_dma;

	qedu_debugfs_init(qdev);

	pr_info("qedu: probe completed; device is ready\n");
	return 0;

err_irq_dma:
	qedu_irq_exit(qdev);
	qedu_dma_exit(qdev);
	goto err_pci;
err_irq:
	qedu_irq_exit(qdev);
err_pci:
	qedu_pci_exit(qdev);
err_free:
	qedu_free_device(qdev);
	return ret;
}

static void qedu_remove(struct pci_dev *pdev)
{
	struct qedu_dev *qdev = pci_get_drvdata(pdev);

	pr_info("qedu: remove called\n");

	qedu_debugfs_exit(qdev);
	qedu_chrdev_exit(qdev);
	qedu_irq_exit(qdev);
	qedu_dma_exit(qdev);
	qedu_pci_exit(qdev);
	qedu_free_device(qdev);
}

static const struct pci_device_id qedu_ids[] = {
	{PCI_DEVICE(0x1234, 0x11e8)},
	{}};
MODULE_DEVICE_TABLE(pci, qedu_ids);

static struct pci_driver qedu_driver = {
	.name = "qedu",
	.id_table = qedu_ids,
	.probe = qedu_probe,
	.remove = qedu_remove,
};

module_pci_driver(qedu_driver);

MODULE_DESCRIPTION("QEMU EDU teaching PCI driver");
MODULE_LICENSE("GPL");
