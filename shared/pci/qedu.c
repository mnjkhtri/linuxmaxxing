#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/dma-mapping.h>
#include <linux/iopoll.h>

/* Core MMIO registers. */
#define QEDU_REG_ID        0x00  /* Read-only EDU identification register. */
#define QEDU_REG_LIVENESS  0x04  /* Read/write liveness inversion register. */
#define QEDU_REG_FACTORIAL 0x08  /* Factorial input and result register. */
#define QEDU_REG_STATUS    0x20  /* Factorial busy and IRQ-enable status. */

/* Interrupt MMIO registers and source values. */
#define QEDU_REG_IRQ_STATUS 0x24  /* Pending interrupt-source bits. */
#define QEDU_REG_IRQ_RAISE  0x60  /* Software interrupt-raise register. */
#define QEDU_REG_IRQ_ACK    0x64  /* Interrupt acknowledgement register. */
#define QEDU_IRQ_FACTORIAL  0x80  /* Factorial-completion IRQ source. */
#define QEDU_IRQ_DMA       0x100  /* DMA-completion IRQ source. */

/* DMA MMIO registers. */
#define QEDU_REG_DMA_SRC 0x80  /* 64-bit DMA source address. */
#define QEDU_REG_DMA_DST 0x88  /* 64-bit DMA destination address. */
#define QEDU_REG_DMA_CNT 0x90  /* 64-bit DMA byte count. */
#define QEDU_REG_DMA_CMD 0x98  /* 64-bit DMA command and status. */

/* DMA memory layout and command bits. */
#define QEDU_DMA_DEV_BUF   0x40000  /* EDU internal 4 KiB DMA buffer. */
#define QEDU_DMA_SIZE         4096  /* Host coherent DMA buffer size. */
#define QEDU_DMA_CMD_START    0x01  /* Start DMA transfer. */
#define QEDU_DMA_CMD_DIR      0x02  /* Direction: EDU to RAM when set. */
#define QEDU_DMA_CMD_IRQ      0x04  /* Raise IRQ when DMA completes. */

/* Software completion-bit indexes stored in completed_events. */
enum qedu_completion_event {
    QEDU_EVENT_FACTORIAL,  /* Factorial completion bit index. */
    QEDU_EVENT_DMA,        /* DMA completion bit index. */
};

struct qedu_dev {
    struct pci_dev *pdev;              /* PCI device owning this state. */
    void __iomem *bar0;                /* Kernel mapping of BAR0 MMIO. */
    void *dma_buf;                     /* CPU address of DMA/result buffer. */
    dma_addr_t dma_handle;             /* Device-visible DMA address. */
    size_t result_size;                /* Valid result bytes in dma_buf. */
    struct mutex lock;                 /* Serializes jobs and buffer access. */
    wait_queue_head_t job_wait;        /* Sleep queue for completion IRQs. */
    unsigned long completed_events;    /* Completion bits set by IRQ handler. */
    struct miscdevice miscdev;         /* Descriptor for /dev/qedu. */
};

static irqreturn_t qedu_irq_handler(int irq, void *dev_id)
{
    struct qedu_dev *qdev = dev_id;
    u32 status;

    status = ioread32(qdev->bar0 + QEDU_REG_IRQ_STATUS);
    if (!status)
        return IRQ_NONE;

    /* Acknowledge every source reported by this EDU device. */
    iowrite32(status, qdev->bar0 + QEDU_REG_IRQ_ACK);

    if (status & QEDU_IRQ_FACTORIAL)
        set_bit(QEDU_EVENT_FACTORIAL, &qdev->completed_events);

    if (status & QEDU_IRQ_DMA)
        set_bit(QEDU_EVENT_DMA, &qdev->completed_events);

    /* Wake job code only for hardware-completion interrupts. */
    if (status & (QEDU_IRQ_FACTORIAL | QEDU_IRQ_DMA))
        wake_up_interruptible(&qdev->job_wait);

    pr_info("qedu: IRQ handled, status=0x%08x\n", status);
    return IRQ_HANDLED;
}

/* Startup hardware self-tests. */
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
    ret = readl_poll_timeout(qdev->bar0 + QEDU_REG_STATUS, status,
                             !(status & 0x1), 10, 1000000);
    if (ret) {
        pr_err("qedu: factorial operation timed out\n");
        return ret;
    }

    fact = ioread32(qdev->bar0 + QEDU_REG_FACTORIAL);
    pr_info("qedu: factorial result = %u\n", fact);

    return 0;
}

static void qedu_raise_test_irq(struct qedu_dev *qdev)
{
    iowrite32(1, qdev->bar0 + QEDU_REG_IRQ_RAISE);
    pr_info("qedu: test IRQ raised\n");
}

/* Submit a small one-way DMA transfer to verify that DMA can start and finish. */
static int qedu_dma_smoke_test(struct qedu_dev *qdev)
{
    static const u8 pattern[] = { 0x11, 0x22, 0x33, 0x44 };
    u64 dma_cmd;
    int ret;

    memcpy(qdev->dma_buf, pattern, sizeof(pattern));

    writeq(qdev->dma_handle, qdev->bar0 + QEDU_REG_DMA_SRC);
    writeq(QEDU_DMA_DEV_BUF, qdev->bar0 + QEDU_REG_DMA_DST);
    writeq(sizeof(pattern), qdev->bar0 + QEDU_REG_DMA_CNT);
    writeq(QEDU_DMA_CMD_START, qdev->bar0 + QEDU_REG_DMA_CMD);

    ret = readq_poll_timeout(qdev->bar0 + QEDU_REG_DMA_CMD, dma_cmd,
                             !(dma_cmd & QEDU_DMA_CMD_START),
                             10, 1000000);
    if (ret) {
        pr_err("qedu: DMA smoke test timed out\n");
        return ret;
    }

    pr_info("qedu: DMA smoke test completed\n");
    return 0;
}

/* Submit a factorial job and wait for its completion IRQ. */
static int qedu_factorial_job(struct qedu_dev *qdev, u32 input, u32 *result)
{
    long wait_ret;

    pr_info("qedu: factorial job started, input=%u\n", input);

    /* Discard a stale completion before submitting the new job. */
    clear_bit(QEDU_EVENT_FACTORIAL, &qdev->completed_events);
    iowrite32(QEDU_IRQ_FACTORIAL, qdev->bar0 + QEDU_REG_STATUS);
    iowrite32(input, qdev->bar0 + QEDU_REG_FACTORIAL);

    wait_ret = wait_event_interruptible_timeout(
        qdev->job_wait,
        test_bit(QEDU_EVENT_FACTORIAL, &qdev->completed_events),
        msecs_to_jiffies(1000));

    if (wait_ret < 0)
        return wait_ret;

    if (wait_ret == 0) {
        pr_err("qedu: factorial job timed out\n");
        return -ETIMEDOUT;
    }

    *result = ioread32(qdev->bar0 + QEDU_REG_FACTORIAL);
    return 0;
}

/* Round-trip the current buffer; both DMA directions complete by IRQ. */
static int qedu_dma_echo_job(struct qedu_dev *qdev, size_t len)
{
    long wait_ret;

    /* Discard stale state, then submit guest RAM -> EDU with IRQ. */
    pr_info("qedu: DMA RAM -> EDU started, bytes=%zu\n", len);
    clear_bit(QEDU_EVENT_DMA, &qdev->completed_events);

    writeq(qdev->dma_handle, qdev->bar0 + QEDU_REG_DMA_SRC);
    writeq(QEDU_DMA_DEV_BUF, qdev->bar0 + QEDU_REG_DMA_DST);
    writeq(len, qdev->bar0 + QEDU_REG_DMA_CNT);
    writeq(QEDU_DMA_CMD_START | QEDU_DMA_CMD_IRQ,
           qdev->bar0 + QEDU_REG_DMA_CMD);

    wait_ret = wait_event_interruptible_timeout(
        qdev->job_wait,
        test_bit(QEDU_EVENT_DMA, &qdev->completed_events),
        msecs_to_jiffies(1000));

    if (wait_ret < 0)
        return wait_ret;

    if (wait_ret == 0) {
        pr_err("qedu: DMA RAM -> EDU timed out\n");
        return -ETIMEDOUT;
    }

    pr_info("qedu: DMA RAM -> EDU completed\n");

    /* Clearing RAM proves that the reverse transfer restores the bytes. */
    memset(qdev->dma_buf, 0, len);

    /* Discard the first event, then submit EDU -> guest RAM with IRQ. */
    pr_info("qedu: DMA EDU -> RAM started, bytes=%zu\n", len);
    clear_bit(QEDU_EVENT_DMA, &qdev->completed_events);

    writeq(QEDU_DMA_DEV_BUF, qdev->bar0 + QEDU_REG_DMA_SRC);
    writeq(qdev->dma_handle, qdev->bar0 + QEDU_REG_DMA_DST);
    writeq(len, qdev->bar0 + QEDU_REG_DMA_CNT);
    writeq(QEDU_DMA_CMD_START | QEDU_DMA_CMD_DIR | QEDU_DMA_CMD_IRQ,
           qdev->bar0 + QEDU_REG_DMA_CMD);

    wait_ret = wait_event_interruptible_timeout(
        qdev->job_wait,
        test_bit(QEDU_EVENT_DMA, &qdev->completed_events),
        msecs_to_jiffies(1000));

    if (wait_ret < 0)
        return wait_ret;

    if (wait_ret == 0) {
        pr_err("qedu: DMA EDU -> RAM timed out\n");
        return -ETIMEDOUT;
    }

    pr_info("qedu: DMA EDU -> RAM completed\n");
    return 0;
}

/*
 * qedu_open() - attach one open file to its qedu_dev
 * @inode: inode for /dev/qedu; unused
 * @file: file whose private_data initially points to struct miscdevice
 *
 * The misc core supplies the embedded miscdevice. container_of() recovers
 * the enclosing qedu_dev once so later callbacks can use it directly.
 */
static int qedu_open(struct inode *inode, struct file *file)
{
    struct miscdevice *miscdev = file->private_data;
    struct qedu_dev *qdev;

    qdev = container_of(miscdev, struct qedu_dev, miscdev);
    file->private_data = qdev;

    pr_info("qedu: open called\n");
    return 0;
}

/*
 * qedu_release() - close one userspace file instance
 * @inode: inode for /dev/qedu; unused by this driver
 * @file:  file being closed; currently no per-open resources need cleanup
 */
static int qedu_release(struct inode *inode, struct file *file)
{
    pr_info("qedu: release called\n");
    return 0;
}

/*
 * qedu_read() - copy the most recent job result to userspace
 * @file: open file carrying struct qedu_dev in private_data
 * @user_buf: userspace destination supplied to read()
 * @count: capacity of user_buf
 * @ppos: per-open offset for partial reads and end-of-file
 *
 * simple_read_from_buffer() bounds the copy, advances ppos, and returns zero
 * after all result_size bytes have been consumed.
 */
static ssize_t qedu_read(struct file *file, char __user *user_buf, size_t count, loff_t *ppos)
{
    struct qedu_dev *qdev = file->private_data;
    ssize_t ret;

    if (mutex_lock_interruptible(&qdev->lock))
        return -ERESTARTSYS;

    ret = simple_read_from_buffer(user_buf, count, ppos,
                                  qdev->dma_buf, qdev->result_size);

    mutex_unlock(&qdev->lock);
    return ret;
}

/*
 * qedu_write() - submit a factorial or DMA echo job
 * @file: open file carrying struct qedu_dev in private_data
 * @user_buf: input bytes supplied to write()
 * @count: number of input bytes
 * @ppos: file offset; unused for command submission
 *
 * A complete unsigned integer selects the factorial engine. Any other input
 * is round-tripped through EDU by DMA. The resulting bytes remain in dma_buf
 * for a later read from /dev/qedu.
 */
static ssize_t qedu_write(struct file *file, const char __user *user_buf,
                          size_t count, loff_t *ppos)
{
    struct qedu_dev *qdev = file->private_data;
    u32 factorial_input;
    u32 factorial_result;
    int ret;

    if (!count)
        return 0;

    /* Reserve one byte for the NUL terminator needed by kstrtou32(). */
    if (count >= QEDU_DMA_SIZE)
        return -EMSGSIZE;

    if (mutex_lock_interruptible(&qdev->lock))
        return -ERESTARTSYS;

    qdev->result_size = 0;

    if (copy_from_user(qdev->dma_buf, user_buf, count)) {
        ret = -EFAULT;
        goto out_unlock;
    }

    ((char *)qdev->dma_buf)[count] = '\0';

    ret = kstrtou32(qdev->dma_buf, 0, &factorial_input);
    if (!ret) {
        ret = qedu_factorial_job(qdev, factorial_input,
                                 &factorial_result);
        if (ret)
            goto out_unlock;

        qdev->result_size = scnprintf(qdev->dma_buf, QEDU_DMA_SIZE,
                                     "%u\n", factorial_result);
        pr_info("qedu: factorial %u submitted, result=%u\n",
                factorial_input, factorial_result);
    } else {
        ret = qedu_dma_echo_job(qdev, count);
        if (ret)
            goto out_unlock;

        qdev->result_size = count;
        pr_info("qedu: DMA echo completed, bytes=%zu\n", count);
    }

    ret = count;

out_unlock:
    mutex_unlock(&qdev->lock);
    return ret;
}

static const struct file_operations qedu_fops = {
    .owner   = THIS_MODULE,
    .open    = qedu_open,
    .read    = qedu_read,
    .write   = qedu_write,
    .release = qedu_release,
};

/* Combine the polling startup checks into one probe-time test. */
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

/* Misc-device lifecycle for /dev/qedu. */
static int qedu_chrdev_init(struct qedu_dev *qdev)
{
    struct pci_dev *pdev = qdev->pdev;
    int ret;

    qdev->miscdev.minor = MISC_DYNAMIC_MINOR;
    qdev->miscdev.name = "qedu";
    qdev->miscdev.fops = &qedu_fops;
    qdev->miscdev.parent = &pdev->dev;

    ret = misc_register(&qdev->miscdev);
    if (ret) {
        pr_err("qedu: misc_register failed: %d\n", ret);
        return ret;
    }

    pr_info("qedu: /dev/qedu created\n");
    return 0;
}

static void qedu_chrdev_exit(struct qedu_dev *qdev)
{
    misc_deregister(&qdev->miscdev);
    pr_info("qedu: /dev/qedu removed\n");
}

/* PCI enable, BAR ownership, and BAR0 mapping lifecycle. */
static int qedu_pci_init(struct qedu_dev *qdev)
{
    struct pci_dev *pdev = qdev->pdev;
    resource_size_t bar0_start;
    resource_size_t bar0_len;
    int ret;

    ret = pci_enable_device(pdev);
    if (ret) {
        pr_err("qedu: failed to enable PCI device: %d\n", ret);
        return ret;
    }

    ret = pci_request_regions(pdev, "qedu");
    if (ret) {
        pr_err("qedu: pci_request_regions failed: %d\n", ret);
        goto err_disable;
    }

    bar0_start = pci_resource_start(pdev, 0);
    bar0_len = pci_resource_len(pdev, 0);
    pr_info("qedu: BAR0 start=%pa len=%pa\n", &bar0_start, &bar0_len);

    qdev->bar0 = pci_iomap(pdev, 0, 0);
    if (!qdev->bar0) {
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

/* Shared IRQ registration lifecycle. */
static int qedu_irq_init(struct qedu_dev *qdev)
{
    struct pci_dev *pdev = qdev->pdev;
    int ret;

    ret = request_irq(pdev->irq, qedu_irq_handler, IRQF_SHARED,
                      "qedu", qdev);
    if (ret) {
        pr_err("qedu: request_irq failed: %d\n", ret);
        return ret;
    }

    pr_info("qedu: IRQ %d requested\n", pdev->irq);
    return 0;
}

static void qedu_irq_exit(struct qedu_dev *qdev)
{
    free_irq(qdev->pdev->irq, qdev);
    pr_info("qedu: IRQ %d freed\n", qdev->pdev->irq);
}

/* DMA mask, bus mastering, and coherent-buffer lifecycle. */
static int qedu_dma_init(struct qedu_dev *qdev)
{
    struct pci_dev *pdev = qdev->pdev;
    int ret;

    ret = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
    if (ret) {
        pr_err("qedu: 32-bit DMA not supported\n");
        return ret;
    }
    pr_info("qedu: 32-bit DMA supported\n");

    pci_set_master(pdev);

    qdev->dma_buf = dma_alloc_coherent(&pdev->dev, QEDU_DMA_SIZE,
                                        &qdev->dma_handle, GFP_KERNEL);
    if (!qdev->dma_buf) {
        pr_err("qedu: dma_alloc_coherent failed\n");
        pci_clear_master(pdev);
        return -ENOMEM;
    }

    pr_info("qedu: DMA buffer allocated\n");
    pr_info("qedu: CPU address = %px\n", qdev->dma_buf);
    pr_info("qedu: DMA address = %pad\n", &qdev->dma_handle);

    return 0;
}

static void qedu_dma_exit(struct qedu_dev *qdev)
{
    if (qdev->dma_buf) {
        dma_free_coherent(&qdev->pdev->dev, QEDU_DMA_SIZE,
                          qdev->dma_buf, qdev->dma_handle);
        qdev->dma_buf = NULL;
        qdev->dma_handle = 0;
        qdev->result_size = 0;
        pr_info("qedu: DMA buffer freed\n");
    }

    pci_clear_master(qdev->pdev);
}

/* Per-device private-state lifecycle. */
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
    pci_set_drvdata(pdev, qdev);
    *out = qdev;
    return 0;
}

static void qedu_free_device(struct qedu_dev *qdev)
{
    pci_set_drvdata(qdev->pdev, NULL);
}

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

    ret = qedu_selftest(qdev);
    if (ret)
        goto err_dma;

    ret = qedu_chrdev_init(qdev);
    if (ret)
        goto err_dma;

    pr_info("qedu: probe completed; device is ready\n");
    return 0;

    /* Unwind only the layers initialized before the failure. */
err_dma:
    qedu_dma_exit(qdev);
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

    qedu_chrdev_exit(qdev);
    qedu_dma_exit(qdev);
    qedu_irq_exit(qdev);
    qedu_pci_exit(qdev);
    qedu_free_device(qdev);
}

/*
 * This table tells Linux:
 *
 *   this driver supports PCI device 1234:11e8
 *
 * 0x1234 = vendor ID
 * 0x11e8 = device ID
 */
static const struct pci_device_id qedu_ids[] = {
    { PCI_DEVICE(0x1234, 0x11e8) },
    { }
};

/*
 * This exposes the ID table to the module system.
 */
MODULE_DEVICE_TABLE(pci, qedu_ids);

/*
 * This structure describes our PCI driver.
 */
static struct pci_driver qedu_driver = {
    .name     = "qedu",
    .id_table = qedu_ids,
    .probe    = qedu_probe,
    .remove   = qedu_remove,
};

/*
 * This is the shortcut.
 *
 * It automatically does:
 *
 *   on insmod:
 *       pci_register_driver(&qedu_driver)
 *
 *   on rmmod:
 *       pci_unregister_driver(&qedu_driver)
 *
 * So we do not write module_init() or module_exit() here.
 */

module_pci_driver(qedu_driver);

MODULE_LICENSE("GPL");
