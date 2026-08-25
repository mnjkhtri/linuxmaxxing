// SPDX-License-Identifier: GPL-2.0
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/uaccess.h>

#include "qedu.h"
#include "qedu_trace.h"

/*
 * The misc core initializes file->private_data with the embedded miscdevice.
 * container_of() recovers the enclosing qedu_dev once, and all later callbacks use that device-private pointer directly.
 */
static int qedu_open(struct inode *inode, struct file *file)
{
	struct miscdevice *miscdev = file->private_data;
	struct qedu_dev *qdev;

	qdev = container_of(miscdev, struct qedu_dev, miscdev);
	Trace_qedu_file_op(pci_name(qdev->pdev), 0, QEDU_FILE_OPEN, QEDU_FILE_ENTER, (unsigned long)file, 0, 0, 0, QEDU_ENGINE_NONE);
	file->private_data = qdev;
	Trace_qedu_file_op(pci_name(qdev->pdev), 0, QEDU_FILE_OPEN, QEDU_FILE_EXIT, (unsigned long)file, 0, 0, 0, QEDU_ENGINE_NONE);

	pr_info("qedu: open called\n");
	return 0;
}

/*
 * There is currently no per-open state to release; the result belongs to the device and is shared by every open file.
 */
static int qedu_release(struct inode *inode, struct file *file)
{
	struct qedu_dev *qdev = file->private_data;
	u64 io_id = READ_ONCE(qdev->result_io_id);

	Trace_qedu_file_op(pci_name(qdev->pdev), io_id, QEDU_FILE_RELEASE, QEDU_FILE_ENTER, (unsigned long)file, 0, 0, 0, QEDU_ENGINE_NONE);
	pr_info("qedu: release called\n");
	Trace_qedu_file_op(pci_name(qdev->pdev), io_id, QEDU_FILE_RELEASE, QEDU_FILE_EXIT, (unsigned long)file, 0, 0, 0, QEDU_ENGINE_NONE);
	return 0;
}

/*
 * Return the most recent result.
 * simple_read_from_buffer() bounds the copy, supports partial reads, advances the per-open offset, and returns EOF after qdev->result_size valid bytes have been consumed.
 */
static ssize_t qedu_read(struct file *file, char __user *user_buf, size_t count, loff_t *ppos)
{
	struct qedu_dev *qdev = file->private_data;
	ssize_t ret;
	loff_t offset = *ppos;
	u64 io_id = READ_ONCE(qdev->result_io_id);

	Trace_qedu_file_op(pci_name(qdev->pdev), io_id, QEDU_FILE_READ, QEDU_FILE_ENTER, (unsigned long)file, count, offset, 0, QEDU_ENGINE_NONE);
	if (mutex_lock_interruptible(&qdev->lock))
	{
		ret = -ERESTARTSYS;
		goto out_trace;
	}

	io_id = qdev->result_io_id;
	ret = simple_read_from_buffer(user_buf, count, ppos, qdev->dma_cpu_addr, qdev->result_size);
	Trace_qedu_cpu_buffer_io(pci_name(qdev->pdev), io_id, QEDU_BUFFER_COPY_TO_USER, offset, count, ret);
	if (ret > 0)
		qdev->tx += ret;

	mutex_unlock(&qdev->lock);

out_trace:
	Trace_qedu_file_op(pci_name(qdev->pdev), io_id, QEDU_FILE_READ, QEDU_FILE_EXIT, (unsigned long)file, count, offset, ret, QEDU_ENGINE_NONE);
	return ret;
}

/*
 * Submit one synchronous job through write(2):
 *
 *   complete unsigned integer -> factorial engine -> decimal result text
 *   any other input           -> DMA RAM -> EDU -> RAM byte echo
 *
 * For example:
 *
 *   echo 10 > /dev/qedu; cat /dev/qedu       # 3628800
 *   echo hello > /dev/qedu; cat /dev/qedu    # hello
 *
 * kstrtou32() accepts echo's trailing newline. For DMA echo that newline is payload.
 * Writes must be smaller than QEDU_DMA_SIZE because one byte is temporarily reserved for the integer parser's NUL terminator.
 *
 * qdev->lock serializes the shared DMA/result buffer, result_size, and EDU's single factorial/DMA engines.
 * Process context may hold this mutex while it sleeps for IRQ completion because the hardirq handler never acquires it.
 * Coherent DMA handles CPU/device cache visibility; it does not serialize CPU threads, so the mutex remains necessary.
 */
static ssize_t qedu_write(struct file *file, const char __user *user_buf, size_t count, loff_t *ppos)
{
	struct qedu_dev *qdev = file->private_data;
	enum qedu_io_engine selected_engine = QEDU_ENGINE_NONE;
	u32 factorial_input;
	u32 factorial_result;
	u64 io_id = atomic64_inc_return(&qdev->next_io_id);
	unsigned long not_copied;
	loff_t offset = *ppos;
	int ret;

	Trace_qedu_file_op(pci_name(qdev->pdev), io_id, QEDU_FILE_WRITE, QEDU_FILE_ENTER, (unsigned long)file, count, offset, 0, QEDU_ENGINE_NONE);
	if (!count)
	{
		ret = 0;
		goto out_trace;
	}

	if (count >= QEDU_DMA_SIZE)
	{
		ret = -EMSGSIZE;
		goto out_trace;
	}

	if (mutex_lock_interruptible(&qdev->lock))
	{
		ret = -ERESTARTSYS;
		goto out_trace;
	}

	WRITE_ONCE(qdev->active_io_id, io_id);
	WRITE_ONCE(qdev->active_engine, QEDU_ENGINE_NONE);
	qdev->result_size = 0;

	not_copied = copy_from_user(qdev->dma_cpu_addr, user_buf, count);
	Trace_qedu_cpu_buffer_io(pci_name(qdev->pdev), io_id, QEDU_BUFFER_COPY_FROM_USER, 0, count, count - not_copied);
	if (not_copied)
	{
		ret = -EFAULT;
		goto out_unlock;
	}

	((char *)qdev->dma_cpu_addr)[count] = '\0';

	ret = kstrtou32(qdev->dma_cpu_addr, 0, &factorial_input);
	if (!ret)
	{
		ret = qedu_factorial_job(qdev, factorial_input, &factorial_result, io_id);
		if (ret)
			goto out_unlock;

		qdev->result_size = scnprintf(qdev->dma_cpu_addr, QEDU_DMA_SIZE, "%u\n", factorial_result);
		pr_info("qedu: factorial %u submitted, result=%u\n", factorial_input, factorial_result);
	}
	else
	{
		ret = qedu_dma_echo_job(qdev, count, io_id);
		if (ret)
			goto out_unlock;

		qdev->result_size = count;
		pr_info("qedu: DMA echo completed, bytes=%zu\n", count);
	}

	qdev->result_io_id = io_id;
	qdev->rx += count;
	ret = count;

out_unlock:
	selected_engine = READ_ONCE(qdev->active_engine);
	WRITE_ONCE(qdev->active_engine, QEDU_ENGINE_NONE);
	mutex_unlock(&qdev->lock);

out_trace:
	Trace_qedu_file_op(pci_name(qdev->pdev), io_id, QEDU_FILE_WRITE, QEDU_FILE_EXIT, (unsigned long)file, count, offset, ret, selected_engine);
	return ret;
}

/*
 * misc_register() publishes /dev/qedu with this dispatch table:
 *
 *   open()    -> qedu_open()     attach qedu_dev to the file
 *   read()    -> qedu_read()     return the latest result
 *   write()   -> qedu_write()    submit factorial or DMA work
 *   close()   -> qedu_release()  no per-open cleanup yet
 */

static const struct file_operations qedu_fops = {
	.owner = THIS_MODULE,
	.open = qedu_open,
	.read = qedu_read,
	.write = qedu_write,
	.release = qedu_release,
};

int qedu_chrdev_init(struct qedu_dev *qdev)
{
	struct pci_dev *pdev = qdev->pdev;
	int ret;

	qdev->miscdev.minor = MISC_DYNAMIC_MINOR;
	qdev->miscdev.name = "qedu";
	qdev->miscdev.fops = &qedu_fops;
	qdev->miscdev.parent = &pdev->dev;

	/*
	 * The definitions live in qedu_sysfs.c, but the groups must be attached before misc_register() creates the qedu device and its attributes.
	 */
	qdev->miscdev.groups = qedu_sysfs_groups();
	ret = misc_register(&qdev->miscdev);
	if (ret)
	{
		pr_err("qedu: misc_register failed: %d\n", ret);
		return ret;
	}

	Trace_qedu_probe_stage(pci_name(pdev), QEDU_CHARDEV_PUBLISHED, "misc_register",
						   "/dev/qedu", qdev->miscdev.minor, 0, 0);
	Trace_qedu_probe_stage(pci_name(pdev), QEDU_SYSFS_PUBLISHED, "misc_register",
						   "/sys/class/misc/qedu", qdev->miscdev.minor, 0, 0);
	pr_info("qedu: /dev/qedu created\n");
	return 0;
}

void qedu_chrdev_exit(struct qedu_dev *qdev)
{
	misc_deregister(&qdev->miscdev);
	pr_info("qedu: /dev/qedu removed\n");
}
