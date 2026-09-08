// SPDX-License-Identifier: GPL-2.0
#include <linux/debugfs.h>
#include <linux/err.h>
#include <linux/module.h>
#include <linux/seq_file.h>

#include "qedu.h"
#include "qedu_trace.h"

/*
 * debugfs is for developer diagnostics, not a stable userspace ABI.
 * Unlike sysfs, which exposes one value per file, a debugfs file may present a rich multi-line snapshot of internal driver state.
 *
 * Read this file after mounting debugfs:
 *
 *   mount -t debugfs none /sys/kernel/debug
 *   cat /sys/kernel/debug/qedu/status
 *
 * Applications must not depend on this format; it may change with the driver.
 */
static int qedu_debugfs_status_show(struct seq_file *m, void *unused)
{
	struct qedu_dev *qdev = m->private;
	struct pci_dev *pdev = qdev->pdev;
	resource_size_t bar0_start = pci_resource_start(pdev, 0);
	resource_size_t bar0_len = pci_resource_len(pdev, 0);
	unsigned long completed_events;
	unsigned int timeout_ms;
	size_t result_size;
	int rx;
	int tx;

	mutex_lock(&qdev->lock);
	tx = qdev->tx;
	rx = qdev->rx;
	timeout_ms = qdev->timeout_ms;
	result_size = qdev->result_size;
	completed_events = qdev->completed_events;

	seq_puts(m, "qedu debug status\n");
	seq_puts(m, "=================\n");
	seq_printf(m, "pci_device: %s\n", pci_name(pdev));
	seq_printf(m, "vendor_device: %04x:%04x\n", pdev->vendor, pdev->device);
	seq_printf(m, "bar0_start: %pa\n", &bar0_start);
	seq_printf(m, "bar0_length: %pa\n", &bar0_len);
	seq_printf(m, "bar0_mapping: %px\n", qdev->bar0);
	seq_printf(m, "irq: %d\n", pdev->irq);
	seq_printf(m, "misc_minor: %d\n", qdev->miscdev.minor);
	seq_puts(m, "\nI/O\n---\n");
	seq_printf(m, "tx_bytes_to_user: %d\n", tx);
	seq_printf(m, "rx_bytes_from_user: %d\n", rx);
	seq_printf(m, "result_size: %zu\n", result_size);
	seq_printf(m, "timeout_ms: %u\n", timeout_ms);
	seq_puts(m, "\nDMA\n---\n");
	seq_printf(m, "cpu_address: %px\n", qdev->dma_cpu_addr);
	seq_printf(m, "device_address: %pad\n", &qdev->dma_addr);
	seq_printf(m, "buffer_size: %u\n", QEDU_DMA_SIZE);
	seq_printf(m, "completed_events: 0x%lx\n", completed_events);
	mutex_unlock(&qdev->lock);

	return 0;
}

static int qedu_debugfs_status_open(struct inode *inode, struct file *file)
{
	return single_open(file, qedu_debugfs_status_show, inode->i_private);
}

/*
 * seq_file handles arbitrarily sized formatted output, partial userspace reads, seeks, and cleanup without hand-written buffer management.
 */
static const struct file_operations qedu_debugfs_status_fops = {
	.owner = THIS_MODULE,
	.open = qedu_debugfs_status_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

void qedu_debugfs_init(struct qedu_dev *qdev)
{
	struct dentry *status_file;

	qdev->debugfs_dir = debugfs_create_dir("qedu", NULL);
	if (IS_ERR(qdev->debugfs_dir))
	{
		Trace_qedu_probe_stage(pci_name(qdev->pdev), QEDU_DEBUGFS_PUBLISHED, "debugfs_create_dir",
				       "/sys/kernel/debug/qedu/status", 0, 0,
				       PTR_ERR(qdev->debugfs_dir));
		qdev->debugfs_dir = NULL;
		return;
	}

	status_file = debugfs_create_file("status", 0444, qdev->debugfs_dir, qdev, &qedu_debugfs_status_fops);
	if (IS_ERR(status_file))
	{
		Trace_qedu_probe_stage(pci_name(qdev->pdev), QEDU_DEBUGFS_PUBLISHED, "debugfs_create_file",
				       "/sys/kernel/debug/qedu/status", 0, 0,
				       PTR_ERR(status_file));
		debugfs_remove(qdev->debugfs_dir);
		qdev->debugfs_dir = NULL;
		return;
	}

	Trace_qedu_probe_stage(pci_name(qdev->pdev), QEDU_DEBUGFS_PUBLISHED, "debugfs_create_file",
			       "/sys/kernel/debug/qedu/status",
			       (unsigned long)status_file, 0444, 0);
	pr_info("qedu: debugfs status created\n");
}

void qedu_debugfs_exit(struct qedu_dev *qdev)
{
	debugfs_remove(qdev->debugfs_dir);
	qdev->debugfs_dir = NULL;
}
