// SPDX-License-Identifier: GPL-2.0
#include <linux/device.h>
#include <linux/kernel.h>

#include "qedu.h"

/*
 * sysfs exposes device attributes as one value per file.
 * It is suitable for small configuration and statistics that userspace may inspect reliably; it is not intended for the multi-line internal dump provided by debugfs.
 *
 * Registering qedu's miscdevice creates the device below /sys/class/misc/qedu.
 * Its groups pointer adds:
 *
 *   tx          0444  bytes returned to userspace
 *   rx          0444  bytes accepted from userspace
 *   timeout_ms  0644  hardware-completion wait timeout
 *
 * A show() callback formats the current kernel value for read(2).
 * A store() callback parses and validates text supplied through write(2), then returns the byte count on success.
 * DEVICE_ATTR_RO/RW connects those callbacks to attribute names and permissions.
 *
 * Examples:
 *
 *   cat /sys/class/misc/qedu/tx
 *   cat /sys/class/misc/qedu/rx
 *   cat /sys/class/misc/qedu/timeout_ms
 *   echo 1999 > /sys/class/misc/qedu/timeout_ms
 */
static struct qedu_dev *qedu_from_sysfs(struct device *dev)
{
	struct miscdevice *miscdev = dev_get_drvdata(dev);

	/*
	 * misc_register() stored the embedded miscdevice as this device's driver * data. Recover its enclosing qedu_dev just as qedu_open() does.
	 */
	return container_of(miscdev, struct qedu_dev, miscdev);
}

static ssize_t tx_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct qedu_dev *qdev = qedu_from_sysfs(dev);
	int tx;

	mutex_lock(&qdev->lock);
	tx = qdev->tx;
	mutex_unlock(&qdev->lock);

	return sysfs_emit(buf, "%d\n", tx);
}
static DEVICE_ATTR_RO(tx);

static ssize_t rx_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct qedu_dev *qdev = qedu_from_sysfs(dev);
	int rx;

	mutex_lock(&qdev->lock);
	rx = qdev->rx;
	mutex_unlock(&qdev->lock);

	return sysfs_emit(buf, "%d\n", rx);
}
static DEVICE_ATTR_RO(rx);

static ssize_t timeout_ms_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct qedu_dev *qdev = qedu_from_sysfs(dev);
	unsigned int timeout_ms;

	mutex_lock(&qdev->lock);
	timeout_ms = qdev->timeout_ms;
	mutex_unlock(&qdev->lock);

	return sysfs_emit(buf, "%u\n", timeout_ms);
}

static ssize_t timeout_ms_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	struct qedu_dev *qdev = qedu_from_sysfs(dev);
	unsigned int timeout_ms;
	int ret;

	ret = kstrtouint(buf, 0, &timeout_ms);
	if (ret)
		return ret;
	if (!timeout_ms || timeout_ms > QEDU_MAX_TIMEOUT_MS)
		return -ERANGE;

	mutex_lock(&qdev->lock);
	qdev->timeout_ms = timeout_ms;
	mutex_unlock(&qdev->lock);

	return count;
}
static DEVICE_ATTR_RW(timeout_ms);

static struct attribute *qedu_attrs[] = {
	&dev_attr_tx.attr,
	&dev_attr_rx.attr,
	&dev_attr_timeout_ms.attr,
	NULL,
};
ATTRIBUTE_GROUPS(qedu);

/*
 * Keep the attribute definitions private to this file. qedu_chrdev_init() needs only the completed group array when it prepares struct miscdevice.
 */
const struct attribute_group **qedu_sysfs_groups(void)
{
	return qedu_groups;
}
