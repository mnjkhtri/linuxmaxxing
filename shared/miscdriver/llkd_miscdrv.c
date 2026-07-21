// SPDX-License-Identifier: GPL-2.0
/*
 * Tiny misc character driver for learning four kernel/user interfaces:
 *
 *   /dev/llkd_miscdrv                 data path: read/write a stored string
 *   /proc/llkd_miscdrv/{status,config} procfs comparison interface
 *   /sys/class/misc/llkd_miscdrv/<attrs> sysfs one-value-per-file attributes
 *   /sys/kernel/debug/llkd_miscdrv/status rich debug-only diagnostic dump
 */
#define pr_fmt(fmt) "%s:%s(): " fmt, KBUILD_MODNAME, __func__

#include <linux/debugfs.h>	  /* debugfs_create_dir(), debugfs_create_file() */
#include <linux/device.h>	  /* struct device, dev_info(), dev_warn() */
#include <linux/fs.h>		  /* struct file_operations */
#include <linux/init.h>		  /* __init, __exit */
#include <linux/kernel.h>	  /* min_t(), unlikely() */
#include <linux/mm.h>		  /* kvmalloc(), kvfree() */
#include <linux/miscdevice.h> /* struct miscdevice, misc_register() */
#include <linux/module.h>	  /* module metadata, THIS_MODULE */
#include <linux/mutex.h>	  /* struct mutex */
#include <linux/proc_fs.h>	  /* proc_mkdir(), proc_create() */
#include <linux/sched.h>	  /* current, get_task_comm() */
#include <linux/seq_file.h>	  /* seq_file helpers for procfs output */
#include <linux/slab.h>		  /* devm_kzalloc(), GFP_KERNEL */
#include <linux/string.h>	  /* strlen(), strscpy(), memset() */
#include <linux/uaccess.h>	  /* copy_to_user(), copy_from_user() */

#define MAXBYTES 128 /* max stored string size; userspace should match it */

/* ---------- shared driver state ---------- */

struct drv_ctx
{
	struct device *dev;				 /* misc device object used for dev_* logs */
	int tx;							 /* total bytes read from driver */
	int rx;							 /* total bytes written into driver */
	int config;						 /* tunable exposed through procfs/sysfs */
	struct mutex lock;				 /* protects the fields below */
	struct proc_dir_entry *proc_dir; /* /proc/llkd_miscdrv directory */
	struct dentry *debugfs_dir;		 /* /sys/kernel/debug/llkd_miscdrv */
	char oursecret[MAXBYTES];		 /* backing store for /dev reads/writes */
	size_t secret_len;				 /* valid bytes in oursecret */
};

static struct drv_ctx *ctx;			   /* one global context: one teaching device */
static struct miscdevice llkd_miscdev; /* forward declaration for sysfs/procfs */

/* ---------- sysfs device attributes ---------- */

/*
 * Sysfs is for simple device attributes. The convention is one value per file.
 * These files appear below the misc device, for example:
 *
 *   /sys/class/misc/llkd_miscdrv/config
 *   /sys/class/misc/llkd_miscdrv/tx
 *   /sys/class/misc/llkd_miscdrv/rx
 *   /sys/class/misc/llkd_miscdrv/secret_len
 *
 * For DEVICE_ATTR_RW(config), names matter:
 *   config_show()  handles: cat config
 *   config_store() handles: echo 7 > config
 *   dev_attr_config is created by the macro and registered later.
 */
static ssize_t config_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	int config;

	mutex_lock(&ctx->lock);
	config = ctx->config;
	mutex_unlock(&ctx->lock);

	dev_info(dev, "sysfs config read: %d\n", config);
	return sysfs_emit(buf, "%d\n", config); /* show() writes text into buf */
}

static ssize_t config_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	int ret;
	int val;

	ret = kstrtoint(buf, 0, &val); /* convert text like "7\n" to integer 7 */
	if (ret)
		return ret;

	mutex_lock(&ctx->lock);
	ctx->config = val;
	mutex_unlock(&ctx->lock);

	dev_info(dev, "sysfs config write: %d\n", val);
	return count; /* store() returns bytes consumed on success */
}

static DEVICE_ATTR_RW(config); /* creates dev_attr_config from config_show/store */

static ssize_t tx_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	int tx;

	mutex_lock(&ctx->lock);
	tx = ctx->tx;
	mutex_unlock(&ctx->lock);

	dev_info(dev, "sysfs tx read: %d\n", tx);
	return sysfs_emit(buf, "%d\n", tx);
}

static DEVICE_ATTR_RO(tx); /* read-only: creates dev_attr_tx from tx_show() */

static ssize_t rx_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	int rx;

	mutex_lock(&ctx->lock);
	rx = ctx->rx;
	mutex_unlock(&ctx->lock);

	dev_info(dev, "sysfs rx read: %d\n", rx);
	return sysfs_emit(buf, "%d\n", rx);
}

static DEVICE_ATTR_RO(rx); /* read-only: creates dev_attr_rx from rx_show() */

static ssize_t secret_len_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	size_t secret_len;

	mutex_lock(&ctx->lock);
	secret_len = ctx->secret_len;
	mutex_unlock(&ctx->lock);

	dev_info(dev, "sysfs secret_len read: %zu\n", secret_len);
	return sysfs_emit(buf, "%zu\n", secret_len);
}

static DEVICE_ATTR_RO(secret_len); /* creates dev_attr_secret_len */

static struct attribute *llkd_misc_attrs[] = {
	&dev_attr_config.attr,
	&dev_attr_tx.attr,
	&dev_attr_rx.attr,
	&dev_attr_secret_len.attr,
	NULL,
};

static const struct attribute_group llkd_misc_attr_group = {
	.attrs = llkd_misc_attrs, /* register/remove all sysfs files as a group */
};

/* ---------- procfs control/status path ---------- */

/*
 * procfs here is a teaching comparison to sysfs. status is a rich multi-line
 * dump, while config is a direct read/write scalar. For new stable per-device
 * ABI, prefer sysfs one-value-per-file attributes.
 */
static int status_proc_show(struct seq_file *m, void *v)
{
	dev_info(ctx->dev, "procfs status read\n");

	seq_printf(m, "device: /dev/%s\n", llkd_miscdev.name); /* print into proc buffer */
	seq_printf(m, "minor: %d\n", llkd_miscdev.minor);

	mutex_lock(&ctx->lock);
	seq_printf(m, "tx: %d\n", ctx->tx);
	seq_printf(m, "rx: %d\n", ctx->rx);
	seq_printf(m, "secret_len: %zu\n", ctx->secret_len);
	seq_printf(m, "config: %d\n", ctx->config);
	mutex_unlock(&ctx->lock);

	return 0;
}

static int status_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, status_proc_show, NULL); /* call show() once */
}

static const struct proc_ops status_proc_ops = {
	.proc_open = status_proc_open,
	.proc_read = seq_read,			/* copies seq_printf() output to userspace */
	.proc_lseek = seq_lseek,		/* seek support for seq_file */
	.proc_release = single_release, /* cleanup for single_open() */
};

static ssize_t config_proc_read(struct file *file, char __user *ubuf, size_t count, loff_t *off)
{
	char kbuf[32];
	int config;
	int len;

	mutex_lock(&ctx->lock);
	config = ctx->config;
	mutex_unlock(&ctx->lock);

	dev_info(ctx->dev, "procfs config read: %d\n", config);
	len = scnprintf(kbuf, sizeof(kbuf), "%d\n", config);		 /* format into kernel buffer */
	return simple_read_from_buffer(ubuf, count, off, kbuf, len); /* copy to userspace */
}

static ssize_t config_proc_write(struct file *file, const char __user *ubuf, size_t count, loff_t *off)
{
	int ret;
	int val;

	ret = kstrtoint_from_user(ubuf, count, 0, &val); /* parse userspace text */
	if (ret)
		return ret;

	mutex_lock(&ctx->lock);
	ctx->config = val;
	mutex_unlock(&ctx->lock);

	dev_info(ctx->dev, "procfs config write: %d\n", val);
	return count;
}

static const struct proc_ops config_proc_ops = {
	.proc_read = config_proc_read,	 /* simple scalar read; no seq_file needed */
	.proc_write = config_proc_write, /* parse text into ctx->config */
};

/* ---------- debugfs rich diagnostics ---------- */

/*
 * debugfs is for developer/debug information, not stable userspace ABI.
 *
 * This is the right place for a rich, multi-line dump because sysfs wants one
 * value per file and procfs is mostly for process/kernel-wide or legacy data.
 * The file appears after debugfs is mounted, usually at:
 *
 *   /sys/kernel/debug/llkd_miscdrv/status
 *
 * Mount command inside the guest if needed:
 *
 *   mount -t debugfs none /sys/kernel/debug
 */
static int debugfs_status_show(struct seq_file *m, void *v)
{
	char secret[MAXBYTES];
	int config;
	int minor;
	int rx;
	int tx;
	size_t secret_len;

	mutex_lock(&ctx->lock);
	config = ctx->config;
	tx = ctx->tx;
	rx = ctx->rx;
	secret_len = ctx->secret_len;
	strscpy(secret, ctx->oursecret, sizeof(secret));
	mutex_unlock(&ctx->lock);

	minor = llkd_miscdev.minor;
	dev_info(ctx->dev, "debugfs status read\n");

	seq_puts(m, "llkd_miscdrv debug status\n");
	seq_puts(m, "========================\n");
	seq_printf(m, "module: %s\n", KBUILD_MODNAME);
	seq_printf(m, "devnode: /dev/%s\n", llkd_miscdev.name);
	seq_printf(m, "misc_major: 10\n");
	seq_printf(m, "misc_minor: %d\n", minor);
	seq_printf(m, "ctx: %px\n", ctx);
	seq_printf(m, "device: %px\n", ctx->dev);
	seq_puts(m, "\n");
	seq_puts(m, "counters\n");
	seq_puts(m, "--------\n");
	seq_printf(m, "tx_bytes_to_user: %d\n", tx);
	seq_printf(m, "rx_bytes_from_user: %d\n", rx);
	seq_puts(m, "\n");
	seq_puts(m, "state\n");
	seq_puts(m, "-----\n");
	seq_printf(m, "config: %d\n", config);
	seq_printf(m, "maxbytes: %d\n", MAXBYTES);
	seq_printf(m, "secret_len: %zu\n", secret_len);
	seq_printf(m, "secret_preview: %s\n", secret);
	seq_puts(m, "\n");
	seq_puts(m, "interfaces\n");
	seq_puts(m, "----------\n");
	seq_puts(m, "/dev/llkd_miscdrv: read/write stored string\n");
	seq_puts(m, "/proc/llkd_miscdrv/status: rich procfs comparison dump\n");
	seq_puts(m, "/proc/llkd_miscdrv/config: procfs config read/write\n");
	seq_puts(m, "/sys/class/misc/llkd_miscdrv/config: sysfs config attribute\n");
	seq_puts(m, "/sys/class/misc/llkd_miscdrv/tx: sysfs read-only tx counter\n");
	seq_puts(m, "/sys/class/misc/llkd_miscdrv/rx: sysfs read-only rx counter\n");
	seq_puts(m, "/sys/class/misc/llkd_miscdrv/secret_len: sysfs read-only length\n");

	return 0;
}

static int debugfs_status_open(struct inode *inode, struct file *file)
{
	return single_open(file, debugfs_status_show, NULL); /* one rich dump per open */
}

static const struct file_operations debugfs_status_fops = {
	.owner = THIS_MODULE,
	.open = debugfs_status_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

/* ---------- /dev/llkd_miscdrv data path ---------- */

/*
 * The /dev node is the actual character-device I/O interface. Userspace opens
 * /dev/llkd_miscdrv and reaches these callbacks through llkd_misc_fops below.
 *
 * This path is different from sysfs/procfs: it is meant to move data, not just
 * expose attributes. Here, write(2) replaces ctx->oursecret and read(2) copies
 * ctx->oursecret back to userspace.
 */

/*
 * open(2) callback.
 *
 * A real driver often allocates per-open state here and stores it in
 * filp->private_data. This sample has only one global ctx, so open only logs.
 */
static int open_miscdrv(struct inode *inode, struct file *filp)
{
	dev_info(ctx->dev, "opened\n");
	return 0;
}

/*
 * read(2) callback.
 *
 * ubuf is a userspace pointer, so the driver must use copy_to_user(); direct
 * dereference is not allowed. off is the file position. Updating off is what
 * lets tools like cat(1) eventually see EOF instead of reading forever.
 */
static ssize_t read_miscdrv(struct file *filp, char __user *ubuf, size_t count, loff_t *off)
{
	struct device *dev = ctx->dev;
	char tasknm[TASK_COMM_LEN];
	size_t nbytes;
	int rx;
	int tx;

	dev_info(dev, "%s wants to read (upto) %zd bytes\n", get_task_comm(tasknm, current), count);

	mutex_lock(&ctx->lock);
	if (*off >= ctx->secret_len)
	{ /* EOF after the stored string is consumed */
		mutex_unlock(&ctx->lock);
		return 0;
	}

	nbytes = min_t(size_t, count, ctx->secret_len - *off);
	if (copy_to_user(ubuf, ctx->oursecret + *off, nbytes))
	{ /* never dereference __user */
		mutex_unlock(&ctx->lock);
		dev_warn(dev, "copy_to_user() failed\n");
		return -EFAULT;
	}

	*off += nbytes; /* makes repeated read() calls progress to EOF */
	ctx->tx += nbytes;
	tx = ctx->tx;
	rx = ctx->rx;
	mutex_unlock(&ctx->lock);

	dev_info(dev, " %zu bytes read, returning... (stats: tx=%d, rx=%d)\n", nbytes, tx, rx);
	return nbytes;
}

/*
 * write(2) callback.
 *
 * ubuf is a userspace pointer, so the driver first copies it into temporary
 * kernel memory with copy_from_user(). After that, ctx->oursecret is updated
 * under the mutex so sysfs/procfs/read() cannot observe a half-written value.
 */
static ssize_t write_miscdrv(struct file *filp, const char __user *ubuf, size_t count, loff_t *off)
{
	struct device *dev = ctx->dev;
	char tasknm[TASK_COMM_LEN];
	void *kbuf = NULL;
	size_t len;
	int ret;
	int rx;
	int tx;

	if (unlikely(count >= MAXBYTES))
	{ /* reserve one byte for trailing NUL */
		dev_warn(dev, "count %zu exceeds max # of bytes allowed, aborting write\n", count);
		return -EINVAL;
	}

	dev_info(dev, "%s wants to write %zd bytes\n", get_task_comm(tasknm, current), count);

	kbuf = kvmalloc(count + 1, GFP_KERNEL); /* temporary kernel copy of user data */
	if (unlikely(!kbuf))
		return -ENOMEM;

	memset(kbuf, 0, count + 1); /* safe string termination for this sample */

	ret = -EFAULT;
	if (copy_from_user(kbuf, ubuf, count))
	{ /* never dereference __user */
		dev_warn(dev, "copy_from_user() failed\n");
		goto out_free;
	}

	mutex_lock(&ctx->lock);
	len = strscpy(ctx->oursecret, kbuf, sizeof(ctx->oursecret)); /* backing device write */
	ctx->secret_len = len;
	ctx->rx += count;
	tx = ctx->tx;
	rx = ctx->rx;
	mutex_unlock(&ctx->lock);

	ret = count;
	dev_info(dev, " %zd bytes written, returning... (stats: tx=%d, rx=%d)\n", count, tx, rx);

out_free:
	kvfree(kbuf);
	return ret;
}

/*
 * release callback for close(2).
 *
 * If open allocated per-file state, this would free it. This sample only logs.
 */
static int close_miscdrv(struct inode *inode, struct file *filp)
{
	dev_info(ctx->dev, "closed\n");
	return 0;
}

/* ---------- misc device registration data ---------- */

/*
 * file_operations is the dispatch table for /dev/llkd_miscdrv. The VFS calls
 * these function pointers when userspace performs open/read/write/close.
 */
static const struct file_operations llkd_misc_fops = {
	.owner = THIS_MODULE,	  /* pin module while file operations run */
	.open = open_miscdrv,	  /* open(2) */
	.read = read_miscdrv,	  /* read(2) */
	.write = write_miscdrv,	  /* write(2) */
	.release = close_miscdrv, /* close(2) */
};

/*
 * miscdevice tells the misc framework what /dev node to create and which
 * file_operations table should handle that node. MISC_DYNAMIC_MINOR asks the
 * kernel to choose a free minor number under misc major 10.
 */
static struct miscdevice llkd_miscdev = {
	.minor = MISC_DYNAMIC_MINOR, /* ask misc core for a free minor */
	.name = "llkd_miscdrv",		 /* creates /dev/llkd_miscdrv */
	.mode = 0666,				 /* teaching only: world-readable/writable */
	.fops = &llkd_misc_fops,	 /* syscall dispatch table */
};

/* ---------- module lifetime ---------- */

/*
 * Module init runs when insmod loads the .ko. The order matters:
 *
 *   1. misc_register() creates the device and struct device.
 *   2. devm_kzalloc() allocates private state tied to that device.
 *   3. sysfs_create_group() adds one-value-per-file attributes.
 *   4. proc_mkdir()/proc_create() add the procfs teaching interface.
 *   5. debugfs_create_dir()/debugfs_create_file() add debug-only rich status.
 *
 * If any later step fails, the goto labels unwind earlier registrations.
 */
static int __init llkd_misc_init(void)
{
	struct device *dev;
	int ret;

	ret = misc_register(&llkd_miscdev); /* creates /dev node and device object */
	if (ret)
		return ret;

	dev = llkd_miscdev.this_device; /* valid only after misc_register() */

	ctx = devm_kzalloc(dev, sizeof(*ctx), GFP_KERNEL); /* zeroed, device-managed */
	if (unlikely(!ctx))
	{
		misc_deregister(&llkd_miscdev);
		return -ENOMEM;
	}

	ctx->dev = dev;
	mutex_init(&ctx->lock);
	ctx->config = 1;
	strscpy(ctx->oursecret, "initmsg", sizeof(ctx->oursecret));
	ctx->secret_len = strlen(ctx->oursecret);

	dev_info(ctx->dev, "creating sysfs files config/tx/rx/secret_len\n");
	ret = sysfs_create_group(&ctx->dev->kobj, &llkd_misc_attr_group);
	if (ret)
		goto err_misc;

	dev_info(ctx->dev, "creating procfs directory /proc/llkd_miscdrv\n");
	ctx->proc_dir = proc_mkdir("llkd_miscdrv", NULL);
	if (!ctx->proc_dir)
	{
		ret = -ENOMEM;
		goto err_sysfs;
	}

	dev_info(ctx->dev, "creating procfs file /proc/llkd_miscdrv/status\n");
	if (!proc_create("status", 0444, ctx->proc_dir, &status_proc_ops))
	{
		ret = -ENOMEM;
		goto err_proc;
	}

	dev_info(ctx->dev, "creating procfs file /proc/llkd_miscdrv/config\n");
	if (!proc_create("config", 0666, ctx->proc_dir, &config_proc_ops))
	{
		ret = -ENOMEM;
		goto err_proc;
	}

	dev_info(ctx->dev, "creating debugfs file /sys/kernel/debug/llkd_miscdrv/status\n");
	ctx->debugfs_dir = debugfs_create_dir("llkd_miscdrv", NULL);
	if (IS_ERR(ctx->debugfs_dir))
	{
		ret = PTR_ERR(ctx->debugfs_dir);
		ctx->debugfs_dir = NULL;
		goto err_proc;
	}

	if (ctx->debugfs_dir && !debugfs_create_file("status", 0444, ctx->debugfs_dir, NULL, &debugfs_status_fops))
	{
		ret = -ENOMEM;
		goto err_debugfs;
	}

	dev_info(ctx->dev, "registered /dev/%s with minor %d\n", llkd_miscdev.name, llkd_miscdev.minor);
	return 0;

err_debugfs:
	debugfs_remove_recursive(ctx->debugfs_dir);
err_proc:
	remove_proc_subtree("llkd_miscdrv", NULL);
err_sysfs:
	sysfs_remove_group(&ctx->dev->kobj, &llkd_misc_attr_group);
err_misc:
	misc_deregister(&llkd_miscdev);
	return ret;
}

/*
 * Module exit runs when rmmod unloads the .ko. Remove procfs and sysfs before
 * unregistering the misc device so userspace cannot enter removed state.
 */
static void __exit llkd_misc_exit(void)
{
	dev_info(ctx->dev, "deregistering /dev/%s tx=%d rx=%d\n", llkd_miscdev.name, ctx->tx, ctx->rx);
	dev_info(ctx->dev, "removing debugfs subtree /sys/kernel/debug/llkd_miscdrv\n");
	debugfs_remove_recursive(ctx->debugfs_dir);
	dev_info(ctx->dev, "removing procfs subtree /proc/llkd_miscdrv\n");
	remove_proc_subtree("llkd_miscdrv", NULL);
	dev_info(ctx->dev, "removing sysfs files config/tx/rx/secret_len\n");
	sysfs_remove_group(&ctx->dev->kobj, &llkd_misc_attr_group);
	misc_deregister(&llkd_miscdev);
	ctx = NULL; /* devm allocation is released with the device */
}

module_init(llkd_misc_init);
module_exit(llkd_misc_exit);

MODULE_AUTHOR("Manoj Khatri");
MODULE_DESCRIPTION("Simple misc character driver skeleton");
MODULE_LICENSE("GPL");
