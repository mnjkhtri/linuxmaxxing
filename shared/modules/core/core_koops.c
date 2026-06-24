// SPDX-License-Identifier: GPL-2.0
// Linux 6.6+ module: show every thread/task on the system.

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>

static void show_idle_thread(void)
{
	struct task_struct *t = &init_task;

	/* init_task is CPU0's idle task and is not visited by normal traversal. */
	pr_info("KOOPS_CORE %8d %8d %pK %pK [%16s] %8s\n",
		t->tgid, t->pid, t, t->stack, t->comm, "idle");
}

static int show_all_threads(void)
{
	struct task_struct *p;
	struct task_struct *t;
	int total = 0;

	pr_info("KOOPS_CORE --------------------------------------------------------------------------------\n");
	pr_info("KOOPS_CORE     TGID      PID        task_struct        kernel_stack       Thread Name       Type\n");
	pr_info("KOOPS_CORE --------------------------------------------------------------------------------\n");

	show_idle_thread();
	total++;

	rcu_read_lock();

	for_each_process_thread(p, t) {
		const char *type;
		int nr_threads;

		get_task_struct(t);
		task_lock(t);

		nr_threads = get_nr_threads(t);

		if (!t->mm)
			type = "kthread";
		else if (nr_threads > 1)
			type = "user-MT";
		else
			type = "user-ST";

		if (!t->mm) {
			pr_info("KOOPS_CORE %8d %8d %pK %pK [%16s] %8s\n",
				t->tgid, t->pid, t, t->stack, t->comm, type);
		} else {
			pr_info("KOOPS_CORE %8d %8d %pK %pK  %16s  %8s\n",
				t->tgid, t->pid, t, t->stack, t->comm, type);
		}

		task_unlock(t);
		put_task_struct(t);

		total++;
	}

	rcu_read_unlock();

	return total;
}

static int __init core_koops_init(void)
{
	int total;

	pr_info("KOOPS_CORE %s inserted\n", KBUILD_MODNAME);
	total = show_all_threads();
	pr_info("KOOPS_CORE %s total threads/tasks shown: %d\n", KBUILD_MODNAME, total);

	return 0;
}

static void __exit core_koops_exit(void)
{
	pr_info("KOOPS_CORE %s removed\n", KBUILD_MODNAME);
}

module_init(core_koops_init);
module_exit(core_koops_exit);

MODULE_AUTHOR("Manoj Khatri, based on Kaiwan N Billimoria's example");
MODULE_DESCRIPTION("Show all Linux threads using for_each_process_thread()");
MODULE_LICENSE("GPL");
