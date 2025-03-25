// SPDX-License-Identifier: GPL-2.0-only
/*
 * DMA-BUF sysfs statistics.
 *
 * Copyright (C) 2021 Google LLC.
 */

#include <linux/dma-buf.h>
#include <linux/dma-resv.h>
#include <linux/kobject.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/workqueue.h>

#include <trace/hooks/dmabuf.h>

#ifdef CONFIG_SYSFS_STATS_SETUP_ASYNC
#include <linux/swap.h>
#include <linux/kthread.h>
#include <linux/suspend.h>
#include <uapi/linux/sched/types.h>
#else
#include <trace/hooks/dmabuf.h>
#endif

#include "dma-buf-sysfs-stats.h"

#define to_dma_buf_entry_from_kobj(x) container_of(x, struct dma_buf_sysfs_entry, kobj)

struct dma_buf_stats_attribute {
	struct attribute attr;
	ssize_t (*show)(struct dma_buf *dmabuf,
			struct dma_buf_stats_attribute *attr, char *buf);
};
#define to_dma_buf_stats_attr(x) container_of(x, struct dma_buf_stats_attribute, attr)

#ifdef CONFIG_SYSFS_STATS_SETUP_ASYNC
struct dma_buf_sysfs_entry_list {
	struct list_head head;
	struct mutex lock;
};
static struct dma_buf_sysfs_entry_list dbse_list;
static wait_queue_head_t scan_dbse_wait;
static atomic_t scan_dbse_wait_flag;
static struct task_struct *scan_dbse_worker;
#endif

static ssize_t dma_buf_stats_attribute_show(struct kobject *kobj,
					    struct attribute *attr,
					    char *buf)
{
	struct dma_buf_stats_attribute *attribute;
	struct dma_buf_sysfs_entry *sysfs_entry;
	struct dma_buf *dmabuf;

	attribute = to_dma_buf_stats_attr(attr);
	sysfs_entry = to_dma_buf_entry_from_kobj(kobj);
	dmabuf = sysfs_entry->dmabuf;

	if (!dmabuf || !attribute->show)
		return -EIO;

	return attribute->show(dmabuf, attribute, buf);
}

static const struct sysfs_ops dma_buf_stats_sysfs_ops = {
	.show = dma_buf_stats_attribute_show,
};

static ssize_t exporter_name_show(struct dma_buf *dmabuf,
				  struct dma_buf_stats_attribute *attr,
				  char *buf)
{
	return sysfs_emit(buf, "%s\n", dmabuf->exp_name);
}

static ssize_t size_show(struct dma_buf *dmabuf,
			 struct dma_buf_stats_attribute *attr,
			 char *buf)
{
	return sysfs_emit(buf, "%zu\n", dmabuf->size);
}

static struct dma_buf_stats_attribute exporter_name_attribute =
	__ATTR_RO(exporter_name);
static struct dma_buf_stats_attribute size_attribute = __ATTR_RO(size);

static struct attribute *dma_buf_stats_default_attrs[] = {
	&exporter_name_attribute.attr,
	&size_attribute.attr,
	NULL,
};
ATTRIBUTE_GROUPS(dma_buf_stats_default);

static void dma_buf_sysfs_release(struct kobject *kobj)
{
	struct dma_buf_sysfs_entry *sysfs_entry;

	sysfs_entry = to_dma_buf_entry_from_kobj(kobj);
	kfree(sysfs_entry);
	pr_debug("dma_buf_sysfs_release\n");
}

static struct kobj_type dma_buf_ktype = {
	.sysfs_ops = &dma_buf_stats_sysfs_ops,
	.release = dma_buf_sysfs_release,
	.default_groups = dma_buf_stats_default_groups,
};

/*
 * Statistics files do not need to send uevents.
 */
static int dmabuf_sysfs_uevent_filter(struct kset *kset, struct kobject *kobj)
{
	return 0;
}

static const struct kset_uevent_ops dmabuf_sysfs_no_uevent_ops = {
	.filter = dmabuf_sysfs_uevent_filter,
};

static struct kset *dma_buf_stats_kset;
static struct kset *dma_buf_per_buffer_stats_kset;

#ifdef CONFIG_SYSFS_STATS_SETUP_ASYNC
static void scan_dma_buf_dbse_list(void)
{
	int ret;
	struct dma_buf_sysfs_entry *sysfs_entry, *next;
	LIST_HEAD(tmp_list);

	ret = mutex_lock_interruptible(&dbse_list.lock);
	if (ret) {
		pr_err("scan_dma_buf_dbse_list get lock fail ret is %d\n", ret);
		return;
	}
	if (list_empty(&dbse_list.head)) {
		pr_info("scan_dma_buf_dbse_list dbse_list is empty\n");
		mutex_unlock(&dbse_list.lock);
		return;
	}

	list_for_each_entry_safe(sysfs_entry, next, &dbse_list.head, lazy_entry_node) {
		if (sysfs_entry->kobj.state_initialized) {
			list_del_init(&sysfs_entry->lazy_entry_node);
			list_add(&sysfs_entry->lazy_entry_node, &tmp_list);
		}
	}
	mutex_unlock(&dbse_list.lock);

	if (list_empty(&tmp_list)) {
		pr_info("scan_dma_buf_dbse_list tmp_list is empty\n");
		return;
	}

	list_for_each_entry_safe(sysfs_entry, next, &tmp_list, lazy_entry_node) {
		list_del_init(&sysfs_entry->lazy_entry_node);
		kobject_del(&sysfs_entry->kobj);
		kobject_put(&sysfs_entry->kobj);
	}

	return;
}

static int scan_dma_buf_dbse_list_worker(void *p)
{
	set_freezable();

	while (!kthread_should_stop()) {
		wait_event_freezable(scan_dbse_wait,
				     atomic_read(&scan_dbse_wait_flag));
		atomic_set(&scan_dbse_wait_flag, 0);

		scan_dma_buf_dbse_list();
	}

	return 0;
}

static void try_wake_up_scan_dbse_list_worker(void)
{
	if (!wq_has_sleeper(&scan_dbse_wait)) {
		pr_debug("ignore the wake up for wq_has_sleeper\n");
		return;
	}

	if (!atomic_read(&scan_dbse_wait_flag)) {
		pr_debug("%s:woken up\n", __func__);

		atomic_set(&scan_dbse_wait_flag, 1);
		wake_up_interruptible(&scan_dbse_wait);
	}
}

static int create_scan_dma_buf_dbse_list_thread(void)
{
	const unsigned int priority_less = 5;
	struct sched_param param = {
		.sched_priority = MAX_PRIO - priority_less,
	};

	init_waitqueue_head(&scan_dbse_wait);
	atomic_set(&scan_dbse_wait_flag, 0);

	scan_dbse_worker = kthread_create(scan_dma_buf_dbse_list_worker, NULL,
					   "scan_dbse_worke");
	if (IS_ERR(scan_dbse_worker)) {
		pr_err("Failed to create scan_dbse_worker\n");
		return PTR_ERR(scan_dbse_worker);
	}

	sched_setscheduler_nocheck(scan_dbse_worker, SCHED_NORMAL, &param);
	set_user_nice(scan_dbse_worker, PRIO_TO_NICE(param.sched_priority));
	wake_up_process(scan_dbse_worker);
	return 0;
}
#endif

void dma_buf_stats_teardown(struct dma_buf *dmabuf)
{
	struct dma_buf_sysfs_entry *sysfs_entry;

#ifndef CONFIG_SYSFS_STATS_SETUP_ASYNC
	bool skip_sysfs_release = false;
#endif

	sysfs_entry = dmabuf->sysfs_entry;
	if (!sysfs_entry)
		return;

#ifdef CONFIG_SYSFS_STATS_SETUP_ASYNC
	mutex_lock(&dbse_list.lock);
	list_add(&sysfs_entry->lazy_entry_node, &dbse_list.head);
	sysfs_entry->dmabuf = NULL;
	mutex_unlock(&dbse_list.lock);
	try_wake_up_scan_dbse_list_worker();
#else
	trace_android_rvh_dma_buf_stats_teardown(sysfs_entry, &skip_sysfs_release);
	if (sysfs_entry->dmabuf == NULL) {
		pr_info("sysfs_entry->dmabuf == NULL\n");
	}
	if (!skip_sysfs_release) {
		pr_debug("dma_buf_stats_teardown\n");
		kobject_del(&sysfs_entry->kobj);
		kobject_put(&sysfs_entry->kobj);
	}
#endif
}

int dma_buf_init_sysfs_statistics(void)
{
#ifdef CONFIG_SYSFS_STATS_SETUP_ASYNC
	int ret;
#endif

	dma_buf_stats_kset = kset_create_and_add("dmabuf",
						 &dmabuf_sysfs_no_uevent_ops,
						 kernel_kobj);
	if (!dma_buf_stats_kset)
		return -ENOMEM;

	dma_buf_per_buffer_stats_kset = kset_create_and_add("buffers",
							    &dmabuf_sysfs_no_uevent_ops,
							    &dma_buf_stats_kset->kobj);
	if (!dma_buf_per_buffer_stats_kset) {
		kset_unregister(dma_buf_stats_kset);
		return -ENOMEM;
	}

#ifdef CONFIG_SYSFS_STATS_SETUP_ASYNC
	mutex_init(&dbse_list.lock);
	INIT_LIST_HEAD(&dbse_list.head);
	ret = create_scan_dma_buf_dbse_list_thread();
	if (ret)
		pr_err("create_scan_dma_buf_dbse_list_thread fail\n");
#endif

	return 0;
}

void dma_buf_uninit_sysfs_statistics(void)
{
	kset_unregister(dma_buf_per_buffer_stats_kset);
	kset_unregister(dma_buf_stats_kset);
}

struct dma_buf_create_sysfs_entry {
	struct dma_buf *dmabuf;
	struct work_struct work;
};

union dma_buf_create_sysfs_work_entry {
	struct dma_buf_create_sysfs_entry create_entry;
	struct dma_buf_sysfs_entry sysfs_entry;
};

static void sysfs_add_workfn(struct work_struct *work)
{
	struct dma_buf_create_sysfs_entry *create_entry =
		container_of(work, struct dma_buf_create_sysfs_entry, work);
	struct dma_buf *dmabuf = create_entry->dmabuf;

	if (!dmabuf) {
		pr_err("dmabuf is null in sysfs_add_workfn\n");
		return;
	}
	/*
	 * A dmabuf is ref-counted via its file member. If this handler holds the only
	 * reference to the dmabuf, there is no need for sysfs kobject creation. This is an
	 * optimization and a race; when the reference count drops to 1 immediately after
	 * this check it is not harmful as the sysfs entry will still get cleaned up in
	 * dma_buf_stats_teardown, which won't get called until the final dmabuf reference
	 * is released, and that can't happen until the end of this function.
	 */
	if (file_count(dmabuf->file) > 1) {
		dmabuf->sysfs_entry->dmabuf = dmabuf;
		/*
		 * kobject_init_and_add expects kobject to be zero-filled, but we have populated it
		 * to trigger this work function.
		 */
		memset(&dmabuf->sysfs_entry->kobj, 0, sizeof(dmabuf->sysfs_entry->kobj));
		dmabuf->sysfs_entry->kobj.kset = dma_buf_per_buffer_stats_kset;
		if (kobject_init_and_add(&dmabuf->sysfs_entry->kobj, &dma_buf_ktype, NULL,
						"%lu", file_inode(dmabuf->file)->i_ino)) {
			kobject_put(&dmabuf->sysfs_entry->kobj);
			dmabuf->sysfs_entry = NULL;
		}
	} else {
		/*
		 * Free the sysfs_entry and reset the pointer so dma_buf_stats_teardown doesn't
		 * attempt to operate on it.
		 */
		kfree(dmabuf->sysfs_entry);
		dmabuf->sysfs_entry = NULL;
	}
	dma_buf_put(dmabuf);
}

int dma_buf_stats_setup(struct dma_buf *dmabuf)
{
	struct dma_buf_create_sysfs_entry *create_entry;
	union dma_buf_create_sysfs_work_entry *work_entry;

	if (!dmabuf || !dmabuf->file)
		return -EINVAL;

	if (!dmabuf->exp_name) {
		pr_err("exporter name must not be empty if stats needed\n");
		return -EINVAL;
	}

	work_entry = kmalloc(sizeof(union dma_buf_create_sysfs_work_entry), GFP_KERNEL);
	if (!work_entry)
		return -ENOMEM;

	dmabuf->sysfs_entry = &work_entry->sysfs_entry;

	create_entry = &work_entry->create_entry;
	create_entry->dmabuf = dmabuf;

	INIT_WORK(&create_entry->work, sysfs_add_workfn);
	get_dma_buf(dmabuf); /* This reference will be dropped in sysfs_add_workfn. */
	schedule_work(&create_entry->work);

	return 0;
}
