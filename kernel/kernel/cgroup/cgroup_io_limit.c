/*
 * cgroup_io_limit.c
 *
 * Control group iolimit subsystem
 *
 * Copyright (c) 2017-2020 Honor Technologies Co., Ltd
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <linux/iolimit_cgroup.h>

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/jiffies.h>
#include <linux/blk-cgroup.h>
#include <linux/sched/signal.h>
#include <linux/version.h>

#define WAIT_INTERVAL_MS	(125)
#define WAIT_PARTS_NUM		(8)

enum Switch_Stat {
	STAT_OFF,
	STAT_ON,
};

static int is_need_iolimit(struct iolimit_cgroup *iolimitcg)
{
	int ret = 0;
	struct blkcg *blkcg = task_blkcg(current);

	if (blkcg->type <= BLK_THROTL_KBG)
		return 0;

	ret = signal_pending_state(TASK_INTERRUPTIBLE, current);
	if (ret == TASK_INTERRUPTIBLE)
		return 0;

	return atomic64_read(&iolimitcg->switching);
}

static bool is_write_need_wakeup(struct iolimit_cgroup *iolimitcg)
{
	int ret = false;
	struct blkcg *blkcg = NULL;

	if (atomic64_read(&iolimitcg->switching) == 0)
		ret = true;

	if (iolimitcg->write_part_nbyte > iolimitcg->write_already_used)
		ret = true;

	rcu_read_lock();
	if (iolimitcg != task_iolimitcg(current))
		ret = true;

	blkcg = task_blkcg(current);
	if (blkcg->type <= BLK_THROTL_KBG)
		ret = true;

	rcu_read_unlock();
	return ret;
}

static bool is_read_need_wakeup(struct iolimit_cgroup *iolimitcg)
{
	int ret = false;
	struct blkcg *blkcg = NULL;

	if (atomic64_read(&iolimitcg->switching) == 0)
		ret = true;

	if (iolimitcg->read_part_nbyte > iolimitcg->read_already_used)
		ret = true;

	rcu_read_lock();
	if (iolimitcg != task_iolimitcg(current))
		ret = true;

	blkcg = task_blkcg(current);
	if (blkcg->type <= BLK_THROTL_KBG)
		ret = true;

	rcu_read_unlock();
	return ret;
}

void do_io_write_bandwidth_control(size_t count)
{
	size_t may_io_cnt;
	struct iolimit_cgroup *iolimitcg = NULL;

repeat:
	rcu_read_lock();
	iolimitcg = task_iolimitcg(current);
	if (!is_need_iolimit(iolimitcg)) {
		rcu_read_unlock();
		return;
	}

	spin_lock_bh(&iolimitcg->write_lock);
	may_io_cnt = iolimitcg->write_part_nbyte -
		iolimitcg->write_already_used;
	if (may_io_cnt < count) {
		spin_unlock_bh(&iolimitcg->write_lock);
		if (css_tryget_online(&iolimitcg->css)) {
			rcu_read_unlock();
			/*lint -save -e666*/
			wait_event_interruptible_timeout(iolimitcg->write_wait,
				is_write_need_wakeup(iolimitcg),
				msecs_to_jiffies(WAIT_INTERVAL_MS));
			/*lint -restore*/
			css_put(&iolimitcg->css);
		} else {
			rcu_read_unlock();
		}
		goto repeat;
	} else {
		iolimitcg->write_already_used += count;
	}

	spin_unlock_bh(&iolimitcg->write_lock);
	rcu_read_unlock();
}

void do_io_read_bandwidth_control(size_t count)
{
	size_t may_io_cnt;
	struct iolimit_cgroup *iolimitcg = NULL;

repeat:
	rcu_read_lock();
	iolimitcg = task_iolimitcg(current);
	if (!is_need_iolimit(iolimitcg)) {
		rcu_read_unlock();
		return;
	}

	spin_lock_bh(&iolimitcg->read_lock);
	may_io_cnt = iolimitcg->read_part_nbyte - iolimitcg->read_already_used;
	if (may_io_cnt < count) {
		spin_unlock_bh(&iolimitcg->read_lock);
		if (css_tryget_online(&iolimitcg->css)) {
			rcu_read_unlock();
			/*lint -save -e666*/
			wait_event_interruptible_timeout(iolimitcg->read_wait,
				is_read_need_wakeup(iolimitcg),
				msecs_to_jiffies(WAIT_INTERVAL_MS));
			/*lint -restore*/
			css_put(&iolimitcg->css);
		} else {
			rcu_read_unlock();
		}

		if (task_in_pagefault(current))
			return;
		goto repeat;
	} else {
		iolimitcg->read_already_used += count;
	}

	spin_unlock_bh(&iolimitcg->read_lock);
	rcu_read_unlock();
}

static void handle_write_timer(struct iolimit_cgroup *iolimitcg)
{
	if (!iolimitcg)
		return;
	spin_lock_bh(&iolimitcg->write_lock);
	iolimitcg->write_already_used = 0;
	spin_unlock_bh(&iolimitcg->write_lock);
	wake_up_all(&iolimitcg->write_wait);
	mod_timer(&iolimitcg->write_timer, jiffies + (HZ / WAIT_PARTS_NUM));
}

static void handle_read_timer(struct iolimit_cgroup *iolimitcg)
{
	if (!iolimitcg)
		return;
	spin_lock_bh(&iolimitcg->read_lock);
	iolimitcg->read_already_used = 0;
	spin_unlock_bh(&iolimitcg->read_lock);
	wake_up_all(&iolimitcg->read_wait);
	mod_timer(&iolimitcg->read_timer, jiffies + (HZ / WAIT_PARTS_NUM));
}

/* timer_list->function prototype changed in v4.15 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 15, 0)
static void write_timer_handler(unsigned long data)
{
	struct iolimit_cgroup *iolimitcg = (struct iolimit_cgroup *)data;

	handle_write_timer(iolimitcg);
}

static void read_timer_handler(unsigned long data)
{
	struct iolimit_cgroup *iolimitcg = (struct iolimit_cgroup *)data;

	handle_read_timer(iolimitcg);
}

static void init_write_timer(struct iolimit_cgroup *iolimitcg)
{
	setup_timer(&iolimitcg->write_timer, write_timer_handler,
			(unsigned long)iolimitcg);
}

static void init_read_timer(struct iolimit_cgroup *iolimitcg)
{
	setup_timer(&iolimitcg->read_timer, read_timer_handler,
			(unsigned long)iolimitcg);
}
#else
static void write_timer_handler(struct timer_list *t)
{
	struct iolimit_cgroup *iolimitcg = from_timer(iolimitcg, t, write_timer);

	handle_write_timer(iolimitcg);
}

static void read_timer_handler(struct timer_list *t)
{
	struct iolimit_cgroup *iolimitcg = from_timer(iolimitcg, t, read_timer);

	handle_read_timer(iolimitcg);
}

static void init_write_timer(struct iolimit_cgroup *iolimitcg)
{
	timer_setup(&iolimitcg->write_timer, write_timer_handler, 0);
}

static void init_read_timer(struct iolimit_cgroup *iolimitcg)
{
	timer_setup(&iolimitcg->read_timer, read_timer_handler, 0);
}
#endif

static struct cgroup_subsys_state *iolimit_css_alloc(
	struct cgroup_subsys_state *parent)
{
	struct iolimit_cgroup *iolimitcg =
		kzalloc(sizeof(struct iolimit_cgroup), GFP_KERNEL);

	if (!iolimitcg)
		return ERR_PTR(-ENOMEM);

	atomic64_set(&iolimitcg->switching, 0);

	atomic64_set(&iolimitcg->write_limit, 0);
	iolimitcg->write_part_nbyte = 0;
	iolimitcg->write_already_used = 0;
	init_write_timer(iolimitcg);
	spin_lock_init(&iolimitcg->write_lock);
	init_waitqueue_head(&iolimitcg->write_wait);

	atomic64_set(&iolimitcg->read_limit, 0);
	iolimitcg->read_part_nbyte = 0;
	iolimitcg->read_already_used = 0;
	init_read_timer(iolimitcg);
	spin_lock_init(&iolimitcg->read_lock);
	init_waitqueue_head(&iolimitcg->read_wait);

	return &iolimitcg->css;
}

static void iolimit_css_free(struct cgroup_subsys_state *css)
{
	struct iolimit_cgroup *iolimitcg = NULL;

	if (!css)
		return;

	iolimitcg = css_iolimit(css);
	del_timer_sync(&iolimitcg->write_timer);
	del_timer_sync(&iolimitcg->read_timer);
	kfree(css_iolimit(css));
}

static s64 iolimit_switching_read(
	struct cgroup_subsys_state *css, struct cftype *cft)
{
	struct iolimit_cgroup *iolimitcg = NULL;

	if (!css)
		return -EINVAL;

	iolimitcg = css_iolimit(css);
	return atomic64_read(&iolimitcg->switching);
}

static int iolimit_switching_write(
	struct cgroup_subsys_state *css, struct cftype *cft, s64 switching)
{
	struct iolimit_cgroup *iolimitcg = NULL;
	int err = 0;

	if (((switching != STAT_OFF) && (switching != STAT_ON)) || !css) {
		err = -EINVAL;
		goto out;
	}

	iolimitcg = css_iolimit(css);
	atomic64_set(&iolimitcg->switching, switching);
	if (switching == STAT_OFF) {
		wake_up_all(&iolimitcg->write_wait);
		del_timer_sync(&iolimitcg->write_timer);

		wake_up_all(&iolimitcg->read_wait);
		del_timer_sync(&iolimitcg->read_timer);
	} else {
		mod_timer(&iolimitcg->write_timer,
			jiffies + (HZ / WAIT_PARTS_NUM));
		iolimitcg->write_already_used = iolimitcg->write_part_nbyte;

		mod_timer(&iolimitcg->read_timer,
			jiffies + (HZ / WAIT_PARTS_NUM));
		iolimitcg->read_already_used = iolimitcg->read_part_nbyte;
	}
out:
	return err;
}

static s64 writeiolimit_read(
	struct cgroup_subsys_state *css, struct cftype *cft)
{
	struct iolimit_cgroup *iolimitcg = NULL;

	if (!css)
		return -EINVAL;

	iolimitcg = css_iolimit(css);
	return atomic64_read(&iolimitcg->write_limit);
}

static int writeiolimit_write(
	struct cgroup_subsys_state *css, struct cftype *cft, s64 limit)
{
	struct iolimit_cgroup *iolimitcg = NULL;
	int err = 0;

	if ((limit <= 0) || !css) {
		err = -EINVAL;
		goto out;
	}

	iolimitcg = css_iolimit(css);
	atomic64_set(&iolimitcg->write_limit, limit);
	spin_lock_bh(&iolimitcg->write_lock);
	iolimitcg->write_part_nbyte = limit / WAIT_PARTS_NUM;
	spin_unlock_bh(&iolimitcg->write_lock);
out:
	return err;
}

static s64 readiolimit_read(
	struct cgroup_subsys_state *css, struct cftype *cft)
{
	struct iolimit_cgroup *iolimitcg = NULL;

	if (!css)
		return -EINVAL;

	iolimitcg = css_iolimit(css);
	return atomic64_read(&iolimitcg->read_limit);
}

static int readiolimit_write(
	struct cgroup_subsys_state *css, struct cftype *cft, s64 limit)
{
	struct iolimit_cgroup *iolimitcg = NULL;
	int err = 0;

	if ((limit <= 0) || !css) {
		err = -EINVAL;
		goto out;
	}

	iolimitcg = css_iolimit(css);
	atomic64_set(&iolimitcg->read_limit, limit);
	spin_lock_bh(&iolimitcg->read_lock);
	iolimitcg->read_part_nbyte = limit / WAIT_PARTS_NUM;
	spin_unlock_bh(&iolimitcg->read_lock);
out:
	return err;
}

static struct cftype iolimit_files[] = {
	{
		.name = "switching",
		.flags = CFTYPE_NOT_ON_ROOT,
		.read_s64 = iolimit_switching_read,
		.write_s64 = iolimit_switching_write,
	},
	{
		.name = "write_limit",
		.flags = CFTYPE_NOT_ON_ROOT,
		.read_s64 = writeiolimit_read,
		.write_s64 = writeiolimit_write,
	},
	{
		.name = "read_limit",
		.flags = CFTYPE_NOT_ON_ROOT,
		.read_s64 = readiolimit_read,
		.write_s64 = readiolimit_write,
	},
	{}
};

struct cgroup_subsys iolimit_cgrp_subsys = {
	.css_alloc      = iolimit_css_alloc,
	.css_free       = iolimit_css_free,
	.attach         = NULL,
	.legacy_cftypes = iolimit_files,
};

