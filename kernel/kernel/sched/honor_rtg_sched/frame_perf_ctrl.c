/*
 * Copyright (c) Honor Device Co., Ltd. 2019-2020. All rights reserved.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * frame related interfaces defined for perf_ctrl
 *
 */

#include <linux/uaccess.h>
#include <include/rtg_sched.h>
#include <include/frame.h>

#ifdef CONFIG_USE_RTG_FRAME_SCHED
int perf_ctrl_set_frame_rate(void __user *uarg)
{
	int frame_rate, ret;

	if (uarg == NULL)
		return -EINVAL;

	if (copy_from_user(&frame_rate, uarg, sizeof(int))) {
		pr_err("%s: copy_from_user fail\n", __func__);
		return -EFAULT;
	}

	ret = set_frame_rate(frame_rate);
	if (ret)
		return ret;

	ret = sched_set_group_window_size(DEFAULT_RT_FRAME_ID, frame_rate);
	return ret;
}
#else
int perf_ctrl_set_frame_rate(void __user *uarg)
{
	return 0;
}
#endif

#ifdef CONFIG_USE_RTG_FRAME_SCHED
int perf_ctrl_set_frame_margin(void __user *uarg)
{
	int frame_margin, ret;

	if (uarg == NULL)
		return -EINVAL;

	if (copy_from_user(&frame_margin, uarg, sizeof(int))) {
		pr_err("%s: copy_from_user fail\n", __func__);
		return -EFAULT;
	}

	ret = set_frame_margin(frame_margin);

	return ret;
}
#else
int perf_ctrl_set_frame_margin(void __user *uarg)
{
	return 0;
}
#endif

#ifdef CONFIG_USE_RTG_FRAME_SCHED
int perf_ctrl_set_frame_status(void __user *uarg)
{
	unsigned long frame_status;
	int ret;

	if (uarg == NULL)
		return -EINVAL;

	if (copy_from_user(&frame_status, uarg, sizeof(unsigned long))) {
		pr_err("%s: copy_from_user fail\n", __func__);
		return -EFAULT;
	}

	ret = sched_set_group_window_rollover(DEFAULT_RT_FRAME_ID);
	if (ret != 0)
		return ret;

	ret = set_frame_status(frame_status);
	return ret;
}
#else
int perf_ctrl_set_frame_status(void __user *uarg)
{
	return 0;
}
#endif
