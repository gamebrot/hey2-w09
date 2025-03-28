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
 * rtg ioctl entry
 */

#include "include/iaware_rtg.h"

#include <linux/atomic.h>
#include <linux/cred.h>
#include <linux/compat.h>

#include "include/frame_timer.h"
#include "include/proc_state.h"
#include "include/set_rtg.h"
#include "include/trans_rtg.h"
#include "include/frame_rme.h"

#ifdef  CONFIG_HONOR_RTG_PSEUDO_TICK
#include "include/rtg_pseudo.h"
#endif

atomic_t g_rtg_enable = ATOMIC_INIT(0);
atomic_t g_enable_type = ATOMIC_INIT(ALL_ENABLE); // default: all enable



static int set_enable_config(char *config_str)
{
	char *p = NULL;
	char *tmp = NULL;
	int value;
	int config[RTG_CONFIG_NUM];
	int i;

	for (i = 0; i < RTG_CONFIG_NUM; i++)
		config[i] = INVALID_VALUE;
	/* eg: key1:value1;key2:value2;key3:value3 */
	for (p = strsep(&config_str, ";"); p != NULL;
		p = strsep(&config_str, ";")) {
		tmp = strsep(&p, ":");
		if ((tmp == NULL) || (p == NULL))
			continue;
		if (kstrtoint((const char *)p, DECIMAL, &value))
			return -INVALID_ARG;

		if (!strcmp(tmp, "load_freq_switch")) {
			config[RTG_LOAD_FREQ] = value;
		} else if (!strcmp(tmp, "sched_cycle")) {
			config[RTG_FREQ_CYCLE] = value;
		} else if (!strcmp(tmp, "transfer_level")) {
			config[RTG_TRANS_DEPTH] = value;
		} else if (!strcmp(tmp, "max_threads")) {
			config[RTG_MAX_THREADS] = value;
		} else if (!strcmp(tmp, "frame_max_util")) {
			config[RTG_FRAME_MAX_UTIL] = value;
		} else if (!strcmp(tmp, "act_max_util")) {
			config[RTG_ACT_MAX_UTIL] = value;
		} else if (!strcmp(tmp, "invalid_interval")) {
			config[RTG_INVALID_INTERVAL] = value;
		} else if (!strcmp(tmp, "enable_type")) {
			atomic_set(&g_enable_type, value);
		} else {
			pr_err("[AWARE_RTG] parse enable config failed!\n");
			return -INVALID_ARG;
		}
	}
	for (i = 0; i < RTG_CONFIG_NUM; i++)
		pr_info("[AWARE_RTG] config[%d] = %d\n", i, config[i]);

	set_trans_config(config[RTG_TRANS_DEPTH], config[RTG_MAX_THREADS]);
	return init_proc_state(config, RTG_CONFIG_NUM);
}

/*lint -save -e446 -e666 -e732 -e734*/
static void enable(const struct rtg_enable_data *data)
{
	char temp[MAX_DATA_LEN];

	if (atomic_read(&g_rtg_enable) == 1) {
		pr_info("[AWARE_RTG] already enabled!\n");
		return;
	}
	if ((data->len <= 0) || (data->len >= MAX_DATA_LEN)) {
		pr_err("[AWARE_RTG] %s data len invalid\n", __func__);
		return;
	}
	if (copy_from_user(&temp, (void __user *)data->data, data->len)) {
		pr_err("[AWARE_RTG] %s copy user data failed\n", __func__);
		return;
	}
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
	temp[data->len] = '\0';

	if (set_enable_config(&temp) != SUCC) {
		pr_err("[AWARE_RTG] %s failed!\n", __func__);
		return;
	}
#pragma GCC diagnostic pop

	frame_timer_boost_init();
	atomic_set(&g_rtg_enable, 1);
#ifdef CONFIG_HONOR_RTG_PSEUDO_TICK
	frame_pseudo_create();
#endif
	pr_info("[AWARE_RTG] enabled!\n");
}

static void disable(void)
{
	if (atomic_read(&g_rtg_enable) == 0) {
		pr_info("[AWARE_RTG] already disabled!\n");
		return;
	}
	pr_info("[AWARE_RTG] disabled!\n");
	atomic_set(&g_rtg_enable, 0);
	deinit_proc_state();
	frame_timer_boost_stop();
#ifdef CONFIG_HONOR_RTG_PSEUDO_TICK
	frame_pseudo_destroy();
#endif
}

static long ctrl_set_enable(unsigned long arg)
{
	void __user *uarg = (void __user *)arg;
	struct rtg_enable_data rs_enable;

	if (uarg == NULL)
		return -INVALID_ARG;

	if (current_uid().val != SYSTEM_SERVER_UID)
		return -NOT_SYSTEM_UID;

	if (copy_from_user(&rs_enable, uarg, sizeof(rs_enable))) {
		pr_err("[AWARE_RTG] CMD_ID_SET_ENABLE copy data failed\n");
		return -INVALID_ARG;
	}
	if (rs_enable.enable == 1)
		enable(&rs_enable);
	else
		disable();

	return SUCC;
}

#ifdef CONFIG_USE_RTG_FRAME_SCHED
static long ctrl_set_config(int abi, unsigned long arg)
{
	void __user *uarg = (void __user *)arg;
	struct rtg_str_data rs;
	char temp[MAX_DATA_LEN];
	long ret = SUCC;

	if (uarg == NULL)
		return -INVALID_ARG;

	if (current_uid().val != SYSTEM_SERVER_UID)
		return -NOT_SYSTEM_UID;

	if (copy_from_user(&rs, uarg, sizeof(rs))) {
		pr_err("[AWARE_RTG] CMD_ID_SET_CONFIG copy data failed\n");
		return -INVALID_ARG;
	}
	if ((rs.len <= 0) || (rs.len >= MAX_DATA_LEN)) {
		pr_err("[AWARE_RTG] CMD_ID_SET_CONFIG data len invalid\n");
		return -INVALID_ARG;
	}

	switch (abi) {
	case IOCTL_ABI_ARM32:
		ret = copy_from_user(&temp,
			(void __user *)compat_ptr((compat_uptr_t)rs.data), rs.len);
		break;
	case IOCTL_ABI_AARCH64:
		ret = copy_from_user(&temp, (void __user *)rs.data, rs.len);
		break;
	default:
		pr_err("[AWARE_RTG] abi format error");
		return -INVALID_ARG;
	}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
	temp[rs.len] = '\0';
	rs.data = &temp;
	return parse_config(&rs);
#pragma GCC diagnostic pop
}
#endif /* CONFIG_USE_RTG_FRAME_SCHED */

static long ctrl_set_rtg_thread(int abi, unsigned long arg)
{
	void __user *uarg = (void __user *)arg;
	struct rtg_str_data rs;
	char temp[MAX_DATA_LEN];
	long ret = SUCC;

	if (uarg == NULL)
		return -INVALID_ARG;

	if (current_uid().val != SYSTEM_SERVER_UID)
		return -NOT_SYSTEM_UID;

	if (copy_from_user(&rs, uarg, sizeof(rs))) {
		pr_err("[AWARE_RTG] CMD_ID_SET_RTG_THREAD  copy data failed\n");
		return -INVALID_ARG;
	}
	if ((rs.len <= 0) || (rs.len >= MAX_DATA_LEN)) {
		pr_err("[AWARE_RTG] CMD_ID_SET_RTG_THREAD data len invalid\n");
		return -INVALID_ARG;
	}

	switch (abi) {
	case IOCTL_ABI_ARM32:
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-to-int-cast"
		ret = copy_from_user(&temp,
			(void __user *)compat_ptr((compat_uptr_t)rs.data), rs.len);
#pragma GCC diagnostic pop
		break;
	case IOCTL_ABI_AARCH64:
		ret = copy_from_user(&temp, (void __user *)rs.data, rs.len);
		break;
	default:
		pr_err("[AWARE_RTG] abi format error");
		return -INVALID_ARG;
	}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wincompatible-pointer-types"
	temp[rs.len] = '\0';
	rs.data = &temp;
	if (strstr(temp, "aux"))
		return parse_aux_thread(&rs);
	else if (strstr(temp, "key"))
		return parse_aux_comm_config(&rs);
	else if (strstr(temp, "boost"))
		return parse_boost_thread(&rs);
	else
		return parse_frame_thread(&rs);
#pragma GCC diagnostic pop
}

static long ctrl_get_qos(unsigned long arg)
{
	void __user *uarg = (void __user *)arg;
	struct rtg_qos_data qos_data;

	if (uarg == NULL)
		return -INVALID_ARG;

	if (copy_from_user(&qos_data, uarg, sizeof(qos_data))) {
		pr_err("[AWARE_RTG] CMD_ID_GET_QOS_CLASS copy data failed\n");
		return -INVALID_ARG;
	}
	qos_data.is_rtg = is_cur_frame();
	if (copy_to_user(uarg, &qos_data, sizeof(qos_data))) {
		pr_err("[AWARE_RTG] CMD_ID_GET_QOS_CLASS send data failed\n");
		return -INVALID_ARG;
	}
	return SUCC;
}

static long ctrl_activity_state(unsigned long arg, bool is_enter)
{
	void __user *uarg = (void __user *)arg;
	struct proc_state_data state_data;

	if (uarg == NULL)
		return -INVALID_ARG;

	if (copy_from_user(&state_data, uarg, sizeof(state_data))) {
		pr_err("[AWARE_RTG] CMD_ID_ACTIVITY_FREQ copy data failed\n");
		return -INVALID_ARG;
	}
	return update_act_state(&(state_data.head), is_enter);
}

static long ctrl_frame_state(unsigned long arg, bool is_enter)
{
	void __user *uarg = (void __user *)arg;
	struct proc_state_data state_data;
	int freq_type;

	if (uarg == NULL)
		return -INVALID_ARG;

	if (copy_from_user(&state_data, uarg, sizeof(state_data))) {
		pr_err("[AWARE_RTG] CMD_ID_FRAME_FREQ copy data failed\n");
		return -INVALID_ARG;
	}
#ifdef CONFIG_HONOR_RTG_FRAME_RME
	freq_type = ctrl_rme_state(state_data.frame_freq_type);
#else
	freq_type = state_data.frame_freq_type;
#endif

	return update_frame_state(&(state_data.head), freq_type, is_enter);
}

static long ctrl_stop_frame_freq(unsigned long arg)
{
	void __user *uarg = (void __user *)arg;
	struct rtg_data_head rd;

	if (uarg == NULL)
		return -INVALID_ARG;

	if (copy_from_user(&rd, uarg, sizeof(rd))) {
		pr_err("[AWARE_RTG] CMD_ID_END_FREQ copy data failed\n");
		return -INVALID_ARG;
	}

	return stop_frame_freq(&rd);
}

static long ctrl_rtg_boost(unsigned long arg)
{
	void __user *uarg = (void __user *)arg;
	struct rtg_boost_data boost_data;
	int duration;
	int min_util;

	if (uarg == NULL)
		return -INVALID_ARG;

	if (copy_from_user(&boost_data, uarg, sizeof(boost_data))) {
		pr_err("[AWARE_RTG] CMD_ID_END_FREQ copy data failed\n");
		return -INVALID_ARG;
	}

	duration = boost_data.duration;
	min_util = boost_data.min_util;
	if ((duration <= 0) || (duration > MAX_BOOST_DURATION_MS) ||
		(min_util <= 0) || (min_util > DEFAULT_MAX_UTIL))
		return -ERR_RTG_BOOST_ARG;

	start_rtg_boost();
	frame_timer_boost_start(duration, min_util);
	return 0;
}

static long rtg_config_ioctl(int abi, unsigned int cmd, unsigned long arg)
{
	long ret = SUCC;

	switch (cmd) {
	case CMD_ID_GET_QOS_CLASS: {
#ifdef CONFIG_RTG_DEBUG_LOG
		pr_err("[AWARE_RTG_XXX] CMD_ID_GET_QOS_CLASS !!!\n");
#endif
		ret = ctrl_get_qos(arg);
		break;
	}
	case CMD_ID_ENABLE_RTG_BOOST: {
#ifdef CONFIG_RTG_DEBUG_LOG
		pr_err("[AWARE_RTG_XXX] CMD_ID_ENABLE_RTG_BOOST !!!\n");
#endif
		ret = ctrl_rtg_boost(arg);
		break;
	}
#ifdef CONFIG_USE_RTG_FRAME_SCHED
	case CMD_ID_SET_CONFIG: {
		ret = ctrl_set_config(abi, arg);
		break;
	}
#endif /* CONFIG_USE_RTG_FRAME_SCHED */
	case CMD_ID_SET_ENABLE: {
#ifdef CONFIG_RTG_DEBUG_LOG
		pr_err("[AWARE_RTG_XXX] CMD_ID_SET_ENABLE !!!\n");
#endif
		ret = ctrl_set_enable(arg);
		break;
	}
	/* rme ioctl interface start CONFIG_HONOR_RTG_FRAME_RME */
	case CMD_ID_SET_MIN_UTIL: {
#ifdef CONFIG_RTG_DEBUG_LOG
		pr_err("[AWARE_RTG_XXX] CMD_ID_SET_MIN_UTIL !!!\n");
#endif
		ret = ctrl_set_min_util(arg);
		break;
	}
	case CMD_ID_SET_MARGIN: {
#ifdef CONFIG_RTG_DEBUG_LOG
		pr_err("[AWARE_RTG_XXX] CMD_ID_SET_MARGIN !!!\n");
#endif
		ret = ctrl_set_margin(arg);
		break;
	}
	case CMD_ID_SET_MIM_UTIL_AND_MARGIN: {
#ifdef CONFIG_RTG_DEBUG_LOG
		pr_err("[AWARE_RTG_XXX] CMD_ID_SET_MIM_UTIL_AND_MARGIN !!!\n");
#endif
		ret = ctrl_set_min_util_and_margin(arg);
		break;
	}
	case CMD_ID_SET_RME_MARGIN: {
#ifdef CONFIG_RTG_DEBUG_LOG
		pr_err("[AWARE_RTG_XXX] CMD_ID_SET_RME_MARGIN !!!\n");
#endif
		ret = ctrl_set_rme_margin(arg);
		break;
	}
	case CMD_ID_GET_RME_MARGIN: {
#ifdef CONFIG_RTG_DEBUG_LOG
		pr_err("[AWARE_RTG_XXX] CMD_ID_GET_RME_MARGIN !!!\n");
#endif
		ret = ctrl_get_rme_margin(arg);
		break;
	}
	/* rme ioctl interface end CONFIG_HONOR_RTG_FRAME_RME */
	default:
		pr_err("[AWARE_RTG] CMD error, here is default, cmd=%u(%d)\n",
			cmd, _IOC_NR(cmd));
		ret = -INVALID_CMD;
		break;
	}
	return ret;
}

static long do_proc_rtg_ioctl(int abi, struct file *file, unsigned int cmd, unsigned long arg)
{
	long ret = SUCC;

	if (_IOC_TYPE(cmd) != RTG_SCHED_IPC_MAGIC)
		return -INVALID_MAGIC;

	if ((cmd != CMD_ID_SET_ENABLE) && !atomic_read(&g_rtg_enable))
		return -RTG_DISABLED;

	if (_IOC_NR(cmd) >= CMD_ID_MAX)
		return -INVALID_CMD;

	switch (cmd) {
	case CMD_ID_BEGIN_FRAME_FREQ: {
#ifdef CONFIG_RTG_DEBUG_LOG
		pr_err("[AWARE_RTG_XXX] CMD_ID_BEGIN_FRAME_FREQ !!!\n");
#endif
		ret = ctrl_frame_state(arg, true);
		break;
	}
	case CMD_ID_END_FRAME_FREQ: {
#ifdef CONFIG_RTG_DEBUG_LOG
		pr_err("[AWARE_RTG_XXX] CMD_ID_END_FRAME_FREQ !!!\n");
#endif
		ret = ctrl_frame_state(arg, false);
		break;
	}
	case CMD_ID_BEGIN_ACTIVITY_FREQ: {
#ifdef CONFIG_RTG_DEBUG_LOG
		pr_err("[AWARE_RTG_XXX] CMD_ID_BEGIN_ACTIVITY_FREQ !!!\n");
#endif
		ret = ctrl_activity_state(arg, true);
		break;
	}
	case CMD_ID_END_ACTIVITY_FREQ: {
#ifdef CONFIG_RTG_DEBUG_LOG
		pr_err("[AWARE_RTG_XXX] CMD_ID_END_ACTIVITY_FREQ !!!\n");
#endif
		ret = ctrl_activity_state(arg, false);
		break;
	}
	case CMD_ID_SET_RTG_THREAD: {
#ifdef CONFIG_RTG_DEBUG_LOG
		pr_err("[AWARE_RTG_XXX] CMD_ID_SET_RTG_THREAD !!!\n");
#endif
		ret = ctrl_set_rtg_thread(abi, arg);
		break;
	}
	case CMD_ID_END_FREQ: {
#ifdef CONFIG_RTG_DEBUG_LOG
		pr_err("[AWARE_RTG_XXX] CMD_ID_END_FREQ !!!\n");
#endif
		ret = ctrl_stop_frame_freq(arg);
		break;
	}
	default:
		ret = rtg_config_ioctl(abi, cmd, arg);
		break;
	}
	return ret;
}

bool is_frame_rtg_enable(void)
{
	return atomic_read(&g_rtg_enable) == 1;
}

int get_enable_type(void)
{
	return atomic_read(&g_enable_type);
}

int proc_rtg_open(struct inode *inode, struct file *filp)
{
	if ((current_uid().val != SYSTEM_SERVER_UID) &&
		(current_uid().val < MIN_APP_UID))
		return -OPEN_ERR_UID;
	if ((current_uid().val >= MIN_APP_UID) &&
		(current->pid != current->tgid))
		return -OPEN_ERR_TID;
	return SUCC;
}

#ifdef CONFIG_COMPAT
long proc_rtg_compat_ioctl(struct file *file,
	unsigned int cmd, unsigned long arg)
{
	/*lint -e712*/
	return do_proc_rtg_ioctl(IOCTL_ABI_ARM32, file, cmd,
		(unsigned long)(compat_ptr((compat_uptr_t)arg)));
	/*lint +e712*/
}
#endif

long proc_rtg_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	return do_proc_rtg_ioctl(IOCTL_ABI_AARCH64, file, cmd, arg);
}
/*lint -restore*/
