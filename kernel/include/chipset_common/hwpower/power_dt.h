/*
 * power_dt.h
 *
 * power debug test
 *
 * Copyright (c) 2023-2023 Honor Device Co., Ltd.
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
 */

#ifndef _POWER_DT_H_
#define _POWER_DT_H_

#include <linux/list.h>
#include <linux/device.h>

#define POWER_DT_CONF_MAX_CNT  64
#define POWER_DT_INF_MAX_CNT   64
#define POWER_DT_REG_VAL_LEN   8
#define POWER_DT_UEVENT_LEN    1024
#define POWER_DT_NOTIFY_NUM    2
#define POWER_DT_WORK_INTERVAL 100
#define POWER_DT_WAIT_TIMEOUT  1000
#define POWER_DT_EXTRA_VAL_LEN 128
#define POWER_DT_BUF_LEN       256


enum power_dt_type {
	POWER_DT_TYPE_BEGIN = 0,
	POWER_DT_TYPE_BUCK = POWER_DT_TYPE_BEGIN,
	POWER_DT_TYPE_DIRECT_CHARGER,
	POWER_DT_TYPE_BATTERY_UI,
	POWER_DT_TYPE_SCP_PROTOCOL,
	POWER_DT_TYPE_MT6360,
	POWER_DT_TYPE_SC8545,
	POWER_DT_TYPE_FG_COUL,
	POWER_DT_TYPE_MAX,
	POWER_DT_TYPE_END = POWER_DT_TYPE_MAX,
};

struct power_dt_config {
	char *desc[POWER_DT_CONF_MAX_CNT];
	void *conf[POWER_DT_CONF_MAX_CNT];
	size_t size[POWER_DT_CONF_MAX_CNT];
};

struct power_dt_ops {
	int (*dump_reg)(u8 *reg_val, int start, int num);
	int (*mock_register)(void);
	int (*mock_unregister)(void);
};

struct power_dt_dump_reg {
	int start_reg_addr;
	int reg_num;
};

struct power_dt_mock {
	bool mock_done;
	bool changed;
	int val;
	char extra_val[POWER_DT_EXTRA_VAL_LEN];
	int ret_val;
};

struct power_dt {
	char *name;
	struct device *dev;
	struct mutex mock_lock;
	struct delayed_work mock_change_work;
	wait_queue_head_t wait_que;
	enum power_dt_type type;
	struct power_dt_config config;
	struct power_dt_ops ops;
	struct power_dt_dump_reg reg_info;
	int mock_enable;
	int mock_interface_num;
	struct power_dt_mock mock_info[POWER_DT_INF_MAX_CNT];
};

#ifdef CONFIG_HONOR_POWER_DT
int power_dt_register(struct power_dt *pdt);
void power_dt_unregister(enum power_dt_type type);
void power_dt_mock_set_interface(struct power_dt *pdt, int index, int val, char *extra_val);
void power_dt_mock_get_interface(struct power_dt *pdt, int index);

#else
static inline int power_dt_register(struct power_dt *pdt)
{
	return 0;
}

static inline void power_dt_unregister(enum power_dt_type type)
{
}

static inline void power_dt_mock_set_interface(int index, int val, char *extra_val)
{
}

static inline void power_dt_mock_get_interface(int index)
{
}

#endif /* CONFIG_HONOR_POWER_DT */
#endif /* _POWER_DT_H_ */
