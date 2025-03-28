 /*
  * process for honor rtc driver
  *
  * Copyright (c) 2019-2021 Honor Technologies Co., Ltd.
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

#ifndef __HONOR_RTC_H__
#define __HONOR_RTC_H__

#include <linux/platform_device.h>
#include <linux/rtc.h>

int honor_rtc_remove(struct platform_device *pdev);
int honor_rtc_init(struct device *dev);
const struct rtc_class_ops *get_honor_rtc_rw_ops(const struct rtc_class_ops
						*qpnp_rtc_rw_ops_ptr);

#endif
