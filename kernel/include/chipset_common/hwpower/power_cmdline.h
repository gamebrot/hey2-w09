/*
 * power_cmdline.h
 *
 * cmdline parse interface for power module
 *
 * Copyright (c) 2020-2020 Honor Device Co., Ltd.
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

#ifndef _POWER_CMDLINE_H_
#define _POWER_CMDLINE_H_

#define MAX_CMDLINE_LEN 640

int get_power_cmdline(char *cmdline);
bool power_cmdline_is_root_mode(void);
bool power_cmdline_is_factory_mode(void);
bool power_cmdline_is_runtest_mode(void);
bool power_cmdline_is_recovery_mode(void);
bool power_cmdline_is_erecovery_mode(void);
bool power_cmdline_is_powerdown_charging_mode(void);
int power_cmdline_get_battery_info(char *name, unsigned int name_size, int role);

#endif /* _POWER_CMDLINE_H_ */
