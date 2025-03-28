/*
 * direct_charge_cable.h
 *
 * cable detect for direct charge module
 *
 * Copyright (c) 2022 Honor Technologies Co., Ltd.
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

#ifndef _DIRECT_CHARGE_CABLE_H_
#define _DIRECT_CHARGE_CABLE_H_

struct resist_data {
	int vadapt;
	int iadapt;
	int vbus;
	int ibus;
};

#ifdef CONFIG_DIRECT_CHARGER
int dc_get_cable_max_current(void);
void dc_detect_cable(void);
int dc_calculate_path_resistance(int *rpath);
int dc_calculate_second_path_resistance(void);
int dc_resist_handler(int mode, int value);
int dc_second_resist_handler(void);
#else
static inline int dc_get_cable_max_current(void)
{
	return -1;
}

static inline void dc_detect_cable(void)
{
}

static inline int dc_calculate_path_resistance(int *rpath)
{
	return -1;
}

static inline int dc_calculate_second_path_resistance(int *rpath)
{
	return -1;
}

static inline int dc_resist_handler(int mode, int value)
{
	return 0;
}

static inline int dc_second_resist_handler(void)
{
	return 0;
}
#endif /* CONFIG_DIRECT_CHARGER */

#endif /* _DIRECT_CHARGE_CABLE_H_ */
