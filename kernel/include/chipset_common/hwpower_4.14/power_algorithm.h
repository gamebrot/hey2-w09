/*
 * power_algorithm.h
 *
 * algorithm (compensation \ hysteresis \ filter) interface for power module
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

#ifndef _POWER_ALGORITHM_H_
#define _POWER_ALGORITHM_H_

#include <linux/slab.h>
#include <linux/bitops.h>
#include <linux/types.h>
#include <linux/math64.h>
#include <linux/ctype.h>

struct hysteresis_para {
	int refer_lth;
	int refer_hth;
	int hys_value;
};

struct common_hys_data {
	int refer;
	int para_size;
	struct hysteresis_para *para;
};

struct compensation_para {
	int refer;
	int comp_value;
};

struct common_comp_data {
	int refer;
	int para_size;
	struct compensation_para *para;
};

struct adc_comp_data {
	u32 adc_accuracy;
	int adc_v_ref;
	int v_pullup;
	int r_pullup;
	int r_comp;
};

struct smooth_comp_data {
	int current_comp;
	int current_raw;
	int last_comp;
	int last_raw;
	int max_delta;
};

struct smooth_rate {
	int curr_rate;
	int last_rate;
};

struct smooth_comp_para {
	struct smooth_rate fall_rate;
	struct smooth_rate rise_rate;
};

unsigned char power_change_char_to_digit(unsigned char data);
int power_get_min_value(const int *data, int size);
int power_get_max_value(const int *data, int size);
int power_get_average_value(const int *data, int size);
int power_get_hysteresis_index(int index, struct common_hys_data *data);
int power_get_compensation_value(int raw, struct common_comp_data *data);
int power_get_smooth_compensation_value(struct smooth_comp_data *data);
int power_get_adc_compensation_value(int adc_value, struct adc_comp_data *data);
int power_select_compensation_value(struct common_comp_data *data);
int power_calcu_smooth_compensation(struct smooth_comp_para *para, int current_comp, int last_comp);

#endif /* _POWER_ALGORITHM_H_ */
