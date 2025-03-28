/*
 * Copyright (c) Honor Technologies Co., Ltd. 2020. All rights reserved.
 * Description: hyperhold header file
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Author:	He Biao <hebiao6.>
 *		Wang Cheng Ke <wangchengke2.>
 *		Wang Fa <fa.wang.>
 *
 * Create: 2020-4-16
 *
 */

#ifndef _HYPERHOLD_LIST_H_
#define _HYPERHOLD_LIST_H_

#define HH_LIST_PTR_SHIFT 23
#define HH_LIST_MCG_SHIFT_HALF 8
#define HH_LIST_LOCK_BIT HH_LIST_MCG_SHIFT_HALF
#define HH_LIST_PRIV_BIT (HH_LIST_PTR_SHIFT + HH_LIST_MCG_SHIFT_HALF + \
				HH_LIST_MCG_SHIFT_HALF + 1)
struct hh_list_head {
	unsigned int mcg_hi : HH_LIST_MCG_SHIFT_HALF;
	unsigned int lock : 1;
	unsigned int prev : HH_LIST_PTR_SHIFT;
	unsigned int mcg_lo : HH_LIST_MCG_SHIFT_HALF;
	unsigned int priv : 1;
	unsigned int next : HH_LIST_PTR_SHIFT;
};
struct hh_list_table {
	struct hh_list_head *(*get_node)(int, void *);
	void *private;
};
#define idx_node(idx, tab) ((tab)->get_node((idx), (tab)->private))
#define next_idx(idx, tab) (idx_node((idx), (tab))->next)
#define prev_idx(idx, tab) (idx_node((idx), (tab))->prev)

#define is_last_idx(idx, hidx, tab) (next_idx(idx, tab) == (hidx))
#define is_first_idx(idx, hidx, tab) (prev_idx(idx, tab) == (hidx))

struct hh_list_table *alloc_table(struct hh_list_head *(*get_node)(int, void *),
				  void *private, gfp_t gfp);
void hh_lock_list(int idx, struct hh_list_table *table);
void hh_unlock_list(int idx, struct hh_list_table *table);

void hh_list_init(int idx, struct hh_list_table *table);
void hh_list_add_nolock(int idx, int hidx, struct hh_list_table *table);
void hh_list_add_tail_nolock(int idx, int hidx, struct hh_list_table *table);
void hh_list_del_nolock(int idx, int hidx, struct hh_list_table *table);
void hh_list_add(int idx, int hidx, struct hh_list_table *table);
void hh_list_add_tail(int idx, int hidx, struct hh_list_table *table);
void hh_list_del(int idx, int hidx, struct hh_list_table *table);

unsigned short hh_list_get_mcgid(int idx, struct hh_list_table *table);
void hh_list_set_mcgid(int idx, struct hh_list_table *table, int mcg_id);
bool hh_list_set_priv(int idx, struct hh_list_table *table);
bool hh_list_clear_priv(int idx, struct hh_list_table *table);

bool hh_list_empty(int hidx, struct hh_list_table *table);

#define hh_list_for_each_entry(idx, hidx, tab) \
	for ((idx) = next_idx((hidx), (tab)); \
	     (idx) != (hidx); (idx) = next_idx((idx), (tab)))
#define hh_list_for_each_entry_safe(idx, tmp, hidx, tab) \
	for ((idx) = next_idx((hidx), (tab)), (tmp) = next_idx((idx), (tab)); \
	     (idx) != (hidx); (idx) = (tmp), (tmp) = next_idx((idx), (tab)))
#define hh_list_for_each_entry_reverse(idx, hidx, tab) \
	for ((idx) = prev_idx((hidx), (tab)); \
	     (idx) != (hidx); (idx) = prev_idx((idx), (tab)))
#define hh_list_for_each_entry_reverse_safe(idx, tmp, hidx, tab) \
	for ((idx) = prev_idx((hidx), (tab)), (tmp) = prev_idx((idx), (tab)); \
	     (idx) != (hidx); (idx) = (tmp), (tmp) = prev_idx((idx), (tab)))

#endif
