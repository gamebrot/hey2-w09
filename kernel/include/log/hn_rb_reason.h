/*
  * Copyright (c) Honor Device Co., Ltd. 2023-2023. All rights reserved.
  * Description:honor Android Exception Engine reboot reason record interface
  * Author: Chen Erlei
  * Create: 2023-03-30
  */

#ifndef _HN_RB_REASON_H_
#define _HN_RB_REASON_H_

#include <linux/types.h>

#define RB_MREASON_STR_MAX      32
#define RB_SREASON_STR_MAX      128

enum rb_mreason_type {
	RB_M_UNINIT = 0,
	RB_M_NORMAL,
	RB_M_APANIC,
	RB_M_AWDT,
	RB_M_TEE_CRASH,
	RB_M_UNKNOWN,
};

struct hn_aee_reboot_reason {
	uint32_t reset_reason;          /* reserve flag */
	uint32_t inner_reset_reason;
	uint32_t reset_type;
	uint32_t mreason_num;
	uint32_t mreason_str_flag;
	uint32_t sreason_str_flag;
	uint32_t attach_info_flag;
	uint32_t emmc_flag;
	char mreason_str[RB_MREASON_STR_MAX];
	char sreason_str[RB_SREASON_STR_MAX];
	char attach_info[RB_SREASON_STR_MAX];
};

size_t get_hn_aee_rb_reason_len(void);

unsigned long get_hn_aee_rb_reason_buf(void);

void set_hn_aee_rb_main_reason(uint32_t reason);

void set_hn_aee_rb_sub_reason(const char *sub, ...);

void set_hn_aee_rb_attach_info(const char *info, ...);

#endif // _HN_RB_REASON_H_
