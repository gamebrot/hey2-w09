/*
 * process for himntn function
 *
 * Copyright (c) 2019-2019 Honor Technologies Co., Ltd.
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

#ifndef __HIMNTN_KERNEL_H__
#define __HIMNTN_KERNEL_H__

#include <linux/printk.h>

/*
 * factory version config default
 * 000000000001110010000101111101101111111000000000
 * beta version config default
 * 000000000000010000000101101101101111111000000000
 * commercial version config default
 * 000000000000010000100000000001000000000000000000
 */
#define HIMNTN_DEFAULT_FACTORY 0x1C85F6FE00
#define HIMNTN_DEFAULT_BETA 0x405B6FE00
#define HIMNTN_DEDAULT_COMMERCIAL 0x420040000

/*
 * Description: himntn log level switch, close when code upload
 * 4: print all level log
 * 3: print ERR/WARN/INFO level log
 * 2: print ERR/WARN level log
 * 1: print only ERR level log
 */
#define HIMNTN_LOG_LEVEL 4

enum log_level_enum {
	HIMNTN_LOG_ERROR = 1,
	HIMNTN_LOG_WARNING,
	HIMNTN_LOG_INFO,
	HIMNTN_LOG_DEBUG,
	HIMNTN_LOG_UNKNOWN,
};

/* log print control implement */
#define HIMNTN_ERR(msg, ...)                                               \
do {                                                                       \
	if (HIMNTN_LOG_LEVEL >= HIMNTN_LOG_ERROR)                          \
		pr_err("[HIMNTN/E]%s: " msg, __func__, ##__VA_ARGS__);     \
} while (0)

#define HIMNTN_WARNING(msg, ...)                                           \
do {                                                                       \
	if (HIMNTN_LOG_LEVEL >= HIMNTN_LOG_WARNING)                        \
		pr_warn("[HIMNTN/W]%s: " msg, __func__, ##__VA_ARGS__);    \
} while (0)

#define HIMNTN_INFO(msg, ...)                                              \
do {                                                                       \
	if (HIMNTN_LOG_LEVEL >= HIMNTN_LOG_INFO)                           \
		pr_info("[HIMNTN/I]%s: " msg, __func__, ##__VA_ARGS__);    \
} while (0)

#define HIMNTN_DEBUG(msg, ...)                                             \
do {                                                                       \
	if (HIMNTN_LOG_LEVEL >= HIMNTN_LOG_DEBUG)                          \
		pr_debug("[HIMNTN/D]%s: " msg, __func__, ##__VA_ARGS__);   \
} while (0)

/*
 * 100000000000000000000000000000000000000000000000
 * before get item switch, the value from partition
 * should be >> calculate with this value
 */
#define BASE_VALUE_GET_SWITCH 0x800000000000

enum himntn_id_enum {
	HIMNTN_ID_HEAD = 0,
	HIMNTN_ID_FIRST_BOOT,
	HIMNTN_ID_RESERVED,
	HIMNTN_ID_SAHARA_CTRL = 10,
	HIMNTN_ID_SUBSYS_REBOOT_SWITCH,
	HIMNTN_ID_WARMRESET_SWITCH,
	HIMNTN_ID_PL_LOG_SWITCH,
	HIMNTN_ID_LK_LOG_SWITCH,
	HIMNTN_ID_LK_LOG_LEVEL,
	HIMNTN_ID_FASTBOOT_SWITCH,
	HIMNTN_ID_BOOTDUMP_SWITCH,
	HIMNTN_ID_FINAL_RELEASE,
	HIMNTN_ID_LK_WDT_SWITCH,
	HIMNTN_ID_LK_WDT_TIMEOUT,
	HIMNTN_ID_LKMSG_PRESS_SWITCH,
	HIMNTN_ID_UART_LOG_SWITCH,
	HIMNTN_ID_MRK_SWITCH,
	HIMNTN_ID_THREE_KEY_SWITCH,
	HIMNTN_ID_KEl_DEBUGLOG_SWITCH,
	HIMNTN_ID_PROC_PLLK_SWITCH,
	HIMNTN_ID_PROC_LKMSG_SWITCH,
	HIMNTN_ID_KERNEL_BUF_SWITCH,
	HIMNTN_ID_USER_LOG_SWITCH,
	HIMNTN_ID_SYSRQ_SWITCH,
	HIMNTN_ID_KERNEL_WDT_TIMEOUT,
	HIMNTN_ID_AEE_MODE,
	HIMNTN_ID_REBOOT_DB_SWITCH,
	HIMNTN_ID_EE_DB_SWITCH,
	HIMNTN_ID_OCP_DB_SWITCH,
	HIMNTN_ID_MRK_DB_SWITCH,
	HIMNTN_ID_SYSAPI_DB_SWITCH,
	HIMNTN_ID_KELAPI_DB_SWITCH,
	HIMNTN_ID_KMEMLEAK_SWITCH,
	HIMNTN_ID_LOGCAT_KMSG1,
	HIMNTN_ID_LOGCAT_KMSG2,
	HIMNTN_ID_LOGCAT_KMSG3,
	HIMNTN_ID_CONSOLE_LVL1,
	HIMNTN_ID_CONSOLE_LVL2,
	HIMNTN_ID_CONSOLE_LVL3,
	HIMNTN_ID_CONSOLE_LVL4,
	HIMNTN_ID_LOG_DUMP,
	HIMNTN_ID_BOTTOM = 48,
};

/* core interface for business module */
bool cmd_himntn_item_switch(unsigned int index);

unsigned long long get_global_himntn_data(void);
void set_global_himntn_data(unsigned long long value);

#endif

