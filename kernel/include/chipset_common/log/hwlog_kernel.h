/*
 * hwlog_kernel.h
 *
 * hwlog expansion interfaces, supporting jank and dubai
 *
 * Copyright (c) 2018-2019 Honor Device Co., Ltd.
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

#ifndef _LINUX_HWLOG_KERNEL_H
#define _LINUX_HWLOG_KERNEL_H

#include <log/janklogconstants.h>

#define HW_LOG_PRIO_VERBOSE	2
#define HW_LOG_PRIO_DEBUG	3
#define HW_LOG_PRIO_INFO	4
#define HW_LOG_PRIO_WARN	5
#define HW_LOG_PRIO_ERROR	6

enum hwlog_id {
	HW_LOG_ID_MIN       = 0,
	HW_LOG_ID_EXCEPTION = HW_LOG_ID_MIN,
	HW_LOG_ID_JANK      = 1,
	HW_LOG_ID_DUBAI     = 2,
	HW_LOG_ID_MAX
};

#if IS_ENABLED(CONFIG_LOG_KERNEL)
int hievent_to_write(int prio, int bufid, const char *tag, const char *fmt, ...);
int hievent_to_jank(int tag, int prio, const char *fmt, ...);

/*
 * For forward compatibility, HW_LOG_PRIO_DEBUG level is just for HW service.
 * And the interface name stay the same "pr_HW".
 * Use LOG_HW_W / LOG_HW_V / LOG_HW_I / LOG_HW_E for other purpose.
 */

#ifndef pr_jank
#define pr_jank(tag, fmt, ...)	\
	hievent_to_jank(tag, HW_LOG_PRIO_DEBUG, fmt, ##__VA_ARGS__)
#endif

#ifndef LOG_JANK_D
#define LOG_JANK_D(tag, fmt, ...) \
	hievent_to_jank(tag, HW_LOG_PRIO_DEBUG, fmt, ##__VA_ARGS__)
#endif

#ifndef LOG_JANK_W
#define LOG_JANK_W(tag, fmt, ...) \
	hievent_to_jank(tag, HW_LOG_PRIO_WARN, fmt, ##__VA_ARGS__)
#endif

#ifndef LOG_JANK_V
#define LOG_JANK_V(tag, fmt, ...) \
	hievent_to_jank(tag, HW_LOG_PRIO_VERBOSE, fmt, ##__VA_ARGS__)
#endif

#ifndef LOG_JANK_I
#define LOG_JANK_I(tag, fmt, ...) \
	hievent_to_jank(tag, HW_LOG_PRIO_INFO, fmt, ##__VA_ARGS__)
#endif

#ifndef LOG_JANK_E
#define LOG_JANK_E(tag, fmt, ...) \
	hievent_to_jank(tag, HW_LOG_PRIO_ERROR, fmt, ##__VA_ARGS__)
#endif

#ifndef HWDUBAI_pr
#define HWDUBAI_pr(tag, fmt, ...) \
	hievent_to_write(HW_LOG_PRIO_DEBUG, HW_LOG_ID_DUBAI, \
			tag, fmt, ##__VA_ARGS__)
#endif

#ifndef HWDUBAI_LOGV
#define HWDUBAI_LOGV(tag, fmt, ...) \
	hievent_to_write(HW_LOG_PRIO_VERBOSE, HW_LOG_ID_DUBAI, \
			tag, fmt, ##__VA_ARGS__)
#endif

#ifndef HWDUBAI_LOGD
#define HWDUBAI_LOGD(tag, fmt, ...) \
	hievent_to_write(HW_LOG_PRIO_DEBUG, HW_LOG_ID_DUBAI, \
			tag, fmt, ##__VA_ARGS__)
#endif

#ifndef HWDUBAI_LOGI
#define HWDUBAI_LOGI(tag, fmt, ...) \
	hievent_to_write(HW_LOG_PRIO_INFO, HW_LOG_ID_DUBAI, \
			tag, fmt, ##__VA_ARGS__)
#endif

#ifndef HWDUBAI_LOGW
#define HWDUBAI_LOGW(tag, fmt, ...) \
	hievent_to_write(HW_LOG_PRIO_WARN, HW_LOG_ID_DUBAI, \
			tag, fmt, ##__VA_ARGS__)
#endif

#ifndef HWDUBAI_LOGE
#define HWDUBAI_LOGE(tag, fmt, ...) \
	hievent_to_write(HW_LOG_PRIO_ERROR, HW_LOG_ID_DUBAI, \
			tag, fmt, ##__VA_ARGS__)
#endif

#else
#define pr_jank(tag, fmt, ...)		(-ENOENT)
#define LOG_JANK_D(tag, fmt, ...)	(-ENOENT)
#define LOG_JANK_W(tag, fmt, ...)	(-ENOENT)
#define LOG_JANK_V(tag, fmt, ...)	(-ENOENT)
#define LOG_JANK_I(tag, fmt, ...)	(-ENOENT)
#define LOG_JANK_E(tag, fmt, ...)	(-ENOENT)

#define HWDUBAI_pr(tag, fmt, ...)	(-ENOENT)
#define HWDUBAI_LOGV(tag, fmt, ...)	(-ENOENT)
#define HWDUBAI_LOGD(tag, fmt, ...)	(-ENOENT)
#define HWDUBAI_LOGI(tag, fmt, ...)	(-ENOENT)
#define HWDUBAI_LOGW(tag, fmt, ...)	(-ENOENT)
#define HWDUBAI_LOGE(tag, fmt, ...)	(-ENOENT)
#endif

int hwlog_wq_init(void);
void hwlog_wq_destroy(void);
#endif
