/*
 * log_exception.h
 *
 * interfaces to write messages to exception node
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
#ifndef _LOG_EXCEPTION_H
#define _LOG_EXCEPTION_H
#include <log/hw_logger.h>

struct idapheader {
	char level;
	char category;
	char log_type;
	char sn;
};

#define IDAP_LOGTYPE_CMD		1
#define IDAP_LOGTYPE_MSG		2
#define IDAP_LOGTYPE_REG		3

#define IDAP_LOGSN_BAD			(-1)
#define IDAP_LOGSN_END			0
#define IDAP_LOGSN_CONTINUING		1

#ifdef CONFIG_LOGGER_LEGACY
int logbuf_to_exception(char category, int level, char log_type,
			char sn, void *msg, int msglen);
#endif

ssize_t send_hievent(const char sn, const char *msg, ssize_t msg_len);

#endif
