/*
 * Copyright (c) Honor Device Co., Ltd. 2016-2018. All rights reserved.
 * Description: the hw_rscan_utils.c - get current run mode, eng or user
 * Author: likun <quentin.lee.>
 *         likan <likan82.>
 * Create: 2016-06-18
 */

#include "./include/hw_rscan_utils.h"

int get_ro_secure(void)
{
#ifdef CONFIG_HN_ROOT_SCAN_ENG_DEBUG
	return RO_SECURE;
#else
	return RO_NORMAL;
#endif
}
EXPORT_SYMBOL(get_ro_secure);

