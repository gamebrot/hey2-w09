/*
 * Copyright (c) Honor Device Co., Ltd. 2016-2019. All rights reserved.
 * Description: the kcode.h for kernel code integrity checking
 * Author: likun <quentin.lee.>
 *         likan <likan82.>
 * Create: 2016-06-18
 */

#ifndef _KCODE_H_
#define _KCODE_H_

#include <asm/sections.h>
#include <asm/syscall.h>
#include <linux/crypto.h>
#include <linux/kernel.h>
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/version.h>
#include <crypto/hash.h>
#include <crypto/hash_info.h>
#include "./include/hw_rscan_utils.h"

int kcode_scan(uint8_t *hash, size_t hash_len);
size_t kcode_get_size(void);
int kcode_syscall_scan(uint8_t *hash, size_t hash_len);

#endif

