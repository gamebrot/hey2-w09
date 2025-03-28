// SPDX-License-Identifier: GPL-2.0+
/*
 * erofs-utils/lib/compressor-lz4.c
 *
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Gao Xiang <gaoxiang25@huawei.com>
 */
#include <lz4.h>
#include "erofs/internal.h"
#include "compressor.h"

static int lz4_compress_destsize(struct erofs_compress *c,
				 int compression_level,
				 void *src, unsigned int *srcsize,
				 void *dst, unsigned int dstsize)
{
	int srcSize = (int)*srcsize;
	int rc = LZ4_compress_destSize(src, dst, &srcSize, (int)dstsize);

	UNUSED(c);
	UNUSED(compression_level);
	if (!rc)
		return -EFAULT;
	*srcsize = srcSize;
	return rc;
}

static int compressor_lz4_exit(struct erofs_compress *c)
{
	UNUSED(c);
	return 0;
}

static int compressor_lz4_init(struct erofs_compress *c,
				 char *alg_name)
{
	if (alg_name && strcmp(alg_name, "lz4"))
		return -EINVAL;
	c->alg = &erofs_compressor_lz4;
	return 0;
}

struct erofs_compressor erofs_compressor_lz4 = {
	.default_level = 0,
	.best_level = 0,
	.init = compressor_lz4_init,
	.exit = compressor_lz4_exit,
	.compress_destsize = lz4_compress_destsize,
};

