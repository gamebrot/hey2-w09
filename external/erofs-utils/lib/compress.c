// SPDX-License-Identifier: GPL-2.0+
/*
 * erofs_utils/lib/compress.c
 *
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Miao Xie <miaoxie@huawei.com>
 * with heavy changes by Gao Xiang <gaoxiang25@huawei.com>
 */
#define _LARGEFILE64_SOURCE
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "erofs/print.h"
#include "erofs/io.h"
#include "erofs/cache.h"
#include "erofs/compress.h"
#include "erofs/map.h"
#include "compressor.h"

struct z_erofs_compressindex_vec {
	union {
		erofs_blk_t blkaddr;
		u16 delta[2];
	} u;
	u16 clusterofs;
	u8  clustertype;
};

struct erofs_compress compresshandle;
int compressionlevel;

static struct z_erofs_map_header mapheader;

static unsigned int vle_compressmeta_capacity(erofs_off_t filesize)
{
	const unsigned int indexsize = BLK_ROUND_UP(filesize) *
		sizeof(struct z_erofs_vle_decompressed_index);

	return sizeof(struct erofs_extent_header) + indexsize;
}

static void vle_write_indexes_final(struct z_erofs_vle_compress_ctx *ctx)
{
	const unsigned int type = Z_EROFS_VLE_CLUSTER_TYPE_PLAIN;
	struct z_erofs_vle_decompressed_index di;

	if (!ctx->clusterofs)
		return;

	di.di_clusterofs = cpu_to_le16(ctx->clusterofs);
	di.di_u.blkaddr = ctx->blkaddr;
	di.di_advise = cpu_to_le16(type << Z_EROFS_VLE_DI_CLUSTER_TYPE_BIT);

	memcpy(ctx->metacur, &di, sizeof(di));
	ctx->metacur += sizeof(di);
}

static void vle_write_indexes(struct z_erofs_vle_compress_ctx *ctx,
			      unsigned int count, bool raw)
{
	unsigned int clusterofs = ctx->clusterofs;
	unsigned int d0 = 0, d1 = (clusterofs + count) / EROFS_BLKSIZ;
	struct z_erofs_vle_decompressed_index di;
	unsigned int type;
	__le16 advise;

	di.di_clusterofs = cpu_to_le16(ctx->clusterofs);

	/* whether the tail-end (un)compressed block or not */
	if (!d1) {
		type = raw ? Z_EROFS_VLE_CLUSTER_TYPE_PLAIN :
			Z_EROFS_VLE_CLUSTER_TYPE_HEAD;
		advise = cpu_to_le16(type << Z_EROFS_VLE_DI_CLUSTER_TYPE_BIT);

		di.di_advise = advise;
		di.di_u.blkaddr = cpu_to_le32(ctx->blkaddr);
		memcpy(ctx->metacur, &di, sizeof(di));
		ctx->metacur += sizeof(di);

		/* don't add the final index if the tail-end block exists */
		ctx->clusterofs = 0;
		return;
	}

	do {
		if (d0) {
			type = Z_EROFS_VLE_CLUSTER_TYPE_NONHEAD;

			di.di_u.delta[0] = cpu_to_le16(d0);
			di.di_u.delta[1] = cpu_to_le16(d1);
		} else {
			type = raw ? Z_EROFS_VLE_CLUSTER_TYPE_PLAIN :
				Z_EROFS_VLE_CLUSTER_TYPE_HEAD;
			di.di_u.blkaddr = cpu_to_le32(ctx->blkaddr);
		}
		advise = cpu_to_le16(type << Z_EROFS_VLE_DI_CLUSTER_TYPE_BIT);
		di.di_advise = advise;

		memcpy(ctx->metacur, &di, sizeof(di));
		ctx->metacur += sizeof(di);

		count -= EROFS_BLKSIZ - clusterofs;
		clusterofs = 0;

		++d0;
		--d1;
	} while (clusterofs + count >= EROFS_BLKSIZ);

	ctx->clusterofs = clusterofs + count;
}

static int write_uncompressed_block(struct z_erofs_vle_compress_ctx *ctx,
				    unsigned int *len,
				    char *dst, bool is_write)
{
	int ret;
	unsigned int count;

	if (sbi.requirements & EROFS_REQUIREMENT_LZ4_0PADDING) {
		/* use shift format */
		count = min(EROFS_BLKSIZ, *len);

		memcpy(dst, ctx->queue + ctx->head, count);
	} else {
		/* fix up clusterofs to 0 if possable */
		if (ctx->head >= ctx->clusterofs) {
			ctx->head -= ctx->clusterofs;
			*len += ctx->clusterofs;
			ctx->clusterofs = 0;
		}

		/* write uncompressed data */
		count = min(EROFS_BLKSIZ, *len);

		memcpy(dst, ctx->queue + ctx->head, count);
	}
	memset(dst + count, 0, EROFS_BLKSIZ - count);

	erofs_dbg("Writing %u uncompressed data to block %u",
		  count, ctx->blkaddr);
#if PATCH_ENABLED
	if (!is_write)
		ret = 0;
	else
		ret = blk_write(dst, ctx->blkaddr, 1);
#else
	UNUSED(is_write);
	ret = blk_write(dst, ctx->blkaddr, 1);
#endif
	if (ret)
		return ret;
	return count;
}

static int vle_compress_one(struct erofs_inode *inode,
			    struct z_erofs_vle_compress_ctx *ctx,
			    bool final,
			    struct erofs_inode *org_inode,
			    bool is_write, u32 *used_block_count)
{
	struct erofs_compress *const h = &compresshandle;
	unsigned int len = ctx->tail - ctx->head;
	unsigned int count;
	int ret;
	static char dstbuf[EROFS_BLKSIZ * 2];
	char *const dst = dstbuf + EROFS_BLKSIZ;

	while (len) {
		bool raw;

#if PATCH_ENABLED
		if (org_inode && *used_block_count >= org_inode->nblocks)
			return -1;
#endif

		if (len <= EROFS_BLKSIZ) {
			if (final)
				goto nocompression;
			break;
		}

		count = len;
		ret = erofs_compress_destsize(h, compressionlevel,
					      ctx->queue + ctx->head,
					      &count, dst, EROFS_BLKSIZ);
		if (ret <= 0) {
			if (ret != -EAGAIN) {
				erofs_err("failed to compress %s: %s",
					  inode->i_srcpath,
					  erofs_strerror(ret));
				return ret;
			}
nocompression:
			ret = write_uncompressed_block(ctx, &len, dst, is_write);
			if (ret < 0)
				return ret;
			count = ret;
			raw = true;
		} else {
			/* write compressed data */
			erofs_dbg("Writing %u compressed data to block %u",
				  count, ctx->blkaddr);
#if PATCH_ENABLED
			if (is_write && sbi.requirements &
				EROFS_REQUIREMENT_LZ4_0PADDING)
				ret = blk_write(dst - (EROFS_BLKSIZ - ret),
						ctx->blkaddr, 1);
			else if (is_write)
				ret = blk_write(dst, ctx->blkaddr, 1);
			else
				ret = 0;
#else
			UNUSED(is_write);
			UNUSED(org_inode);
			if (sbi.requirements & EROFS_REQUIREMENT_LZ4_0PADDING)
				ret = blk_write(dst - (EROFS_BLKSIZ - ret),
						ctx->blkaddr, 1);
			else
				ret = blk_write(dst, ctx->blkaddr, 1);
#endif

			if (ret)
				return ret;
			raw = false;
		}

		ctx->head += count;
		/* write compression indexes for this blkaddr */
		vle_write_indexes(ctx, count, raw);
		erofs_output_mapbin_block(EROFS_INODE_FLAT_COMPRESSION,
					  raw, ctx->blkaddr, count);

		++(*used_block_count);
		++ctx->blkaddr;
		len -= count;

		if (!final && ctx->head >= EROFS_CONFIG_COMPR_MAX_SZ) {
			const uint qh_aligned = round_down(ctx->head, EROFS_BLKSIZ);
			const uint qh_after = ctx->head - qh_aligned;

			memmove(ctx->queue, ctx->queue + qh_aligned,
				len + qh_after);
			ctx->head = qh_after;
			ctx->tail = qh_after + len;
			break;
		}
	}
	return 0;
}

static void *parse_legacy_indexes(struct z_erofs_compressindex_vec *cv,
				  unsigned int nr, void *metacur)
{
	struct z_erofs_vle_decompressed_index *const db = metacur;
	unsigned int i;

	for (i = 0; i < nr; ++i, ++cv) {
		struct z_erofs_vle_decompressed_index *const di = db + i;
		const unsigned int advise = le16_to_cpu(di->di_advise);

		cv->clustertype = (advise >> Z_EROFS_VLE_DI_CLUSTER_TYPE_BIT) &
			((1 << Z_EROFS_VLE_DI_CLUSTER_TYPE_BITS) - 1);
		cv->clusterofs = le16_to_cpu(di->di_clusterofs);

		if (cv->clustertype == Z_EROFS_VLE_CLUSTER_TYPE_NONHEAD) {
			cv->u.delta[0] = le16_to_cpu(di->di_u.delta[0]);
			cv->u.delta[1] = le16_to_cpu(di->di_u.delta[1]);
		} else {
			cv->u.blkaddr = le32_to_cpu(di->di_u.blkaddr);
		}
	}
	return db + nr;
}

static void *write_compacted_indexes(u8 *out,
				     struct z_erofs_compressindex_vec *cv,
				     erofs_blk_t *blkaddr_ret,
				     unsigned int destsize,
				     unsigned int logical_clusterbits)
{
	unsigned int vcnt, encodebits, pos, i;
	erofs_blk_t blkaddr;

	if (destsize == 4) {
		vcnt = 2;
	} else if (destsize == 2 && logical_clusterbits == 12) {
		vcnt = 16;
	} else {
		return ERR_PTR(-EINVAL);
	}
	encodebits = (vcnt * destsize * 8 - 32) / vcnt;
	blkaddr = *blkaddr_ret;

	pos = 0;
	for (i = 0; i < vcnt; ++i) {
		unsigned int offset, v;
		u8 ch, rem;

		if (cv[i].clustertype == Z_EROFS_VLE_CLUSTER_TYPE_NONHEAD) {
			if (i + 1 == vcnt)
				offset = cv[i].u.delta[1];
			else
				offset = cv[i].u.delta[0];
		} else {
			offset = cv[i].clusterofs;
			++blkaddr;
			if (i + 1 != vcnt)
				DBG_BUGON(cv[i].u.blkaddr != blkaddr);
			else
				DBG_BUGON(cv[i].u.blkaddr &&
					  cv[i].u.blkaddr != blkaddr);
		}
		v = (cv[i].clustertype << logical_clusterbits) | offset;
		rem = pos & 7;
		ch = out[pos / 8] & ((1 << rem) - 1);
		out[pos / 8] = (v << rem) | ch;
		out[pos / 8 + 1] = v >> (8 - rem);
		out[pos / 8 + 2] = v >> (16 - rem);
		pos += encodebits;
	}
	DBG_BUGON(destsize * vcnt * 8 != pos + 32);
	*(__le32 *)(out + destsize * vcnt - 4) = cpu_to_le32(*blkaddr_ret);
	*blkaddr_ret = blkaddr;
	return out + destsize * vcnt;
}

int z_erofs_convert_to_compacted_format(struct erofs_inode *inode,
					erofs_blk_t blkaddr,
					unsigned int legacymetasize,
					unsigned int logical_clusterbits)
{
	const uint headerpos = Z_EROFS_VLE_EXTENT_ALIGN(inode->inode_isize +
							inode->xattr_isize) +
			       sizeof(struct z_erofs_map_header);
	const uint totalidx = (legacymetasize -
			       sizeof(struct erofs_extent_header)) / 8;
	u8 *out, *in;
	struct z_erofs_compressindex_vec cv[16];
	/* # of 8-byte units so that it can be aligned with 32 bytes */
	unsigned int compacted_4b_initial, compacted_4b_end;
	unsigned int compacted_2b;

	if (logical_clusterbits < LOG_BLOCK_SIZE || LOG_BLOCK_SIZE < 12)
		return -EINVAL;
	if (logical_clusterbits > 14)	/* currently not supported */
		return -ENOTSUP;
	if (logical_clusterbits == 12) {
		compacted_4b_initial = (32 - headerpos % 32) / 4;
		if (compacted_4b_initial == 32 / 4)
			compacted_4b_initial = 0;

		if (compacted_4b_initial > totalidx) {
			compacted_4b_initial = compacted_2b = 0;
			compacted_4b_end = totalidx;
		} else {
			compacted_2b = rounddown(totalidx -
						 compacted_4b_initial, 16);
			compacted_4b_end = totalidx - compacted_4b_initial -
					   compacted_2b;
		}
	} else {
		compacted_2b = compacted_4b_initial = 0;
		compacted_4b_end = totalidx;
	}

	out = in = inode->compressmeta;

	/* write out compacted header */
	memcpy(out, &mapheader, sizeof(mapheader));
	out += sizeof(mapheader);
	in += sizeof(struct erofs_extent_header);

	/* generate compacted_4b_initial */
	while (compacted_4b_initial) {
		in = parse_legacy_indexes(cv, 2, in);
		out = write_compacted_indexes(out, cv, &blkaddr,
					      4, logical_clusterbits);
		compacted_4b_initial -= 2;
	}
	DBG_BUGON(compacted_4b_initial);

	/* generate compacted_2b */
	while (compacted_2b) {
		in = parse_legacy_indexes(cv, 16, in);
		out = write_compacted_indexes(out, cv, &blkaddr,
					      2, logical_clusterbits);
		compacted_2b -= 16;
	}
	DBG_BUGON(compacted_2b);

	/* generate compacted_4b_end */
	while (compacted_4b_end > 1) {
		in = parse_legacy_indexes(cv, 2, in);
		out = write_compacted_indexes(out, cv, &blkaddr,
					      4, logical_clusterbits);
		compacted_4b_end -= 2;
	}

	/* generate final compacted_4b_end if needed */
	if (compacted_4b_end) {
		memset(cv, 0, sizeof(cv));
		in = parse_legacy_indexes(cv, 1, in);
		if (cv[0].clustertype != Z_EROFS_VLE_CLUSTER_TYPE_NONHEAD) {
			cv[1].u.blkaddr = cv[0].u.blkaddr + 1;
		} else {
			cv[1].u.blkaddr = blkaddr + 1;
		}

		out = write_compacted_indexes(out, cv, &blkaddr,
					      4, logical_clusterbits);
	}
	inode->extent_isize = out - (u8 *)inode->compressmeta;
	inode->data_mapping_mode = EROFS_INODE_FLAT_COMPRESSION;
	return 0;
}

int erofs_write_compressed_file(struct erofs_inode *inode,
				struct erofs_inode *org_inode,
				bool is_write)
{
	struct erofs_buffer_head *bh;
	struct z_erofs_vle_compress_ctx ctx;
	erofs_off_t remaining;
	erofs_blk_t blkaddr;
	unsigned int legacymetasize;
	u32 used_block_count = 0;

	int ret, fd;

	u8 *compressmeta = malloc(vle_compressmeta_capacity(inode->i_size));
	if (!compressmeta)
		return -ENOMEM;

	fd = open(inode->i_srcpath, O_RDONLY | O_BINARY);
	if (fd < 0) {
		erofs_err("%s:%s", inode->i_srcpath, strerror(errno));
		ret = -errno;
		goto err_free;
	}

	memset(compressmeta, 0, sizeof(struct erofs_extent_header));
#if PATCH_ENABLED
	if (org_inode) {
		blkaddr = org_inode->startaddr;
	} else {
		/* allocate main data buffer */
		bh = erofs_balloc(DATA, 0, 0, 0);
		if (IS_ERR(bh)) {
			ret = PTR_ERR(bh);
			goto err_close;
		}
		blkaddr = erofs_mapbh(bh->block, true);	/* start_blkaddr */
	}
#else
	/* allocate main data buffer */
	bh = erofs_balloc(DATA, 0, 0, 0);
	if (IS_ERR(bh)) {
		ret = PTR_ERR(bh);
		goto err_close;
	}
	blkaddr = erofs_mapbh(bh->block, true);	/* start_blkaddr */
#endif
	ctx.blkaddr = blkaddr;
	ctx.metacur = compressmeta + sizeof(struct erofs_extent_header);
	ctx.head = ctx.tail = 0;
	ctx.clusterofs = 0;
	remaining = inode->i_size;

	while (remaining) {
		const uint readcount = min_t(uint, remaining,
					     sizeof(ctx.queue) - ctx.tail);

		ret = read(fd, ctx.queue + ctx.tail, readcount);
		if (ret < 0 || (uint)ret != readcount) {
			ret = -errno;
			goto err_bdrop;
		}
		remaining -= readcount;
		ctx.tail += readcount;

		/* do one compress round */
		ret = vle_compress_one(inode, &ctx, false,
				       org_inode, is_write, &used_block_count);
		if (ret)
			goto err_bdrop;
	}

	/* do the final round */
	ret = vle_compress_one(inode, &ctx, true,
			       org_inode, is_write, &used_block_count);

	if (ret)
		goto err_bdrop;

	/* fall back to no compression mode */
	if (ctx.blkaddr - blkaddr >= BLK_ROUND_UP(inode->i_size)) {
		erofs_info("Fall back: %u-->%u diff:%u size:%lu-(%lu bytes) %s ",
			blkaddr, ctx.blkaddr, ctx.blkaddr-blkaddr,
			BLK_ROUND_UP(inode->i_size), inode->i_size, inode->i_srcpath);
		ret = -ENOSPC;
		goto err_bdrop;
	}

	inode->nblocks = ctx.blkaddr - blkaddr;
	inode->startaddr = blkaddr;

	vle_write_indexes_final(&ctx);

	close(fd);

#if PATCH_ENABLED
	if (!org_inode)
		ret = erofs_bh_balloon(bh,
			blknr_to_addr(ctx.blkaddr - blkaddr));
#else
	ret = erofs_bh_balloon(bh, blknr_to_addr(ctx.blkaddr - blkaddr));
#endif
	DBG_BUGON(ret);

	erofs_info("compressed %s (%lu bytes) into %u blocks, %u-->%u",
		   inode->i_srcpath, inode->i_size, ctx.blkaddr - blkaddr, blkaddr, ctx.blkaddr);

#if PATCH_ENABLED
	if (org_inode && !is_write)
		goto err_free;
#endif

	/*
	 * TODO: need to move erofs_bdrop to erofs_write_tail_end
	 *       when both mkfs & kernel support compression inline.
	 */
#if PATCH_ENABLED
	if (!org_inode)
		erofs_bdrop(bh, false);
#else
	erofs_bdrop(bh, false);
#endif

	inode->u.i_blkaddr = blkaddr;
	inode->u.i_blocks = ctx.blkaddr - blkaddr;
	inode->compressmeta = compressmeta;
	inode->idata_size = 0;

	/* map should be at the front of compact index */
	erofs_output_map_blocks(inode->i_srcpath, inode->u.i_blkaddr, inode->u.i_blocks);

	legacymetasize = ctx.metacur - compressmeta;
	if (cfg.c_legacy_compress) {
		inode->extent_isize = legacymetasize;
		inode->data_mapping_mode = EROFS_INODE_FLAT_COMPRESSION_LEGACY;
	} else {
		ret = z_erofs_convert_to_compacted_format(inode, blkaddr - 1,
							  legacymetasize, 12);
		DBG_BUGON(ret);
	}
	return 0;

err_bdrop:

#if PATCH_ENABLED
	if (!org_inode)
		erofs_bdrop(bh, true);	/* revoke buffer */
#else
	erofs_bdrop(bh, true);	/* revoke buffer */
#endif

err_close:
	close(fd);
err_free:
	free(compressmeta);
	return ret;
}

static int erofs_get_compress_algorithm_id(const char *name)
{
	if (!strcmp(name, "lz4") || !strcmp(name, "lz4hc"))
		return Z_EROFS_COMPRESSION_LZ4;
	return -ENOTSUP;
}

int z_erofs_compress_init(void)
{
	unsigned int algorithmtype[2];
	/* initialize for primary compression algorithm */
	int ret = erofs_compressor_init(&compresshandle,
					cfg.c_compr_alg_master);
	if (ret)
		return ret;

	compressionlevel = cfg.c_compr_level_master < 0 ?
		compresshandle.alg->default_level :
		cfg.c_compr_level_master;

	if (!cfg.c_compr_alg_master)
		return 0;

	/* figure out mapheader */
	ret = erofs_get_compress_algorithm_id(cfg.c_compr_alg_master);
	if (ret < 0)
		return ret;

	algorithmtype[0] = ret;	/* primary algorithm (head 0) */
	algorithmtype[1] = 0;	/* secondary algorithm (head 1) */
	mapheader.h_advise |= Z_EROFS_ADVISE_COMPACTED_2B;
	mapheader.h_algorithmtype = algorithmtype[1] << 4 |
					  algorithmtype[0];
	mapheader.h_clusterbits = LOG_BLOCK_SIZE - 12;
	return 0;
}

int z_erofs_compress_exit(void)
{
	return erofs_compressor_exit(&compresshandle);
}

