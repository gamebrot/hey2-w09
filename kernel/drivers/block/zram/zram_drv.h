/*
 * Compressed RAM block device
 *
 * Copyright (C) 2008, 2009, 2010  Nitin Gupta
 *               2012, 2013 Minchan Kim
 *
 * This code is released using a dual license strategy: BSD/GPL
 * You can choose the licence that better fits your requirements.
 *
 * Released under the terms of 3-clause BSD License
 * Released under the terms of GNU General Public License Version 2.0
 *
 */

#ifndef _ZRAM_DRV_H_
#define _ZRAM_DRV_H_

#include <linux/rwsem.h>
#include <linux/zsmalloc.h>
#include <linux/crypto.h>

#include "zcomp.h"

#define SECTORS_PER_PAGE_SHIFT	(PAGE_SHIFT - SECTOR_SHIFT)
#define SECTORS_PER_PAGE	(1 << SECTORS_PER_PAGE_SHIFT)
#define ZRAM_LOGICAL_BLOCK_SHIFT 12
#define ZRAM_LOGICAL_BLOCK_SIZE	(1 << ZRAM_LOGICAL_BLOCK_SHIFT)
#define ZRAM_SECTOR_PER_LOGICAL_BLOCK	\
	(1 << (ZRAM_LOGICAL_BLOCK_SHIFT - SECTOR_SHIFT))

#ifdef CONFIG_ZRAM_WRITEBACK_EXT
#define ZRAM_WB_FLAGS_DISABLE		(0)
#define ZRAM_WB_FLAGS_FAST_ENABLE	(1)
#define WRITEBACK_LIMIT_CYCLE_DEFAULT	(24 * 60 * 60)
#define WRITEBACK_LIMIT_CYCLE_MIN	(24 * 60 * 60)
#define WRITEBACK_LIMIT_MAX_DEFAULT	(500 * 1024 * 1024 / 4096)
#define WRITEBACK_LIMIT_MAX_MAX		(1024 * 1024 * 1024 / 4096)
#endif

/*
 * The lower ZRAM_FLAG_SHIFT bits of table.flags is for
 * object size (excluding header), the higher bits is for
 * zram_pageflags.
 *
 * zram is mainly used for memory efficiency so we want to keep memory
 * footprint small so we can squeeze size and flags into a field.
 * The lower ZRAM_FLAG_SHIFT bits is for object size (excluding header),
 * the higher bits is for zram_pageflags.
 */
#ifdef CONFIG_HYPERHOLD_CONCURRENT_OPT
#define ZRAM_FLAG_SHIFT (PAGE_SHIFT + 1)
#define ZRAM_OBJ_MAX_SIZE PAGE_SIZE
#else
#define ZRAM_FLAG_SHIFT 24
#endif

/* Flags for zram pages (table[page_no].flags) */
enum zram_pageflags {
	/* zram slot is locked */
	ZRAM_LOCK = ZRAM_FLAG_SHIFT,
	ZRAM_SAME,	/* Page consists the same element */
	ZRAM_WB,	/* page is stored on backing_device */
	ZRAM_UNDER_WB,	/* page is under writeback */
	ZRAM_HUGE,	/* Incompressible page */
	ZRAM_IDLE,	/* not accessed page since last idle marking */
#if (defined CONFIG_HYPERHOLD_CORE) || (defined CONFIG_HYPERHOLD_GKI)
	ZRAM_BATCHING_OUT,
	ZRAM_FROM_HYPERHOLD,
	ZRAM_MCGID_CLEAR,
#endif
#ifdef CONFIG_ZRAM_WRITEBACK_EXT
	ZRAM_IDLE_FAST,	/* not accessed page since last idle_fast marking */
#endif

	__NR_ZRAM_PAGEFLAGS,
};

/*-- Data structures */

/* Allocated for each disk page */
struct zram_table_entry {
	union {
		unsigned long handle;
		unsigned long element;
	};
#ifdef CONFIG_HYPERHOLD_CONCURRENT_OPT
	/* bits of flags must be greater than __NR_ZRAM_PAGEFLAGS */
	unsigned int flags;
	atomic_t hh_faultout_refcount;
#else
	unsigned long flags;
#endif
#ifdef CONFIG_ZRAM_MEMORY_TRACKING
	ktime_t ac_time;
#endif
};

struct zram_stats {
	atomic64_t compr_data_size;	/* compressed size of pages stored */
	atomic64_t num_reads;	/* failed + successful */
	atomic64_t num_writes;	/* --do-- */
	atomic64_t failed_reads;	/* can happen when memory is too low */
	atomic64_t failed_writes;	/* can happen when memory is too low */
	atomic64_t invalid_io;	/* non-page-aligned I/O requests */
	atomic64_t notify_free;	/* no. of swap slot free notifications */
	atomic64_t same_pages;		/* no. of same element filled pages */
	atomic64_t huge_pages;		/* no. of huge pages */
#ifdef CONFIG_ZRAM_WRITEBACK_EXT
	atomic64_t idle_pages;		/* no. of idle pages */
	atomic64_t idle_fast_pages;	/* no. of idle_fast pages */
#endif
	atomic64_t pages_stored;	/* no. of pages currently stored */
	atomic_long_t max_used_pages;	/* no. of maximum pages stored */
	atomic64_t writestall;		/* no. of write slow paths */
	atomic64_t miss_free;		/* no. of missed free */
#ifdef	CONFIG_ZRAM_WRITEBACK
	atomic64_t bd_count;		/* no. of pages in backing device */
	atomic64_t bd_reads;		/* no. of reads from backing device */
	atomic64_t bd_writes;		/* no. of writes from backing device */
#endif
};

struct zram {
	struct zram_table_entry *table;
	struct zs_pool *mem_pool;
	struct zcomp *comp;
	struct gendisk *disk;
	/* Prevent concurrent execution of device init */
	struct rw_semaphore init_lock;
	/*
	 * the number of pages zram can consume for storing compressed data
	 */
	unsigned long limit_pages;

	struct zram_stats stats;
	/*
	 * This is the limit on amount of *uncompressed* worth of data
	 * we can store in a disk.
	 */
	u64 disksize;	/* bytes */
	char compressor[CRYPTO_MAX_ALG_NAME];
	/*
	 * zram is claimed so open request will be failed
	 */
	bool claim; /* Protected by bdev->bd_mutex */
#if (defined CONFIG_ZRAM_WRITEBACK) || (defined CONFIG_ZRAM_NON_COMPRESS)
	spinlock_t wb_limit_lock;
#endif

#if (defined CONFIG_ZRAM_WRITEBACK) || (defined CONFIG_ZRAM_NON_COMPRESS) || (defined CONFIG_HYPERHOLD_GKI)
	struct file *backing_dev;
	struct block_device *bdev;
	unsigned long *bitmap;
	unsigned long nr_pages;

#ifdef CONFIG_ZRAM_WRITEBACK
	bool wb_limit_enable;
	u64 bd_wb_limit;
#endif
#endif

#ifdef CONFIG_ZRAM_WRITEBACK_EXT
	unsigned long wb_flags;
	u64 bd_wb_limit_max;
	int bd_wb_limit_cycle;
	unsigned long pre_wb_limit_time;
#endif
#if (defined CONFIG_ZRAM_WRITEBACK) || (defined CONFIG_HYPERHOLD_CORE)
	unsigned int old_block_size;
#endif
#if (defined CONFIG_HYPERHOLD_CORE) || (defined CONFIG_HYPERHOLD_GKI)
	struct hyperhold_area *area;
#endif
#ifdef CONFIG_ZRAM_MEMORY_TRACKING
	struct dentry *debugfs_dir;
#endif
#ifdef CONFIG_ZRAM_NON_COMPRESS
	bool noncompress_enable;
#endif
};
#if (defined CONFIG_HYPERHOLD_CORE) || (defined CONFIG_HYPERHOLD_GKI)
static inline int zram_slot_trylock(struct zram *zram, u32 index)
{
#ifdef CONFIG_HYPERHOLD_CONCURRENT_OPT
	return bit_spin_trylock(ZRAM_LOCK, (unsigned long *)&zram->table[index].flags);
#else
	return bit_spin_trylock(ZRAM_LOCK, &zram->table[index].flags);
#endif
}

static inline void zram_slot_lock(struct zram *zram, u32 index)
{
#ifdef CONFIG_HYPERHOLD_CONCURRENT_OPT
	bit_spin_lock(ZRAM_LOCK, (unsigned long *)&zram->table[index].flags);
#else
	bit_spin_lock(ZRAM_LOCK, &zram->table[index].flags);
#endif
}

static inline void zram_slot_unlock(struct zram *zram, u32 index)
{
#ifdef CONFIG_HYPERHOLD_CONCURRENT_OPT
	bit_spin_unlock(ZRAM_LOCK, (unsigned long *)&zram->table[index].flags);
#else
	bit_spin_unlock(ZRAM_LOCK, &zram->table[index].flags);
#endif
}

static inline unsigned long zram_get_handle(struct zram *zram, u32 index)
{
	return zram->table[index].handle;
}

static inline void zram_set_handle(struct zram *zram,
					u32 index, unsigned long handle)
{
	zram->table[index].handle = handle;
}

static inline bool zram_test_flag(struct zram *zram, u32 index,
			enum zram_pageflags flag)
{
	return zram->table[index].flags & BIT(flag);
}

static inline void zram_set_flag(struct zram *zram, u32 index,
			enum zram_pageflags flag)
{
	zram->table[index].flags |= BIT(flag);
}

static inline void zram_clear_flag(struct zram *zram, u32 index,
			enum zram_pageflags flag)
{
	zram->table[index].flags &= ~BIT(flag);
}

static inline void zram_set_element(struct zram *zram, u32 index,
			unsigned long element)
{
	zram->table[index].element = element;
}

static inline unsigned long zram_get_element(struct zram *zram, u32 index)
{
	return zram->table[index].element;
}

static inline size_t zram_get_obj_size(struct zram *zram, u32 index)
{
	return zram->table[index].flags & (BIT(ZRAM_FLAG_SHIFT) - 1);
}

static inline void zram_set_obj_size(struct zram *zram,
					u32 index, size_t size)
{
#ifdef CONFIG_HYPERHOLD_CONCURRENT_OPT
	unsigned int flags = zram->table[index].flags >> ZRAM_FLAG_SHIFT;
#else
	unsigned long flags = zram->table[index].flags >> ZRAM_FLAG_SHIFT;
#endif

	zram->table[index].flags = (flags << ZRAM_FLAG_SHIFT) | size;
}
#endif
#endif
