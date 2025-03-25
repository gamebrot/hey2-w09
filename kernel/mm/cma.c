// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Contiguous Memory Allocator
 *
 * Copyright (c) 2010-2011 by Samsung Electronics.
 * Copyright IBM Corporation, 2013
 * Copyright LG Electronics Inc., 2014
 * Written by:
 *	Marek Szyprowski <m.szyprowski@samsung.com>
 *	Michal Nazarewicz <mina86@mina86.com>
 *	Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
 *	Joonsoo Kim <iamjoonsoo.kim@lge.com>
 */

#define pr_fmt(fmt) "cma: " fmt

#ifdef CONFIG_CMA_DEBUG
#ifndef DEBUG
#  define DEBUG
#endif
#endif
#define CREATE_TRACE_POINTS

#include <linux/memblock.h>
#include <linux/err.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/log2.h>
#include <linux/cma.h>
#include <linux/highmem.h>
#include <linux/io.h>
#include <linux/kmemleak.h>
#include <linux/sched.h>
#include <linux/jiffies.h>
#include <trace/events/cma.h>

#ifdef CONFIG_CMA_REPORT
#include <linux/mem_report.h>
#endif
#ifdef CONFIG_GCMA
#include "gcma.h"
#endif
#undef CREATE_TRACE_POINTS
#include <trace/hooks/mm.h>

#include "cma.h"

#ifdef CONFIG_CMA_REPORT
static unsigned int cma_alloc_timeout_threshold = 5000;
#endif

extern void lru_cache_disable(void);
extern void lru_cache_enable(void);

struct cma cma_areas[MAX_CMA_AREAS];
unsigned cma_area_count;
static DEFINE_MUTEX(cma_mutex);

phys_addr_t cma_get_base(const struct cma *cma)
{
	return PFN_PHYS(cma->base_pfn);
}

unsigned long cma_get_size(const struct cma *cma)
{
	return cma->count << PAGE_SHIFT;
}

const char *cma_get_name(const struct cma *cma)
{
	return cma->name;
}
EXPORT_SYMBOL_GPL(cma_get_name);

static unsigned long cma_bitmap_aligned_mask(const struct cma *cma,
					     unsigned int align_order)
{
	if (align_order <= cma->order_per_bit)
		return 0;
	return (1UL << (align_order - cma->order_per_bit)) - 1;
}

/*
 * Find the offset of the base PFN from the specified align_order.
 * The value returned is represented in order_per_bits.
 */
static unsigned long cma_bitmap_aligned_offset(const struct cma *cma,
					       unsigned int align_order)
{
	return (cma->base_pfn & ((1UL << align_order) - 1))
		>> cma->order_per_bit;
}

static unsigned long cma_bitmap_pages_to_bits(const struct cma *cma,
					      unsigned long pages)
{
	return ALIGN(pages, 1UL << cma->order_per_bit) >> cma->order_per_bit;
}

static void cma_clear_bitmap(struct cma *cma, unsigned long pfn,
			     unsigned int count)
{
	unsigned long bitmap_no, bitmap_count;

	bitmap_no = (pfn - cma->base_pfn) >> cma->order_per_bit;
	bitmap_count = cma_bitmap_pages_to_bits(cma, count);

	mutex_lock(&cma->lock);
	bitmap_clear(cma->bitmap, bitmap_no, bitmap_count);
	mutex_unlock(&cma->lock);
}

#ifdef CONFIG_GCMA
static void __init __cma_activate_area(struct cma *cma)
{
	unsigned long base_pfn = cma->base_pfn, pfn;

	if (cma->gcma) {
		gcma_area_init(base_pfn, cma->count);
	} else {
		struct page *page;

		for (pfn = base_pfn; pfn < base_pfn + cma->count;
				pfn += pageblock_nr_pages) {
			page = pfn_to_page(pfn);
			init_cma_reserved_pageblock(page);
		}
	}
}

static int cma_alloc_range(struct cma *cma, unsigned long pfn,
			   unsigned long count, bool no_warn)
{
	struct acr_info info = {0};
	if (cma->gcma) {
		/* GCMA never fails */
		gcma_discard_range(pfn, pfn + count - 1);
		return 0;
	} else
		return alloc_contig_range(pfn, pfn + count, MIGRATE_CMA,
					  GFP_KERNEL |
					  (no_warn ? __GFP_NOWARN : 0), &info);
}

static void cma_free_range(struct cma *cma, unsigned long pfn,
			   unsigned long count)
{
	if (cma->gcma)
		gcma_free_range(pfn, pfn + count - 1);
	else
		free_contig_range(pfn, count);
}
#endif

static void __init cma_activate_area(struct cma *cma)
{
	unsigned long base_pfn = cma->base_pfn, pfn;
	struct zone *zone;

	cma->bitmap = bitmap_zalloc(cma_bitmap_maxno(cma), GFP_KERNEL);
	if (!cma->bitmap)
		goto out_error;

	/*
	 * alloc_contig_range() requires the pfn range specified to be in the
	 * same zone. Simplify by forcing the entire CMA resv range to be in the
	 * same zone.
	 */
	WARN_ON_ONCE(!pfn_valid(base_pfn));
	zone = page_zone(pfn_to_page(base_pfn));
	for (pfn = base_pfn + 1; pfn < base_pfn + cma->count; pfn++) {
		WARN_ON_ONCE(!pfn_valid(pfn));
		if (page_zone(pfn_to_page(pfn)) != zone)
			goto not_in_zone;
	}
#ifdef CONFIG_GCMA
	__cma_activate_area(cma);
#else
	for (pfn = base_pfn; pfn < base_pfn + cma->count;
	     pfn += pageblock_nr_pages)
		init_cma_reserved_pageblock(pfn_to_page(pfn));
#endif
	mutex_init(&cma->lock);

#ifdef CONFIG_CMA_DEBUGFS
	INIT_HLIST_HEAD(&cma->mem_head);
	spin_lock_init(&cma->mem_head_lock);
#endif

	return;

not_in_zone:
	bitmap_free(cma->bitmap);
out_error:
	/* Expose all pages to the buddy, they are useless for CMA. */
	for (pfn = base_pfn; pfn < base_pfn + cma->count; pfn++)
		free_reserved_page(pfn_to_page(pfn));
	totalcma_pages -= cma->count;
	cma->count = 0;
	pr_err("CMA area %s could not be activated\n", cma->name);
	return;
}

static int __init cma_init_reserved_areas(void)
{
	int i;

	for (i = 0; i < cma_area_count; i++)
		cma_activate_area(&cma_areas[i]);

	return 0;
}
core_initcall(cma_init_reserved_areas);

/**
 * cma_init_reserved_mem() - create custom contiguous area from reserved memory
 * @base: Base address of the reserved area
 * @size: Size of the reserved area (in bytes),
 * @order_per_bit: Order of pages represented by one bit on bitmap.
 * @name: The name of the area. If this parameter is NULL, the name of
 *        the area will be set to "cmaN", where N is a running counter of
 *        used areas.
 * @res_cma: Pointer to store the created cma region.
 *
 * This function creates custom contiguous area from already reserved memory.
 */
#ifdef CONFIG_GCMA
int __init cma_init_reserved_mem(phys_addr_t base, phys_addr_t size,
				 unsigned int order_per_bit,
				 const char *name,
				 struct cma **res_cma, bool gcma)
#else
int __init cma_init_reserved_mem(phys_addr_t base, phys_addr_t size,
				 unsigned int order_per_bit,
				 const char *name,
				 struct cma **res_cma)
#endif
{
	struct cma *cma;
	phys_addr_t alignment;

	/* Sanity checks */
	if (cma_area_count == ARRAY_SIZE(cma_areas)) {
		pr_err("Not enough slots for CMA reserved regions!\n");
		return -ENOSPC;
	}

	if (!size || !memblock_is_region_reserved(base, size))
		return -EINVAL;

	/* ensure minimal alignment required by mm core */
	alignment = PAGE_SIZE <<
			max_t(unsigned long, MAX_ORDER - 1, pageblock_order);

	/* alignment should be aligned with order_per_bit */
	if (!IS_ALIGNED(alignment >> PAGE_SHIFT, 1 << order_per_bit))
		return -EINVAL;

	if (ALIGN(base, alignment) != base || ALIGN(size, alignment) != size)
		return -EINVAL;

	/*
	 * Each reserved area must be initialised later, when more kernel
	 * subsystems (like slab allocator) are available.
	 */
	cma = &cma_areas[cma_area_count];

	if (name)
		snprintf(cma->name, CMA_MAX_NAME, name);
	else
		snprintf(cma->name, CMA_MAX_NAME,  "cma%d\n", cma_area_count);

	cma->base_pfn = PFN_DOWN(base);
	cma->count = size >> PAGE_SHIFT;
	cma->order_per_bit = order_per_bit;
#ifdef CONFIG_GCMA
	cma->gcma = gcma;
#endif
	*res_cma = cma;
	cma_area_count++;
	totalcma_pages += (size / PAGE_SIZE);

	return 0;
}

/**
 * cma_declare_contiguous_nid() - reserve custom contiguous area
 * @base: Base address of the reserved area optional, use 0 for any
 * @size: Size of the reserved area (in bytes),
 * @limit: End address of the reserved memory (optional, 0 for any).
 * @alignment: Alignment for the CMA area, should be power of 2 or zero
 * @order_per_bit: Order of pages represented by one bit on bitmap.
 * @fixed: hint about where to place the reserved area
 * @name: The name of the area. See function cma_init_reserved_mem()
 * @res_cma: Pointer to store the created cma region.
 * @nid: nid of the free area to find, %NUMA_NO_NODE for any node
 *
 * This function reserves memory from early allocator. It should be
 * called by arch specific code once the early allocator (memblock or bootmem)
 * has been activated and all other subsystems have already allocated/reserved
 * memory. This function allows to create custom reserved areas.
 *
 * If @fixed is true, reserve contiguous area at exactly @base.  If false,
 * reserve in range from @base to @limit.
 */
int __init cma_declare_contiguous_nid(phys_addr_t base,
			phys_addr_t size, phys_addr_t limit,
			phys_addr_t alignment, unsigned int order_per_bit,
			bool fixed, const char *name, struct cma **res_cma,
			int nid)
{
	phys_addr_t memblock_end = memblock_end_of_DRAM();
	phys_addr_t highmem_start;
	int ret = 0;

	/*
	 * We can't use __pa(high_memory) directly, since high_memory
	 * isn't a valid direct map VA, and DEBUG_VIRTUAL will (validly)
	 * complain. Find the boundary by adding one to the last valid
	 * address.
	 */
	highmem_start = __pa(high_memory - 1) + 1;
	pr_debug("%s(size %pa, base %pa, limit %pa alignment %pa)\n",
		__func__, &size, &base, &limit, &alignment);

	if (cma_area_count == ARRAY_SIZE(cma_areas)) {
		pr_err("Not enough slots for CMA reserved regions!\n");
		return -ENOSPC;
	}

	if (!size)
		return -EINVAL;

	if (alignment && !is_power_of_2(alignment))
		return -EINVAL;

	/*
	 * Sanitise input arguments.
	 * Pages both ends in CMA area could be merged into adjacent unmovable
	 * migratetype page by page allocator's buddy algorithm. In the case,
	 * you couldn't get a contiguous memory, which is not what we want.
	 */
	alignment = max(alignment,  (phys_addr_t)PAGE_SIZE <<
			  max_t(unsigned long, MAX_ORDER - 1, pageblock_order));
	if (fixed && base & (alignment - 1)) {
		ret = -EINVAL;
		pr_err("Region at %pa must be aligned to %pa bytes\n",
			&base, &alignment);
		goto err;
	}
	base = ALIGN(base, alignment);
	size = ALIGN(size, alignment);
	limit &= ~(alignment - 1);

	if (!base)
		fixed = false;

	/* size should be aligned with order_per_bit */
	if (!IS_ALIGNED(size >> PAGE_SHIFT, 1 << order_per_bit))
		return -EINVAL;

	/*
	 * If allocating at a fixed base the request region must not cross the
	 * low/high memory boundary.
	 */
	if (fixed && base < highmem_start && base + size > highmem_start) {
		ret = -EINVAL;
		pr_err("Region at %pa defined on low/high memory boundary (%pa)\n",
			&base, &highmem_start);
		goto err;
	}

	/*
	 * If the limit is unspecified or above the memblock end, its effective
	 * value will be the memblock end. Set it explicitly to simplify further
	 * checks.
	 */
	if (limit == 0 || limit > memblock_end)
		limit = memblock_end;

	if (base + size > limit) {
		ret = -EINVAL;
		pr_err("Size (%pa) of region at %pa exceeds limit (%pa)\n",
			&size, &base, &limit);
		goto err;
	}

	/* Reserve memory */
	if (fixed) {
		if (memblock_is_region_reserved(base, size) ||
		    memblock_reserve(base, size) < 0) {
			ret = -EBUSY;
			goto err;
		}
	} else {
		phys_addr_t addr = 0;

		/*
		 * All pages in the reserved area must come from the same zone.
		 * If the requested region crosses the low/high memory boundary,
		 * try allocating from high memory first and fall back to low
		 * memory in case of failure.
		 */
		if (base < highmem_start && limit > highmem_start) {
			addr = memblock_alloc_range_nid(size, alignment,
					highmem_start, limit, nid, true);
			limit = highmem_start;
		}

		/*
		 * If there is enough memory, try a bottom-up allocation first.
		 * It will place the new cma area close to the start of the node
		 * and guarantee that the compaction is moving pages out of the
		 * cma area and not into it.
		 * Avoid using first 4GB to not interfere with constrained zones
		 * like DMA/DMA32.
		 */
#ifdef CONFIG_PHYS_ADDR_T_64BIT
		if (!memblock_bottom_up() && memblock_end >= SZ_4G + size) {
			memblock_set_bottom_up(true);
			addr = memblock_alloc_range_nid(size, alignment, SZ_4G,
							limit, nid, true);
			memblock_set_bottom_up(false);
		}
#endif

		if (!addr) {
			addr = memblock_alloc_range_nid(size, alignment, base,
					limit, nid, true);
			if (!addr) {
				ret = -ENOMEM;
				goto err;
			}
		}

		/*
		 * kmemleak scans/reads tracked objects for pointers to other
		 * objects but this address isn't mapped and accessible
		 */
		kmemleak_ignore_phys(addr);
		base = addr;
	}
#ifdef CONFIG_GCMA
	ret = cma_init_reserved_mem(base, size, order_per_bit, name, res_cma,
				    false);
#else
	ret = cma_init_reserved_mem(base, size, order_per_bit, name, res_cma);
#endif
	if (ret)
		goto free_mem;

	pr_info("Reserved %ld MiB at %pa\n", (unsigned long)size / SZ_1M,
		&base);
	return 0;

free_mem:
	memblock_free(base, size);
err:
	pr_err("Failed to reserve %ld MiB\n", (unsigned long)size / SZ_1M);
	return ret;
}

#ifdef CONFIG_CMA_DEBUG
static void cma_debug_show_areas(struct cma *cma)
{
	unsigned long next_zero_bit, next_set_bit, nr_zero;
	unsigned long start = 0;
	unsigned long nr_part, nr_total = 0;
	unsigned long nbits = cma_bitmap_maxno(cma);

	mutex_lock(&cma->lock);
	pr_info("number of available pages: ");
	for (;;) {
		next_zero_bit = find_next_zero_bit(cma->bitmap, nbits, start);
		if (next_zero_bit >= nbits)
			break;
		next_set_bit = find_next_bit(cma->bitmap, nbits, next_zero_bit);
		nr_zero = next_set_bit - next_zero_bit;
		nr_part = nr_zero << cma->order_per_bit;
		pr_cont("%s%lu@%lu", nr_total ? "+" : "", nr_part,
			next_zero_bit);
		nr_total += nr_part;
		start = next_zero_bit + nr_zero;
	}
	pr_cont("=> %lu free of %lu total pages\n", nr_total, cma->count);
	mutex_unlock(&cma->lock);
}
#else
static inline void cma_debug_show_areas(struct cma *cma) { }
#endif

/**
 * cma_alloc() - allocate pages from contiguous area
 * @cma:   Contiguous memory region for which the allocation is performed.
 * @count: Requested number of pages.
 * @align: Requested alignment of pages (in PAGE_SIZE order).
 * @gfp_mask: GFP mask to use during the cma allocation.
 *
 * This function allocates part of contiguous memory on specific
 * contiguous memory area.
 */
struct page *cma_alloc(struct cma *cma, size_t count, unsigned int align,
		       gfp_t gfp_mask)
{
	unsigned long mask, offset;
	unsigned long pfn = -1;
	unsigned long start = 0;
	unsigned long bitmap_maxno, bitmap_no, bitmap_count;
	size_t i;
	struct page *page = NULL;
	int ret = -ENOMEM;
	int num_attempts = 0;
	int default_max_retries = 25;
	int max_retries = 100;
	s64 ts;
	struct cma_alloc_info cma_info = {0};
#ifdef CONFIG_CMA_REPORT
	unsigned long alloc_start = jiffies;
	u64 wait_ms;
	u64 wait_us;
#endif

	trace_android_vh_cma_alloc_start(&ts);

	/* Default code flow for no_warn users */
	if (gfp_mask & __GFP_NOWARN) {
		max_retries = default_max_retries;
	}
	if (!cma || !cma->count || !cma->bitmap)
		goto out;

	pr_debug("%s(cma %p, count %zu, align %d gfp_mask 0x%x)\n", __func__,
			(void *)cma, count, align, gfp_mask);

	if (!count)
		goto out;

	trace_cma_alloc_start(cma->name, count, align);

	mask = cma_bitmap_aligned_mask(cma, align);
	offset = cma_bitmap_aligned_offset(cma, align);
	bitmap_maxno = cma_bitmap_maxno(cma);
	bitmap_count = cma_bitmap_pages_to_bits(cma, count);

	if (bitmap_count > bitmap_maxno)
		goto out;

	lru_cache_disable();
	for (;;) {
		struct acr_info info = {0};

		mutex_lock(&cma->lock);
		bitmap_no = bitmap_find_next_zero_area_off(cma->bitmap,
				bitmap_maxno, start, bitmap_count, mask,
				offset);
		if (bitmap_no >= bitmap_maxno) {
			if ((num_attempts < max_retries) && (ret == -EBUSY)) {
				mutex_unlock(&cma->lock);

				if (fatal_signal_pending(current) ||
				    (gfp_mask & __GFP_NORETRY))
					break;

				/*
				 * Page may be momentarily pinned by some other
				 * process which has been scheduled out, e.g.
				 * in exit path, during unmap call, or process
				 * fork and so cannot be freed there. Sleep
				 * for 100ms and retry the allocation.
				 */
				start = 0;
				ret = -ENOMEM;
				schedule_timeout_killable(msecs_to_jiffies(100));
				num_attempts++;
				continue;
			} else {
				mutex_unlock(&cma->lock);
				break;
			}
		}
		bitmap_set(cma->bitmap, bitmap_no, bitmap_count);
		/*
		 * It's safe to drop the lock here. We've marked this region for
		 * our exclusive use. If the migration fails we will take the
		 * lock again and unmark it.
		 */
		mutex_unlock(&cma->lock);

		pfn = cma->base_pfn + (bitmap_no << cma->order_per_bit);
		mutex_lock(&cma_mutex);
#ifdef CONFIG_GCMA
		ret = cma_alloc_range(cma, pfn, count,
				GFP_KERNEL | (gfp_mask & __GFP_NOWARN ? __GFP_NOWARN : 0));
#else
		ret = alloc_contig_range(pfn, pfn + count, MIGRATE_CMA, gfp_mask, &info);
#endif
		mutex_unlock(&cma_mutex);
		cma_info.nr_migrated += info.nr_migrated;
		cma_info.nr_reclaimed += info.nr_reclaimed;
		cma_info.nr_mapped += info.nr_mapped;
		if (info.err) {
			if (info.err & ACR_ERR_ISOLATE)
				cma_info.nr_isolate_fail++;
			if (info.err & ACR_ERR_MIGRATE)
				cma_info.nr_migrate_fail++;
			if (info.err & ACR_ERR_TEST)
				cma_info.nr_test_fail++;
		}
		if (ret == 0) {
			page = pfn_to_page(pfn);
			break;
		}

		cma_clear_bitmap(cma, pfn, count);
		if (ret != -EBUSY)
			break;

		pr_debug("%s(): memory range at %p is busy, retrying\n",
			 __func__, pfn_to_page(pfn));

		trace_cma_alloc_busy_retry(cma->name, pfn, pfn_to_page(pfn),
					   count, align);

		if (info.failed_pfn && gfp_mask & __GFP_NORETRY) {
			/* try again from following failed page */
			start = (pfn_max_align_up(info.failed_pfn + 1) -
				 cma->base_pfn) >> cma->order_per_bit;

		} else {
			/* try again with a bit different memory target */
			start = bitmap_no + mask + 1;
		}
	}

	lru_cache_enable();
	trace_cma_alloc_finish(cma->name, pfn, page, count, align);
	trace_cma_alloc_info(cma->name, page, count, align, &cma_info);

	/*
	 * CMA can allocate multiple page blocks, which results in different
	 * blocks being marked with different tags. Reset the tags to ignore
	 * those page blocks.
	 */
	if (page) {
		for (i = 0; i < count; i++)
			page_kasan_tag_reset(page + i);
	}
	if (!ret && num_attempts > default_max_retries) {
		pr_err("Succeeeded after %d retries treating as failure", num_attempts);
#ifdef CONFIG_CMA_DEBUG
 		ret = -EBUSY;
#endif
	}
	if (ret && !(gfp_mask & __GFP_NOWARN)) {
		pr_err("%s: %s: alloc failed, req-size: %zu pages, ret: %d\n",
		       __func__, cma->name, count, ret);
		if (ret == -EBUSY) {
			pr_err("Triggering crash due to cma allocation failure, %s", cma->name);
			cma_debug_show_areas(cma);
#ifdef CONFIG_CMA_DEBUG
			panic("cma allocation failed.");
#endif
		}
	}

	pr_debug("%s(): returned %p\n", __func__, page);
out:
#ifdef CONFIG_CMA_REPORT
	wait_us = jiffies_to_usecs(jiffies - alloc_start);
	wait_ms = wait_us / 1000;
	count_alloc_time(&cma_alloc_stat, wait_us);
#endif
	trace_android_vh_cma_alloc_finish(cma, page, count, align, gfp_mask, ts);
	if (page) {
		count_vm_event(CMA_ALLOC_SUCCESS);
		cma_sysfs_account_success_pages(cma, count);
#ifdef CONFIG_CMA_REPORT
		if (unlikely(wait_ms > cma_alloc_timeout_threshold)) {
			cma_debug_show_areas(cma);
			mem_alloc_report("cma", cma->name, count, "time_out", wait_ms);
		}
#endif
	} else {
		count_vm_event(CMA_ALLOC_FAIL);
		if (cma) {
			cma_sysfs_account_fail_pages(cma, count);
#ifdef CONFIG_CMA_REPORT
			mem_alloc_report("cma", cma->name, count, "fail", wait_ms);
#endif
		}
	}

	return page;
}
EXPORT_SYMBOL_GPL(cma_alloc);

/**
 * cma_release() - release allocated pages
 * @cma:   Contiguous memory region for which the allocation is performed.
 * @pages: Allocated pages.
 * @count: Number of allocated pages.
 *
 * This function releases memory allocated by cma_alloc().
 * It returns false when provided pages do not belong to contiguous area and
 * true otherwise.
 */
bool cma_release(struct cma *cma, const struct page *pages, unsigned int count)
{
	unsigned long pfn;

	if (!cma || !pages)
		return false;

	pr_debug("%s(page %p, count %u)\n", __func__, (void *)pages, count);

	pfn = page_to_pfn(pages);

	if (pfn < cma->base_pfn || pfn >= cma->base_pfn + cma->count)
		return false;

	VM_BUG_ON(pfn + count > cma->base_pfn + cma->count);
#ifdef CONFIG_GCMA
	cma_free_range(cma, pfn, count);
#else
	free_contig_range(pfn, count);
#endif
	cma_clear_bitmap(cma, pfn, count);
	trace_cma_release(cma->name, pfn, pages, count);

	return true;
}
EXPORT_SYMBOL_GPL(cma_release);

int cma_for_each_area(int (*it)(struct cma *cma, void *data), void *data)
{
	int i;

	for (i = 0; i < cma_area_count; i++) {
		int ret = it(&cma_areas[i], data);

		if (ret)
			return ret;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(cma_for_each_area);

#ifdef CONFIG_CMA_REPORT
static ssize_t cma_alloc_timeout_show(struct kobject *kobj,struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%d\n", cma_alloc_timeout_threshold);
}

static ssize_t cma_alloc_timeout_store(struct kobject *kobj,struct kobj_attribute *attr, const char *buf, size_t count)
{
	unsigned int value;
	int ret;

	ret = kstrtouint(buf, 10, &value);
	if (ret) {
		pr_info("%s fail to set cma_alloc_timeout_threshold:%s\n", __func__, buf);
		return -EINVAL;
	}
	if (value > 0)
		cma_alloc_timeout_threshold = value;

	return count;
}
static struct kobj_attribute cma_alloc_timeout_attr =
	__ATTR(cma_alloc_timeout, 0644, cma_alloc_timeout_show, cma_alloc_timeout_store);

static int __init cma_init_sysfs(void)
{
	int ret;

	ret = sysfs_create_file(mm_kobj, &cma_alloc_timeout_attr.attr);
	if(ret) {
		pr_info("%s failed to create cma_alloc_timeout_threshold\n", __func__);
	}

	return 0;
}
subsys_initcall(cma_init_sysfs);
#endif
