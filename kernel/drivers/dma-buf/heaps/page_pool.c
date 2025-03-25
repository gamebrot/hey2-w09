// SPDX-License-Identifier: GPL-2.0
/*
 * DMA BUF page pool system
 *
 * Copyright (C) 2020 Linaro Ltd.
 *
 * Based on the ION page pool code
 * Copyright (C) 2011 Google, Inc.
 */

#include <linux/freezer.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/swap.h>
#include <linux/sched/signal.h>
#include <linux/debugfs.h>

#ifdef CONFIG_HUGEPAGE_POOL
#include <linux/hugepage_pool.h>
#endif

#include "page_pool.h"

struct dmabuf_page_pool_with_spinlock {
	struct dmabuf_page_pool pool;
	struct spinlock spinlock;
};

static LIST_HEAD(pool_list);
static DEFINE_MUTEX(pool_list_lock);

static inline
struct page *dmabuf_page_pool_alloc_pages(struct dmabuf_page_pool *pool)
{
	if (fatal_signal_pending(current))
		return NULL;

#ifdef CONFIG_HUGEPAGE_POOL
	/* we assume that this path is only being used by system heap */
	if (pool->order == HUGEPAGE_ORDER)
		return alloc_hugepage(pool->order, HPAGE_DMA_BUF);
	else
		return alloc_pages(pool->gfp_mask, pool->order);
#else
	return alloc_pages(pool->gfp_mask, pool->order);
#endif
}

static inline void dmabuf_page_pool_free_pages(struct dmabuf_page_pool *pool,
					       struct page *page)
{
	__free_pages(page, pool->order);
}

static void dmabuf_page_pool_add(struct dmabuf_page_pool *pool, struct page *page)
{
	int index;
	struct dmabuf_page_pool_with_spinlock *container_pool =
		container_of(pool, struct dmabuf_page_pool_with_spinlock, pool);

	if (PageHighMem(page))
		index = POOL_HIGHPAGE;
	else
		index = POOL_LOWPAGE;

	spin_lock(&container_pool->spinlock);
	list_add_tail(&page->lru, &pool->items[index]);
	pool->count[index]++;
	spin_unlock(&container_pool->spinlock);
	mod_node_page_state(page_pgdat(page), NR_KERNEL_MISC_RECLAIMABLE,
			    1 << pool->order);
#ifdef CONFIG_DMA_BUF_INFO
	mod_node_page_state(page_pgdat(page), NR_KERNEL_DMA_BUF_RECLAIMABLE,
			    1 << pool->order);
#endif
}

static struct page *dmabuf_page_pool_remove(struct dmabuf_page_pool *pool, int index)
{
	struct page *page;
	struct dmabuf_page_pool_with_spinlock *container_pool =
		container_of(pool, struct dmabuf_page_pool_with_spinlock, pool);

	spin_lock(&container_pool->spinlock);
	page = list_first_entry_or_null(&pool->items[index], struct page, lru);
	if (page) {
		pool->count[index]--;
		list_del(&page->lru);
		spin_unlock(&container_pool->spinlock);
		mod_node_page_state(page_pgdat(page), NR_KERNEL_MISC_RECLAIMABLE,
				    -(1 << pool->order));
#ifdef CONFIG_DMA_BUF_INFO
		mod_node_page_state(page_pgdat(page), NR_KERNEL_DMA_BUF_RECLAIMABLE,
				    -(1 << pool->order));
#endif
		goto out;
	}
	spin_unlock(&container_pool->spinlock);

out:
	return page;
}

static struct page *dmabuf_page_pool_fetch(struct dmabuf_page_pool *pool)
{
	struct page *page = NULL;

	page = dmabuf_page_pool_remove(pool, POOL_HIGHPAGE);
	if (!page)
		page = dmabuf_page_pool_remove(pool, POOL_LOWPAGE);

	return page;
}

struct page *dmabuf_page_pool_alloc(struct dmabuf_page_pool *pool)
{
	struct page *page = NULL;

	if (WARN_ON(!pool))
		return NULL;

	page = dmabuf_page_pool_fetch(pool);

	if (!page)
		page = dmabuf_page_pool_alloc_pages(pool);
	return page;
}
EXPORT_SYMBOL_GPL(dmabuf_page_pool_alloc);

void dmabuf_page_pool_free(struct dmabuf_page_pool *pool, struct page *page)
{
	if (WARN_ON(pool->order != compound_order(page)))
		return;

	dmabuf_page_pool_add(pool, page);
}
EXPORT_SYMBOL_GPL(dmabuf_page_pool_free);

static int dmabuf_page_pool_total(struct dmabuf_page_pool *pool, bool high)
{
	int count = pool->count[POOL_LOWPAGE];

	if (high)
		count += pool->count[POOL_HIGHPAGE];

	return count << pool->order;
}

struct dmabuf_page_pool *dmabuf_page_pool_create(gfp_t gfp_mask, unsigned int order)
{
	struct dmabuf_page_pool *pool;
	struct dmabuf_page_pool_with_spinlock *container_pool =
		kmalloc(sizeof(*container_pool), GFP_KERNEL);
	int i;

	if (!container_pool)
		return NULL;

	spin_lock_init(&container_pool->spinlock);
	pool = &container_pool->pool;

	for (i = 0; i < POOL_TYPE_SIZE; i++) {
		pool->count[i] = 0;
		INIT_LIST_HEAD(&pool->items[i]);
	}
	pool->gfp_mask = gfp_mask | __GFP_COMP;
	pool->order = order;
	mutex_init(&pool->mutex); /* No longer used! */

	mutex_lock(&pool_list_lock);
	list_add(&pool->list, &pool_list);
	mutex_unlock(&pool_list_lock);

	return pool;
}
EXPORT_SYMBOL_GPL(dmabuf_page_pool_create);

void dmabuf_page_pool_destroy(struct dmabuf_page_pool *pool)
{
	struct page *page;
	struct dmabuf_page_pool_with_spinlock *container_pool;
	int i;

	/* Remove us from the pool list */
	mutex_lock(&pool_list_lock);
	list_del(&pool->list);
	mutex_unlock(&pool_list_lock);

	/* Free any remaining pages in the pool */
	for (i = 0; i < POOL_TYPE_SIZE; i++) {
		while ((page = dmabuf_page_pool_remove(pool, i)))
			dmabuf_page_pool_free_pages(pool, page);
	}

	container_pool = container_of(pool, struct dmabuf_page_pool_with_spinlock, pool);
	kfree(container_pool);
}
EXPORT_SYMBOL_GPL(dmabuf_page_pool_destroy);

static int dmabuf_page_pool_do_shrink(struct dmabuf_page_pool *pool, gfp_t gfp_mask,
				      int nr_to_scan)
{
	int freed = 0;
	bool high;

	if (current_is_kswapd())
		high = true;
	else
		high = !!(gfp_mask & __GFP_HIGHMEM);

	if (nr_to_scan == 0)
		return dmabuf_page_pool_total(pool, high);

	while (freed < nr_to_scan) {
		struct page *page;

		/* Try to free low pages first */
		page = dmabuf_page_pool_remove(pool, POOL_LOWPAGE);
		if (!page)
			page = dmabuf_page_pool_remove(pool, POOL_HIGHPAGE);

		if (!page)
			break;

		dmabuf_page_pool_free_pages(pool, page);
		freed += (1 << pool->order);
	}

	return freed;
}

static int dmabuf_page_pool_shrink(gfp_t gfp_mask, int nr_to_scan)
{
	struct dmabuf_page_pool *pool;
	int nr_total = 0;
	int nr_freed;
	int only_scan = 0;

	if (!nr_to_scan)
		only_scan = 1;

	mutex_lock(&pool_list_lock);
	list_for_each_entry(pool, &pool_list, list) {
		if (only_scan) {
			nr_total += dmabuf_page_pool_do_shrink(pool,
							       gfp_mask,
							       nr_to_scan);
		} else {
			nr_freed = dmabuf_page_pool_do_shrink(pool,
							      gfp_mask,
							      nr_to_scan);
			nr_to_scan -= nr_freed;
			nr_total += nr_freed;
			if (nr_to_scan <= 0)
				break;
		}
	}
	mutex_unlock(&pool_list_lock);

	return nr_total;
}

static unsigned long dmabuf_page_pool_shrink_count(struct shrinker *shrinker,
						   struct shrink_control *sc)
{
	return dmabuf_page_pool_shrink(sc->gfp_mask, 0);
}

static unsigned long dmabuf_page_pool_shrink_scan(struct shrinker *shrinker,
						  struct shrink_control *sc)
{
	if (sc->nr_to_scan == 0)
		return 0;
	return dmabuf_page_pool_shrink(sc->gfp_mask, sc->nr_to_scan);
}

struct shrinker pool_shrinker = {
	.count_objects = dmabuf_page_pool_shrink_count,
	.scan_objects = dmabuf_page_pool_shrink_scan,
	.seeks = DEFAULT_SEEKS,
	.batch = 0,
};

#ifdef CONFIG_HUGEPAGE_DMA_BUF_DEBUG
static int pool_info_show(struct seq_file *s, void *v)
{
	struct dmabuf_page_pool *pool;

	mutex_lock(&pool_list_lock);
	seq_printf(s, "%-5s  %-8s  %-8s\n", "order", "LOWPAGE", "HIGHPAGE");
	list_for_each_entry(pool, &pool_list, list) {
		seq_printf(s, "%-5u, %-9d, %-9d\n",
			pool->order, pool->count[POOL_LOWPAGE], pool->count[POOL_LOWPAGE]);
	}
	mutex_unlock(&pool_list_lock);

	seq_printf(s, "%s\n", "pool_info_show end");

	return 0;
}

static int pool_info_open(struct inode *inode, struct file *file)
{
	//(void)inode;
	//return seq_open(file, &_seq_ops);
	return single_open(file, pool_info_show, NULL);
}

static const struct file_operations pool_info_fops = {
	.open = pool_info_open,
	.read = seq_read,
	.llseek = seq_lseek,
	//.release = seq_release,
	.release = single_release,
};

static void dmabuf_pool_debugfs_init(void)
{
	struct dentry *dmabuf_pool_debugfs_dir;
	struct dentry *dentry;

	dmabuf_pool_debugfs_dir = debugfs_create_dir("dmabuf_pool", NULL);
	if (IS_ERR_OR_NULL(dmabuf_pool_debugfs_dir))
		return;

	dentry = debugfs_create_file("pool_info", 0444, dmabuf_pool_debugfs_dir,
		NULL, &pool_info_fops);

	if (IS_ERR(dentry))
		WARN_ONCE(1, "Unable to create 'pool_info' file for dmabuf_pool\n");
}
#endif

static int dmabuf_page_pool_init_shrinker(void)
{
#ifdef CONFIG_HUGEPAGE_DMA_BUF_DEBUG
	dmabuf_pool_debugfs_init();
#endif

	return register_shrinker(&pool_shrinker);
}
module_init(dmabuf_page_pool_init_shrinker);
MODULE_LICENSE("GPL v2");
