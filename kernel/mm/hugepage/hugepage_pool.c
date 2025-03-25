// SPDX-License-Identifier: GPL-2.0-only
/*
 * linux/mm/hugepage_pool.c
 *
 * Copyright (c) 2023, The Linux Foundation. All rights reserved.
 */

#include <uapi/linux/sched/types.h>
#include <linux/suspend.h>
#include <linux/kthread.h>
#include <linux/module.h>
#include <linux/magic.h>
#include <linux/mount.h>
#include <linux/pseudo_fs.h>
#include <linux/migrate.h>
#include <linux/ratelimit.h>
#include <linux/swap.h>
#include <linux/vmstat.h>
#include <linux/memblock.h>
#include <linux/hugepage_pool.h>
#include <linux/debugfs.h>
#include <linux/swap.h>
#include <linux/workqueue.h>
#include <linux/compaction.h>
#include <uapi/linux/sched/types.h>

#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
#include <linux/kprobes.h>
#include <asm/traps.h>
#endif

#include "../mm/internal.h"

#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
#define HUGEPAGE_TAG			"HUGEPAGE"
#define hugepage_debug(fmt, ...) pr_debug("["HUGEPAGE_TAG "][D] %s: " fmt "\n", __func__, ##__VA_ARGS__)
#define hugepage_info(fmt, ...)	pr_info("["HUGEPAGE_TAG "][I] %s: " fmt "\n", __func__, ##__VA_ARGS__)
#define hugepage_err(fmt, ...)	pr_err("["HUGEPAGE_TAG "][E] %s: " fmt "\n", __func__, ##__VA_ARGS__)
#else
#define hugepage_debug(fmt, ...) ((void)0)
#define hugepage_info(fmt, ...)	((void)0)
#define hugepage_err(fmt, ...)	((void)0)
#endif

#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
static int zero_alloc_cnt = 0;
static int alloced_cnt = 0;
static int alloc_successed_cnt = 0;
static int alloc_failed_cnt = 0;
static int alloced_cnts[HPAGE_TYPE_MAX] = {0};
static int refill_skip_cnt = 0;
static int free_add_cnt = 0;
static int none_to_zero_cnt = 0;
static int none_shrink_cnt = 0;
static int zero_shrink_cnt = 0;
static int shrink_cnt = 0;
static int skip_cnt = 0;
#endif

/**
 * struct hugepage_pool - Structure to hold information for the pool
 * @order: Page order describing the size of the page
 * @count: Number of pages currently present in the pool
 * @nonzero_count:Number of nonzero pages currently present in the pool
 * @list_lock: Spinlock for page list in the pool
 * @page_list: List of pages held/reserved in this pool
 * @max_hpages: Limit on number of pages this pool can hold
 * @reserved_hpages: Number of pages reserved at init for the pool
 * @noshrink_hpages: Number of pages cannot be shrinked by the pool shrinker
 * @shrinking: mark is shrinking
 * @kobj: Pointer to the sysfs for this pool
 * @pool_shrink: shrink the pool free page
 * @compact_work: compact pages thread
 */
struct hugepage_pool {
	unsigned int order;
	unsigned int count;
	unsigned int nonzero_count;
	gfp_t gfp_mask;
	spinlock_t list_lock;
	struct list_head page_list;
	spinlock_t nonzero_list_lock;
	struct list_head nonzero_list;
	unsigned int max_hpages;
	unsigned int reserved_hpages;
	unsigned int noshrink_hpages;
	wait_queue_head_t refill_wait;
	atomic_t refill_wait_flag;
	atomic_t shrinking;
	/* sysfs node */
	struct kobject kobj;
	struct shrinker pool_shrink;
#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
	struct dentry *hugepage_pool_debugfs_dir;
#endif
};

static struct hugepage_pool g_pool;

static DEFINE_RATELIMIT_STATE(refill_worker_rs, HZ * 600, 1);

#define SHRINK_STEP_MAX 3
#define REFILL_STEP_MAX 10

#define RESERVE_MAX_PERCENT 8
#define RESERVE_MIN_PERCENT 1

static unsigned long zones_available_simple(void)
{
	unsigned long available = 0;
	unsigned long wmark_low = 0;
	unsigned long pagecache = 0;
	struct zone *zone;

	available = global_zone_page_state(NR_FREE_PAGES) - totalreserve_pages;
	pagecache = global_node_page_state(NR_LRU_BASE + LRU_ACTIVE_FILE) +
		global_node_page_state(NR_LRU_BASE + LRU_INACTIVE_FILE);
	pagecache >>= 1;
	for_each_zone(zone) {
		if (!managed_zone(zone))
			continue;
		wmark_low += low_wmark_pages(zone);
	}
	pagecache -= min(pagecache >> 1, wmark_low);

	available += pagecache;

	hugepage_info("available = %lu", available);

	return available;
}

static unsigned int hugepage_pool_size(struct hugepage_pool *pool)
{
	return pool->count + pool->nonzero_count;
}

static unsigned int hugepage_pool_size_nonreserved(struct hugepage_pool *pool)
{
	unsigned int total = hugepage_pool_size(pool);

	if (total > pool->noshrink_hpages)
		total -= pool->noshrink_hpages;
	else
		total = 0;

	return total;
}

unsigned long total_hugepage_pool_pages(void)
{
	return hugepage_pool_size(&g_pool) << HUGEPAGE_ORDER;
}

static void try_wake_up_refill_worker(struct hugepage_pool *pool)
{
	if (!wq_has_sleeper(&pool->refill_wait)) {
		hugepage_debug("ignore the wake up for wq_has_sleeper");
		return;
	}

	hugepage_debug("try_wake_up_refill_worker");

	if (!__ratelimit(&refill_worker_rs)) {
		hugepage_debug("ignore the wake up for ratelimit");
		return;
	}

	hugepage_debug("refill_worker_rs flags = %u", refill_worker_rs.flags);

	if (!atomic_read(&pool->refill_wait_flag) && ((pool->count < pool->noshrink_hpages) ||
		(pool->nonzero_count == 0))) {
		hugepage_debug("woken up");

		atomic_set(&pool->refill_wait_flag, 1);
		wake_up_interruptible(&pool->refill_wait);
	}
}

void wakeup_hugepool_refill_worker(void)
{
	try_wake_up_refill_worker(&g_pool);
}

bool hugepage_nonzero_list_add(struct page *page)
{
	struct hugepage_pool *pool = &g_pool;

	if (unlikely(!pool->order)) {
#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
		skip_cnt++;
#endif
		return false;
	}
	if ((pool->count + pool->nonzero_count) > pool->max_hpages)
		return false;

	spin_lock(&pool->nonzero_list_lock);
	list_add(&page->lru, &pool->nonzero_list);
	pool->nonzero_count++;
	spin_unlock(&pool->nonzero_list_lock);

#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
	free_add_cnt++;
#endif

	return true;
}

static void nozerolist_to_list(struct hugepage_pool *pool)
{
#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
	ktime_t t_ktime = ktime_get();
	s64 delta;
	unsigned int cnt = 0;
#endif
	if (pool->nonzero_count == 0)
		return;

	spin_lock(&pool->nonzero_list_lock);
	spin_lock(&pool->list_lock);
	while (!list_empty(&pool->nonzero_list)) {
		struct page *page = list_first_entry(&pool->nonzero_list,
						     struct page, lru);
		list_del(&page->lru);
		pool->nonzero_count--;

		prep_new_page(page, HUGEPAGE_ORDER, __GFP_ZERO | __GFP_COMP, 0);
		list_add(&page->lru, &pool->page_list);
		pool->count++;
#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
		cnt++;
#endif
	}
#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
	none_to_zero_cnt += cnt;
#endif
	spin_unlock(&pool->nonzero_list_lock);
	spin_unlock(&pool->list_lock);

#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
	if (pool->nonzero_count > 0)
		hugepage_info("move_list move list unfinished still have count %d", pool->nonzero_count);

	delta = ktime_us_delta(ktime_get(), t_ktime);
	hugepage_info("move_list_delta = %lld , move cnt = %d", delta, cnt);
#endif
}

static unsigned int hugepage_refill_count(struct hugepage_pool *pool)
{
#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
	ktime_t watermark_ktime = ktime_get();
	s64 delta;
#endif
	unsigned int avail_hps = (unsigned int)(zones_available_simple() >> pool->order);
	unsigned int pool_free = hugepage_pool_size(pool);
	unsigned int refill_high_mark = 0;
	unsigned int refill_low_mark = 0;
	unsigned int cnt = 0;

	//not refill pool when shringing
	if (unlikely(atomic_read(&pool->shrinking))) {
		atomic_set(&pool->shrinking, 0);
		return 0;
	}

	refill_low_mark = avail_hps >> 3;
	refill_high_mark = refill_low_mark + (avail_hps >> 5);

	if (unlikely(refill_high_mark > pool->max_hpages))
		refill_high_mark = pool->max_hpages;

	if (pool_free < refill_low_mark)
		cnt = refill_low_mark - pool_free;
	else if (pool_free < refill_high_mark)
		cnt = refill_high_mark - pool_free;

#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
	delta = ktime_us_delta(ktime_get(), watermark_ktime);
	hugepage_info("hugepage_refill_count delta = %lld", delta);
	hugepage_info("hugepage_refill_count cnt = %u", cnt);
	hugepage_info("hugepage_refill_count refill_low_mark = %u", refill_low_mark);
	hugepage_info("hugepage_refill_count avail_hps = %u", avail_hps);
#endif

	return cnt > REFILL_STEP_MAX ? REFILL_STEP_MAX : cnt;
}

static inline void hugepage_pool_add(struct hugepage_pool *pool, struct page *page)
{
	spin_lock(&pool->list_lock);
	list_add(&page->lru, &pool->page_list);
	pool->count++;
	spin_unlock(&pool->list_lock);
#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
	zero_alloc_cnt++;
#endif
}

static void hugepage_pool_refill(struct hugepage_pool *pool)
{
	int refill_count = hugepage_refill_count(pool);
#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
	ktime_t t_ktime = ktime_get();
	s64 delta;
	int cnt = refill_count;
#endif

	if (refill_count == 0)
		return;

	while (refill_count--) {
		struct page* page = alloc_pages(pool->gfp_mask, HUGEPAGE_ORDER);

		if (!page)
			break;
		hugepage_pool_add(pool, page);
	}
#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
	delta = ktime_us_delta(ktime_get(), t_ktime);
	hugepage_info("pool_refill delta = %lld, refill cnt = %d", delta, (cnt - refill_count));
	if (refill_count >= 0) {
		refill_skip_cnt++;
		hugepage_info("refill count remained = %d", refill_count + 1);
	}
#endif
}

static int hugepage_refill_worker(void *p)
{
	set_freezable();

	while (!kthread_should_stop()) {
		wait_event_freezable(g_pool.refill_wait,
				     atomic_read(&g_pool.refill_wait_flag));

		atomic_set(&g_pool.refill_wait_flag, 0);

		nozerolist_to_list(&g_pool);
		hugepage_pool_refill(&g_pool);
	}

	return 0;
}

static struct page *__alloc_hugepage(struct hugepage_pool *pool, int order,
				    enum hpage_type type)
{
	struct page* page = NULL;
	unsigned long flags;

	if (unlikely(order != pool->order))
		return alloc_pages(GFP_KERNEL | __GFP_COMP | __GFP_NORETRY, order);

	spin_lock_irqsave(&pool->list_lock, flags);
	if (!list_empty(&pool->page_list)) {
		page = list_first_entry(&pool->page_list, struct page, lru);
		list_del(&page->lru);
		pool->count--;
	}
	spin_unlock_irqrestore(&pool->list_lock, flags);

#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
	if (likely(page)) {
		alloc_successed_cnt++;
		hugepage_debug("alloc_hugepage success!");
		if (type >= HPAGE_DMA_BUF && type < HPAGE_TYPE_MAX)
			alloced_cnts[type]++;
	} else {
		alloc_failed_cnt++;
	}
#endif

	return page;
}

struct page *alloc_hugepage(int order, enum hpage_type type)
{
#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
	hugepage_info("alloc_hugepage");
	alloced_cnt++;
#endif

	return __alloc_hugepage(&g_pool, order, type);
}
EXPORT_SYMBOL_GPL(alloc_hugepage);

static unsigned long hugepage_pool_shrink_scan(struct shrinker *shrink,
				struct shrink_control *sc)
{
	struct hugepage_pool *pool = container_of(shrink, struct hugepage_pool, pool_shrink);
	unsigned long freed = 0;
	unsigned long nr_to_scan = sc->nr_to_scan;
	unsigned int shrink_free = hugepage_pool_size_nonreserved(pool) >> SHRINK_STEP_MAX;
	struct page *page;

	if (nr_to_scan > shrink_free)
		nr_to_scan = shrink_free;
	hugepage_info("hugepage_pool_shrink_scan--nr_to_scan = %u, nr_scanned = %u",
			nr_to_scan, sc->nr_scanned);

	if (unlikely(nr_to_scan == 0))
		return SHRINK_STOP;

	atomic_set(&pool->shrinking, 1);

	spin_lock(&pool->nonzero_list_lock);
	while (!list_empty(&pool->nonzero_list) &&
			freed < nr_to_scan) {
		page = list_first_entry(&pool->nonzero_list,
				struct page, lru);
		list_del(&page->lru);
		if (page_count(page)) {
			hugepage_debug("hugepage_pool_shrink_scan nonzero_list page_count = %d", page_count(page));
			put_page_testzero(page);
		}
		___free_pages_ok(page, HUGEPAGE_ORDER, FPI_NONE, true);
		pool->nonzero_count--;
#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
		none_shrink_cnt++;
#endif
		freed++;
	}
	spin_unlock(&pool->nonzero_list_lock);

	spin_lock(&pool->list_lock);
	while (!list_empty(&pool->page_list) &&
			freed < nr_to_scan) {
		page = list_first_entry(&pool->page_list,
				struct page, lru);
		list_del(&page->lru);
		if (page_count(page)) {
			hugepage_debug("hugepage_pool_shrink_scan page_list page_count = %d", page_count(page));
			put_page_testzero(page);
		}
		___free_pages_ok(page, HUGEPAGE_ORDER, FPI_NONE, true);
		pool->count--;
#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
		zero_shrink_cnt++;
#endif
		freed++;
	}

#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
	shrink_cnt += freed;
#endif
	spin_unlock(&pool->list_lock);

	hugepage_info("hugepage_pool_shrink_scan--freed = %u", freed);

	return freed << pool->order;
}

static unsigned int __hugepage_pool_shrink_count(struct hugepage_pool *pool)
{
	unsigned int pool_free = hugepage_pool_size_nonreserved(pool);

	return pool_free >> SHRINK_STEP_MAX;
}

DEFINE_RATELIMIT_STATE(ratelimit_scan_rs, HZ, 1);
static unsigned long hugepage_pool_shrink_count(struct shrinker *shrink,
				struct shrink_control *sc)
{
	struct hugepage_pool *pool = container_of(shrink, struct hugepage_pool, pool_shrink);
	unsigned int cnt;

	if (!__ratelimit(&ratelimit_scan_rs))
		return 0;

	cnt = __hugepage_pool_shrink_count(pool);

	return cnt << pool->order;
}

#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
static int pool_info_show(struct seq_file *s, void *v)
{
	struct hugepage_pool *pool = s->private;

	seq_printf(s, "order : %u\n", pool->order);
	seq_printf(s, "count : %u\n", pool->count);
	seq_printf(s, "nonzero_count : %u\n", pool->nonzero_count);
	seq_printf(s, "zero_alloc_cnt : %u\n", zero_alloc_cnt);
	seq_printf(s, "alloced_cnt : %u\n", alloced_cnt);
	seq_printf(s, "alloc_successed_cnt : %u\n", alloc_successed_cnt);
	seq_printf(s, "alloc_failed_cnt : %u\n", alloc_failed_cnt);
	seq_printf(s, "refill_skip_cnt : %u\n", refill_skip_cnt);
	seq_printf(s, "none_to_zero_cnt : %u\n", none_to_zero_cnt);
	seq_printf(s, "none_shrink_cnt : %u\n", none_shrink_cnt);
	seq_printf(s, "zero_shrink_cnt : %u\n", zero_shrink_cnt);
	seq_printf(s, "free_add_cnt : %u\n", free_add_cnt);
	seq_printf(s, "shrink_cnt : %u\n", shrink_cnt);
	seq_printf(s, "skip_cnt : %u\n", skip_cnt);

	seq_printf(s, "dma_alloced : %u\n", alloced_cnts[HPAGE_DMA_BUF]);
	seq_printf(s, "reserved_hpages : %u\n", pool->reserved_hpages);
	seq_printf(s, "noshrink_hpages : %u\n", pool->noshrink_hpages);
	seq_printf(s, "max_hpages : %u\n", pool->max_hpages);
	return 0;
}

static int pool_info_open(struct inode *inode, struct file *file)
{
	return single_open(file, pool_info_show, inode->i_private);
}

static const struct file_operations pool_info_fops = {
	.open = pool_info_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};

static void hugepage_pool_debugfs_init(struct hugepage_pool *pool)
{
	struct dentry *dentry;
	pool->hugepage_pool_debugfs_dir = debugfs_create_dir("hugepage_pool", NULL);
	if (IS_ERR_OR_NULL(pool->hugepage_pool_debugfs_dir))
		return;

	dentry = debugfs_create_file("pool_info", 0444, pool->hugepage_pool_debugfs_dir,
		pool, &pool_info_fops);

	if (IS_ERR(dentry))
		WARN_ONCE(1, "Unable to create 'pool_info' file for hugepage_pool\n");
}

static void hugepage_pool_debugfs_close(struct hugepage_pool *pool)
{
	debugfs_remove_recursive(pool->hugepage_pool_debugfs_dir);
}
#endif

static void __init hugpage_pool_reserve_page(struct hugepage_pool *pool)
{
	int i;
	struct page *page;

	for (i = 0; i < pool->reserved_hpages; i++) {
		page = alloc_pages(pool->gfp_mask, HUGEPAGE_ORDER);
		if (!page)
			break;

		hugepage_pool_add(pool, page);
	}
}

#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
#define HUGEPAGE_MODE_RO 0440
#define HUGEPAGE_MODE_RW 0660

#define HUGEPAGE_ATTR(_name, _mode, _show, _store) \
	struct kobj_attribute kobj_attr_##_name \
		= __ATTR(_name, _mode, _show, _store)

static ssize_t pool_info_show_(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	struct hugepage_pool *pool = container_of(kobj, struct hugepage_pool, kobj);
	ssize_t ret;

	ret = scnprintf(buf, PAGE_SIZE, "%-5s %-5s %-13s\n",
			"order", "count", "nonzero_count");
	ret += scnprintf(buf + ret, PAGE_SIZE - ret, "%-6u %-6u  %-14u\n",
			pool->order, pool->count, pool->nonzero_count);

	return ret;
}

static ssize_t pool_shrink_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	ssize_t ret = 0;

	ret += scnprintf(buf + ret, PAGE_SIZE - ret, "zero_alloc_cnt : %u\n", zero_alloc_cnt);
	ret += scnprintf(buf + ret, PAGE_SIZE - ret, "alloced_cnt : %u\n", alloced_cnt);
	ret += scnprintf(buf + ret, PAGE_SIZE - ret, "alloc_successed_cnt : %u\n", alloc_successed_cnt);
	ret += scnprintf(buf + ret, PAGE_SIZE - ret, "alloc_failed_cnt : %u\n", alloc_failed_cnt);
	ret += scnprintf(buf + ret, PAGE_SIZE - ret, "refill_skip_cnt : %u\n", refill_skip_cnt);
	ret += scnprintf(buf + ret, PAGE_SIZE - ret, "none_to_zero_cnt : %u\n", none_to_zero_cnt);
	ret += scnprintf(buf + ret, PAGE_SIZE - ret, "none_shrink_cnt : %u\n", none_shrink_cnt);
	ret += scnprintf(buf + ret, PAGE_SIZE - ret, "zero_shrink_cnt : %u\n", zero_shrink_cnt);
	ret += scnprintf(buf + ret, PAGE_SIZE - ret, "free_add_cnt : %u\n", free_add_cnt);
	ret += scnprintf(buf + ret, PAGE_SIZE - ret, "shrink_cnt : %u\n", shrink_cnt);
	ret += scnprintf(buf + ret, PAGE_SIZE - ret, "skip_cnt : %u\n", skip_cnt);

	ret += scnprintf(buf + ret, PAGE_SIZE - ret, "dma_alloced : %u, gpu_alloced : %u, vmalloced : %u\n",
			alloced_cnts[HPAGE_DMA_BUF], alloced_cnts[HPAGE_GPU], alloced_cnts[HPAGE_VMALLOC]);

	return ret;
}

static HUGEPAGE_ATTR(pool_info, HUGEPAGE_MODE_RW, pool_info_show_, NULL);
static HUGEPAGE_ATTR(pool_shrink, HUGEPAGE_MODE_RW, pool_shrink_show, NULL);
#endif

static struct attribute *hugepage_attrs[] = {
#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
	&kobj_attr_pool_info.attr,
	&kobj_attr_pool_shrink.attr,
#endif
	NULL,
};

static struct attribute_group hugepage_attr_group = {
	.attrs = hugepage_attrs,
};

/**
 * purpose: create sysfs nodes for module
 * arguments:
 *    none
 * return:
 *    kobject : for future destroy.
 */
static void sysfs_create(struct hugepage_pool *pool)
{
	int ret;

	kobject_init(&pool->kobj, kernel_kobj->ktype);

	pool->kobj.kset = kernel_kobj->kset;
	ret = kobject_add(&pool->kobj, kernel_kobj, "%s", "hugepage");
	if (ret != 0) {
		hugepage_err("failed to kobject_add node");
		kobject_put(&pool->kobj);
		return;
	}
	ret = sysfs_create_group(&pool->kobj, &hugepage_attr_group);
	if (ret != 0) {
		hugepage_err("failed to create sysfs attrs");
		kobject_put(&pool->kobj);
		return;
	}
}

static void __init hugepage_pool_create(struct hugepage_pool *pool)
{
	unsigned long total_hpages = totalram_pages() >> HUGEPAGE_ORDER;

	pool->order = HUGEPAGE_ORDER;
	pool->count = 0;
	pool->nonzero_count = 0;
	pool->gfp_mask = ((GFP_HIGHUSER | __GFP_ZERO | __GFP_NOWARN |
			   __GFP_COMP | __GFP_NORETRY) &
			  ~__GFP_RECLAIM); //GFP_TRANSHUGE

	spin_lock_init(&pool->list_lock);
	spin_lock_init(&pool->nonzero_list_lock);
	INIT_LIST_HEAD(&pool->page_list);
	INIT_LIST_HEAD(&pool->nonzero_list);

	pool->reserved_hpages = total_hpages * RESERVE_MAX_PERCENT / 100;
	pool->noshrink_hpages = total_hpages * RESERVE_MIN_PERCENT / 100;
	pool->max_hpages = pool->reserved_hpages * 3 / 2;

	init_waitqueue_head(&pool->refill_wait);
	atomic_set(&pool->refill_wait_flag, 0);
	atomic_set(&pool->shrinking, 0);

	hugepage_info("hugepage_pool_create");
}

#define REFILL_WORKER_BIND_CPUS "0-6"
static void __init refill_worker_update_cpumask(struct task_struct *tsk)
{
	int retval;
	pg_data_t *pgdat = NODE_DATA(0);
	struct cpumask temp_mask;
	const struct cpumask *cpumask = cpumask_of_node(pgdat->node_id);

	cpumask_clear(&temp_mask);
	retval = cpulist_parse(REFILL_WORKER_BIND_CPUS, &temp_mask);
	if (retval < 0 || cpumask_empty(&temp_mask)) {
		pr_err("%s are invalid, use default\n", REFILL_WORKER_BIND_CPUS);
		goto use_default;
	}

	if (!cpumask_subset(&temp_mask, cpu_present_mask)) {
		pr_err("%s is not subset of cpu_present_mask, use default\n", REFILL_WORKER_BIND_CPUS);
		goto use_default;
	}

	if (!cpumask_subset(&temp_mask, cpumask)) {
		pr_err("%s is not subset of cpumask, use default\n", REFILL_WORKER_BIND_CPUS);
		goto use_default;
	}

	set_cpus_allowed_ptr(tsk, &temp_mask);
	return;

use_default:
	if (!cpumask_empty(cpumask))
		set_cpus_allowed_ptr(tsk, cpumask);
}

static int __init hugepage_pool_init(void)
{
	const unsigned int hugepage_pool_nice = 5;
	struct hugepage_pool *pool = &g_pool;
	struct sched_attr attr = {
		.sched_flags = SCHED_FLAG_UTIL_CLAMP,
		.sched_nice = hugepage_pool_nice,
		.sched_util_min = 0,
		.sched_util_max = 40,
	};
	struct task_struct *refill_worker;
	int ret;

	hugepage_pool_create(pool);
	hugpage_pool_reserve_page(pool);
	ratelimit_set_flags(&refill_worker_rs, RATELIMIT_MSG_ON_RELEASE);
	ratelimit_set_flags(&ratelimit_scan_rs, RATELIMIT_MSG_ON_RELEASE);

	refill_worker = kthread_create(hugepage_refill_worker, NULL,
					   "refill_worker_hugepage_pool");
	if (IS_ERR(refill_worker)) {
		hugepage_err("Failed to start refill_worker");
		return PTR_ERR(refill_worker);
	}

	ret = sched_setattr(refill_worker, &attr);
	if (ret) {
		pr_warn("%s: failed to set sched attr for refill_worker_hugepage_pool\n", __func__);
		kthread_stop(refill_worker);
		return ret;
	}

	pool->pool_shrink.count_objects = hugepage_pool_shrink_count;
	pool->pool_shrink.scan_objects = hugepage_pool_shrink_scan;
	pool->pool_shrink.seeks = DEFAULT_SEEKS;
	if (register_shrinker(&pool->pool_shrink)) {
		hugepage_err("register shrinker Failed");
		kthread_stop(refill_worker);
	}

	sysfs_create(pool);

#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
	hugepage_pool_debugfs_init(pool);
#endif

	refill_worker_update_cpumask(refill_worker);
	wake_up_process(refill_worker);

	return 0;
}

static void __exit hugepage_pool_exit(void)
{
	struct hugepage_pool *pool = &g_pool;

	/* Unregister shrinker */
	unregister_shrinker(&pool->pool_shrink);

#ifdef CONFIG_HUGEPAGE_POOL_DEBUG
	hugepage_pool_debugfs_close(pool);
#endif
}

module_init(hugepage_pool_init);
module_exit(hugepage_pool_exit);
