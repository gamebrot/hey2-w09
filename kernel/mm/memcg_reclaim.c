/*
 * memcg_reclaim.c
 *
 * Copyright (C) Honor Technologies Co., Ltd. 2020. All rights reserved.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#ifndef CONFIG_HYPERHOLD_GKI
#ifdef CONFIG_HYPERHOLD
#ifndef SCAN_CONTROL_NO_EXPORT
#include <linux/mm.h>
#include <linux/sched/mm.h>
#include <linux/module.h>
#include <linux/gfp.h>
#include <linux/kernel_stat.h>
#include <linux/swap.h>
#include <linux/pagemap.h>
#include <linux/init.h>
#include <linux/highmem.h>
#include <linux/vmpressure.h>
#include <linux/vmstat.h>
#include <linux/file.h>
#include <linux/writeback.h>
#include <linux/blkdev.h>
#include <linux/buffer_head.h>
#include <linux/mm_inline.h>
#include <linux/backing-dev.h>
#include <linux/rmap.h>
#include <linux/topology.h>
#include <linux/cpu.h>
#include <linux/cpuset.h>
#include <linux/compaction.h>
#include <linux/notifier.h>
#include <linux/rwsem.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/memcontrol.h>
#include <linux/delayacct.h>
#include <linux/sysctl.h>
#include <linux/oom.h>
#include <linux/prefetch.h>
#include <linux/printk.h>
#include <linux/dax.h>
#include <linux/psi.h>

#include <asm/tlbflush.h>
#include <asm/div64.h>
#include <linux/atomic.h>
#include <linux/swapops.h>
#include <linux/balloon_compaction.h>
#include <trace/events/vmscan.h>
#endif
#include <uapi/linux/sched/types.h>

#ifdef CONFIG_MEMCG_PROTECT_LRU
#include <linux/protect_lru.h>
#endif

#ifdef CONFIG_HYPERHOLD
#include <linux/hyperhold_inf.h>
#endif

#include <linux/version.h>
#include <linux/memcg_policy.h>
#include "memcg_policy_internal.h"
#include "internal.h"

#if (KERNEL_VERSION(5, 10, 0) > LINUX_VERSION_CODE)
#ifdef CONFIG_RCC
extern unsigned rcc_thread_id;
#endif
#endif

static wait_queue_head_t snapshotd_wait;
static atomic_t snapshotd_wait_flag;
static atomic_t snapshotd_init_flag = ATOMIC_LONG_INIT(0);
static struct task_struct *snapshotd_task;

#if (KERNEL_VERSION(4, 19, 0) < LINUX_VERSION_CODE)
static void zswapd_pause_timer_handle(struct timer_list *unused)
{
	set_zswapd_pause_stat(0);
}
#else
static void zswapd_pause_timer_handle(unsigned long data)
{
	set_zswapd_pause_stat(0);
}
#endif

#if (KERNEL_VERSION(4, 19, 0) < LINUX_VERSION_CODE)
static DEFINE_TIMER(zswapd_pause_timer, zswapd_pause_timer_handle);
#else
static DEFINE_TIMER(zswapd_pause_timer, zswapd_pause_timer_handle, 0, 0);
#endif

unsigned long reclaim_anon_memcg(struct pglist_data *pgdat,
		struct mem_cgroup *memcg, unsigned long nr_to_scan)
{
	LIST_HEAD(page_list);
#if (KERNEL_VERSION(5, 10, 0) <= LINUX_VERSION_CODE)
	struct lruvec *lruvec = mem_cgroup_lruvec(memcg, pgdat);
#else
	struct lruvec *lruvec = mem_cgroup_lruvec(pgdat, memcg);
#endif
	unsigned long nr_reclaimed;
	unsigned long nr_taken;
	unsigned long nr_lru_size;
	unsigned long nr_scanned;
	struct page *page = NULL;
	struct reclaim_stat stat = {};
	struct scan_control sc = {
		.gfp_mask = GFP_KERNEL,
		.reclaim_idx = MAX_NR_ZONES - 1,
		.may_writepage = 1,
		.may_unmap = 1,
		.may_swap = 1,
	};

	spin_lock_irq(&pgdat->lru_lock);
	nr_lru_size = lruvec_lru_size(lruvec, LRU_INACTIVE_ANON, MAX_NR_ZONES);
	nr_to_scan = min(nr_lru_size, nr_to_scan);
	nr_taken = isolate_lru_pages(nr_to_scan, lruvec, &page_list,
				     &nr_scanned, &sc,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 61)
				     (isolate_mode_t)0,
#endif
					  LRU_INACTIVE_ANON);
	spin_unlock_irq(&pgdat->lru_lock);

#if (KERNEL_VERSION(5, 10, 0) <= LINUX_VERSION_CODE)
	nr_reclaimed = shrink_page_list(&page_list, NULL, &sc,
			&stat, true);
#else
	nr_reclaimed = shrink_page_list(&page_list, NULL, &sc,
				TTU_IGNORE_ACCESS, &stat, true);
#endif

	while (!list_empty(&page_list)) {
		page = lru_to_page(&page_list);
		list_del(&page->lru);
		putback_lru_page(page);
	}
	return nr_reclaimed;
}

unsigned long reclaim_all_anon_memcg(struct pglist_data *pgdat,
		struct mem_cgroup *memcg)
{
#if (KERNEL_VERSION(5, 10, 0) <= LINUX_VERSION_CODE)
	struct lruvec *lruvec = mem_cgroup_lruvec(memcg, pgdat);
#else
	struct lruvec *lruvec = mem_cgroup_lruvec(pgdat, memcg);
#endif
	unsigned long nr_to_scan;

	nr_to_scan = lruvec_lru_size(lruvec, LRU_INACTIVE_ANON, MAX_NR_ZONES);
	return reclaim_anon_memcg(pgdat, memcg, nr_to_scan);
}

#ifdef CONFIG_HYPERHOLD_FILE_LRU
static inline bool is_swap_not_allowed(struct scan_control *sc, int swappiness)
{
	return !sc->may_swap || !swappiness || !get_nr_swap_pages();
}

#ifdef CONFIG_DIRECT_SWAPPINESS
static inline int get_direct_swappiness(void)
{
#if defined(CONFIG_HYPERHOLD_CORE) && defined(CONFIG_HYPERHOLD_ZSWAPD)
	return hyperhold_enable() ? 0 : direct_vm_swappiness;
#else
	return direct_vm_swappiness;
#endif
}
#endif

static void get_scan_count_hyperhold(struct pglist_data *pgdat,
		struct scan_control *sc, unsigned long *nr,
		unsigned long *lru_pages)
{
	int swappiness = vm_swappiness;
	struct lruvec *lruvec = node_lruvec(pgdat);
	u64 fraction[2];
	u64 denominator;
	unsigned long anon_prio, file_prio;
	enum scan_balance scan_balance;
	unsigned long ap, fp;
	unsigned long pgdatfile;
	enum lru_list lru;


#if (KERNEL_VERSION(5, 10, 0) <= LINUX_VERSION_CODE)
	unsigned long anon_cost, file_cost, total_cost;
	bool balance_anon_file_reclaim = false;
#else
	struct zone_reclaim_stat *reclaim_stat = &lruvec->reclaim_stat;
	unsigned long anon, file;
	unsigned long pgdatfree;
	int z;
	unsigned long total_high_wmark = 0;
#endif

#ifdef CONFIG_DIRECT_SWAPPINESS
	if (!current_is_kswapd())
		swappiness = get_direct_swappiness();

	pgdatfile = node_page_state(pgdat, NR_ACTIVE_FILE) +
		node_page_state(pgdat, NR_INACTIVE_FILE);
	if (pgdatfile <= 20 * SZ_1M / PAGE_SIZE)
		swappiness = 0;
#endif

	/* If we have no swap space, do not bother scanning anon pages. */
	if (is_swap_not_allowed(sc, swappiness)) {
		scan_balance = SCAN_FILE;
		goto out;
	}

	/*
	 * Do not apply any pressure balancing cleverness when the
	 * system is close to OOM, scan both anon and file equally
	 * (unless the swappiness setting disagrees with swapping).
	 */
	if (!sc->priority && swappiness) {
		scan_balance = SCAN_EQUAL;
		goto out;
	}

#if (KERNEL_VERSION(5, 10, 0) <= LINUX_VERSION_CODE)
	/*
	 * If the system is almost out of file pages, force-scan anon.
	 */
	if (sc->file_is_tiny) {
		scan_balance = SCAN_ANON;
		goto out;
	}
#else
	pgdatfree = sum_zone_node_page_state(pgdat->node_id, NR_FREE_PAGES);
	pgdatfile = node_page_state(pgdat, NR_ACTIVE_FILE) +
		node_page_state(pgdat, NR_INACTIVE_FILE);
	for (z = 0; z < MAX_NR_ZONES; z++) {
		struct zone *zone = &pgdat->node_zones[z];

		if (!managed_zone(zone))
			continue;

		total_high_wmark += high_wmark_pages(zone);
	}

	if (unlikely(pgdatfile + pgdatfree <= total_high_wmark)) {
		/*
		 * Force SCAN_ANON if there are enough inactive
		 * anonymous pages on the LRU in eligible zones.
		 * Otherwise, the small LRU gets thrashed.
		 */
		if (!inactive_list_is_low(lruvec, false, sc, false) &&
			(lruvec_lru_size(lruvec, LRU_INACTIVE_ANON,
				sc->reclaim_idx) >>
				(unsigned int)sc->priority)) {
			scan_balance = SCAN_ANON;
			goto out;
		}
	}
#endif

	/*
	 * If there is enough inactive page cache, i.e. if the size of the
	 * inactive list is greater than that of the active list *and* the
	 * inactive list actually has some pages to scan on this priority, we
	 * do not reclaim anything from the anonymous working set right now.
	 * Without the second condition we could end up never scanning an
	 * lruvec even if it has plenty of old anonymous pages unless the
	 * system is under heavy pressure.
	 */
#if (KERNEL_VERSION(5, 10, 0) <= LINUX_VERSION_CODE)
	if (!balance_anon_file_reclaim && sc->cache_trim_mode) {
		scan_balance = SCAN_FILE;
		goto out;
	}
#else
	if (enough_inactive_file == 0 &&
		!inactive_list_is_low(lruvec, true, sc, false) &&
		(lruvec_lru_size(lruvec, LRU_INACTIVE_FILE,
			sc->reclaim_idx) >> (unsigned int)sc->priority)) {
		scan_balance = SCAN_FILE;
		goto out;
	}
#endif


	scan_balance = SCAN_FRACT;

	/*
	 * With swappiness at 100, anonymous and file have the same priority.
	 * This scanning priority is essentially the inverse of IO cost.
	 */
	anon_prio = swappiness;
	file_prio = 200 - anon_prio;

	/*
	 * Calculate the pressure balance between anon and file pages.
	 *
	 * The amount of pressure we put on each LRU is inversely
	 * proportional to the cost of reclaiming each list, as
	 * determined by the share of pages that are refaulting, times
	 * the relative IO cost of bringing back a swapped out
	 * anonymous page vs reloading a filesystem page (swappiness).
	 *
	 * Although we limit that influence to ensure no list gets
	 * left behind completely: at least a third of the pressure is
	 * applied, before swappiness.
	 *
	 * With swappiness at 100, anon and file have equal IO cost.
	 */
	/*
	 * Determine the scan balance between anon and file LRUs.
	 */
#if (KERNEL_VERSION(5, 10, 0) <= LINUX_VERSION_CODE)
	spin_lock_irq(&pgdat->lru_lock);
	sc->anon_cost = lruvec->anon_cost;
	sc->file_cost = lruvec->file_cost;
	spin_unlock_irq(&pgdat->lru_lock);

	total_cost = sc->anon_cost + sc->file_cost;
	anon_cost = total_cost + sc->anon_cost;
	file_cost = total_cost + sc->file_cost;
	total_cost = anon_cost + file_cost;

	ap = swappiness * (total_cost + 1);
	ap /= anon_cost + 1;

	fp = (200 - swappiness) * (total_cost + 1);
	fp /= file_cost + 1;
#else
	anon  = lruvec_lru_size(lruvec, LRU_ACTIVE_ANON, MAX_NR_ZONES) +
		lruvec_lru_size(lruvec, LRU_INACTIVE_ANON, MAX_NR_ZONES);
	file  = lruvec_lru_size(lruvec, LRU_ACTIVE_FILE, MAX_NR_ZONES) +
		lruvec_lru_size(lruvec, LRU_INACTIVE_FILE, MAX_NR_ZONES);

	spin_lock_irq(&pgdat->lru_lock);
	if (unlikely(reclaim_stat->recent_scanned[0] > anon / 4)) {
		reclaim_stat->recent_scanned[0] /= 2;
		reclaim_stat->recent_rotated[0] /= 2;
	}

	if (unlikely(reclaim_stat->recent_scanned[1] > file / 4)) {
		reclaim_stat->recent_scanned[1] /= 2;
		reclaim_stat->recent_rotated[1] /= 2;
	}

	/*
	 * The amount of pressure on anon vs file pages is inversely
	 * proportional to the fraction of recently scanned pages on
	 * each list that were recently referenced and in active use.
	 */
	ap = anon_prio * (reclaim_stat->recent_scanned[0] + 1);
	ap /= reclaim_stat->recent_rotated[0] + 1;

	fp = file_prio * (reclaim_stat->recent_scanned[1] + 1);
	fp /= reclaim_stat->recent_rotated[1] + 1;
	spin_unlock_irq(&pgdat->lru_lock);
#endif

	fraction[0] = ap;
	fraction[1] = fp;
	denominator = ap + fp + 1;
out:
#if (KERNEL_VERSION(5, 10, 0) <= LINUX_VERSION_CODE)
	trace_android_vh_tune_scan_type((char *)(&scan_balance));
#else
#ifdef CONFIG_RCC
	if (current->pid == rcc_thread_id)
		scan_balance = SCAN_ANON;
#endif
#endif
	*lru_pages = 0;
	for_each_evictable_lru(lru) {
		int file; /*lint !e578*/
		unsigned long size;
		unsigned long scan;

		file = is_file_lru(lru);
		size = lruvec_lru_size(lruvec, lru, sc->reclaim_idx);
		scan = size >> (unsigned int)sc->priority;
		/*
		 * If the cgroup's already been deleted, make sure to
		 * scrape out the remaining cache.
		 */
		switch (scan_balance) {
		case SCAN_EQUAL:
			/* Scan lists relative to size */
			break;
		case SCAN_FRACT:
			/*
			 * Scan types proportional to swappiness and
			 * their relative recent reclaim efficiency.
			 * Make sure we don't miss the last page
			 * because of a round-off error.
			 */
			scan = DIV64_U64_ROUND_UP(scan * fraction[file],
					denominator); /*lint !e644*/
			break;
		case SCAN_FILE:
		case SCAN_ANON:
			/* Scan one type exclusively */
			if ((scan_balance == SCAN_FILE) != file) {
				size = 0;
				scan = 0;
			}
			break;
		default:
			break;
		}

		*lru_pages += size;
		nr[lru] = scan;
	}
}

#define ISOLATE_LIMIT_CNT 5
void shrink_anon_memcg(struct pglist_data *pgdat,
		struct mem_cgroup *memcg, struct scan_control *sc,
		unsigned long *nr)
{
#if (KERNEL_VERSION(5, 10, 0) <= LINUX_VERSION_CODE)
	struct lruvec *lruvec = mem_cgroup_lruvec(memcg, pgdat);
#else
	struct lruvec *lruvec = mem_cgroup_lruvec(pgdat, memcg);
#endif
	unsigned long nr_to_scan;
	enum lru_list lru;
	unsigned long nr_reclaimed = 0;
	struct blk_plug plug;

	blk_start_plug(&plug);

	while (nr[LRU_INACTIVE_ANON] || nr[LRU_ACTIVE_ANON]) {
		for (lru = 0; lru <= LRU_ACTIVE_ANON; lru++) {
			if (nr[lru]) {
				nr_to_scan = min(nr[lru], SWAP_CLUSTER_MAX);
				nr[lru] -= nr_to_scan;
				nr_reclaimed +=
					shrink_list(lru, nr_to_scan,
							lruvec, sc);
			}
		}

		cond_resched();

		if ((sc->nr_reclaimed + nr_reclaimed) >= sc->nr_to_reclaim ||
				(sc->isolate_count > ISOLATE_LIMIT_CNT &&
				sc->invoker == DIRECT_RECLAIM))
			break;
	}
	blk_finish_plug(&plug);
	sc->nr_reclaimed += nr_reclaimed;
}

static void shrink_anon(struct pglist_data *pgdat,
		struct scan_control *sc, unsigned long *nr)
{
	unsigned long reclaimed;
	unsigned long scanned;
	struct mem_cgroup *memcg = NULL;
	unsigned long nr_memcg[NR_LRU_LISTS];
	unsigned long nr_node_active = lruvec_lru_size(
			node_lruvec(pgdat), LRU_ACTIVE_ANON, MAX_NR_ZONES);
	unsigned long nr_node_inactive = lruvec_lru_size(
			node_lruvec(pgdat), LRU_INACTIVE_ANON, MAX_NR_ZONES);

	while ((memcg = get_next_memcg(memcg))) {
#if (KERNEL_VERSION(5, 10, 0) <= LINUX_VERSION_CODE)
		struct lruvec *lruvec = mem_cgroup_lruvec(memcg, pgdat);
#else
		struct lruvec *lruvec = mem_cgroup_lruvec(pgdat, memcg);
#endif
		reclaimed = sc->nr_reclaimed;
		scanned = sc->nr_scanned;

		nr_memcg[LRU_ACTIVE_ANON] = nr[LRU_ACTIVE_ANON] *
			lruvec_lru_size(lruvec, LRU_ACTIVE_ANON,
					MAX_NR_ZONES) / (nr_node_active + 1);
		nr_memcg[LRU_INACTIVE_ANON] = nr[LRU_INACTIVE_ANON] *
			lruvec_lru_size(lruvec, LRU_INACTIVE_ANON,
					MAX_NR_ZONES) / (nr_node_inactive + 1);
		nr_memcg[LRU_ACTIVE_FILE] = 0;
		nr_memcg[LRU_INACTIVE_FILE] = 0;

		shrink_anon_memcg(pgdat, memcg, sc, nr_memcg);

		vmpressure(sc->gfp_mask, memcg, false,
				sc->nr_scanned - scanned,
				sc->nr_reclaimed - reclaimed);

		if (sc->nr_reclaimed >= sc->nr_to_reclaim ||
			(sc->isolate_count > ISOLATE_LIMIT_CNT &&
			sc->invoker == DIRECT_RECLAIM)) {
			get_next_memcg_break(memcg);
			break;
		}
	}
}

static void shrink_file(struct pglist_data *pgdat,
		struct scan_control *sc, unsigned long *nr)
{
	struct lruvec *lruvec = node_lruvec(pgdat);
	unsigned long nr_to_scan;
	enum lru_list lru;
	unsigned long nr_reclaimed = 0;
	struct blk_plug plug;

	blk_start_plug(&plug);

	while (nr[LRU_ACTIVE_FILE] || nr[LRU_INACTIVE_FILE]) {
		for (lru = LRU_INACTIVE_FILE; lru <= LRU_ACTIVE_FILE; lru++) {
			if (nr[lru]) {
				nr_to_scan = min(nr[lru], SWAP_CLUSTER_MAX);
				nr[lru] -= nr_to_scan;
				nr_reclaimed +=
					shrink_list(lru,
							nr_to_scan,
							lruvec, sc);
			}
		}

		cond_resched();

	}
	blk_finish_plug(&plug);
	sc->nr_reclaimed += nr_reclaimed;
}

bool shrink_node_hyperhold(pg_data_t *pgdat, struct scan_control *sc)
{
	struct reclaim_state *reclaim_state = current->reclaim_state;
	unsigned long nr_reclaimed, nr_scanned;
	bool reclaimable = false;
#if (KERNEL_VERSION(5, 10, 0) <= LINUX_VERSION_CODE)
	struct lruvec *target_lruvec;
	unsigned long file;
#endif


#ifdef CONFIG_MEMCG_PROTECT_LRU
	if (current_is_kswapd()) {
		shrink_prot_memcg_by_overratio();
	}
#endif
	do {
		/* Get scan count for file and anon */
		unsigned long node_lru_pages = 0;
		unsigned long nr[NR_LRU_LISTS] = {0};

		nr_reclaimed = sc->nr_reclaimed;
		nr_scanned = sc->nr_scanned;

#if (KERNEL_VERSION(5, 10, 0) <= LINUX_VERSION_CODE)

#ifdef CONFIG_HYPERHOLD_FILE_LRU
		target_lruvec = node_lruvec(pgdat);
#else
		target_lruvec = mem_cgroup_lruvec(sc->target_mem_cgroup, pgdat);
#endif
		/*
		* Target desirable inactive:active list ratios for the anon
		* and file LRU lists.
		*/
		if (!sc->force_deactivate) {
			unsigned long refaults;

			refaults = lruvec_page_state(target_lruvec,
					WORKINGSET_ACTIVATE_ANON);
			if (refaults != target_lruvec->refaults[0] ||
				inactive_is_low(target_lruvec, LRU_INACTIVE_ANON))
				sc->may_deactivate |= DEACTIVATE_ANON;
			else
				sc->may_deactivate &= ~DEACTIVATE_ANON;

			/*
			* When refaults are being observed, it means a new
			* workingset is being established. Deactivate to get
			* rid of any stale active pages quickly.
			*/
#ifdef CONFIG_HYPERHOLD_FILE_LRU
			if (inactive_is_low(target_lruvec, LRU_INACTIVE_FILE))
#else
			refaults = lruvec_page_state(target_lruvec,
					WORKINGSET_ACTIVATE_FILE);
			if (refaults != target_lruvec->refaults[1] ||
				inactive_is_low(target_lruvec, LRU_INACTIVE_FILE))
#endif
				sc->may_deactivate |= DEACTIVATE_FILE;
			else
				sc->may_deactivate &= ~DEACTIVATE_FILE;
		} else
			sc->may_deactivate = DEACTIVATE_ANON | DEACTIVATE_FILE;

		/*
		* If we have plenty of inactive file pages that aren't
		* thrashing, try to reclaim those first before touching
		* anonymous pages.
		*/
		file = lruvec_page_state(target_lruvec, NR_INACTIVE_FILE);
		if (file >> sc->priority && !(sc->may_deactivate & DEACTIVATE_FILE))
			sc->cache_trim_mode = 1;
		else
			sc->cache_trim_mode = 0;

		/*
		* Prevent the reclaimer from falling into the cache trap: as
		* cache pages start out inactive, every cache fault will tip
		* the scan balance towards the file LRU.  And as the file LRU
		* shrinks, so does the window for rotation from references.
		* This means we have a runaway feedback loop where a tiny
		* thrashing file LRU becomes infinitely more attractive than
		* anon pages.  Try to detect this based on file LRU size.
		*/
		if (!cgroup_reclaim(sc)) {
			unsigned long total_high_wmark = 0;
			unsigned long free, anon;
			int z;

			free = sum_zone_node_page_state(pgdat->node_id, NR_FREE_PAGES);
			file = node_page_state(pgdat, NR_ACTIVE_FILE) +
				node_page_state(pgdat, NR_INACTIVE_FILE);

			for (z = 0; z < MAX_NR_ZONES; z++) {
				struct zone *zone = &pgdat->node_zones[z];
				if (!managed_zone(zone))
					continue;

				total_high_wmark += high_wmark_pages(zone);
			}

			/*
			* Consider anon: if that's low too, this isn't a
			* runaway file reclaim problem, but rather just
			* extreme pressure. Reclaim as per usual then.
			*/
			anon = node_page_state(pgdat, NR_INACTIVE_ANON);

			sc->file_is_tiny =
				file + free <= total_high_wmark &&
				!(sc->may_deactivate & DEACTIVATE_ANON) &&
				anon >> sc->priority;
		}
#endif
		get_scan_count_hyperhold(pgdat, sc, nr, &node_lru_pages);
		/* Shrink the Total-File-LRU */
		shrink_file(pgdat, sc, nr);
#if (KERNEL_VERSION(5, 10, 0) <= LINUX_VERSION_CODE)
		if (waitqueue_active(&pgdat->pfmemalloc_wait) &&
				allow_direct_reclaim(pgdat))
			wake_up_all(&pgdat->pfmemalloc_wait);
#endif

		/* Shrink Anon by iterating score_list */
		shrink_anon(pgdat, sc, nr);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
		shrink_slab(sc->gfp_mask, pgdat->node_id, NULL,
			sc->nr_scanned - nr_scanned,
			node_lru_pages);
#else
		shrink_slab(sc->gfp_mask, pgdat->node_id, NULL, sc->priority);
#endif

		if (reclaim_state) {
			sc->nr_reclaimed += reclaim_state->reclaimed_slab;
			reclaim_state->reclaimed_slab = 0;
		}

		/* Record the subtree's reclaim efficiency */
		vmpressure(sc->gfp_mask, sc->target_mem_cgroup, true,
			   sc->nr_scanned - nr_scanned,
			   sc->nr_reclaimed - nr_reclaimed);

		if (sc->nr_reclaimed - nr_reclaimed)
			reclaimable = true;

	} while (should_continue_reclaim(pgdat, sc->nr_reclaimed - nr_reclaimed,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 61)
					 sc->nr_scanned - nr_scanned,
#endif
					 sc));

	/*
	 * Kswapd gives up on balancing particular nodes after too
	 * many failures to reclaim anything from them and goes to
	 * sleep. On reclaim progress, reset the failure counter. A
	 * successful direct reclaim run will revive a dormant kswapd.
	 */
	if (reclaimable)
		pgdat->kswapd_failures = 0;

	return reclaimable;
}
#endif

#ifdef CONFIG_HYPERHOLD_ZSWAPD
static pid_t zswapd_pid = -1;
static unsigned long long area_last_anon_pagefault;
static unsigned long last_anon_snapshot_time;
unsigned long long global_anon_refault_ratio;
unsigned long long zswapd_skip_interval;
bool last_round_is_empty;
unsigned long last_zswapd_time;

#define M(x) ((x) >> (20 - PAGE_SHIFT))
unsigned int calc_sys_cur_avail_buffers(void)
{
	return M(si_mem_available());
}

void zswapd_status_show(struct seq_file *m)
{
	unsigned int buffers = calc_sys_cur_avail_buffers();

	seq_printf(m, "buffer size: %u MB\n", buffers);
	seq_printf(m, "recent refault: %lu\n", global_anon_refault_ratio);
}

pid_t get_zswapd_pid(void)
{
	return zswapd_pid;
}

static bool min_buffer_is_suitable(void)
{
	u32 curr_buffers = calc_sys_cur_avail_buffers();

	if (curr_buffers >= get_min_avail_buffers_value())
		return true;

	return false;
}

static bool buffer_is_suitable(void)
{
	u32 curr_buffers = calc_sys_cur_avail_buffers();

	if (curr_buffers >= get_avail_buffers_value())
		return true;

	return false;
}

static bool high_buffer_is_suitable(void)
{
	u32 curr_buffers = calc_sys_cur_avail_buffers();

	if (curr_buffers >= get_high_avail_buffers_value())
		return true;

	return false;
}

static void snapshot_anon_refaults(void)
{
	struct mem_cgroup *memcg = NULL;

	while ((memcg = get_next_memcg(memcg)))
		memcg->memcg_reclaimed.reclaimed_pagefault =
			hyperhold_read_mcg_stats(memcg, MCG_ANON_FAULT_CNT);

	area_last_anon_pagefault = hyperhold_get_zram_pagefault();
	last_anon_snapshot_time = jiffies;
}

/*
 * Return true if refault changes between two read operations.
 */
static bool get_memcg_anon_refault_status(struct mem_cgroup *memcg)
{
	const unsigned int percent_constant = 100;
	unsigned long long cur_anon_pagefault;
	unsigned long anon_total;
	unsigned long long ratio;

	struct mem_cgroup_per_node *mz = NULL;
	struct lruvec *lruvec = NULL;

	if (!memcg)
		return false;

	cur_anon_pagefault =
		hyperhold_read_mcg_stats(memcg, MCG_ANON_FAULT_CNT);

	if (cur_anon_pagefault == memcg->memcg_reclaimed.reclaimed_pagefault)
		return false;

	mz = mem_cgroup_nodeinfo(memcg, 0);
	if (!mz)
		return false;
	lruvec = &mz->lruvec;
	if (!lruvec)
		return false;
	anon_total = lruvec_lru_size(lruvec, LRU_ACTIVE_ANON, MAX_NR_ZONES) +
		lruvec_lru_size(lruvec, LRU_INACTIVE_ANON, MAX_NR_ZONES) +
		hyperhold_read_mcg_stats(memcg, MCG_DISK_STORED_PG_SZ) +
		hyperhold_read_mcg_stats(memcg, MCG_ZRAM_PG_SZ);

	ratio = (cur_anon_pagefault -
		memcg->memcg_reclaimed.reclaimed_pagefault) *
		percent_constant / (anon_total + 1);

	if (ratio > (unsigned int)atomic_read(
			&memcg->memcg_reclaimed.refault_threshold))
		return true;

	return false;
}

static bool get_area_anon_refault_status(void)
{
	const unsigned int percent_constant = 1000;
	unsigned long long cur_anon_pagefault;
	unsigned long long cur_time;
	unsigned long long ratio;

	cur_anon_pagefault = hyperhold_get_zram_pagefault();
	cur_time = jiffies;

	if (cur_anon_pagefault == area_last_anon_pagefault
		|| cur_time == last_anon_snapshot_time)
		return false;

	ratio = (cur_anon_pagefault - area_last_anon_pagefault) *
		percent_constant / (jiffies_to_msecs(cur_time -
					last_anon_snapshot_time) + 1);

	global_anon_refault_ratio = ratio;

	if (ratio > get_area_anon_refault_threshold_value())
		return true;

	return false;
}

static bool anon_size_is_low(void)
{
	unsigned long nr_anon_pages = global_node_page_state(NR_INACTIVE_ANON) +
		global_node_page_state(NR_ACTIVE_ANON);
	unsigned long anon_min_pages = get_zswapd_min_anon_size() *
		SZ_1M / PAGE_SIZE; /* MB to pages */
	return nr_anon_pages < anon_min_pages;
}

void wakeup_snapshotd(void)
{
	unsigned long curr_snapshot_interval;

	curr_snapshot_interval =
		jiffies_to_msecs(jiffies - last_anon_snapshot_time);

	if (curr_snapshot_interval >=
		get_anon_refault_snapshot_min_interval_value()) {
		atomic_set(&snapshotd_wait_flag, 1);
		wake_up_interruptible(&snapshotd_wait);
	}
}

static int snapshotd(void *p)
{
	int ret;

	while (!kthread_should_stop()) {
		/*lint -e578 */
		ret = wait_event_interruptible(snapshotd_wait,
			atomic_read(&snapshotd_wait_flag));
		/*lint +e578 */
		if (ret)
			continue;

		atomic_set(&snapshotd_wait_flag, 0);

		snapshot_anon_refaults();
		count_vm_event(ZSWAPD_SNAPSHOT_TIMES);
	}

	return 0;
}

void set_snapshotd_init_flag(unsigned int val)
{
	atomic_set(&snapshotd_init_flag, val);
}
/*
 * This snapshotd start function will be called by init.
 */
int snapshotd_run(void)
{
	atomic_set(&snapshotd_wait_flag, 0);
	init_waitqueue_head(&snapshotd_wait);
	snapshotd_task = kthread_run(snapshotd, NULL, "snapshotd");
	if (IS_ERR(snapshotd_task)) {
		pr_err("Failed to start snapshotd\n");
		return PTR_ERR(snapshotd_task);
	}

	return 0;
}

static int __init snapshotd_init(void)
{
	snapshotd_run();

	return 0;
}

module_init(snapshotd_init)

int get_zram_current_watermark(void)
{
	long long diff_buffers;
	const unsigned int percent_constant = 10;
	u64 nr_total;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 61)
	nr_total = totalram_pages();
#else
	nr_total = totalram_pages;
#endif
	diff_buffers = get_avail_buffers_value() -
		calc_sys_cur_avail_buffers(); /* B_target - B_current */
	diff_buffers *= SZ_1M / PAGE_SIZE; /* MB to page */
	diff_buffers *=
		get_compress_ratio_value(); /* after_comp to before_comp */
	diff_buffers = diff_buffers * percent_constant /
		nr_total; /* page to ratio */
	/*lint -e666 */
	return min(get_zram_wm_ratio_value(),
		get_zram_wm_ratio_value() - diff_buffers);
	/*lint +e666 */
}

bool zram_watermark_ok(void)
{
	const unsigned int percent_constant = 100;
	u64 curr_ratio;
	u64 nr_zram_used;
	u64 nr_wm;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 61)
        nr_wm = totalram_pages();
#else
        nr_wm = totalram_pages;
#endif

	curr_ratio = get_zram_current_watermark();
	nr_zram_used = hyperhold_get_zram_used_pages();
	nr_wm = nr_wm * curr_ratio / percent_constant;
	if (nr_zram_used > nr_wm)
		return true;
	return false;
}

bool zram_watermark_exceed(void)
{
	u64 nr_zram_used;
	const u64 nr_wm =
		get_zram_critical_threshold_value() * (SZ_1M / PAGE_SIZE);

	if (!nr_wm)
		return false;

	nr_zram_used = hyperhold_get_zram_used_pages();
	if (nr_zram_used > nr_wm)
		return true;
	return false;
}

void wakeup_zswapd(pg_data_t *pgdat)
{
	unsigned long curr_interval;

	if (IS_ERR(pgdat->zswapd))
		return;

	if (!wq_has_sleeper(&pgdat->zswapd_wait))
		return;

	/* make anon pagefault snapshots */
	/* wake up snapshotd */
	if (atomic_read(&snapshotd_init_flag) == 1)
		wakeup_snapshotd();

	/* wake up when the buffer is lower than min_avail_buffer */
	if (min_buffer_is_suitable())
		return;

	curr_interval =
		jiffies_to_msecs(jiffies - last_zswapd_time);
	if (curr_interval < zswapd_skip_interval) {
		count_vm_event(ZSWAPD_EMPTY_ROUND_SKIP_TIMES);
		return;
	}

	atomic_set(&pgdat->zswapd_wait_flag, 1);
	wake_up_interruptible(&pgdat->zswapd_wait);
}

void wake_all_zswapd(void)
{
	pg_data_t *pgdat = NULL;
	int nid;
	unsigned int zswapd_pause_interval_tmp;

	// 1 means pause trigger zswapd
	if (get_zswapd_pause_stat() == 1)
		return;

	set_zswapd_pause_stat(1);
	zswapd_pause_interval_tmp = get_zswapd_pause_interval();
	mod_timer(&zswapd_pause_timer, jiffies + (HZ * zswapd_pause_interval_tmp));

	for_each_online_node(nid) {
		pgdat = NODE_DATA(nid);
		wakeup_zswapd(pgdat);
	}
}

static void zswapd_shrink_active_list(unsigned long nr_to_scan,
	struct lruvec *lruvec, struct scan_control *sc, enum lru_list lru)
{
	unsigned long nr_scanned;
	unsigned long nr_taken;
	LIST_HEAD(l_hold);
	LIST_HEAD(l_inactive);
	struct page *page = NULL;
	unsigned int nr_deactivate;
	struct pglist_data *pgdat = lruvec_pgdat(lruvec);
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(5, 4, 61))
	struct zone_reclaim_stat *reclaim_stat = &lruvec->reclaim_stat;
	struct zone_reclaim_stat *node_reclaim_stat = &pgdat->lruvec.reclaim_stat;
#endif

	lru_add_drain();

	spin_lock_irq(&pgdat->lru_lock);
	nr_taken = isolate_lru_pages(nr_to_scan, lruvec, &l_hold,
				     &nr_scanned, sc,
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 61)
				     (isolate_mode_t)0,
#endif
				     lru);
	__mod_node_page_state(pgdat, NR_ISOLATED_ANON, nr_taken);
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(5, 4, 61))
	reclaim_stat->recent_scanned[0] += nr_taken;
	node_reclaim_stat->recent_scanned[0] += nr_taken;
#endif
	__count_vm_events(PGREFILL, nr_scanned);
	count_memcg_events(lruvec_memcg(lruvec), PGREFILL, nr_scanned);
	spin_unlock_irq(&pgdat->lru_lock);

	while (!list_empty(&l_hold)) {
		cond_resched();
		page = lru_to_page(&l_hold);
		list_del(&page->lru);

		if (unlikely(!page_evictable(page))) {
			putback_lru_page(page);
			continue;
		}

		ClearPageActive(page);	/* we are de-activating */
		SetPageWorkingset(page);
		list_add(&page->lru, &l_inactive);
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 61)
	spin_lock_irq(&pgdat->lru_lock);
	nr_deactivate = move_active_pages_to_lru(lruvec, &l_inactive,
			&l_hold, lru - LRU_ACTIVE);
#else
	spin_lock_irq(&pgdat->lru_lock);
	nr_deactivate = move_pages_to_lru(lruvec, &l_inactive);
	list_splice(&l_inactive, &l_hold);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 19, 0)
	/*lint -e501*/
	__mod_node_page_state(pgdat, NR_ISOLATED_ANON, -nr_taken);
	/*lint +e501*/
	spin_unlock_irq(&pgdat->lru_lock);
	mem_cgroup_uncharge_list(&l_hold);
	free_hot_cold_page_list(&l_hold, true);
#else
	/*lint -e501*/
	__mod_node_page_state(pgdat, NR_ISOLATED_ANON, -nr_taken);
	/*lint +e501*/
	spin_unlock_irq(&pgdat->lru_lock);
	mem_cgroup_uncharge_list(&l_hold);
	free_unref_page_list(&l_hold);
#endif
	trace_mm_vmscan_lru_zswapd_shrink_active(pgdat->node_id,
			nr_taken, nr_deactivate, sc->priority);
}

static unsigned long zswapd_shrink_list(enum lru_list lru,
		unsigned long nr_to_scan, struct lruvec *lruvec,
		struct scan_control *sc)
{
	if (is_active_lru(lru)) {
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(5, 4, 61))
		if (inactive_list_is_low(lruvec, is_file_lru(lru), sc, true))
#else
		if (inactive_is_low(lruvec, lru))
#endif
			zswapd_shrink_active_list(nr_to_scan, lruvec, sc, lru);
		return 0;
	}
	return shrink_inactive_list(nr_to_scan, lruvec, sc, lru);
}

static void zswapd_shrink_anon_memcg(struct pglist_data *pgdat,
		struct mem_cgroup *memcg, struct scan_control *sc,
		unsigned long *nr)
{
#if (KERNEL_VERSION(5, 10, 0) <= LINUX_VERSION_CODE)
		struct lruvec *lruvec = mem_cgroup_lruvec(memcg, pgdat);
#else
		struct lruvec *lruvec = mem_cgroup_lruvec(pgdat, memcg);
#endif
	unsigned long nr_to_scan;
	enum lru_list lru;
	unsigned long nr_reclaimed = 0;
	struct blk_plug plug;

	blk_start_plug(&plug);

	while (nr[LRU_INACTIVE_ANON] || nr[LRU_ACTIVE_ANON]) {
		for (lru = 0; lru <= LRU_ACTIVE_ANON; lru++) {
			if (nr[lru]) {
				nr_to_scan = min(nr[lru], SWAP_CLUSTER_MAX);
				nr[lru] -= nr_to_scan;
				nr_reclaimed +=
					zswapd_shrink_list(lru,
							nr_to_scan,
							lruvec, sc);
			}
		}
	}
	blk_finish_plug(&plug);
	sc->nr_reclaimed += nr_reclaimed;

}

static bool zswapd_shrink_anon(pg_data_t *pgdat, struct scan_control *sc)
{
	unsigned long nr[NR_LRU_LISTS];
	struct mem_cgroup *memcg = NULL;
	const u32 percent_constant = 100;

	while ((memcg = get_next_memcg(memcg))) {
#if (KERNEL_VERSION(5, 10, 0) <= LINUX_VERSION_CODE)
		struct lruvec *lruvec = mem_cgroup_lruvec(memcg, pgdat);
#else
		struct lruvec *lruvec = mem_cgroup_lruvec(pgdat, memcg);
#endif
		u64 nr_active, nr_inactive;
		u64 nr_zram, nr_eswap;
		u64 zram_ratio;

		/* reclaim and try to meet the high buffer watermark */
		if (high_buffer_is_suitable()) {
			get_next_memcg_break(memcg);
			break;
		}

#ifdef CONFIG_MEMCG_PROTECT_LRU
		/* Skip if it is a protect memcg. */
		if (is_prot_memcg(memcg, false))
			continue;
#endif

		if (get_memcg_anon_refault_status(memcg)) {
			count_vm_event(ZSWAPD_MEMCG_REFAULT_SKIP);
			continue;
		}

		nr_active = lruvec_lru_size(lruvec, LRU_ACTIVE_ANON,
				MAX_NR_ZONES);
		nr_inactive = lruvec_lru_size(lruvec,
				LRU_INACTIVE_ANON, MAX_NR_ZONES);
		nr_zram = hyperhold_read_mcg_stats(memcg, MCG_ZRAM_PG_SZ);
		nr_eswap =
			hyperhold_read_mcg_stats(memcg, MCG_DISK_STORED_PG_SZ);

		zram_ratio = (nr_zram + nr_eswap) * percent_constant /
			(nr_inactive + nr_active + nr_zram + nr_eswap + 1);

		if (zram_ratio >= (u32)atomic_read(
				&memcg->memcg_reclaimed.ub_mem2zram_ratio)) {
			count_vm_event(ZSWAPD_MEMCG_RATIO_SKIP);
			continue;
		}

		nr[LRU_ACTIVE_ANON] = nr_active >> (unsigned int)sc->priority;
		nr[LRU_INACTIVE_ANON] =
				nr_inactive >> (unsigned int)sc->priority;
		nr[LRU_ACTIVE_FILE] = 0;
		nr[LRU_INACTIVE_FILE] = 0;
#ifdef CONFIG_HYPERHOLD_FILE_LRU
		zswapd_shrink_anon_memcg(pgdat, memcg, sc, nr);
#else
		shrink_node_memcg(pgdat, memcg, sc, nr);
#endif

		if (sc->nr_reclaimed >= sc->nr_to_reclaim) {
			get_next_memcg_break(memcg);
			break;
		}
	}

	return sc->nr_scanned >= sc->nr_to_reclaim;
}

static u64 __calc_nr_to_reclaim(void)
{
	u32 curr_buffers;
	u64 high_buffers;
	u64 max_reclaim_size_value;
	u64 reclaim_size = 0;

	high_buffers = get_high_avail_buffers_value();
	curr_buffers = calc_sys_cur_avail_buffers();
	max_reclaim_size_value = get_zswapd_max_reclaim_size();
	if (curr_buffers < high_buffers)
		reclaim_size = high_buffers - curr_buffers;

	/* once max reclaim target is max_reclaim_size_value */
	reclaim_size = min(reclaim_size, max_reclaim_size_value);

	return reclaim_size * SZ_1M / PAGE_SIZE; /* MB to pages */
}

static void zswapd_shrink_node(pg_data_t *pgdat)
{
	struct scan_control sc = {
		.gfp_mask = GFP_KERNEL,
		.order = 0,
		.priority = DEF_PRIORITY / 2,
		.may_writepage = !laptop_mode,
		.may_unmap = 1,
		.may_swap = 1,
		.reclaim_idx = MAX_NR_ZONES - 1,
	};
	const unsigned int increase_rate = 2;

	do {
		unsigned long nr_reclaimed = sc.nr_reclaimed = 0;
		bool raise_priority = true;

		/* reclaim and try to meet the high buffer watermark */
		if (high_buffer_is_suitable())
			break;

		sc.nr_scanned = 0;
		sc.nr_to_reclaim = __calc_nr_to_reclaim();

		if (zswapd_shrink_anon(pgdat, &sc))
			raise_priority = false;

		if (try_to_freeze() || kthread_should_stop())
			break;

		nr_reclaimed = sc.nr_reclaimed - nr_reclaimed;
		if (raise_priority || !nr_reclaimed)
			sc.priority--;
	} while (sc.priority >= 1);

	/*
	 * When meets the first empty round, set the interval to t.
	 * If the following round is still empty, set the interval
	 * to 2t. If the round is always empty, then 4t, 8t, and so on.
	 * But make sure the interval is not more than the max_skip_interval.
	 * Once a non-empty round occurs, reset the interval to 0.
	 */
	if (sc.nr_reclaimed < get_empty_round_check_threshold_value()) {
		count_vm_event(ZSWAPD_EMPTY_ROUND);
		if (last_round_is_empty)
			zswapd_skip_interval = min(zswapd_skip_interval *
				increase_rate,
				get_max_skip_interval_value());/*lint !e666*/
		else
			zswapd_skip_interval =
				get_empty_round_skip_interval_value();
		last_round_is_empty = true;
	} else {
		zswapd_skip_interval = 0;
		last_round_is_empty = false;
	}
}

static int zswapd(void *p)
{
	pg_data_t *pgdat = (pg_data_t *)p;
	struct task_struct *tsk = current;
	const struct cpumask *cpumask = cpumask_of_node(pgdat->node_id);

	/* save zswapd pid for schedule strategy */
	zswapd_pid = tsk->pid;

	if (!cpumask_empty(cpumask))
		set_cpus_allowed_ptr(tsk, cpumask);

	set_freezable();

	while (!kthread_should_stop()) {
		bool refault = false;
		bool low_anon = false;
		u32 curr_buffers, avail;
		u64 size;

		/*lint -e578 */
		(void)wait_event_freezable(pgdat->zswapd_wait,
			atomic_read(&pgdat->zswapd_wait_flag));
		/*lint +e578 */
		atomic_set(&pgdat->zswapd_wait_flag, 0);
		count_vm_event(ZSWAPD_WAKEUP);
		zswapd_pressure_report(LEVEL_LOW);

		if (get_area_anon_refault_status()) {
			refault = true;
			count_vm_event(ZSWAPD_REFAULT);
			goto do_eswap;
		}

		if (anon_size_is_low()) {
			low_anon = true;
			goto do_eswap;
		}

		zswapd_shrink_node(pgdat);
		last_zswapd_time = jiffies;

do_eswap:
		if (!hyperhold_reclaim_work_running() &&
			(zram_watermark_ok() || refault || low_anon)) {
			avail = get_eswap_avail_buffers_value();
			if (avail == 0)
				avail = get_high_avail_buffers_value();
			curr_buffers = calc_sys_cur_avail_buffers();
			size = (avail - curr_buffers) * SZ_1M;
			if (curr_buffers < avail) {
				count_vm_event(ZSWAPD_SWAPOUT);
#ifdef CONFIG_HYPERHOLD_CORE
				size = hyperhold_reclaim_in(size);
#endif
			}
		}

		if (!buffer_is_suitable()) {
			if (free_swap_is_low() || zram_watermark_exceed()) {
				zswapd_pressure_report(LEVEL_CRITICAL);
				count_vm_event(ZSWAPD_CRITICAL_PRESS);
			} else {
				zswapd_pressure_report(LEVEL_MEDIUM);
				count_vm_event(ZSWAPD_MEDIUM_PRESS);
			}
		}
	}

	return 0;
}

/*
 * This zswapd start function will be called by init and node-hot-add.
 */
int zswapd_run(int nid)
{
	pg_data_t *pgdat = NODE_DATA(nid);
	const unsigned int priority_less = 5;
	struct sched_param param = {
		.sched_priority = MAX_PRIO - priority_less,
	};

	if (pgdat->zswapd)
		return 0;

	atomic_set(&pgdat->zswapd_wait_flag, 0);
	pgdat->zswapd = kthread_create(zswapd, pgdat, "zswapd%d", nid);
	if (IS_ERR(pgdat->zswapd)) {
		pr_err("Failed to start zswapd on node %d\n", nid);
		return PTR_ERR(pgdat->zswapd);
	}

	sched_setscheduler_nocheck(pgdat->zswapd, SCHED_NORMAL, &param);
	set_user_nice(pgdat->zswapd, PRIO_TO_NICE(param.sched_priority));
	wake_up_process(pgdat->zswapd);

	return 0;
}

/*
 * Called by memory hotplug when all memory in a node is offlined.  Caller must
 * hold mem_hotplug_begin/end().
 */
void zswapd_stop(int nid)
{
	struct task_struct *zswapd = NODE_DATA(nid)->zswapd; /*lint !e578*/

	if (zswapd) {
		kthread_stop(zswapd);
		NODE_DATA(nid)->zswapd = NULL;
	}

	zswapd_pid = -1;
}

/* It's optimal to keep kswapds on the same CPUs as their memory, but
 * not required for correctness.  So if the last cpu in a node goes
 * away, we get changed to run anywhere: as the first one comes back,
 * restore their cpu bindings.
 */
static int zswapd_cpu_online(unsigned int cpu)
{
	int nid;

	for_each_node_state(nid, N_MEMORY) {
		pg_data_t *pgdat = NODE_DATA(nid);
		const struct cpumask *mask;

		mask = cpumask_of_node(pgdat->node_id);
		/*lint -e574 */
		if (cpumask_any_and(cpu_online_mask, mask) < nr_cpu_ids)
		/*lint +e574 */
			/* One of our CPUs online: restore mask */
			set_cpus_allowed_ptr(pgdat->zswapd, mask);
	}
	return 0;
}

static int __init zswapd_init(void)
{
	int nid;
	int ret;

	ret = cpuhp_setup_state_nocalls(CPUHP_AP_ONLINE_DYN,
					"mm/zswapd:online", zswapd_cpu_online,
					NULL);
	if (ret < 0) {
		pr_err("zswapd: failed to register hotplug callbacks.\n");
		return ret;
	}

	for_each_node_state(nid, N_MEMORY)
		zswapd_run(nid);

	return 0;
}
module_init(zswapd_init)
#endif
#endif
#endif
