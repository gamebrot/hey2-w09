/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __INCLUDE_LINUX_HUGEPAGE_POOL_H
#define __INCLUDE_LINUX_HUGEPAGE_POOL_H

#include <linux/sched.h>
#include <linux/oom.h>

#define HUGEPAGE_ORDER HPAGE_PMD_ORDER

enum hpage_type {
	HPAGE_DMA_BUF,
	HPAGE_GPU,
	HPAGE_VMALLOC,
	HPAGE_ANON,
	HPAGE_TYPE_MAX,
};

#ifdef CONFIG_HUGEPAGE_POOL
unsigned long total_hugepage_pool_pages(void);
void wakeup_hugepool_refill_worker(void);
#else
static __attribute__((unused)) unsigned long total_hugepage_pool_pages(void) { return 0; }
#endif

extern struct page *alloc_hugepage(int order, enum hpage_type type);
extern bool hugepage_nonzero_list_add(struct page *page);
#endif /* __INCLUDE_LINUX_HUGEPAGE_POOL_H */
