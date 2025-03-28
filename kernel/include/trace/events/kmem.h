/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM kmem

#if !defined(_TRACE_KMEM_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_KMEM_H

#include <linux/types.h>
#include <linux/tracepoint.h>
#include <trace/events/mmflags.h>

DECLARE_EVENT_CLASS(kmem_alloc,

	TP_PROTO(unsigned long call_site,
		 const void *ptr,
		 size_t bytes_req,
		 size_t bytes_alloc,
		 gfp_t gfp_flags),

	TP_ARGS(call_site, ptr, bytes_req, bytes_alloc, gfp_flags),

	TP_STRUCT__entry(
		__field(	unsigned long,	call_site	)
		__field(	const void *,	ptr		)
		__field(	size_t,		bytes_req	)
		__field(	size_t,		bytes_alloc	)
		__field(	gfp_t,		gfp_flags	)
	),

	TP_fast_assign(
		__entry->call_site	= call_site;
		__entry->ptr		= ptr;
		__entry->bytes_req	= bytes_req;
		__entry->bytes_alloc	= bytes_alloc;
		__entry->gfp_flags	= gfp_flags;
	),

	TP_printk("call_site=%pS ptr=%p bytes_req=%zu bytes_alloc=%zu gfp_flags=%s",
		(void *)__entry->call_site,
		__entry->ptr,
		__entry->bytes_req,
		__entry->bytes_alloc,
		show_gfp_flags(__entry->gfp_flags))
);

DEFINE_EVENT(kmem_alloc, kmalloc,

	TP_PROTO(unsigned long call_site, const void *ptr,
		 size_t bytes_req, size_t bytes_alloc, gfp_t gfp_flags),

	TP_ARGS(call_site, ptr, bytes_req, bytes_alloc, gfp_flags)
);

DEFINE_EVENT(kmem_alloc, kmem_cache_alloc,

	TP_PROTO(unsigned long call_site, const void *ptr,
		 size_t bytes_req, size_t bytes_alloc, gfp_t gfp_flags),

	TP_ARGS(call_site, ptr, bytes_req, bytes_alloc, gfp_flags)
);

DECLARE_EVENT_CLASS(kmem_alloc_node,

	TP_PROTO(unsigned long call_site,
		 const void *ptr,
		 size_t bytes_req,
		 size_t bytes_alloc,
		 gfp_t gfp_flags,
		 int node),

	TP_ARGS(call_site, ptr, bytes_req, bytes_alloc, gfp_flags, node),

	TP_STRUCT__entry(
		__field(	unsigned long,	call_site	)
		__field(	const void *,	ptr		)
		__field(	size_t,		bytes_req	)
		__field(	size_t,		bytes_alloc	)
		__field(	gfp_t,		gfp_flags	)
		__field(	int,		node		)
	),

	TP_fast_assign(
		__entry->call_site	= call_site;
		__entry->ptr		= ptr;
		__entry->bytes_req	= bytes_req;
		__entry->bytes_alloc	= bytes_alloc;
		__entry->gfp_flags	= gfp_flags;
		__entry->node		= node;
	),

	TP_printk("call_site=%pS ptr=%p bytes_req=%zu bytes_alloc=%zu gfp_flags=%s node=%d",
		(void *)__entry->call_site,
		__entry->ptr,
		__entry->bytes_req,
		__entry->bytes_alloc,
		show_gfp_flags(__entry->gfp_flags),
		__entry->node)
);

DEFINE_EVENT(kmem_alloc_node, kmalloc_node,

	TP_PROTO(unsigned long call_site, const void *ptr,
		 size_t bytes_req, size_t bytes_alloc,
		 gfp_t gfp_flags, int node),

	TP_ARGS(call_site, ptr, bytes_req, bytes_alloc, gfp_flags, node)
);

DEFINE_EVENT(kmem_alloc_node, kmem_cache_alloc_node,

	TP_PROTO(unsigned long call_site, const void *ptr,
		 size_t bytes_req, size_t bytes_alloc,
		 gfp_t gfp_flags, int node),

	TP_ARGS(call_site, ptr, bytes_req, bytes_alloc, gfp_flags, node)
);

DECLARE_EVENT_CLASS(kmem_free,

	TP_PROTO(unsigned long call_site, const void *ptr),

	TP_ARGS(call_site, ptr),

	TP_STRUCT__entry(
		__field(	unsigned long,	call_site	)
		__field(	const void *,	ptr		)
	),

	TP_fast_assign(
		__entry->call_site	= call_site;
		__entry->ptr		= ptr;
	),

	TP_printk("call_site=%pS ptr=%p",
		  (void *)__entry->call_site, __entry->ptr)
);

DEFINE_EVENT(kmem_free, kfree,

	TP_PROTO(unsigned long call_site, const void *ptr),

	TP_ARGS(call_site, ptr)
);

DEFINE_EVENT(kmem_free, kmem_cache_free,

	TP_PROTO(unsigned long call_site, const void *ptr),

	TP_ARGS(call_site, ptr)
);

TRACE_EVENT(mm_page_free,

	TP_PROTO(struct page *page, unsigned int order),

	TP_ARGS(page, order),

	TP_STRUCT__entry(
		__field(	unsigned long,	pfn		)
		__field(	unsigned int,	order		)
	),

	TP_fast_assign(
		__entry->pfn		= page_to_pfn(page);
		__entry->order		= order;
	),

	TP_printk("page=%p pfn=%lu order=%d",
			pfn_to_page(__entry->pfn),
			__entry->pfn,
			__entry->order)
);

TRACE_EVENT(mm_page_free_batched,

	TP_PROTO(struct page *page),

	TP_ARGS(page),

	TP_STRUCT__entry(
		__field(	unsigned long,	pfn		)
	),

	TP_fast_assign(
		__entry->pfn		= page_to_pfn(page);
	),

	TP_printk("page=%p pfn=%lu order=0",
			pfn_to_page(__entry->pfn),
			__entry->pfn)
);

#ifdef CONFIG_HONOR_SCM_BUILDIN
TRACE_EVENT(mm_page_alloc_entry,

	TP_PROTO(gfp_t gfp_mask, unsigned int order),

	TP_ARGS(gfp_mask, order),

	TP_STRUCT__entry(
		__field(	gfp_t,		gfp_mask	)
		__field(	int,		order	)
	),

	TP_fast_assign(
		__entry->gfp_mask	= gfp_mask;
		__entry->order		= order;
	),

	TP_printk("order=%d gfp_mask=%s",
		__entry->order,
		show_gfp_flags(__entry->gfp_mask))
);
#endif // #ifdef CONFIG_HONOR_SCM_BUILDIN

TRACE_EVENT(mm_page_alloc,

	TP_PROTO(struct page *page, unsigned int order,
			gfp_t gfp_flags, int migratetype),

	TP_ARGS(page, order, gfp_flags, migratetype),

	TP_STRUCT__entry(
		__field(	unsigned long,	pfn		)
		__field(	unsigned int,	order		)
		__field(	gfp_t,		gfp_flags	)
		__field(	int,		migratetype	)
	),

	TP_fast_assign(
		__entry->pfn		= page ? page_to_pfn(page) : -1UL;
		__entry->order		= order;
		__entry->gfp_flags	= gfp_flags;
		__entry->migratetype	= migratetype;
	),

	TP_printk("page=%p pfn=%lu order=%d migratetype=%d gfp_flags=%s",
		__entry->pfn != -1UL ? pfn_to_page(__entry->pfn) : NULL,
		__entry->pfn != -1UL ? __entry->pfn : 0,
		__entry->order,
		__entry->migratetype,
		show_gfp_flags(__entry->gfp_flags))
);

DECLARE_EVENT_CLASS(mm_page,

	TP_PROTO(struct page *page, unsigned int order, int migratetype),

	TP_ARGS(page, order, migratetype),

	TP_STRUCT__entry(
		__field(	unsigned long,	pfn		)
		__field(	unsigned int,	order		)
		__field(	int,		migratetype	)
	),

	TP_fast_assign(
		__entry->pfn		= page ? page_to_pfn(page) : -1UL;
		__entry->order		= order;
		__entry->migratetype	= migratetype;
	),

	TP_printk("page=%p pfn=%lu order=%u migratetype=%d percpu_refill=%d",
		__entry->pfn != -1UL ? pfn_to_page(__entry->pfn) : NULL,
		__entry->pfn != -1UL ? __entry->pfn : 0,
		__entry->order,
		__entry->migratetype,
		__entry->order == 0)
);

DEFINE_EVENT(mm_page, mm_page_alloc_zone_locked,

	TP_PROTO(struct page *page, unsigned int order, int migratetype),

	TP_ARGS(page, order, migratetype)
);

TRACE_EVENT(mm_page_pcpu_drain,

	TP_PROTO(struct page *page, unsigned int order, int migratetype),

	TP_ARGS(page, order, migratetype),

	TP_STRUCT__entry(
		__field(	unsigned long,	pfn		)
		__field(	unsigned int,	order		)
		__field(	int,		migratetype	)
	),

	TP_fast_assign(
		__entry->pfn		= page ? page_to_pfn(page) : -1UL;
		__entry->order		= order;
		__entry->migratetype	= migratetype;
	),

	TP_printk("page=%p pfn=%lu order=%d migratetype=%d",
		pfn_to_page(__entry->pfn), __entry->pfn,
		__entry->order, __entry->migratetype)
);

TRACE_EVENT(mm_page_alloc_extfrag,

	TP_PROTO(struct page *page,
		int alloc_order, int fallback_order,
		int alloc_migratetype, int fallback_migratetype),

	TP_ARGS(page,
		alloc_order, fallback_order,
		alloc_migratetype, fallback_migratetype),

	TP_STRUCT__entry(
		__field(	unsigned long,	pfn			)
		__field(	int,		alloc_order		)
		__field(	int,		fallback_order		)
		__field(	int,		alloc_migratetype	)
		__field(	int,		fallback_migratetype	)
		__field(	int,		change_ownership	)
	),

	TP_fast_assign(
		__entry->pfn			= page_to_pfn(page);
		__entry->alloc_order		= alloc_order;
		__entry->fallback_order		= fallback_order;
		__entry->alloc_migratetype	= alloc_migratetype;
		__entry->fallback_migratetype	= fallback_migratetype;
		__entry->change_ownership	= (alloc_migratetype ==
					get_pageblock_migratetype(page));
	),

	TP_printk("page=%p pfn=%lu alloc_order=%d fallback_order=%d pageblock_order=%d alloc_migratetype=%d fallback_migratetype=%d fragmenting=%d change_ownership=%d",
		pfn_to_page(__entry->pfn),
		__entry->pfn,
		__entry->alloc_order,
		__entry->fallback_order,
		pageblock_order,
		__entry->alloc_migratetype,
		__entry->fallback_migratetype,
		__entry->fallback_order < pageblock_order,
		__entry->change_ownership)
);

#ifdef CONFIG_HONOR_ALLOC_STATS
TRACE_EVENT(mm_alloc_time,

	TP_PROTO(const char *name, uint nr_page, u64 delta, struct alloc_time_stat *stat),

	TP_ARGS(name, nr_page, delta, stat),

	TP_STRUCT__entry(
		__field(short,	adj	)
		__field(short,	prio	)
		__field(uint, 	nr_page	)
		__field(u64,	delta	)
		__array(char, name, ALLOC_STATS_NAME_LEN)
		__field(unsigned long,	count_total	)
		__field(unsigned long,	total_time	)
		__array(unsigned long,	counts,	ALLOC_STATS_MAX	)
	),

	TP_fast_assign(
		__entry->adj	= current->signal->oom_score_adj;
		__entry->prio	= current->prio;
		__entry->nr_page	= nr_page;
		__entry->delta		= delta;
		memcpy(__entry->name, name, sizeof(__entry->name));
		__entry->name[ALLOC_STATS_NAME_LEN - 1]	= '\0';
		__entry->count_total	= stat->count_total;
		__entry->total_time	= stat->total_time;
		memcpy(__entry->counts, stat->counts, sizeof(__entry->counts));
	),

	TP_printk("adj=%d prio=%d nr_page=%u delta_us=%lu name=%s total=%lu avg_us=%lu counts=%lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
		__entry->adj, __entry->prio,
		__entry->nr_page, __entry->delta, __entry->name,
		__entry->count_total,
		__entry->total_time / (__entry->count_total ? : 1),
		__entry->counts[0], __entry->counts[1],
		__entry->counts[2], __entry->counts[3],
		__entry->counts[4], __entry->counts[5],
		__entry->counts[6], __entry->counts[7],
		__entry->counts[8], __entry->counts[9],
		__entry->counts[10], __entry->counts[11])
);
#endif

/*
 * Required for uniquely and securely identifying mm in rss_stat tracepoint.
 */
#ifndef __PTR_TO_HASHVAL
static unsigned int __maybe_unused mm_ptr_to_hash(const void *ptr)
{
	int ret;
	unsigned long hashval;

	ret = ptr_to_hashval(ptr, &hashval);
	if (ret)
		return 0;

	/* The hashed value is only 32-bit */
	return (unsigned int)hashval;
}
#define __PTR_TO_HASHVAL
#endif

TRACE_EVENT(rss_stat,

	TP_PROTO(struct mm_struct *mm,
		int member,
		long count),

	TP_ARGS(mm, member, count),

	TP_STRUCT__entry(
		__field(unsigned int, mm_id)
		__field(unsigned int, curr)
		__field(int, member)
		__field(long, size)
	),

	TP_fast_assign(
		__entry->mm_id = mm_ptr_to_hash(mm);
		__entry->curr = !!(current->mm == mm);
		__entry->member = member;
		__entry->size = (count << PAGE_SHIFT);
	),

	TP_printk("mm_id=%u curr=%d member=%d size=%ldB",
		__entry->mm_id,
		__entry->curr,
		__entry->member,
		__entry->size)
	);
#endif /* _TRACE_KMEM_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
