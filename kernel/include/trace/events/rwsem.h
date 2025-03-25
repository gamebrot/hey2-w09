/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM rwsem

#if !defined(_TRACE_RWSEM_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_RWSEM_H

#include <linux/tracepoint.h>

#ifdef CONFIG_HN_RW_SEM_DEBUG
#include <linux/rwsem.h>

TRACE_EVENT(rw_sem_debug,

	TP_PROTO(struct rwsem_waiter *waiter, char *func,
		unsigned long caller_addr0, unsigned long caller_addr1, unsigned long caller_addr2,
		unsigned long caller_addr3, unsigned long caller_addr4, unsigned long caller_addr5),

	TP_ARGS(waiter, func, caller_addr0, caller_addr1, caller_addr2, caller_addr3, caller_addr4, caller_addr5),

	TP_STRUCT__entry(
		__string(function, func)
		__field(unsigned long, last_rowner)
		__field(unsigned long, addr0)
		__field(unsigned long, addr1)
		__field(unsigned long, addr2)
		__field(unsigned long, addr3)
		__field(unsigned long, addr4)
		__field(unsigned long, addr5)
	),

	TP_fast_assign(
		__assign_str(function, func);
		__entry->last_rowner = waiter->last_rowner;
		__entry->addr0 = caller_addr0;
		__entry->addr1 = caller_addr1;
		__entry->addr2 = caller_addr2;
		__entry->addr3 = caller_addr3;
		__entry->addr4 = caller_addr4;
		__entry->addr5 = caller_addr5;
	),

	TP_printk("func=%s last_rowner=0x%lu caller=(%pS<-%pS<-%pS<-%pS<-%pS<-%pS)",
			__get_str(function), __entry->last_rowner,
			__entry->addr0,	__entry->addr1,
			__entry->addr2, __entry->addr3,
			__entry->addr4, __entry->addr5)
);
#endif

#endif /* _TRACE_RWSEM_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
