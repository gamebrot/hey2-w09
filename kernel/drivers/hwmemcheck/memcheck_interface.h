#ifndef MEMCHECK_INTERFACE_H
#define MEMCHECK_INTERFACE_H

#include <linux/types.h>
#ifdef CONFIG_HONOR_PAGE_TRACE
#include <linux/honor/mem_trace.h>
#else
#include <chipset_common/linux/mem_track/mem_trace.h>
#endif

size_t get_mem_total(int type);
size_t get_mem_detail(int type, void *buf, size_t len);
int page_trace_on(int type, char *name);
int page_trace_off(int type, char *name);
int page_trace_open(int type, int subtype);
int page_trace_close(int type, int subtype);
size_t page_trace_read(int type,
	struct mm_stack_info *info, size_t len, int subtype);
size_t get_ion_by_pid(pid_t pid);
size_t memcheck_get_ion_size_by_pid(pid_t pid);

#endif /* MEMCHECK_INTERFACE_H */
