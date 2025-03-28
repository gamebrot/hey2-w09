/*
 * mem_trace.h	memory track interface declare
 *
 * Copyright(C) 2021 Honor Device Co., Ltd. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef _MEM_TRACE_H
#define _MEM_TRACE_H

#include <linux/types.h>
#include <linux/mm.h>
#include <linux/page-flags.h>

#define SLUB_NAME_LEN  64

enum {
	START_TRACK,
	ION_TRACK = START_TRACK,
	SLUB_TRACK,
	LSLUB_TRACK,
	VMALLOC_TRACK,
	CMA_TRACK,
	ZSPAGE_TRACK,
	BUDDY_TRACK,
	SKB_TRACK,
	NR_TRACK,
};

enum {
	SLUB_ALLOC,
	SLUB_FREE,
	NR_SLUB_ID,
};

struct mm_slub_detail_info {
	char name[SLUB_NAME_LEN];
	unsigned long active_objs;
	unsigned long num_objs;
	unsigned long active_slabs;
	unsigned long num_slabs;
	unsigned long size; /* total size */
	unsigned int objects_per_slab;
	unsigned int objsize;
};

struct mm_ion_detail_info {
	pid_t pid;
	size_t size;
};

struct mm_vmalloc_detail_info {
	int type;
	size_t size;
};

struct mm_stack_info {
	unsigned long caller;
	atomic_t ref;
};

#ifdef CONFIG_MM_PAGE_TRACE
size_t mm_get_mem_total(int type);
size_t mm_get_mem_detail(int type, void *buf, size_t len);
int mm_page_trace_on(int type, char *name);
int mm_page_trace_off(int type, char *name);
int mm_page_trace_open(int type, int subtype);
int mm_page_trace_close(int type, int subtype);
size_t mm_page_trace_read(int type,
	struct mm_stack_info *info, size_t len, int subtype);
size_t mm_get_ion_by_pid(pid_t pid);
void set_buddy_track(struct page *page,
	unsigned int order, unsigned long caller);
void set_lslub_track(struct page *page,
	unsigned int order, unsigned long caller);
void alloc_node_func_map(struct pglist_data *pgdat);
void set_alloc_track(unsigned long caller);
void set_free_track(unsigned long caller);
int buddy_track_map(int nid);
int buddy_track_unmap(void);
void mm_vmalloc_detail_show(void);
void mm_mem_stats_show(void);
void user_memory_dump(bool verbose);
#else
static inline size_t mm_get_mem_total(int type)
{
	return 0;
}

static inline size_t mm_get_mem_detail(int type, void *buf, size_t len)
{
	return 0;
}

static inline size_t mm_get_ion_by_pid(pid_t pid)
{
	return 0;
}

static inline int mm_page_trace_on(int type, char *name)
{
	return 0;
}

static inline int mm_page_trace_off(int type, char *name)
{
	return 0;
}

static inline int mm_page_trace_open(int type, int subtype)
{
	return 0;
}

static inline int mm_page_trace_close(int type, int subtype)
{
	return 0;
}

static inline size_t mm_page_trace_read(int type,
	struct mm_stack_info *info, size_t len, int subtype)
{
	return 0;
}
static inline void set_buddy_track(struct page *page,
	unsigned int order, unsigned long caller) { }
static inline void set_lslub_track(struct page *page,
	unsigned int order, unsigned long caller) { }
static inline void alloc_node_func_map(struct pglist_data *pgdat) { }
static inline void set_alloc_track(unsigned long caller) { }
static inline void set_free_track(unsigned long caller) { }
static inline int buddy_track_map(int nid)
{
	return 0;
}
static inline int buddy_track_unmap(void)
{
	return 0;
}
static inline void mm_vmalloc_detail_show(void) { }
static inline void mm_mem_stats_show(void) { }
static inline void user_memory_dump(bool verbose) { }
#endif
#endif
