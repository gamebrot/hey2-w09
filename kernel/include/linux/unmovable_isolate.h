/*
 * include/linux/unmovable_isolate.h
 *
 * MIGRATE_UNMOVABLE_ISOLATE function
 *
 * Copyright (C) 2017 Honor Device Co., Ltd.
 */

#ifndef _UNMOVABLE_ISOLATE_H_
#define _UNMOVABLE_ISOLATE_H_

#ifdef CONFIG_UNMOVABLE_ISOLATE
/* the unmovable-isolate area size setted by defconfig */
#define UNMOVABLE_ISOLATE1_SIZE_BLOCKS \
	(CONFIG_UNMOVABLE_ISOLATE1_SIZE_MBYTES*SZ_1M/PAGE_SIZE/pageblock_nr_pages)
#define UNMOVABLE_ISOLATE2_SIZE_BLOCKS \
	(CONFIG_UNMOVABLE_ISOLATE2_SIZE_MBYTES*SZ_1M/PAGE_SIZE/pageblock_nr_pages)

/* the allocable page order in unmovable-isolate area */
#define UNMOVABLE_ISOLATE1_MIN_ORDER 0
#define UNMOVABLE_ISOLATE1_MAX_ORDER 0

#ifdef CONFIG_UNMOVABLE_ISOLATE2_MIN_ORDER
#define UNMOVABLE_ISOLATE2_MIN_ORDER CONFIG_UNMOVABLE_ISOLATE2_MIN_ORDER
#else
#define UNMOVABLE_ISOLATE2_MIN_ORDER 2
#endif

#ifdef CONFIG_UNMOVABLE_ISOLATE2_MAX_ORDER
#define UNMOVABLE_ISOLATE2_MAX_ORDER CONFIG_UNMOVABLE_ISOLATE2_MAX_ORDER
#else
#define UNMOVABLE_ISOLATE2_MAX_ORDER 3
#endif

extern int unmovable_isolate_disabled;

int unmovable_isolate_enabled(struct zone* zone);
int valid_order_for_ui(int order, int migratetype);
int valid_zone_for_ui(struct zone* zone);
int get_enhanced_reserve_size(void);
void setup_zone_migrate_unmovable_isolate(struct zone *zone, int unmovable_isolate_type, int disable);
int unmovable_isolate_pageblock(struct zone* zone, struct page* page);

#endif /* CONFIG_HONOR_UNMOVABLE_ISOLATE */
#endif /* _UNMOVABLE_ISOLATE_H_ */

