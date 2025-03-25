#include <linux/mm_types.h>
#include <asm/page.h>
#include <asm/memory.h>
#include <linux/mm.h>
#include <linux/list.h>
#include <linux/string.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/gfp.h>
#include <asm/errno.h>

#define PLACEMENT_MEM_SIZE (512 * 1024) //PAGE_SIZE UNIT 2G size
#define PLACEMENT_RUNS (60)
#define PLACEMENT_ENABLE_SIZE (1024 * 1024) //4G

#define MAGIC_NUMBER (0xAC)
//#define TEST
static LIST_HEAD(placement);

static int allocs;

extern int set_memory_ro(unsigned long addr, int numpages);
extern int set_memory_rw(unsigned long addr, int numpages);
extern int set_direct_map_invalid_noflush(struct page *page);
extern int set_direct_map_default_noflush(struct page *page);
extern int set_direct_map_ro_noflush(struct page *page);

static int psan_alloc_memory(struct list_head *head, size_t size) {
	struct page *page;
	size_t i;

	//use bulk interface maybe the page don't random
	//allocs = alloc_pages_bulk(GFP_KERNEL, size/2, head);
	for (i = 0; i < size/4; i++) {
		page = alloc_page(GFP_DMA);
		if (page) {
			list_add(&page->lru, head);
			++allocs;
		}
	}
	for (i = 0; i < size/4; i++) {
		page = alloc_page(GFP_KERNEL);
		if (page) {
			list_add(&page->lru, head);
			++allocs;
		}
	}
	printk("psan: allocs=%d\n", allocs);
	return 0;
}

static void psan_fill_magic(struct list_head *list) {
	struct page *page, *next;

        list_for_each_entry_safe(page, next, list, lru) {
		void *data = page_to_virt(page);
		memset(data, MAGIC_NUMBER, PAGE_SIZE);
	}
}

static void psan_set_permission(struct list_head *list, int ro) {
	struct page *page, *next;

        list_for_each_entry_safe(page, next, list, lru) {
		unsigned long address = (unsigned long)page_address(page);
		ro ? set_memory_ro(address, 1) : set_memory_rw(address, 1);
		yield();
        }
}

static int psan_match_magic(char *data, size_t size) {
	int dismatch = 0;
	while (size--) {
		if (*data != MAGIC_NUMBER) {
			printk("psan:virtual addr[0x%lx], phy addr[0x%lx] data=%x\n", data, virt_to_phys(data), *data);
			dismatch++;
		}
		data++;
	}
	return dismatch;
}

#ifdef TEST
static void psan_test_memory(struct list_head *list) {
	struct page *page, *next;
	int pos = 0;
	list_for_each_entry_safe(page, next, list, lru) {
		pos++;
		if (pos == 10) {
			void *data = page_to_virt(page);
			memset(data + 11, 0xdd, PAGE_SIZE/512);
			break;
		}
	}
}
#endif

static int psan_check_memory(void *arg)
{
	uint64_t run = 0;
	struct page *page, *next;
	int dismatch = 0;
	struct list_head *head = &placement;

        psan_alloc_memory(&placement, PLACEMENT_MEM_SIZE);

	psan_fill_magic(head);
#ifdef TEST
	psan_test_memory(head);
#endif
	psan_set_permission(head, 1);

	while (true) {
		struct list_head *list = head;
		int count = 0;
		list_for_each_entry_safe(page, next, list, lru) {
			char *data = (char*)page_to_virt(page);
			dismatch += psan_match_magic(data, PAGE_SIZE) ? 1 : 0;
			yield();
			count++;
		}
		if (dismatch) {
#ifdef TEST
			psan_set_permission(head, 0);
			psan_fill_magic(head);
			psan_set_permission(head, 1);
			printk("psan:psan_check_memory failed = %d\n", dismatch);
#else
			panic("psan:psan_check_memory failed = %d\n", dismatch);
#endif
			dismatch = 0;
		}
		run++;
		printk("psan:psan_check_memory run = %lu allocs=%d, count=%d\n",
			run, allocs, count);

		if (run > PLACEMENT_RUNS)
			break;

		msleep(30 * 1000);
	}
	return 0;
}

bool psan_can_enable(void) {
	return (totalram_pages() > PLACEMENT_ENABLE_SIZE);
}

int psan_init(void)
{
	struct task_struct *check_thread;
	if (!psan_can_enable()) {
		printk("psan disable in low memory\n");
		return 0;
	}

	check_thread = kthread_create(psan_check_memory, NULL, "psan_check_memory");
	if (check_thread != NULL) {
		wake_up_process(check_thread);
	}
	return 0;
}

EXPORT_SYMBOL_GPL(psan_init);

subsys_initcall(psan_init);
