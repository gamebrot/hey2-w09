// SPDX-License-Identifier: GPL-2.0-only
/*
 * linux/mm/remap_pfn_alloc_pages.c
 *
 * Copyright (c) 2023, The Linux Foundation. All rights reserved.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/huge_mm.h>
#include <asm/ptdump.h>


#ifdef CONFIG_HUGEPAGE_POOL
#include <linux/hugepage_pool.h>
#endif

#define REMAP_PMD_SHIFT PMD_SHIFT
#define REMAP_PMD_SIZE	((1UL) << REMAP_PMD_SHIFT)
#define REMAP_PMD_MASK	(~(REMAP_PMD_SIZE - 1))

#define BUF_SIZE (512 * PAGE_SIZE)

static int remap_pfn_open(struct inode *inode, struct file *file)
{
	struct mm_struct *mm = current->mm;
	static struct page *start_page;
	int ret = 0;

	printk("remap client: %s %d\n", current->comm, current->pid);
	printk("remap code  section: [0x%lx   0x%lx]\n", mm->start_code, mm->end_code);
	printk("remap data  section: [0x%lx   0x%lx]\n", mm->start_data, mm->end_data);
	printk("remap brk   section: s: 0x%lx, c: 0x%lx\n", mm->start_brk, mm->brk);
	printk("remap mmap  section: s: 0x%lx\n", mm->mmap_base);
	printk("remap stack section: s: 0x%lx\n", mm->start_stack);
	printk("remap arg   section: [0x%lx   0x%lx]\n", mm->arg_start, mm->arg_end);
	printk("remap env   section: [0x%lx   0x%lx]\n", mm->env_start, mm->env_end);

#ifdef CONFIG_HUGEPAGE_POOL
	start_page = alloc_hugepage(get_order(BUF_SIZE), HPAGE_DMA_BUF);
#else
	start_page = alloc_pages(GFP_KERNEL, get_order(BUF_SIZE));
#endif
	if (!start_page) {
		pr_err("remap_pfn_init fail!\n");
		ret = -ENOMEM;
		return ret;
	}

	file->private_data = start_page;

	return 0;
}

void print_pmd(struct mm_struct *mm, unsigned long addr)
{
	pgd_t *pgdp;
	p4d_t *p4d;
	pud_t *pudp;
	pmd_t *pmdp;
	pte_t *ptep;

	pgdp = pgd_offset(mm, addr);
	printk("remap pgdp = %p\n; ", (void*)pgdp);
	printk("remap pgdp value: 0x%llx\n", *pgdp);
	printk("remap pgdp value = 0x%llx \n; ", pgd_val(*pgdp));
	p4d = p4d_offset(pgdp, addr);
	pudp = pud_offset(p4d, addr);
	printk("remap pudp = %p\n; ", (void*)pudp);
	printk("remap pudp value: 0x%llx\n", *pudp);
	printk("remap pudp value = 0x%llx \n; ", pud_val(*pudp));
	pmdp = pmd_offset(pudp, addr);
	printk("remap pmdp = %p\n; ", (void*)pmdp);
	printk("remap pmdp value: 0x%llx\n", *pmdp);
	printk("remap pmdp value = 0x%llx \n; ", pmd_val(*pmdp));

	if (pmd_none(*pmdp) || pmd_sect(*pmdp)) {
		return;
	}

	ptep = pte_offset_map(pmdp, addr);
	printk("remap ptep = %p\n; ", (void*)ptep);
	printk("remap ptep value: 0x%llx\n", *ptep);
	printk("remap ptep value = 0x%llx \n; ", pte_val(*ptep));
	pte_unmap(ptep);
}

static int remap_pfn_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct page *start_page = file->private_data;
	unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
	unsigned long pfn_start = page_to_pfn(start_page) + vma->vm_pgoff;
	unsigned long virt_start = (unsigned long)page_address(start_page);
	unsigned long size = vma->vm_end - vma->vm_start;
	struct mm_struct *mm = vma->vm_mm;
	int ret = 0;

	//unsigned long old_add = 0;
	//unsigned long new_add = 0;

	printk("phy: 0x%lx, offset: 0x%lx, vm_start: 0x%lx, size: 0x%lx\n",
			pfn_start << PAGE_SHIFT, offset, vma->vm_start, size);
	printk("REMAP_PMD_MASK = 0x%lx\n", REMAP_PMD_MASK);
	//if ((vma->vm_start & ~HPAGE_PMD_MASK) != 0 || (size & ~HPAGE_PMD_MASK) != 0) {
	if (size & ~REMAP_PMD_MASK) {
		ret = remap_pfn_range(vma, vma->vm_start, pfn_start, size, vma->vm_page_prot);
		printk("remap_pfn_range phy!\n");
	} else {
		ret = remap_pfn_range(vma, vma->vm_start, pfn_start, size,
						mk_pmd_sect_prot(vma->vm_page_prot));
		printk("remap_pfn_range_thp phy!\n");
		vma->vm_flags |= VM_MERGEABLE;
		if (vma_is_special_huge(vma))
			printk("vma_is_special_huge\n");
	}

	if (ret)
		printk("remap %s: remap_pfn_range failed at [0x%lx  0x%lx]\n",
			__func__, vma->vm_start, vma->vm_end);
	else
		printk("remap %s: map 0x%lx to 0x%lx, size: 0x%lx\n",
			__func__, virt_start, vma->vm_start, size);

	print_pmd(mm, vma->vm_start);

	printk("remap_pfn_mmap %d\n", (int)atomic_read(&start_page->_mapcount));
	//atomic_set(&start_page->_mapcount, 0);
	printk("after remap_pfn_mmap %d\n", (int)atomic_read(&start_page->_mapcount));
	printk("page_to_pfn(start_page) = %x\n", page_to_pfn(start_page));

	return ret;
}

static int remap_pfn_release(struct inode *inode, struct file *file)
{
	struct page *start_page = file->private_data;

	printk("remap_pfn_release\n");


	if (start_page) {
		__free_pages(start_page, get_order(BUF_SIZE));
		printk("remap_pfn_release success\n");
	}

	return 0;
}

static const struct file_operations remap_pfn_fops = {
	.owner = THIS_MODULE,
	.open = remap_pfn_open,
	.mmap = remap_pfn_mmap,
	.release = remap_pfn_release,
};

static struct miscdevice remap_pfn_misc = {
	.minor = MISC_DYNAMIC_MINOR,
	.name = "remap_pfn",
	.fops = &remap_pfn_fops,
};

static int __init remap_pfn_init(void)
{
	int ret = 0;

	ret = misc_register(&remap_pfn_misc);
	if (unlikely(ret)) {
		pr_err("remap failed to register misc device!\n");
		goto err;
	}

	return 0;

err:
	return ret;
}

static void __exit remap_pfn_exit(void)
{
	misc_deregister(&remap_pfn_misc);
}

module_init(remap_pfn_init);
module_exit(remap_pfn_exit);
MODULE_LICENSE("GPL");
