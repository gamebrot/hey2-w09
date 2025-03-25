// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright IBM Corporation, 2021
 *
 * Author: Mike Rapoport <rppt@linux.ibm.com>
 */

#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/swap.h>
#include <linux/mount.h>
#include <linux/module.h>
#include <linux/bitops.h>
#include <linux/printk.h>
#include <linux/pagemap.h>
#include <linux/syscalls.h>
#include <linux/secretmem.h>
#include <linux/set_memory.h>
#include <linux/sched/signal.h>
#include <linux/file.h>
#include <linux/pseudo_fs.h>

#include <uapi/linux/magic.h>
#include <uapi/linux/memfd.h>

#include <asm/tlbflush.h>

#include "internal.h"

#undef pr_fmt
#define pr_fmt(fmt) "secretmem: " fmt

/*
 * Define mode and flag masks to allow validation of the system call
 * parameters.
 */
#define SECRETMEM_MODE_MASK	(MFD_SECRET)
#define SECRETMEM_FLAGS_MASK	SECRETMEM_MODE_MASK

static bool secretmem_enable = 1;
module_param_named(enable, secretmem_enable, bool, 0400);
MODULE_PARM_DESC(secretmem_enable,
		 "Enable secretmem and memfd_secret(2) system call");

extern int set_direct_map_invalid_noflush(struct page *page);
extern int set_direct_map_default_noflush(struct page *page);

static vm_fault_t secretmem_fault(struct vm_fault *vmf)
{
	struct address_space *mapping = vmf->vma->vm_file->f_mapping;
	struct inode *inode = file_inode(vmf->vma->vm_file);
	pgoff_t offset = vmf->pgoff;
	gfp_t gfp = vmf->gfp_mask;
	unsigned long addr;
	struct page *page;
	int err;

	if (((loff_t)vmf->pgoff << PAGE_SHIFT) >= i_size_read(inode))
		return VM_FAULT_ERROR;

retry:
	page = find_lock_page(mapping, offset);
	if (!page) {
		page = alloc_page(gfp | __GFP_ZERO);
		if (!page)
			return VM_FAULT_OOM;

		err = set_direct_map_invalid_noflush(page);
		if (err) {
			put_page(page);
			return err;
		}

		__SetPageUptodate(page);
		err = add_to_page_cache_lru(page, mapping, offset, gfp);
		if (unlikely(err)) {
			put_page(page);
			/*
			 * If a split of large page was required, it
			 * already happened when we marked the page invalid
			 * which guarantees that this call won't fail
			 */
			set_direct_map_default_noflush(page);
			if (err == -EEXIST)
				goto retry;

			return err;
		}

		addr = (unsigned long)page_address(page);
		flush_tlb_kernel_range(addr, addr + PAGE_SIZE);
	}

	vmf->page = page;
	return VM_FAULT_LOCKED;
}

static const struct vm_operations_struct secretmem_vm_ops = {
	.fault = secretmem_fault,
};

static int secretmem_mmap(struct file *file, struct vm_area_struct *vma)
{
	unsigned long len = vma->vm_end - vma->vm_start;

	if ((vma->vm_flags & (VM_SHARED | VM_MAYSHARE)) == 0)
		return -EINVAL;

	if (mlock_future_check(vma->vm_mm, vma->vm_flags | VM_LOCKED, len))
		return -EAGAIN;

	vma->vm_flags |= VM_LOCKED | VM_DONTDUMP;
	vma->vm_ops = &secretmem_vm_ops;

	return 0;
}

bool vma_is_secretmem(struct vm_area_struct *vma)
{
	return vma->vm_ops == &secretmem_vm_ops;
}

static const struct file_operations secretmem_fops = {
	.mmap		= secretmem_mmap,
};

static bool secretmem_isolate_page(struct page *page, isolate_mode_t mode)
{
	return false;
}

static int secretmem_migratepage(struct address_space *mapping,
				 struct page *newpage, struct page *page,
				 enum migrate_mode mode)
{
	return -EBUSY;
}

static void secretmem_freepage(struct page *page)
{
	set_direct_map_default_noflush(page);
	clear_highpage(page);
}

static const struct address_space_operations secretmem_aops = {
	.freepage	= secretmem_freepage,
	.migratepage	= secretmem_migratepage,
	.isolate_page	= secretmem_isolate_page,
};

bool page_is_secretmem(struct page *page)
{
	struct address_space *mapping;

	/*
	 * Using page_mapping() is quite slow because of the actual call
	 * instruction and repeated compound_head(page) inside the
	 * page_mapping() function.
	 * We know that secretmem pages are not compound and LRU so we can
	 * save a couple of cycles here.
	 */
	if (PageCompound(page) || !PageLRU(page))
		return false;

	mapping = (struct address_space *)
		((unsigned long)page->mapping & ~PAGE_MAPPING_FLAGS);

	if (mapping != page->mapping)
		return false;

	return page->mapping->a_ops == &secretmem_aops;
}

static struct vfsmount *secretmem_mnt;

static struct file *secretmem_file_create(const char* name, unsigned long flags)
{
	struct file *file = ERR_PTR(-ENOMEM);
	struct inode *inode;

	inode = alloc_anon_inode(secretmem_mnt->mnt_sb);
	if (IS_ERR(inode))
		return ERR_CAST(inode);

	file = alloc_file_pseudo(inode, secretmem_mnt, name,
				 O_RDWR, &secretmem_fops);
	if (IS_ERR(file))
		goto err_free_inode;

	mapping_set_gfp_mask(inode->i_mapping, GFP_HIGHUSER);
	mapping_set_unevictable(inode->i_mapping);

	inode->i_mapping->a_ops = &secretmem_aops;

	/* pretend we are a normal file with zero size */
	inode->i_mode |= S_IFREG | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;
	inode->i_size = 0;

	return file;

err_free_inode:
	iput(inode);
	return file;
}

#define MFD_NAME_PREFIX "secmem:"
#define MFD_NAME_PREFIX_LEN (sizeof(MFD_NAME_PREFIX) - 1)
#define MFD_NAME_MAX_LEN (NAME_MAX - MFD_NAME_PREFIX_LEN)

int memfd_secret_create(const char __user * uname, unsigned int flags)
{
	struct file *file;
	int fd, err;
	char *name;
	long len;

	/* make sure local flags do not confict with global fcntl.h */
	BUILD_BUG_ON(SECRETMEM_FLAGS_MASK & O_CLOEXEC);

	if (!secretmem_enable)
		return -ENOSYS;

	if (!(flags & ~(SECRETMEM_FLAGS_MASK | O_CLOEXEC)))
		return -EINVAL;

	/* length includes terminating zero */
	len = strnlen_user(uname, MFD_NAME_MAX_LEN + 1);
	if (len <= 0)
		return -EFAULT;

	if (len > MFD_NAME_MAX_LEN + 1)
		return -EINVAL;

	name = kmalloc(len + MFD_NAME_PREFIX_LEN, GFP_KERNEL);
	if (!name)
		return -ENOMEM;

	strcpy(name, MFD_NAME_PREFIX);
	if (copy_from_user(&name[MFD_NAME_PREFIX_LEN], uname, len)) {
		err = -EFAULT;
		goto err_name;
	}

	fd = get_unused_fd_flags(flags & ~SECRETMEM_FLAGS_MASK);
	if (fd < 0)
		return fd;

	file = secretmem_file_create(name, flags);
	if (IS_ERR(file)) {
		err = PTR_ERR(file);
		goto err_put_fd;
	}

        file->f_mode |= FMODE_LSEEK | FMODE_READ | FMODE_WRITE;
        file->f_flags |= O_RDWR | O_LARGEFILE;

	fd_install(fd, file);
        kfree(name);

	return fd;

err_put_fd:
	put_unused_fd(fd);
err_name:
        kfree(name);
	return err;
}

/*
 * anon_inodefs_dname() is called from d_path().
 */
static char *secretmem_inodefs_dname(struct dentry *dentry, char *buffer, int buflen)
{
	return dynamic_dname(dentry, buffer, buflen, "%s",
			dentry->d_name.name);
}

static const struct dentry_operations secretmem_inodefs_dentry_operations = {
	.d_dname        = secretmem_inodefs_dname,
};

/*
 * pipefs should _never_ be mounted by userland - too much of security hassle,
 * no real gain from having the whole whorehouse mounted. So we don't need
 * any operations on the root directory. However, we need a non-trivial
 * d_name - pipe: will go nicely and kill the special-casing in procfs.
 */
static int secretmem_mount(struct fs_context *fc)
{
	struct pseudo_fs_context *ctx = init_pseudo(fc, SECRETMEM_MAGIC);
 	if (!ctx)
 		return -ENOMEM;
	ctx->dops = &secretmem_inodefs_dentry_operations;
	return 0;
}

static struct file_system_type secretmem_fs = {
	.name			 = "secretmem",
	.init_fs_context = secretmem_mount,
	.kill_sb		 = kill_anon_super,
};

static int secretmem_init(void)
{
	int ret = 0;

	if (!secretmem_enable)
		return ret;

	secretmem_mnt = kern_mount(&secretmem_fs);
	if (IS_ERR(secretmem_mnt))
		ret = PTR_ERR(secretmem_mnt);

	return ret;
}
fs_initcall(secretmem_init);

