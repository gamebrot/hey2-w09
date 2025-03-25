// SPDX-License-Identifier: GPL-2.0
/*
 * fs/f2fs/file.c
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd.
 *             http://www.samsung.com/
 */
#include <linux/fs.h>
#include <linux/f2fs_fs.h>
#include <linux/stat.h>
#include <linux/buffer_head.h>
#include <linux/writeback.h>
#include <linux/blkdev.h>
#include <linux/falloc.h>
#include <linux/types.h>
#include <linux/compat.h>
#include <linux/uaccess.h>
#include <linux/mount.h>
#include <linux/pagevec.h>
#include <linux/uio.h>
#include <linux/uuid.h>
#include <linux/file.h>
#include <linux/nls.h>
#include <linux/sched/signal.h>
#ifdef CONFIG_BLK_CGROUP_IOSMART
#include <linux/sched.h>
#endif

#include "f2fs.h"
#include "node.h"
#include "segment.h"
#include "xattr.h"
#include "acl.h"
#include "gc.h"
#include <trace/events/f2fs.h>
#include <uapi/linux/f2fs.h>

#ifdef CONFIG_HONOR_F2FS_DSM
#undef CREATE_TRACE_POINTS
#include <trace/hooks/fs.h>
#if (defined CONFIG_F2FS_FS_COMPRESSION_OPTM) || (defined CONFIG_F2FS_FS_SIS_DISK)
#include <log/hiview_hievent.h>
#include <linux/delay.h>
#endif

void f2fs_dsm_up(char *name, int len)
{
	trace_android_vh_timerfd_create(name, len);
}
#endif

#if (defined CONFIG_F2FS_FS_COMPRESSION_OPTM) || (defined CONFIG_F2FS_FS_SIS_DISK)
#define MAX_LOOP_TIMES 10000
#endif
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
#define COMP_BD_ID		928005005
#define COMP_BD_INFO_SIZE	128
enum COMP_BD_SCENE {
	BD_COMP,
	BD_DECOMP,
	BD_RELS,
	BD_RESV,
};
#endif

#ifdef CONFIG_F2FS_FS_SIS_DISK
#define SIS_BD_ID		928005005
#define F2FS_RECOVER_DSM_LIMIT	100
#define ERROR_INFO_SIZE 	512

#define SIS_META_COINCIDE_FL	0x1
#define SIS_DATA_COINCIDE_FL	0x2
#define SIS_SET_COINCIDE	0x4
#define SIS_GET_COINCIDE	0x8
#define SIS_CLEAR_COINCIDE	0x10
#define SIS_DUP_META		0x20
#define SIS_DUP_DATA		0x40
#define SIS_SYNC_DATA		0x80
#define SIS_LOOP_MOD		10000
#define SIS_MIN_SIZE		65536

enum {
	FAULT_DEDUP = 1,
	FAULT_RECOVRE,
};

enum {
	SIS_DUP_FILE = 0,
	SIS_CONNECT_HIDDEN,
	SIS_DEDUP_FILE,
};

enum {
	REGULAR_INODE = 0,
	DUMMY_INODE,
	HIDDEN_INODE,
};

struct page_list {
	struct list_head list;
	struct page *page;
};
static struct kmem_cache *page_info_slab;

#define page_list_add(head, page)	do {			\
	struct page_list *tmp;					\
	tmp = f2fs_kmem_cache_alloc(page_info_slab, GFP_NOFS);	\
	tmp->page = page;					\
	INIT_LIST_HEAD(&tmp->list);				\
	list_add_tail(&tmp->list, &head);			\
} while (0)

#define page_list_del(head)	do {			\
	struct page_list *tmp;					\
	tmp = list_first_entry(&head, struct page_list, list);	\
	f2fs_put_page(tmp->page, 0);				\
	list_del(&tmp->list);					\
	kmem_cache_free(page_info_slab, tmp);			\
} while (0)

int create_page_info_slab(void)
{
	page_info_slab = f2fs_kmem_cache_create("f2fs_page_info_entry",
				sizeof(struct page_list));
	if (!page_info_slab)
		return -ENOMEM;

	return 0;
}

void destroy_page_info_slab(void)
{
	if (!page_info_slab)
		return;

	kmem_cache_destroy(page_info_slab);
}

/*
 * need lock_op and acquire_orphan by caller
 */
void f2fs_sis_unlink(struct inode *inode)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);

	f2fs_down_write(&F2FS_I(inode)->i_sem);
	f2fs_i_links_write(inode, false);
	f2fs_up_write(&F2FS_I(inode)->i_sem);

	if (inode->i_nlink == 0) {
		f2fs_add_orphan_inode(inode);
	} else {
		f2fs_release_orphan_inode(sbi);
	}
}

int f2fs_sis_blur_inline_addr(struct inode* inode, block_t addr)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct page *node_page;
	struct f2fs_inode *ri;
	block_t orig_addr = (addr == SIS_ADDR)? NULL_ADDR:SIS_ADDR;
	int base = 0;
	int count = 1;
	int i;

repeat:
	node_page = f2fs_get_node_page(sbi, inode->i_ino);
	if (PTR_ERR(node_page) == -ENOMEM) {
		if (!(count++ % SIS_LOOP_MOD))
			f2fs_err(sbi,
				"[sis]: %s: try to get node page %d", __func__, count);

		cond_resched();
		goto repeat;
	} else if (IS_ERR(node_page)) {
		f2fs_err(sbi, "[sis]: %s: get node page fail", __func__);
		return PTR_ERR(node_page);
	}

	f2fs_wait_on_page_writeback(node_page, NODE, true, true);
	ri = F2FS_INODE(node_page);

	if (f2fs_has_extra_attr(inode))
		base = get_extra_isize(inode);

	for (i = 0; i < addrs_per_inode(inode); i++) {

		if (orig_addr == ri->i_addr[i + base]) {
			ri->i_addr[i + base] = cpu_to_le32(addr);
			continue;
		}
		if (f2fs_is_valid_blkaddr(sbi, ri->i_addr[i + base], DATA_GENERIC_ENHANCE)) {
			f2fs_err(sbi, "[f2fs-sis-erro]: %s: inode[%lu] leak data addr[%d:%u]",
				__func__, inode->i_ino, i + base, ri->i_addr[i + base]);
		} else {
			f2fs_err(sbi, "[f2fs-sis-erro]: %s: inode[%lu] illegal inline addr[%d:%u]",
				__func__, inode->i_ino, i + base, ri->i_addr[i + base]);
			ri->i_addr[i + base] = cpu_to_le32(addr);
		}
	}

	for (i = 0; i < DEF_NIDS_PER_INODE; i++) {
		if (!ri->i_nid[i])
			ri->i_nid[i] = cpu_to_le32(0);
		else
			f2fs_err(sbi, "[sis]: %s: inode[%lu] leak node addr[%d:%u]",
				__func__, inode->i_ino, i, ri->i_nid[i]);
	}

	set_page_dirty(node_page);
	f2fs_put_page(node_page, 1);

	return 0;
}

static int f2fs_sis_recover_begin(struct inode *inode)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	int err;

	f2fs_lock_op(sbi);

	err = f2fs_acquire_orphan_inode(sbi);
	if (err) {
		f2fs_unlock_op(sbi);
		f2fs_err(sbi, "[sis]: recover inode[%lu] begin fail, ret:%d",
			inode->i_ino, err);
		return err;
	}

	f2fs_add_orphan_inode(inode);

	set_inode_flag(inode, FI_RECOVER_INODE);

	f2fs_unlock_op(sbi);

	return 0;
}

static void f2fs_sis_report_send(struct f2fs_sb_info *sbi, const char* info,  const char* phen)
{
	struct hiview_hievent *hi_event = NULL;
	unsigned int ret = 0;

	hi_event = hiview_hievent_create(SIS_BD_ID);
	if (!hi_event) {
		f2fs_warn(sbi, "[sis]: %s:create eventobj failed", __func__);
		return;
	}

	ret = ret | hiview_hievent_put_string(hi_event, "CONTENT", info);
	ret = ret | hiview_hievent_put_string(hi_event, "FAULT_PHENOMENON", phen);

	if (ret)
		goto out;

	ret = hiview_hievent_report(hi_event);
out:
	if (ret < 0)
		f2fs_warn(sbi, "[sis]: %s send hievent failed, err: %d", __func__, ret);

	hiview_hievent_destroy(hi_event);
}

static void f2fs_sis_prefree_hidden_inode(struct inode *inode, struct inode *hidden)
{
	struct f2fs_inode_info *fi = F2FS_I(hidden);

	fi->i_flags &= ~F2FS_IMMUTABLE_FL;
	f2fs_set_inode_flags(hidden);
	f2fs_mark_inode_dirty_sync(hidden, true);

	/*
	 * Before free hidden inode, we should wait all reader of
	 * the hidden complete to avoid UAF or read unexpected data.
	 */
	wait_event(fi->sis_wq,
			atomic_read(&fi->transferred_read_cnt) == 0);
}

static int f2fs_sis_recover_end(struct inode *inode)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct f2fs_inode_info *fi = F2FS_I(inode);
	struct inode *h_inode = NULL;
	int err;

	f2fs_lock_op(sbi);

	f2fs_remove_orphan_inode(sbi, inode->i_ino);

	f2fs_down_write(&fi->i_sem);
	clear_inode_flag(inode, FI_RECOVER_INODE);
	clear_inode_flag(inode, FI_SIS_INODE);
	clear_inode_flag(inode, FI_META_COINCIDE);
	clear_inode_flag(inode, FI_DATA_COINCIDE);

	/*
	 * other reader flow:
	 * 1) lock inode
	 * 2) judge whether hidden_inode is NULL
	 * 3) if no, then __iget hidden inode
	 */
	h_inode = fi->i_hidden_inode;
	fi->i_hidden_inode = NULL;
	fi->sis_cp_ver = cur_cp_version(F2FS_CKPT(sbi));
	f2fs_up_write(&fi->i_sem);

	err = f2fs_acquire_orphan_inode(sbi);
	if (err) {
		set_sbi_flag(sbi, SBI_NEED_FSCK);
		f2fs_set_need_fsck_report();
		f2fs_warn(sbi,
			"[sis]: %s: orphan failed (ino=%lx), run fsck to fix.",
			__func__, h_inode->i_ino);
	} else {
		f2fs_info(sbi, "[sis-statistic]: inode[%lu] recoverd, dec hidden[%lu]"
			" link, nlink = %d", inode->i_ino, h_inode->i_ino, h_inode->i_nlink);
		f2fs_sis_unlink(h_inode);
	}
	f2fs_unlock_op(sbi);

	trace_f2fs_sis_recover_inode(inode, h_inode);

	if (h_inode->i_nlink == 0)
		f2fs_sis_prefree_hidden_inode(inode, h_inode);

	iput(h_inode);
	return err;
}

bool f2fs_is_hole_blkaddr(struct inode *inode, pgoff_t pgofs)
{
	struct dnode_of_data dn;
	block_t blkaddr;
	int err = 0;

	if (f2fs_has_inline_data(inode) || f2fs_has_inline_dentry(inode))
		return false;

	set_new_dnode(&dn, inode, NULL, NULL, 0);
	err = f2fs_get_dnode_of_data(&dn, pgofs, LOOKUP_NODE);
	if (err && err != -ENOENT)
		return false;

	/* direct node does not exists */
	if (err == -ENOENT)
		return true;

	blkaddr = f2fs_data_blkaddr(&dn);
	f2fs_put_dnode(&dn);

	if (__is_valid_data_blkaddr(blkaddr) &&
		!f2fs_is_valid_blkaddr(F2FS_I_SB(inode),
			blkaddr, DATA_GENERIC))
		return false;

	if (blkaddr != NULL_ADDR)
		return false;

	return true;
}

static int f2fs_sis_copy_data(struct inode *dst_inode,
		struct inode *src_inode, pgoff_t page_idx, int len, bool from_dup);
static int f2fs_sis_recover_data(struct inode *inode)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	pgoff_t page_idx = 0, last_idx;
	int blk_per_seg = sbi->blocks_per_seg;
	int count;
	int ret1 = 0;
	int ret2 = 0;

	f2fs_sis_blur_inline_addr(inode, NULL_ADDR);
	last_idx = DIV_ROUND_UP(i_size_read(inode), PAGE_SIZE);

	count = last_idx - page_idx;
	while (count) {
		int len = min(blk_per_seg, count);
		ret1 = f2fs_sis_copy_data(inode, NULL, page_idx, len, false);
		if (ret1 < 0)
			break;

		filemap_fdatawrite(inode->i_mapping);

		count -= len;
		page_idx += len;
	}

	ret2 = filemap_write_and_wait_range(inode->i_mapping, 0,
			LLONG_MAX);

	if (ret1 || ret2)
		f2fs_warn(sbi, "[sis]: %s: The sis inode[%lu] recover fail(errno=%d,%d).",
				__func__, inode->i_ino, ret1, ret2);

	return ret1 ? : ret2;
}

static void f2fs_sis_recover_error_handle(struct inode *inode)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);

	f2fs_lock_op(sbi);
	f2fs_sis_inode_trunc(inode, FI_RECOVER_INODE);
	f2fs_remove_orphan_inode(sbi, inode->i_ino);
	F2FS_I(inode)->sis_cp_ver = cur_cp_version(F2FS_CKPT(sbi));
	f2fs_unlock_op(sbi);
	trace_f2fs_sis_recover_fail(inode, F2FS_I(inode)->i_hidden_inode);
}

static void f2fs_sis_recover_inode_report(struct inode *inode,
		nid_t hidden_ino, const char *source, int step, int ret)
{
	struct f2fs_sb_info * sbi = F2FS_I_SB(inode);
	char info[ERROR_INFO_SIZE] = {0};
	char phen[ERROR_INFO_SIZE] = {0};

	f2fs_err(sbi,
		"[f2fs-sis-erro]: %s trigger recover ret[%d], inode[%lu], hidden ino[%lu]",
		source, ret, inode->i_ino, hidden_ino);

	scnprintf(info, sizeof(info),
		"errno:%d, source:%s, inode1:%lu, hidden:%lu, filesize:%lld, recover_step:%d",
		ret, source, inode->i_ino, hidden_ino, i_size_read(inode), step);
	scnprintf(phen, sizeof(phen), "sis recover");

	f2fs_sis_report_send(sbi, info, phen);
}

void f2fs_bd_sis_recover_record(struct inode *inode, const char *source_func, bool is_err)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	int scense;

	scense = get_scense(source_func);
	bd_lock(sbi->sis_info);
	inc_cbd_array_val_check(sbi, sis_info, recv, scense, 1, is_err);
	bd_unlock(sbi->sis_info);
}

/*
 * need inode_lock by caller
 */
int f2fs_recover_sis_inode(struct inode *inode, const char *source_func)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	int err = 0;
	static DEFINE_RATELIMIT_STATE(recover_stats_rs,
				HZ, F2FS_RECOVER_DSM_LIMIT);
	struct inode *h_inode = NULL;
	int step = 0;
	nid_t h_ino = 0;

	if (unlikely(f2fs_cp_error(sbi)))
		return -EIO;

	if (!f2fs_is_dummy_inode(inode)) {
		f2fs_err(F2FS_I_SB(inode), "[sis]: inode[%lu], is not dummy inode", inode->i_ino);
		return -EINVAL;
	}

	err = dquot_initialize(inode);
	if (err)
		return err;

	f2fs_balance_fs(sbi, true);

	h_inode = F2FS_I(inode)->i_hidden_inode;
	if (!h_inode) {
		f2fs_err(F2FS_I_SB(inode),
				"[f2fs-sis-erro]:sis inode[%lu] have not hidden", inode->i_ino);
		err = -EBADF;
		goto ret;
	}
	h_ino = h_inode->i_ino;

	err = fscrypt_prepare_recover(h_inode);
	if (err)
		goto ret;

	step++;
	err = f2fs_sis_recover_begin(inode);
	if (err)
		goto ret;

	step++;
	err = f2fs_sis_recover_data(inode);
	if (err) {
		f2fs_sis_recover_error_handle(inode);
		goto ret;
	}

	step++;
	err = f2fs_sis_recover_end(inode);

ret:
	f2fs_bd_sis_recover_record(inode, source_func, err? true:false);
	if (!err && __ratelimit(&recover_stats_rs)) {
		f2fs_info(F2FS_I_SB(inode), "[sis-statistic]: inode[%lu] recover success,"
			"hidden ino[%lu], recover reason %s", inode->i_ino, h_ino, source_func);
	} else if (err) {
		f2fs_sis_recover_inode_report(inode, h_ino, source_func, step, err);
	}
	return err;
}

static void f2fs_set_coincide_flag(struct inode *inode,
		struct f2fs_sis_coincide_info *info)
{
	if (info->flag & SIS_META_COINCIDE_FL) {
		if (!is_inode_flag_set(inode, FI_META_COINCIDE))
			set_inode_flag(inode, FI_META_COINCIDE);
	}

	if (info->flag & SIS_DATA_COINCIDE_FL) {
		if (!is_inode_flag_set(inode, FI_DATA_COINCIDE))
			set_inode_flag(inode, FI_DATA_COINCIDE);
	}
}

static void f2fs_get_coincide_flag(struct inode *inode,
		struct f2fs_sis_coincide_info *info)
{
	memset(&(info->flag), 0, sizeof(info->flag));

	if (is_inode_flag_set(inode, FI_META_COINCIDE))
		info->flag = info->flag | SIS_META_COINCIDE_FL;

	if (is_inode_flag_set(inode, FI_DATA_COINCIDE))
		info->flag = info->flag | SIS_DATA_COINCIDE_FL;
}

static void f2fs_clear_coincide_flag(struct inode *inode,
		struct f2fs_sis_coincide_info *info)
{
	if (info->flag & SIS_META_COINCIDE_FL) {
		clear_inode_flag(inode, FI_META_COINCIDE);
	}

	if (info->flag & SIS_DATA_COINCIDE_FL) {
		clear_inode_flag(inode, FI_DATA_COINCIDE);
	}

	f2fs_mark_inode_dirty_sync(inode, true);
}

bool f2fs_sis_inode_support(struct f2fs_sb_info *sbi,
		struct inode *inode)
{
	struct f2fs_inode_info *fi = F2FS_I(inode);
	struct f2fs_inode *ri;

	if (!f2fs_sb_has_sis(sbi))
		return false;

	if (!f2fs_has_extra_attr(inode))
		return false;

	if (!F2FS_FITS_IN_INODE(ri, fi->i_extra_isize, i_sis_hidden_ino))
		return false;

	return true;
}

static int f2fs_sis_chk_inode(struct f2fs_sb_info *sbi,
		struct inode *inode, int type)
{
	if (!S_ISREG(inode->i_mode)) {
		f2fs_err(F2FS_I_SB(inode), "[sis]: inode[%lu], is not regular", inode->i_ino);
		return -EINVAL;
	}


	if (type != HIDDEN_INODE && inode->i_size < SIS_MIN_SIZE) {
		f2fs_err(sbi, "[sis]: param check fails, inode[%lu] size < %lu bytes.",
			inode->i_ino, SIS_MIN_SIZE);
		return -EINVAL;
	}

	if (type == DUMMY_INODE &&
		!is_inode_flag_set(inode, FI_DATA_COINCIDE)) {
		f2fs_err(sbi, "[sis]: param check fails, inode[%lu] has been modified.",
			inode->i_ino);
		return -EINVAL;
	}

#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
	if (f2fs_is_compressed_inode(inode)) {
#else
	if (f2fs_compressed_file(inode)) {
#endif
		f2fs_err(sbi, "[sis]: param check fails, inode[%lu] has been compressed.",
			inode->i_ino);
		return -EACCES;
	}

	if (IS_VERITY(inode)) {
		f2fs_err(sbi, "[sis]: param check fails, inode[%lu] enable verity.",
			inode->i_ino);
		return -EACCES;
	}

	if (f2fs_is_atomic_file(inode)) {
		f2fs_err(sbi, "[sis]: param check fails, inode[%lu] is atomic file.",
			inode->i_ino);
		return -EACCES;
	}

	if (f2fs_is_volatile_file(inode)) {
		f2fs_err(sbi, "[sis]: param check fails, inode[%lu] is volatile file.",
			inode->i_ino);
		return -EACCES;
	}

	if (f2fs_is_pinned_file(inode)) {
		f2fs_err(sbi, "[sis]: param check fails, inode[%lu] is pinned file.",
			inode->i_ino);
		return -EACCES;
	}

	if (type != HIDDEN_INODE && IS_IMMUTABLE(inode)) {
		f2fs_err(sbi, "[sis]: param check fails, inode[%lu] is immutable.",
			inode->i_ino);
		return -EACCES;
	}
	return 0;
}

/* chk_reason:
 *    dup_file: inode1:dummy, inode2:hidden;
 *    connect: inode1:dummy, inode2:hidden;
 *    dedup_file: inode2:dummy, inode2:dummy;
 */
static int f2fs_sis_pre_check(struct f2fs_sb_info *sbi,
		struct inode *inode1, struct inode *inode2, int chk_reason)
{
	int ret;

	if (inode1->i_sb != inode2->i_sb) {
		f2fs_err(sbi, "[sis]: input inode[%lu] and [%lu] are not in the same partition.",
				inode1->i_ino, inode2->i_ino);
		return -EINVAL;
	}

	if (inode1 == inode2) {
		f2fs_err(sbi, "[sis]: inode[%lu], not support same inode do sis operation.",
				inode1->i_ino);
		return -EINVAL;
	}

	if (chk_reason && (inode1->i_size != inode2->i_size)) {
		f2fs_err(sbi,
			"[sis]: file size not match inode1[%lu] %u, inode2[%lu] %u",
			inode1->i_ino, inode1->i_size,
			inode2->i_ino, inode2->i_size);
		return -EINVAL;
	}

	if (chk_reason && (inode1->i_nlink == 0)) {
		f2fs_err(sbi,
			"[sis]: inode[%lu] has been removed.", inode1->i_ino);
		return -ENOENT;
	}

	ret = f2fs_sis_chk_inode(sbi, inode1, DUMMY_INODE);
	if (ret)
		return ret;

	if (chk_reason == SIS_DEDUP_FILE)
		ret = f2fs_sis_chk_inode(sbi, inode2, DUMMY_INODE);
	else
		ret = f2fs_sis_chk_inode(sbi, inode2, HIDDEN_INODE);
	if (ret)
		return ret;

	return 0;
}

static void f2fs_sis_dedup_step_report(struct inode *inode1, struct inode *inode2, int ret, int step)
{
	const char* step_name;
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode1);
	struct inode * hidden_inode = NULL;
	char info[ERROR_INFO_SIZE] = {0};
	char phen[ERROR_INFO_SIZE] = {0};

	switch (step) {
	case SIS_DUP_FILE:
		step_name = "dup_file";
		break;
	case SIS_CONNECT_HIDDEN:
		step_name = "connect_hidden";
		break;
	case SIS_DEDUP_FILE:
		step_name = "dedup_file";
		break;
	default:
		f2fs_err(sbi, "[sis]:inode1[%lu] err step #%d, ret = %d.",
			inode1->i_ino, step, ret);
		return;
	}

	scnprintf(phen, sizeof(phen), "sis dedup");
	if (step != SIS_DEDUP_FILE && inode2) {
		scnprintf(info, sizeof(info),
			"errno:%d, source:%s, inode1:%lu, hidden:%lu, filesize:%lld",
			ret, step_name, inode1->i_ino, inode2->i_ino, i_size_read(inode1));
	} else if (inode2) {
		hidden_inode = F2FS_I(inode2)->i_hidden_inode;
		if (hidden_inode)
			scnprintf(info, sizeof(info),
			"errno:%d, source:%s, inode1:%lu, inode2:%lu, hidden:%lu, filesize:%lld",
			ret, step_name, inode1->i_ino, inode2->i_ino, hidden_inode->i_ino, i_size_read(inode1));
		else
			scnprintf(info, sizeof(info),
			"errno:%d, source:%s, inode1:%lu, inode2:%lu, hidden:NA(hidden lost), filesize:%lld",
			ret, step_name, inode1->i_ino, inode2->i_ino, i_size_read(inode1));
	} else {
		f2fs_err(sbi,
			"[f2fs-sis-erro]:inode1[%lu] at #%s, lost inode2, can't report error %d.",
			inode1->i_ino, step_name, ret);
		return;
	}

	f2fs_sis_report_send(sbi, info, phen);
	f2fs_err(F2FS_I_SB(inode1),
		"[f2fs-sis-erro]: inode1:[%lu] and inode2:[%lu] at %s, occur err: %d",
		inode1->i_ino, inode2->i_ino, step_name, ret);
}

static int f2fs_ioc_coincide_flag(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct f2fs_sis_coincide_info info;
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	int ret;

	if (unlikely(f2fs_cp_error(sbi)))
		return -EIO;

	if (f2fs_readonly(sbi->sb))
		return -EROFS;

	if (!inode_owner_or_capable(inode))
		return -EACCES;

	if (!S_ISREG(inode->i_mode)) {
		f2fs_err(F2FS_I_SB(inode), "[sis]: inode[%lu], is not regular", inode->i_ino);
		return -EINVAL;
	}

	if (!f2fs_sis_inode_support(sbi, inode)) {
		f2fs_err(sbi, "[sis]: inode[%lu] notsupport sis.", inode->i_ino);
		return -EOPNOTSUPP;
	}

	if (f2fs_has_inline_data(inode)) {
		f2fs_err(sbi, "[sis]: inode[%lu] has inline data.", inode->i_ino);
		return -EINVAL;
	}

	if (copy_from_user(&info,
		(struct f2fs_sis_coincide_info __user *)arg, sizeof(info)))
		return -EFAULT;

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	inode_lock(inode);
	if (info.mode & SIS_SET_COINCIDE) {
		struct address_space *mapping = inode->i_mapping;
		bool dirty = false;
		int nrpages = 0;

		if (mapping_mapped(mapping)) {
			f2fs_err(sbi, "[sis]: inode[%lu] has mapped vma", inode->i_ino);
			ret = -EBUSY;
			goto out;
		}

		ret = f2fs_sis_chk_inode(sbi, inode, REGULAR_INODE);
		if (ret)
			goto out;

		if (mapping_tagged(mapping, PAGECACHE_TAG_DIRTY) ||
				mapping_tagged(mapping, PAGECACHE_TAG_WRITEBACK)) {
			dirty = true;
			nrpages = get_dirty_pages(inode);
		}

		if (dirty && (info.flag & SIS_SYNC_DATA)) {
			//f2fs_sis_dirty_data_report(inode, __func__, nrpages);

			ret = filemap_write_and_wait_range(mapping, 0, LLONG_MAX);
			if (ret) {
				f2fs_err(sbi, "[sis]: inode[%lu] write data fail(%d)\n",
						inode->i_ino, ret);
				goto out;
			}
		} else if (dirty) {
			f2fs_err(sbi, "[sis]: inode[%lu] have dirty page[%d]\n",
					inode->i_ino, nrpages);
			ret = -EINVAL;
			goto out;
		}

		f2fs_set_coincide_flag(inode, &info);
	} else if (info.mode & SIS_GET_COINCIDE) {
		f2fs_get_coincide_flag(inode, &info);
	} else if (info.mode & SIS_CLEAR_COINCIDE) {
		f2fs_clear_coincide_flag(inode, &info);
	} else {
		ret = -EINVAL;
	}

out:
	inode_unlock(inode);
	mnt_drop_write_file(filp);

	if (copy_to_user((struct f2fs_sis_coincide_info __user *)arg,
		&info, sizeof(info)))
		ret = -EFAULT;

	return ret;
}

static int f2fs_ioc_sis_pre_check(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);

	if (unlikely(f2fs_cp_error(sbi)))
		return -EIO;

	if (f2fs_readonly(sbi->sb))
		return -EROFS;

	if (!inode_owner_or_capable(inode))
		return -EACCES;

	if (!S_ISREG(inode->i_mode))
		return -EINVAL;

	if (!f2fs_sis_inode_support(sbi, inode)) {
		f2fs_err(sbi, "[sis]: inode[%lu] notsupport sis.", inode->i_ino);
		return -EOPNOTSUPP;
	}

	if (f2fs_has_inline_data(inode)) {
		f2fs_err(sbi, "[sis]: inode[%lu] has inline data.", inode->i_ino);
		return -EINVAL;
	}

	return f2fs_sis_chk_inode(sbi, inode, DUMMY_INODE);
}

static int f2fs_sis_copy_data(struct inode *dst_inode,
		struct inode *src_inode, pgoff_t page_idx, int len, bool from_dup)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(dst_inode);
	struct address_space *dst_mapping, *src_mapping;
	filler_t *filler = NULL;
	struct page *page, *newpage;
	pgoff_t copy_idx = page_idx;
	int i, page_len = 0, ret = 0;
	struct dnode_of_data dn;
	LIST_HEAD(pages);
	DEFINE_READAHEAD(ractl, NULL, NULL, page_idx);

	if (!from_dup)
		src_inode = dst_inode;

	src_mapping = src_inode->i_mapping;
	ractl.mapping = src_mapping;

	page_cache_ra_unbounded(&ractl, len, 0);

	for (i = 0; i < len; i++, page_idx++) {
		page = read_cache_page(src_mapping, page_idx, filler, NULL);
		if (IS_ERR(page)) {
			ret = PTR_ERR(page);
			goto out;
		}
		page_len++;
		page_list_add(pages, page);
	}

	for (i = 0; i < page_len; i++, copy_idx++) {
		page = find_lock_page(src_mapping, copy_idx);
		if (!page) {
			ret = -ENOMEM;
			break;
		}

		if (f2fs_is_hole_blkaddr(f2fs_is_dummy_inode(src_inode)?
					F2FS_I(src_inode)->i_hidden_inode:src_inode, copy_idx)) {
			f2fs_put_page(page, 1);
			continue;
		}

		f2fs_do_map_lock(sbi, F2FS_GET_BLOCK_PRE_AIO, true);
		set_new_dnode(&dn, dst_inode, NULL, NULL, 0);
		ret = f2fs_get_block(&dn, copy_idx);
		f2fs_put_dnode(&dn);
		f2fs_do_map_lock(sbi, F2FS_GET_BLOCK_PRE_AIO, false);
		if (ret) {
			f2fs_put_page(page, 1);
			break;
		}

		if (from_dup) {
			dst_mapping = dst_inode->i_mapping;
			newpage = f2fs_grab_cache_page(dst_mapping, copy_idx, true);
			if (!newpage) {
				ret = -ENOMEM;
				f2fs_put_page(page, 1);
				break;
			}
			f2fs_copy_page(page, newpage);

			set_page_dirty(newpage);
			f2fs_put_page(newpage, 1);
		} else {
			set_page_dirty(page);
		}
		f2fs_put_page(page, 1);
	}

out:
	while (!list_empty(&pages))
		page_list_del(pages);

	return ret;
}

static int f2fs_sis_dup_data(struct inode *inode,
		struct inode *s_inode)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(s_inode);
	pgoff_t page_idx = 0, last_idx;
	int blk_per_seg = sbi->blocks_per_seg;
	int count;
	int ret = 0;

	f2fs_balance_fs(sbi, true);
	last_idx = DIV_ROUND_UP(i_size_read(s_inode), PAGE_SIZE);
	count = last_idx - page_idx;

	while (count) {
		int len = min(blk_per_seg, count);
		ret = f2fs_sis_copy_data(inode, s_inode, page_idx, len, true);
		if (ret < 0)
			break;

		filemap_fdatawrite(inode->i_mapping);
		count -= len;
		page_idx += len;
	}

	if (!ret)
		ret = filemap_write_and_wait_range(inode->i_mapping, 0,
				LLONG_MAX);

	return ret;
}

static int f2fs_sis_dup_inode(struct inode *inode,
		struct inode *s_inode, struct f2fs_sis_src_info *info)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(s_inode);
	int ret;

	ret = f2fs_convert_inline_inode(inode);
	if (ret) {
		f2fs_err(sbi,
			"[sis]: inode[%lu] convert inline inode failed, ret:%d",
			inode->i_ino, ret);
		return ret;
	}

	if (info->flags & SIS_DUP_META) {
		inode->i_uid = s_inode->i_uid;
		inode->i_gid = s_inode->i_gid;
		inode->i_size = s_inode->i_size;
	}

	if (info->flags & SIS_DUP_DATA) {
		inode->i_size = s_inode->i_size;
		ret = f2fs_sis_dup_data(inode, s_inode);
		if (ret) {
			f2fs_err(sbi,
				"[sis]: from inode[%lu] to [%lu] dup data failed. ret=%d",
				s_inode->i_ino, inode->i_ino, ret);
			return ret;
		}
	}

	set_inode_flag(inode, FI_DATA_COINCIDE);

	return 0;
}

static void f2fs_set_dup_file_nochange(struct inode *inode) {
	F2FS_I(inode)->i_flags |= F2FS_IMMUTABLE_FL;
	f2fs_set_inode_flags(inode);
	f2fs_mark_inode_dirty_sync(inode, true);
}

static int f2fs_ioc_dup_file(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct inode *s_inode;
	struct f2fs_sis_src_info info;
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct fd s_fd;
	int ret = 0;

	if (unlikely(f2fs_cp_error(F2FS_I_SB(inode))))
		return -EIO;

	if (f2fs_readonly(sbi->sb))
		return -EROFS;

	if (!inode_owner_or_capable(inode))
		return -EACCES;

	if (copy_from_user(&info, (struct f2fs_sis_src_info __user *)arg, sizeof(info)))
		return -EFAULT;

	s_fd = fdget_pos(info.src_fd);
	if (!s_fd.file)
		return -EBADF;

	s_inode = file_inode(s_fd.file);
	if (!f2fs_sis_inode_support(sbi, s_inode)) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	ret = mnt_want_write_file(filp);
	if (ret)
		goto out;

	inode_lock(inode);
	ret = f2fs_sis_pre_check(sbi, s_inode, inode, SIS_DUP_FILE);
	if (ret)
		goto unlock;

	ret = f2fs_sis_dup_inode(inode, s_inode, &info);
	if (ret) {
		f2fs_sis_dedup_step_report(s_inode, inode, ret, SIS_DUP_FILE);
		goto unlock;
	}

	f2fs_set_dup_file_nochange(inode);
unlock:
	inode_unlock(inode);
	mnt_drop_write_file(filp);
out:
	fdput_pos(s_fd);
	return ret;
}

static inline void _truncate_error_handle(struct inode *inode,
		int ret)
{
	set_sbi_flag(F2FS_I_SB(inode), SBI_NEED_FSCK);
	f2fs_set_need_fsck_report();
	f2fs_err(F2FS_I_SB(inode),
		"[f2fs-sis-erro]: truncate data failed, need fsck. inode:%lu ret:%d",
		inode->i_ino, ret);
}

int f2fs_sis_inode_trunc(struct inode *inode, unsigned int flag)
{
	int ret = 0;

	if (!f2fs_is_dummy_inode(inode)) {
		f2fs_err(F2FS_I_SB(inode),
			"[sis]: inode:%lu is not sis inode", inode->i_ino);
		f2fs_bug_on(F2FS_I_SB(inode), 1);
		return 0;
	}

	clear_inode_flag(inode, flag);

	ret = f2fs_truncate_blocks(inode, 0, false);
	if (ret)
		goto err;

	ret = f2fs_sis_blur_inline_addr(inode, SIS_ADDR);
	if (ret)
		goto err;

	return 0;
err:
	_truncate_error_handle(inode, ret);
	return ret;
}

static int f2fs_sis_is_inode_match_dir_crypt_policy(struct dentry *dir,
		struct inode *inode)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);

	if (IS_ENCRYPTED(d_inode(dir)) &&
		!fscrypt_has_permitted_context(d_inode(dir), inode)) {
		f2fs_err(sbi, "[sis]: inode[%lu] not match dir[%lu] fscrypt policy",
			inode->i_ino, d_inode(dir)->i_ino);
		return -EPERM;
	}

	return 0;
}

static int f2fs_sis_fscrypt_policy_match(struct file *file1,
		struct file *file2)
{
	struct dentry *dir1 = dget_parent(file_dentry(file1));
	struct dentry *dir2 = dget_parent(file_dentry(file2));
	struct inode *inode1 = file_inode(file1);
	struct inode *inode2 = file_inode(file2);
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode1);
	int err = 0;

	if (IS_ENCRYPTED(d_inode(dir1)) &&
		!fscrypt_has_permitted_context(d_inode(dir1), inode2)) {
		f2fs_err(sbi, "[sis]: dir[%lu] inode[%lu] and inode[%lu] fscrypt policy not match.",
			d_inode(dir1)->i_ino, inode1->i_ino, inode2->i_ino);
		err = -EPERM;
		goto out;
	}

	if (IS_ENCRYPTED(d_inode(dir2)) &&
		!fscrypt_has_permitted_context(d_inode(dir2), inode1)) {
		f2fs_err(sbi, "[sis]: inode[%lu] and dir[%lu] inode[%lu] fscrypt policy not match.",
			inode1->i_ino, d_inode(dir2)->i_ino, inode2->i_ino);
		err = -EPERM;
	}

out:
	dput(dir2);
	dput(dir1);
	return err;
}

static int f2fs_sis_change_file(struct inode *inode,
		struct inode *h_inode, bool is_connect)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct f2fs_inode_info *fi = F2FS_I(inode);
	int ret = 0;

	if (!h_inode)
		return -EBADF;

	f2fs_lock_op(sbi);
	ret = f2fs_acquire_orphan_inode(sbi);
	if (ret) {
		f2fs_unlock_op(sbi);
		f2fs_err(sbi,
			"[sis]: file acquire orphan fail, ino[%lu], hidden ino[%lu]",
			inode->i_ino, h_inode->i_ino);
		//put_hidden_inode(h_inode);
		return ret;
	}
	f2fs_add_orphan_inode(inode);

	f2fs_down_write(&fi->i_sem);
	fi->i_hidden_inode = h_inode;
	set_inode_flag(inode, FI_SIS_INODE);
	set_inode_flag(inode, FI_BEING_SIS);
	f2fs_up_write(&fi->i_sem);

	f2fs_down_write(&F2FS_I(h_inode)->i_sem);
	igrab(h_inode);
	if (is_connect) {
		set_inode_flag(h_inode, FI_HIDDEN_INODE);
		set_inode_flag(h_inode, FI_SIS_INODE);
	}
	f2fs_i_links_write(h_inode, true);
	f2fs_up_write(&F2FS_I(h_inode)->i_sem);
	if (is_connect)
		f2fs_remove_orphan_inode(sbi, h_inode->i_ino);
	f2fs_unlock_op(sbi);

	wait_event(fi->sis_wq,
			atomic_read(&fi->transferred_read_cnt) == 0);

	f2fs_down_write(&fi->i_gc_rwsem[WRITE]);
	ret = filemap_write_and_wait_range(inode->i_mapping, 0, LLONG_MAX);
	if (ret) {
		f2fs_up_write(&fi->i_gc_rwsem[WRITE]);
		f2fs_err(sbi, "[sis]: inode[%lu] hidden[%lu] deduped but wait writeback err %d",
			inode->i_ino, h_inode->i_ino, ret);
		goto count;
	}

	f2fs_lock_op(sbi);
	f2fs_remove_orphan_inode(sbi, inode->i_ino);
	ret = f2fs_sis_inode_trunc(inode, FI_BEING_SIS);
	/*
	 * Since system may do checkpoint after unlock cp,
	 * we set cp_ver here to let fsync know trunc/dedup have finish.
	 */
	F2FS_I(inode)->sis_cp_ver = cur_cp_version(F2FS_CKPT(sbi));
	f2fs_unlock_op(sbi);
	f2fs_up_write(&fi->i_gc_rwsem[WRITE]);

count:
	bd_lock(sbi->sis_info);
	inc_cbd_val(sbi, sis_info, excute_cnt, 1);
	bd_unlock(sbi->sis_info);

	f2fs_info(sbi, "[sis-statistic]: inode[%lu] dedup success, hidden[%lu] is_connect:%d?",
		inode->i_ino, h_inode->i_ino, is_connect);
	trace_f2fs_ioc_sis_dedup_file(inode, h_inode);
	return ret;
}

static int f2fs_ioc_sis_connect_hidden(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct inode *h_inode = NULL;
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct f2fs_sis_hidden_fd info;
	struct dentry *dir;
	struct fd h_fd;
	int ret;

	if (unlikely(f2fs_cp_error(F2FS_I_SB(inode))))
		return -EIO;

	if (f2fs_readonly(sbi->sb))
		return -EROFS;

	if (!inode_owner_or_capable(inode))
		return -EACCES;

	if (!f2fs_sis_inode_support(sbi, inode))
		return -EOPNOTSUPP;

	if (copy_from_user(&info, (struct f2fs_sis_hidden_fd __user *)arg, sizeof(info)))
		return -EFAULT;

	h_fd = fdget_pos(info.hidden_fd);
	if (!h_fd.file)
		return -EBADF;

	ret = mnt_want_write_file(filp);
	if (ret)
		goto out;

	inode_lock(inode);
	if (f2fs_is_sis_inode(inode)) {
		f2fs_err(sbi, "[sis]: The inode[%lu] is sis inode.",
			inode->i_ino);
		ret = -EINVAL;
		goto unlock;
	}

	h_inode = file_inode(h_fd.file);
	ret = f2fs_sis_pre_check(sbi, inode, h_inode, SIS_CONNECT_HIDDEN);
	if (ret)
		goto unlock;

	if (!IS_IMMUTABLE(h_inode)) {
		f2fs_err(sbi, "[f2fs-sis-erro]: hidden[%lu] is not immutable.",
			h_inode->i_ino);
		ret = -EINVAL;
		goto unlock;
	}

	dir = dget_parent(file_dentry(filp));
	ret = f2fs_sis_is_inode_match_dir_crypt_policy(dir, h_inode);
	dput(dir);
	if (ret)
		goto unlock;

	filemap_fdatawrite(inode->i_mapping);
	ret = filemap_write_and_wait_range(inode->i_mapping, 0, LLONG_MAX);
	if (ret)
		goto unlock;

	//ret = __f2fs_sis_connect_inode(inode, h_inode);
	ret = f2fs_sis_change_file(inode, h_inode, true);
	if (ret)
		f2fs_sis_dedup_step_report(inode, h_inode, ret, SIS_CONNECT_HIDDEN);

unlock:
	inode_unlock(inode);
	mnt_drop_write_file(filp);
out:
	fdput_pos(h_fd);
	return ret;
}

static int f2fs_ioc_sis_dedup_file(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct inode *bro_inode, *h_inode = NULL;
	struct dentry *dir;
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct f2fs_sis_src_fd info;
	struct fd b_fd;
	int ret;

	if (unlikely(f2fs_cp_error(F2FS_I_SB(inode))))
		return -EIO;

	if (f2fs_readonly(sbi->sb))
		return -EROFS;

	if (!inode_owner_or_capable(inode))
		return -EACCES;

	if (!f2fs_sis_inode_support(sbi, inode))
		return -EOPNOTSUPP;

	if (copy_from_user(&info, (struct f2fs_sis_src_fd __user *)arg, sizeof(info)))
		return -EFAULT;

	b_fd = fdget_pos(info.base_fd);
	if (!b_fd.file)
		return -EBADF;

	bro_inode = file_inode(b_fd.file);

	if (!f2fs_sis_inode_support(sbi, bro_inode)) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	ret = mnt_want_write_file(filp);
	if (ret)
		goto out;

	inode_lock(inode);
	if (!inode_trylock(bro_inode)) {
		f2fs_err(sbi, "[sis]: inode[%lu] can't get lock", bro_inode->i_ino);
		ret = -EAGAIN;
		goto unlock2;
	}

	if (f2fs_is_sis_inode(inode)) {
		f2fs_err(sbi, "[sis]: inode[%lu] is sis inode",
			inode->i_ino);
		ret = -EINVAL;
		goto unlock1;
	}

	if (!f2fs_is_sis_inode(bro_inode)) {
		f2fs_err(sbi, "[sis]: inode[%lu] is not sis inode",
			bro_inode->i_ino);
		ret = -EINVAL;
		goto unlock1;
	}

	ret = f2fs_sis_pre_check(sbi, bro_inode, inode, SIS_DEDUP_FILE);
	if (ret)
		goto unlock1;

	h_inode = get_hidden_inode(bro_inode);
	if (!h_inode)
		goto unlock1;
	dir = dget_parent(file_dentry(filp));
	ret = f2fs_sis_is_inode_match_dir_crypt_policy(dir, h_inode);
	//put_hidden_inode(hidden_inode);
	dput(dir);
	if (ret)
		goto puthidden;

	ret = f2fs_sis_fscrypt_policy_match(filp, b_fd.file);
	if (ret)
		goto puthidden;

	filemap_fdatawrite(inode->i_mapping);
	ret = filemap_write_and_wait_range(inode->i_mapping, 0, LLONG_MAX);
	if (ret)
		goto puthidden;

	//ret = f2fs_sis_dedup_file(bro_inode, inode);
	ret = f2fs_sis_change_file(inode, h_inode, false);
	if (ret)
		f2fs_sis_dedup_step_report(inode, bro_inode, ret, SIS_DEDUP_FILE);

puthidden:
	put_hidden_inode(h_inode);
unlock1:
	inode_unlock(bro_inode);
unlock2:
	inode_unlock(inode);
	mnt_drop_write_file(filp);
out:
	fdput_pos(b_fd);
	return ret;
}

static int f2fs_ioc_sis_recover_file(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	int ret = 0;

	if (f2fs_readonly(F2FS_I_SB(inode)->sb))
		return -EROFS;

	if (!inode_owner_or_capable(inode))
		return -EACCES;

	if (!S_ISREG(inode->i_mode))
		return -EINVAL;

	if (unlikely(f2fs_cp_error(F2FS_I_SB(inode))))
		return -EIO;

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	inode_lock(inode);
	if (f2fs_is_dummy_inode(inode)) {
		ret = f2fs_recover_sis_inode(inode, __func__);
		if (ret)
			f2fs_err(F2FS_I_SB(inode), "[sis]: inode[%lu], recover err,"
				" ret = %d", inode->i_ino, ret);
	}
	inode_unlock(inode);

	mnt_drop_write_file(filp);
	return ret;
}

static int f2fs_ioc_sis_get_file_info(struct file *filp, unsigned long arg)
{
	struct f2fs_sis_file_info info = {0};
	struct inode *h_inode;
	struct inode *inode = file_inode(filp);
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	int ret = 0;

	if (unlikely(f2fs_cp_error(F2FS_I_SB(inode))))
		return -EIO;

	if (!f2fs_sis_inode_support(sbi, inode))
		return -EOPNOTSUPP;

	inode_lock(inode);

	if (!is_inode_flag_set(inode, FI_SIS_INODE)) {
		info.is_connected = false;
		info.is_deduped = false;
	} else {
		info.is_connected = true;
		h_inode = F2FS_I(inode)->i_hidden_inode;

		if (h_inode) {
			f2fs_down_write(&F2FS_I(h_inode)->i_sem);
			if (h_inode->i_nlink > 1)
				info.is_deduped = true;

			info.hidden_ino = h_inode->i_ino;
			f2fs_up_write(&F2FS_I(h_inode)->i_sem);
		} else {
			f2fs_err(F2FS_I_SB(inode),
				"[f2fs-sis-erro]:sis inode[%lu] have not hidden", inode->i_ino);
		}
	}

	inode_unlock(inode);

	if (copy_to_user((struct f2fs_sis_file_info __user *)arg, &info, sizeof(info)))
		ret = -EFAULT;

	return ret;
}
#endif /* CONFIG_F2FS_FS_SIS_DISK */

static vm_fault_t f2fs_filemap_fault(struct vm_fault *vmf)
{
	struct inode *inode = file_inode(vmf->vma->vm_file);
	vm_fault_t ret;

	f2fs_down_read(&F2FS_I(inode)->i_mmap_sem);
	ret = filemap_fault(vmf);
	f2fs_up_read(&F2FS_I(inode)->i_mmap_sem);

	if (!ret)
		f2fs_update_iostat(F2FS_I_SB(inode), APP_MAPPED_READ_IO,
							F2FS_BLKSIZE);

	trace_f2fs_filemap_fault(inode, vmf->pgoff, (unsigned long)ret);

	return ret;
}

#if (defined CONFIG_F2FS_FS_COMPRESSION_OPTM) || (defined CONFIG_F2FS_FS_SIS_DISK)
static inline bool inode_trylock_timeout(struct inode *inode)
{
	bool ret = false;
	int spin_times = 0;

	while(spin_times < MAX_LOOP_TIMES) {
		if(inode_trylock(inode)) {
			ret = true;
			break;
		} else {
			usleep_range(1000, 2000);
			spin_times++;
		}
	}

	return ret;
}
#endif

static vm_fault_t f2fs_vm_page_mkwrite(struct vm_fault *vmf)
{
	struct page *page = vmf->page;
	struct inode *inode = file_inode(vmf->vma->vm_file);
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct dnode_of_data dn;
	bool need_alloc = true;
	int err = 0;

	if (unlikely(IS_IMMUTABLE(inode)))
		return VM_FAULT_SIGBUS;
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
	if(!inode_trylock_timeout(inode)) {
		f2fs_compress_err("[mmap-c] inode[%lu] compr try lock fail", inode->i_ino);
		err = -EAGAIN;
		goto err;
	}
	if (f2fs_compressed_file(inode)) {
		err = f2fs_do_decompress_file(inode, DECOMP_VM_PAGE_WRITE);

		if (err) {
			f2fs_compress_err("decompress failed, ino %lu, curr %s,"
				"ret %d", inode->i_ino, current->comm, err);
			inode_unlock(inode);
			goto err;
		}
	}
	inode_unlock(inode);
#endif
	if (is_inode_flag_set(inode, FI_COMPRESS_RELEASED)) {
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
		f2fs_compress_err("file is release status, mkwrite failed, inode %lu", inode->i_ino);
#endif
		return VM_FAULT_SIGBUS;
	}

	if (unlikely(f2fs_cp_error(sbi))) {
		err = -EIO;
		goto err;
	}

	if (!f2fs_is_checkpoint_ready(sbi)) {
		err = -ENOSPC;
		goto err;
	}

	err = f2fs_convert_inline_inode(inode);
	if (err)
		goto err;
#ifdef CONFIG_F2FS_FS_SIS_DISK
	if(!inode_trylock_timeout(inode)) {
		f2fs_err(F2FS_I_SB(inode), "[f2fs-sis-erro] inode[%lu] sis try lock fail", inode->i_ino);
		err = -EAGAIN;
		goto err;
	}
	remove_data_coincide_flag(inode);
	if (f2fs_is_dummy_inode(inode)) {
		err = f2fs_recover_sis_inode(inode, __func__);
		if (err) {
			f2fs_err(F2FS_I_SB(inode), "[sis]: inode[%lu], recover err, "
				"err = %d", inode->i_ino, err);
			inode_unlock(inode);
			goto err;
		}
	}
	inode_unlock(inode);
#endif

#ifdef CONFIG_F2FS_FS_COMPRESSION
	if (f2fs_compressed_file(inode)) {
		int ret = f2fs_is_compressed_cluster(inode, page->index);

		if (ret < 0) {
			err = ret;
			goto err;
		} else if (ret) {
			need_alloc = false;
		}
	}
#endif
	/* should do out of any locked page */
	if (need_alloc)
		f2fs_balance_fs(sbi, true);

	sb_start_pagefault(inode->i_sb);

	f2fs_bug_on(sbi, f2fs_has_inline_data(inode));

	file_update_time(vmf->vma->vm_file);
	f2fs_down_read(&F2FS_I(inode)->i_mmap_sem);
	lock_page(page);
	if (unlikely(page->mapping != inode->i_mapping ||
			page_offset(page) > i_size_read(inode) ||
			!PageUptodate(page))) {
		unlock_page(page);
		err = -EFAULT;
		goto out_sem;
	}

	if (need_alloc) {
		/* block allocation */
		f2fs_do_map_lock(sbi, F2FS_GET_BLOCK_PRE_AIO, true);
		set_new_dnode(&dn, inode, NULL, NULL, 0);
		err = f2fs_get_block(&dn, page->index);
		f2fs_do_map_lock(sbi, F2FS_GET_BLOCK_PRE_AIO, false);
	}

#ifdef CONFIG_F2FS_FS_COMPRESSION
	if (!need_alloc) {
		set_new_dnode(&dn, inode, NULL, NULL, 0);
		err = f2fs_get_dnode_of_data(&dn, page->index, LOOKUP_NODE);
		f2fs_put_dnode(&dn);
	}
#endif
	if (err) {
		unlock_page(page);
		goto out_sem;
	}

	f2fs_wait_on_page_writeback(page, DATA, false, true);

	/* wait for GCed page writeback via META_MAPPING */
	f2fs_wait_on_block_writeback(inode, dn.data_blkaddr);

	/*
	 * check to see if the page is mapped already (no holes)
	 */
	if (PageMappedToDisk(page))
		goto out_sem;

	/* page is wholly or partially inside EOF */
	if (((loff_t)(page->index + 1) << PAGE_SHIFT) >
						i_size_read(inode)) {
		loff_t offset;

		offset = i_size_read(inode) & ~PAGE_MASK;
		zero_user_segment(page, offset, PAGE_SIZE);
	}
	set_page_dirty(page);
	if (!PageUptodate(page))
		SetPageUptodate(page);

	f2fs_update_iostat(sbi, APP_MAPPED_IO, F2FS_BLKSIZE);
	f2fs_update_time(sbi, REQ_TIME);

	trace_f2fs_vm_page_mkwrite(page, DATA);
out_sem:
	f2fs_up_read(&F2FS_I(inode)->i_mmap_sem);

	sb_end_pagefault(inode->i_sb);
err:
	return block_page_mkwrite_return(err);
}

static const struct vm_operations_struct f2fs_file_vm_ops = {
	.fault		= f2fs_filemap_fault,
	.map_pages	= filemap_map_pages,
	.page_mkwrite	= f2fs_vm_page_mkwrite,
#ifdef CONFIG_SPECULATIVE_PAGE_FAULT
	.allow_speculation = filemap_allow_speculation,
#endif
};

static int get_parent_ino(struct inode *inode, nid_t *pino)
{
	struct dentry *dentry;

	/*
	 * Make sure to get the non-deleted alias.  The alias associated with
	 * the open file descriptor being fsync()'ed may be deleted already.
	 */
	dentry = d_find_alias(inode);
	if (!dentry)
		return 0;

	*pino = parent_ino(dentry);
	dput(dentry);
	return 1;
}

static inline enum cp_reason_type need_do_checkpoint(struct inode *inode)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	enum cp_reason_type cp_reason = CP_NO_NEEDED;

	if (!S_ISREG(inode->i_mode))
		cp_reason = CP_NON_REGULAR;
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
	else if (f2fs_compressed_file(inode) ||
		F2FS_I(inode)->compr_cp_ver == cur_cp_version(F2FS_CKPT(sbi)))
#else
	else if (f2fs_compressed_file(inode))
#endif
		cp_reason = CP_COMPRESSED;
#ifdef CONFIG_F2FS_FS_SIS_DISK
	/*
	 * If inode have do sis op recently, we need to do
	 * checkpoint to avoid roll forward recovery after fsync,
	 * which may cause data inconsistency.
	 */
	else if (F2FS_I(inode)->sis_cp_ver == cur_cp_version(F2FS_CKPT(sbi)))
		cp_reason = CP_SIS_NEED_CP;
#endif
	else if (inode->i_nlink != 1)
		cp_reason = CP_HARDLINK;
	else if (is_sbi_flag_set(sbi, SBI_NEED_CP))
		cp_reason = CP_SB_NEED_CP;
	else if (file_wrong_pino(inode))
		cp_reason = CP_WRONG_PINO;
	else if (!f2fs_space_for_roll_forward(sbi))
		cp_reason = CP_NO_SPC_ROLL;
	else if (!f2fs_is_checkpointed_node(sbi, F2FS_I(inode)->i_pino))
		cp_reason = CP_NODE_NEED_CP;
	else if (test_opt(sbi, FASTBOOT))
		cp_reason = CP_FASTBOOT_MODE;
	else if (F2FS_OPTION(sbi).active_logs == 2)
		cp_reason = CP_SPEC_LOG_NUM;
	else if (F2FS_OPTION(sbi).fsync_mode == FSYNC_MODE_STRICT &&
		f2fs_need_dentry_mark(sbi, inode->i_ino) &&
		f2fs_exist_written_data(sbi, F2FS_I(inode)->i_pino,
							TRANS_DIR_INO))
		cp_reason = CP_RECOVER_DIR;

	return cp_reason;
}

static bool need_inode_page_update(struct f2fs_sb_info *sbi, nid_t ino)
{
	struct page *i = find_get_page(NODE_MAPPING(sbi), ino);
	bool ret = false;
	/* But we need to avoid that there are some inode updates */
	if ((i && PageDirty(i)) || f2fs_need_inode_block_update(sbi, ino))
		ret = true;
	f2fs_put_page(i, 0);
	return ret;
}

static void try_to_fix_pino(struct inode *inode)
{
	struct f2fs_inode_info *fi = F2FS_I(inode);
	nid_t pino;

	f2fs_down_write(&fi->i_sem);
	if (file_wrong_pino(inode) && inode->i_nlink == 1 &&
			get_parent_ino(inode, &pino)) {
		f2fs_i_pino_write(inode, pino);
		file_got_pino(inode);
	}
	f2fs_up_write(&fi->i_sem);
}

static int f2fs_do_sync_file(struct file *file, loff_t start, loff_t end,
						int datasync, bool atomic)
{
	struct inode *inode = file->f_mapping->host;
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	nid_t ino = inode->i_ino;
	int ret = 0;
	enum cp_reason_type cp_reason = 0;
	struct writeback_control wbc = {
		.sync_mode = WB_SYNC_ALL,
		.nr_to_write = LONG_MAX,
		.for_reclaim = 0,
	};
#ifdef CONFIG_F2FS_BIGDATA
	u64 fsync_begin = 0, fsync_end = 0, wr_file_end, cp_begin = 0,
		cp_end = 0, sync_node_begin = 0, sync_node_end = 0,
		flush_begin = 0, flush_end = 0;
#endif
	unsigned int seq_id = 0;

	if (unlikely(f2fs_readonly(inode->i_sb)))
		return 0;

	trace_f2fs_sync_file_enter(inode);

	if (S_ISDIR(inode->i_mode))
		goto go_write;

#ifdef CONFIG_F2FS_BIGDATA
	fsync_begin = local_clock();
#endif
	/* if fdatasync is triggered, let's do in-place-update */
	if (datasync || get_dirty_pages(inode) <= SM_I(sbi)->min_fsync_blocks)
		set_inode_flag(inode, FI_NEED_IPU);
	ret = file_write_and_wait_range(file, start, end);
#ifdef CONFIG_F2FS_BIGDATA
	wr_file_end = local_clock();
#endif
	clear_inode_flag(inode, FI_NEED_IPU);

	if (ret || is_sbi_flag_set(sbi, SBI_CP_DISABLED)) {
		trace_f2fs_sync_file_exit(inode, cp_reason, datasync, ret);
		return ret;
	}

	/* if the inode is dirty, let's recover all the time */
	if (!f2fs_skip_inode_update(inode, datasync)) {
		f2fs_write_inode(inode, NULL);
		goto go_write;
	}

	/*
	 * if there is no written data, don't waste time to write recovery info.
	 */
	if (!is_inode_flag_set(inode, FI_APPEND_WRITE) &&
			!f2fs_exist_written_data(sbi, ino, APPEND_INO)) {

		/* it may call write_inode just prior to fsync */
		if (need_inode_page_update(sbi, ino))
			goto go_write;

		if (is_inode_flag_set(inode, FI_UPDATE_WRITE) ||
				f2fs_exist_written_data(sbi, ino, UPDATE_INO))
			goto flush_out;
		goto out;
	}
go_write:
	/*
	 * Both of fdatasync() and fsync() are able to be recovered from
	 * sudden-power-off.
	 */
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
	f2fs_down_read(&F2FS_I(inode)->i_compress_sem);
#endif
	f2fs_down_read(&F2FS_I(inode)->i_sem);
	cp_reason = need_do_checkpoint(inode);
	f2fs_up_read(&F2FS_I(inode)->i_sem);
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
	f2fs_up_read(&F2FS_I(inode)->i_compress_sem);
#endif

	if (cp_reason) {
		/* all the dirty node pages should be flushed for POR */
#ifdef CONFIG_F2FS_BIGDATA
		cp_begin = local_clock();
		ret = f2fs_sync_fs(inode->i_sb, 1);
		cp_end = local_clock();
#else
		ret = f2fs_sync_fs(inode->i_sb, 1);
#endif

		/*
		 * We've secured consistency through sync_fs. Following pino
		 * will be used only for fsynced inodes after checkpoint.
		 */
		try_to_fix_pino(inode);
		clear_inode_flag(inode, FI_APPEND_WRITE);
		clear_inode_flag(inode, FI_UPDATE_WRITE);
		goto out;
	}
sync_nodes:
#ifdef CONFIG_F2FS_BIGDATA
	sync_node_begin = local_clock();
#endif
	atomic_inc(&sbi->wb_sync_req[NODE]);
	ret = f2fs_fsync_node_pages(sbi, inode, &wbc, atomic, &seq_id);
	atomic_dec(&sbi->wb_sync_req[NODE]);
	if (ret)
		goto out;

	/* if cp_error was enabled, we should avoid infinite loop */
	if (unlikely(f2fs_cp_error(sbi))) {
		ret = -EIO;
		goto out;
	}

	if (f2fs_need_inode_block_update(sbi, ino)) {
		f2fs_mark_inode_dirty_sync(inode, true);
		f2fs_write_inode(inode, NULL);
		goto sync_nodes;
	}

	/*
	 * If it's atomic_write, it's just fine to keep write ordering. So
	 * here we don't need to wait for node write completion, since we use
	 * node chain which serializes node blocks. If one of node writes are
	 * reordered, we can see simply broken chain, resulting in stopping
	 * roll-forward recovery. It means we'll recover all or none node blocks
	 * given fsync mark.
	 */
	if (!atomic) {
		ret = f2fs_wait_on_node_pages_writeback(sbi, seq_id);
		if (ret)
			goto out;
	}

	/* once recovery info is written, don't need to tack this */
	f2fs_remove_ino_entry(sbi, ino, APPEND_INO);
	clear_inode_flag(inode, FI_APPEND_WRITE);
#ifdef CONFIG_F2FS_BIGDATA
	sync_node_end = local_clock();
#endif
flush_out:
	if (!atomic && F2FS_OPTION(sbi).fsync_mode != FSYNC_MODE_NOBARRIER) {
#ifdef CONFIG_F2FS_BIGDATA
		flush_begin = local_clock();
		ret = f2fs_issue_flush(sbi, inode->i_ino);
		flush_end = local_clock();
#else
		ret = f2fs_issue_flush(sbi, inode->i_ino);
#endif
	}
	if (!ret) {
		f2fs_remove_ino_entry(sbi, ino, UPDATE_INO);
		clear_inode_flag(inode, FI_UPDATE_WRITE);
		f2fs_remove_ino_entry(sbi, ino, FLUSH_INO);
	}
	f2fs_update_time(sbi, REQ_TIME);
out:
	trace_f2fs_sync_file_exit(inode, cp_reason, datasync, ret);

#ifdef CONFIG_F2FS_BIGDATA
	if (fsync_begin && !ret) {
		fsync_end = local_clock();
		bd_mutex_lock(&sbi->bd_mutex);
		if (S_ISREG(inode->i_mode))
			inc_bd_val(sbi, fsync_reg_file_cnt, 1);
		else if (S_ISDIR(inode->i_mode))
			inc_bd_val(sbi, fsync_dir_cnt, 1);
		inc_bd_val(sbi, fsync_time, fsync_end - fsync_begin);
		max_bd_val(sbi, max_fsync_time, fsync_end - fsync_begin);
		inc_bd_val(sbi, fsync_wr_file_time, wr_file_end - fsync_begin);
		max_bd_val(sbi, max_fsync_wr_file_time, wr_file_end -
			fsync_begin);
		inc_bd_val(sbi, fsync_cp_time, cp_end - cp_begin);
		max_bd_val(sbi, max_fsync_cp_time, cp_end - cp_begin);
		if (sync_node_end) {
			inc_bd_val(sbi, fsync_sync_node_time,
				   sync_node_end - sync_node_begin);
			max_bd_val(sbi, max_fsync_sync_node_time,
				   sync_node_end - sync_node_begin);
		}
		inc_bd_val(sbi, fsync_flush_time, flush_end - flush_begin);
		max_bd_val(sbi, max_fsync_flush_time, flush_end - flush_begin);
		bd_mutex_unlock(&sbi->bd_mutex);
	}
#endif
	return ret;
}

int f2fs_sync_file(struct file *file, loff_t start, loff_t end, int datasync)
{
	if (unlikely(f2fs_cp_error(F2FS_I_SB(file_inode(file)))))
		return -EIO;
	return f2fs_do_sync_file(file, start, end, datasync, false);
}

static bool __found_offset(struct address_space *mapping, block_t blkaddr,
				pgoff_t index, int whence)
{
	switch (whence) {
	case SEEK_DATA:
		if (__is_valid_data_blkaddr(blkaddr))
			return true;
		if (blkaddr == NEW_ADDR &&
		    xa_get_mark(&mapping->i_pages, index, PAGECACHE_TAG_DIRTY))
			return true;
		break;
	case SEEK_HOLE:
		if (blkaddr == NULL_ADDR)
			return true;
		break;
	}
	return false;
}

static loff_t f2fs_seek_block(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file->f_mapping->host;
	loff_t maxbytes = inode->i_sb->s_maxbytes;
	struct dnode_of_data dn;
	pgoff_t pgofs, end_offset;
	loff_t data_ofs = offset;
	loff_t isize;
	int err = 0;
#ifdef CONFIG_F2FS_FS_SIS_DISK
	struct inode *hidden = NULL, *dummy = NULL;
#endif

	inode_lock(inode);

	isize = i_size_read(inode);
	if (offset >= isize)
		goto fail;

	/* handle inline data case */
	if (f2fs_has_inline_data(inode)) {
		if (whence == SEEK_HOLE) {
			data_ofs = isize;
			goto found;
		} else if (whence == SEEK_DATA) {
			data_ofs = offset;
			goto found;
		}
	}

	pgofs = (pgoff_t)(offset >> PAGE_SHIFT);

#ifdef CONFIG_F2FS_FS_SIS_DISK
	hidden = get_hidden_inode(inode);
	if (hidden) {
		dummy = inode;
		inode = hidden;
	}
#endif
	for (; data_ofs < isize; data_ofs = (loff_t)pgofs << PAGE_SHIFT) {
		set_new_dnode(&dn, inode, NULL, NULL, 0);
		err = f2fs_get_dnode_of_data(&dn, pgofs, LOOKUP_NODE);
		if (err && err != -ENOENT) {
			goto fail;
		} else if (err == -ENOENT) {
			/* direct node does not exists */
			if (whence == SEEK_DATA) {
				pgofs = f2fs_get_next_page_offset(&dn, pgofs);
				continue;
			} else {
				goto found;
			}
		}

		end_offset = ADDRS_PER_PAGE(dn.node_page, inode);

		/* find data/hole in dnode block */
		for (; dn.ofs_in_node < end_offset;
				dn.ofs_in_node++, pgofs++,
				data_ofs = (loff_t)pgofs << PAGE_SHIFT) {
			block_t blkaddr;

			blkaddr = f2fs_data_blkaddr(&dn);

			if (__is_valid_data_blkaddr(blkaddr) &&
				!f2fs_is_valid_blkaddr(F2FS_I_SB(inode),
					blkaddr, DATA_GENERIC_ENHANCE)) {
				f2fs_put_dnode(&dn);
				goto fail;
			}

			if (__found_offset(file->f_mapping, blkaddr,
							pgofs, whence)) {
				f2fs_put_dnode(&dn);
				goto found;
			}
		}
		f2fs_put_dnode(&dn);
	}

	if (whence == SEEK_DATA)
		goto fail;
found:
	if (whence == SEEK_HOLE && data_ofs > isize)
		data_ofs = isize;
#ifdef CONFIG_F2FS_FS_SIS_DISK
	if (hidden) {
		inode = dummy;
		put_hidden_inode(hidden);
	}
#endif
	inode_unlock(inode);
	return vfs_setpos(file, data_ofs, maxbytes);
fail:
#ifdef CONFIG_F2FS_FS_SIS_DISK
	if (hidden) {
		inode = dummy;
		put_hidden_inode(hidden);
	}
#endif
	inode_unlock(inode);
	return -ENXIO;
}

static loff_t f2fs_llseek(struct file *file, loff_t offset, int whence)
{
	struct inode *inode = file->f_mapping->host;
	loff_t maxbytes = inode->i_sb->s_maxbytes;

	if (f2fs_compressed_file(inode))
		maxbytes = max_file_blocks(inode) << F2FS_BLKSIZE_BITS;

	switch (whence) {
	case SEEK_SET:
	case SEEK_CUR:
	case SEEK_END:
		return generic_file_llseek_size(file, offset, whence,
						maxbytes, i_size_read(inode));
	case SEEK_DATA:
	case SEEK_HOLE:
		if (offset < 0)
			return -ENXIO;
		return f2fs_seek_block(file, offset, whence);
	}

	return -EINVAL;
}

static int f2fs_file_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct inode *inode = file_inode(file);

	if (unlikely(f2fs_cp_error(F2FS_I_SB(inode))))
		return -EIO;

	if (!f2fs_is_compress_backend_ready(inode))
		return -EOPNOTSUPP;

	file_accessed(file);
	vma->vm_ops = &f2fs_file_vm_ops;
	set_inode_flag(inode, FI_MMAP_FILE);
	return 0;
}

static int f2fs_file_open(struct inode *inode, struct file *filp)
{
#ifdef CONFIG_F2FS_FS_SIS_DISK
	struct inode *hidden = NULL;
#endif
	int err = fscrypt_file_open(inode, filp);

	if (err)
		return err;

	if (!f2fs_is_compress_backend_ready(inode))
		return -EOPNOTSUPP;

	err = fsverity_file_open(inode, filp);
	if (err)
		return err;

	filp->f_mode |= FMODE_NOWAIT;

#ifdef CONFIG_F2FS_FS_SIS_DISK
	err = dquot_file_open(inode, filp);
	if (err)
		return err;

	if (f2fs_is_dummy_inode(inode)) {
		hidden = get_hidden_inode(inode);
		if (hidden)
			err = f2fs_file_open(hidden, filp);
		put_hidden_inode(hidden);
	}
	return err;
#else
	return dquot_file_open(inode, filp);
#endif
}

void f2fs_truncate_data_blocks_range(struct dnode_of_data *dn, int count)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(dn->inode);
	struct f2fs_node *raw_node;
	int nr_free = 0, ofs = dn->ofs_in_node, len = count;
	__le32 *addr;
	int base = 0;
	bool compressed_cluster = false;
	int cluster_index = 0, valid_blocks = 0;
	int cluster_size = F2FS_I(dn->inode)->i_cluster_size;
	bool released = !atomic_read(&F2FS_I(dn->inode)->i_compr_blocks);
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
	int offset = 0;
	pgoff_t dn_start_blkaddr = 0;
#endif

	if (IS_INODE(dn->node_page) && f2fs_has_extra_attr(dn->inode))
		base = get_extra_isize(dn->inode);

	raw_node = F2FS_NODE(dn->node_page);
	addr = blkaddr_in_node(raw_node) + base + ofs;

#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
	if (f2fs_compressed_file(dn->inode) && cluster_size) {
		dn_start_blkaddr = f2fs_start_bidx_of_node(ofs_of_node(dn->node_page), dn->inode) + ofs;
		offset = dn_start_blkaddr % cluster_size;
	}

	if (unlikely(f2fs_compressed_file(dn->inode) &&
			dn_start_blkaddr < ADDRS_PER_INODE(dn->inode) && offset &&
			(offset <= ofs) && (*(addr - offset) == COMPRESS_ADDR)))
		f2fs_compress_err("wrong offset, ino %lu, saddr %lu, ofs %d,"
			" cls_size %d, cls_ofs %d",dn->inode->i_ino,
			dn_start_blkaddr, ofs, cluster_size, offset);
#endif

	/* Assumption: truncateion starts with cluster */
	for (; count > 0; count--, addr++, dn->ofs_in_node++, cluster_index++) {
		block_t blkaddr = le32_to_cpu(*addr);

		if (f2fs_compressed_file(dn->inode) &&
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
					!((cluster_index + offset) & (cluster_size - 1))) {
#else
					!(cluster_index & (cluster_size - 1))) {
#endif
			if (compressed_cluster)
				f2fs_i_compr_blocks_update(dn->inode,
							valid_blocks, false);
			compressed_cluster = (blkaddr == COMPRESS_ADDR);
			valid_blocks = 0;
		}

		if (blkaddr == NULL_ADDR)
			continue;

		dn->data_blkaddr = NULL_ADDR;
		f2fs_set_data_blkaddr(dn);

#ifdef CONFIG_F2FS_FS_SIS_DISK
		if (blkaddr == SIS_ADDR)
			continue;
#endif
		if (__is_valid_data_blkaddr(blkaddr)) {
			if (!f2fs_is_valid_blkaddr(sbi, blkaddr,
					DATA_GENERIC_ENHANCE))
				continue;
			if (compressed_cluster)
				valid_blocks++;
		}

		if (dn->ofs_in_node == 0 && IS_INODE(dn->node_page))
			clear_inode_flag(dn->inode, FI_FIRST_BLOCK_WRITTEN);

		f2fs_invalidate_blocks(sbi, blkaddr);

		if (!released || blkaddr != COMPRESS_ADDR)
			nr_free++;
	}

	if (compressed_cluster)
		f2fs_i_compr_blocks_update(dn->inode, valid_blocks, false);

	if (nr_free) {
		pgoff_t fofs;
		/*
		 * once we invalidate valid blkaddr in range [ofs, ofs + count],
		 * we will invalidate all blkaddr in the whole range.
		 */
		fofs = f2fs_start_bidx_of_node(ofs_of_node(dn->node_page),
							dn->inode) + ofs;
		f2fs_update_read_extent_cache_range(dn, fofs, 0, len);
		f2fs_update_age_extent_cache_range(dn, fofs, nr_free);
		dec_valid_block_count(sbi, dn->inode, nr_free);
	}
	dn->ofs_in_node = ofs;

	f2fs_update_time(sbi, REQ_TIME);
	trace_f2fs_truncate_data_blocks_range(dn->inode, dn->nid,
					 dn->ofs_in_node, nr_free);
}

void f2fs_truncate_data_blocks(struct dnode_of_data *dn)
{
	f2fs_truncate_data_blocks_range(dn, ADDRS_PER_BLOCK(dn->inode));
}

static int truncate_partial_data_page(struct inode *inode, u64 from,
								bool cache_only)
{
	loff_t offset = from & (PAGE_SIZE - 1);
	pgoff_t index = from >> PAGE_SHIFT;
	struct address_space *mapping = inode->i_mapping;
	struct page *page;

	if (!offset && !cache_only)
		return 0;

	if (cache_only) {
		page = find_lock_page(mapping, index);
		if (page && PageUptodate(page))
			goto truncate_out;
		f2fs_put_page(page, 1);
		return 0;
	}

	page = f2fs_get_lock_data_page(inode, index, true);
	if (IS_ERR(page))
		return PTR_ERR(page) == -ENOENT ? 0 : PTR_ERR(page);
truncate_out:
	f2fs_wait_on_page_writeback(page, DATA, true, true);
	zero_user(page, offset, PAGE_SIZE - offset);

	/* An encrypted inode should have a key and truncate the last page. */
	f2fs_bug_on(F2FS_I_SB(inode), cache_only && IS_ENCRYPTED(inode));
	if (!cache_only)
		set_page_dirty(page);
	f2fs_put_page(page, 1);
	return 0;
}

int f2fs_do_truncate_blocks(struct inode *inode, u64 from, bool lock)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct dnode_of_data dn;
	pgoff_t free_from;
	int count = 0, err = 0;
	struct page *ipage;
	bool truncate_page = false;

	trace_f2fs_truncate_blocks_enter(inode, from);

	free_from = (pgoff_t)F2FS_BLK_ALIGN(from);

	if (free_from >= max_file_blocks(inode))
		goto free_partial;

	if (lock)
		f2fs_lock_op(sbi);

	ipage = f2fs_get_node_page(sbi, inode->i_ino);
	if (IS_ERR(ipage)) {
		err = PTR_ERR(ipage);
		goto out;
	}

	if (f2fs_has_inline_data(inode)) {
		f2fs_truncate_inline_inode(inode, ipage, from);
		f2fs_put_page(ipage, 1);
		truncate_page = true;
		goto out;
	}

	set_new_dnode(&dn, inode, ipage, NULL, 0);
	err = f2fs_get_dnode_of_data(&dn, free_from, LOOKUP_NODE_RA);
	if (err) {
		if (err == -ENOENT)
			goto free_next;
		goto out;
	}

	count = ADDRS_PER_PAGE(dn.node_page, inode);

	count -= dn.ofs_in_node;
	f2fs_bug_on(sbi, count < 0);

	if (dn.ofs_in_node || IS_INODE(dn.node_page)) {
		f2fs_truncate_data_blocks_range(&dn, count);
		free_from += count;
	}

	f2fs_put_dnode(&dn);
free_next:
	err = f2fs_truncate_inode_blocks(inode, free_from);
out:
	if (lock)
		f2fs_unlock_op(sbi);
free_partial:
	/* lastly zero out the first data page */
	if (!err)
		err = truncate_partial_data_page(inode, from, truncate_page);

	trace_f2fs_truncate_blocks_exit(inode, err);
	return err;
}

int f2fs_truncate_blocks(struct inode *inode, u64 from, bool lock)
{
	u64 free_from = from;
	int err;

#ifdef CONFIG_F2FS_FS_COMPRESSION
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
	f2fs_down_read(&F2FS_I(inode)->i_compress_sem);
#endif
	/*
	 * for compressed file, only support cluster size
	 * aligned truncation.
	 */
	if (f2fs_compressed_file(inode))
		free_from = round_up(from,
				F2FS_I(inode)->i_cluster_size << PAGE_SHIFT);
#endif

	err = f2fs_do_truncate_blocks(inode, free_from, lock);
	if (err) {
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
		f2fs_up_read(&F2FS_I(inode)->i_compress_sem);
#endif
		return err;
	}

#ifdef CONFIG_F2FS_FS_COMPRESSION
	if (from != free_from) {
		err = f2fs_truncate_partial_cluster(inode, from, lock);
		if (err) {
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
			f2fs_up_read(&F2FS_I(inode)->i_compress_sem);
#endif
			return err;
		}
	}
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
	f2fs_up_read(&F2FS_I(inode)->i_compress_sem);
#endif
#endif

	return 0;
}

int f2fs_truncate(struct inode *inode)
{
	int err;

	if (unlikely(f2fs_cp_error(F2FS_I_SB(inode))))
		return -EIO;

	if (!(S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode) ||
				S_ISLNK(inode->i_mode)))
		return 0;

	trace_f2fs_truncate(inode);

	if (time_to_inject(F2FS_I_SB(inode), FAULT_TRUNCATE)) {
		f2fs_show_injection_info(F2FS_I_SB(inode), FAULT_TRUNCATE);
		return -EIO;
	}

	err = dquot_initialize(inode);
	if (err)
		return err;

	/* we should check inline_data size */
	if (!f2fs_may_inline_data(inode)) {
		err = f2fs_convert_inline_inode(inode);
		if (err)
			return err;
	}

	err = f2fs_truncate_blocks(inode, i_size_read(inode), true);
	if (err)
		return err;

	inode->i_mtime = inode->i_ctime = current_time(inode);
	f2fs_mark_inode_dirty_sync(inode, false);
	return 0;
}

int f2fs_getattr(const struct path *path, struct kstat *stat,
		 u32 request_mask, unsigned int query_flags)
{
	struct inode *inode = d_inode(path->dentry);
	struct f2fs_inode_info *fi = F2FS_I(inode);
	struct f2fs_inode *ri;
	unsigned int flags;
#ifdef CONFIG_F2FS_FS_SIS_DISK
	struct inode *hidden = NULL;
#endif

	if (f2fs_has_extra_attr(inode) &&
			f2fs_sb_has_inode_crtime(F2FS_I_SB(inode)) &&
			F2FS_FITS_IN_INODE(ri, fi->i_extra_isize, i_crtime)) {
		stat->result_mask |= STATX_BTIME;
		stat->btime.tv_sec = fi->i_crtime.tv_sec;
		stat->btime.tv_nsec = fi->i_crtime.tv_nsec;
	}

	flags = fi->i_flags;
	if (flags & F2FS_COMPR_FL)
		stat->attributes |= STATX_ATTR_COMPRESSED;
	if (flags & F2FS_APPEND_FL)
		stat->attributes |= STATX_ATTR_APPEND;
	if (IS_ENCRYPTED(inode))
		stat->attributes |= STATX_ATTR_ENCRYPTED;
	if (flags & F2FS_IMMUTABLE_FL)
		stat->attributes |= STATX_ATTR_IMMUTABLE;
	if (flags & F2FS_NODUMP_FL)
		stat->attributes |= STATX_ATTR_NODUMP;
	if (IS_VERITY(inode))
		stat->attributes |= STATX_ATTR_VERITY;

	stat->attributes_mask |= (STATX_ATTR_COMPRESSED |
				  STATX_ATTR_APPEND |
				  STATX_ATTR_ENCRYPTED |
				  STATX_ATTR_IMMUTABLE |
				  STATX_ATTR_NODUMP |
				  STATX_ATTR_VERITY);

	generic_fillattr(inode, stat);

#ifdef CONFIG_F2FS_FS_SIS_DISK
	hidden = get_hidden_inode(inode);
	if (hidden) {
		f2fs_down_read(&F2FS_I(hidden)->i_sem);
		stat->blocks = hidden->i_blocks / hidden->i_nlink;
		f2fs_up_read(&F2FS_I(hidden)->i_sem);
	}
	put_hidden_inode(hidden);
#endif

	/* we need to show initial sectors used for inline_data/dentries */
	if ((S_ISREG(inode->i_mode) && f2fs_has_inline_data(inode)) ||
					f2fs_has_inline_dentry(inode))
		stat->blocks += (stat->size + 511) >> 9;

	return 0;
}

#ifdef CONFIG_F2FS_FS_POSIX_ACL
static void __setattr_copy(struct inode *inode, const struct iattr *attr)
{
	unsigned int ia_valid = attr->ia_valid;

	if (ia_valid & ATTR_UID)
		inode->i_uid = attr->ia_uid;
	if (ia_valid & ATTR_GID)
		inode->i_gid = attr->ia_gid;
	if (ia_valid & ATTR_ATIME)
		inode->i_atime = attr->ia_atime;
	if (ia_valid & ATTR_MTIME)
		inode->i_mtime = attr->ia_mtime;
	if (ia_valid & ATTR_CTIME)
		inode->i_ctime = attr->ia_ctime;
	if (ia_valid & ATTR_MODE) {
		umode_t mode = attr->ia_mode;

		if (!in_group_p(inode->i_gid) &&
			!capable_wrt_inode_uidgid(inode, CAP_FSETID))
			mode &= ~S_ISGID;
		set_acl_inode(inode, mode);
	}
}
#else
#define __setattr_copy setattr_copy
#endif

int f2fs_setattr(struct dentry *dentry, struct iattr *attr)
{
	struct inode *inode = d_inode(dentry);
	int err;

	if (unlikely(f2fs_cp_error(F2FS_I_SB(inode))))
		return -EIO;

	if (unlikely(IS_IMMUTABLE(inode)))
		return -EPERM;

	if (unlikely(IS_APPEND(inode) &&
			(attr->ia_valid & (ATTR_MODE | ATTR_UID |
				  ATTR_GID | ATTR_TIMES_SET))))
		return -EPERM;

	if ((attr->ia_valid & ATTR_SIZE) &&
		!f2fs_is_compress_backend_ready(inode))
		return -EOPNOTSUPP;

	err = setattr_prepare(dentry, attr);
	if (err)
		return err;

	err = fscrypt_prepare_setattr(dentry, attr);
	if (err)
		return err;

	err = fsverity_prepare_setattr(dentry, attr);
	if (err)
		return err;

	if (is_quota_modification(inode, attr)) {
		err = dquot_initialize(inode);
		if (err)
			return err;
	}
	if ((attr->ia_valid & ATTR_UID &&
		!uid_eq(attr->ia_uid, inode->i_uid)) ||
		(attr->ia_valid & ATTR_GID &&
		!gid_eq(attr->ia_gid, inode->i_gid))) {
		f2fs_lock_op(F2FS_I_SB(inode));
		err = dquot_transfer(inode, attr);
		if (err) {
			set_sbi_flag(F2FS_I_SB(inode),
					SBI_QUOTA_NEED_REPAIR);
			f2fs_unlock_op(F2FS_I_SB(inode));
			return err;
		}
		/*
		 * update uid/gid under lock_op(), so that dquot and inode can
		 * be updated atomically.
		 */
		if (attr->ia_valid & ATTR_UID)
			inode->i_uid = attr->ia_uid;
		if (attr->ia_valid & ATTR_GID)
			inode->i_gid = attr->ia_gid;
		f2fs_mark_inode_dirty_sync(inode, true);
		f2fs_unlock_op(F2FS_I_SB(inode));
	}

	if (attr->ia_valid & ATTR_SIZE) {
		loff_t old_size = i_size_read(inode);

		if (attr->ia_size > MAX_INLINE_DATA(inode)) {
			/*
			 * should convert inline inode before i_size_write to
			 * keep smaller than inline_data size with inline flag.
			 */
			err = f2fs_convert_inline_inode(inode);
			if (err)
				return err;
		}

#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
		if (attr->ia_size <= old_size && f2fs_compressed_file(inode)) {
			err = f2fs_do_decompress_file(inode, DECOMP_SETATTR);
			if (err) {
				f2fs_compress_err("decompress file failed, ino %lu,"
					" ret %d", inode->i_ino, err);
				return err;
			}
		}
#endif

#ifdef CONFIG_F2FS_FS_SIS_DISK
		/*
		 * caller have hold inode lock
		 */
		if (attr->ia_size <= old_size && f2fs_is_dummy_inode(inode)) {
			remove_data_coincide_flag(inode);
			err = f2fs_recover_sis_inode(inode, __func__);
			if (err) {
				f2fs_err(F2FS_I_SB(inode), "[sis]: inode[%lu], recover err, "
					"err = %d", inode->i_ino, err);
				return err;
			}
		}
#endif

		f2fs_down_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);
		f2fs_down_write(&F2FS_I(inode)->i_mmap_sem);

		truncate_setsize(inode, attr->ia_size);

		if (attr->ia_size <= old_size)
			err = f2fs_truncate(inode);
		/*
		 * do not trim all blocks after i_size if target size is
		 * larger than i_size.
		 */
		f2fs_up_write(&F2FS_I(inode)->i_mmap_sem);
		f2fs_up_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);
		if (err)
			return err;

		spin_lock(&F2FS_I(inode)->i_size_lock);
		inode->i_mtime = inode->i_ctime = current_time(inode);
		F2FS_I(inode)->last_disk_size = i_size_read(inode);
		spin_unlock(&F2FS_I(inode)->i_size_lock);
	}

	__setattr_copy(inode, attr);

	if (attr->ia_valid & ATTR_MODE) {
		err = posix_acl_chmod(inode, f2fs_get_inode_mode(inode));

		if (is_inode_flag_set(inode, FI_ACL_MODE)) {
			if (!err)
				inode->i_mode = F2FS_I(inode)->i_acl_mode;
			clear_inode_flag(inode, FI_ACL_MODE);
		}
	}

	/* file size may changed here */
	f2fs_mark_inode_dirty_sync(inode, true);

	/* inode change will produce dirty node pages flushed by checkpoint */
	f2fs_balance_fs(F2FS_I_SB(inode), true);

	return err;
}

const struct inode_operations f2fs_file_inode_operations = {
	.getattr	= f2fs_getattr,
	.setattr	= f2fs_setattr,
	.get_acl	= f2fs_get_acl,
	.set_acl	= f2fs_set_acl,
	.listxattr	= f2fs_listxattr,
	.fiemap		= f2fs_fiemap,
};

static int fill_zero(struct inode *inode, pgoff_t index,
					loff_t start, loff_t len)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct page *page;

	if (!len)
		return 0;

	f2fs_balance_fs(sbi, true);

	f2fs_lock_op(sbi);
	page = f2fs_get_new_data_page(inode, NULL, index, false);
	f2fs_unlock_op(sbi);

	if (IS_ERR(page))
		return PTR_ERR(page);

	f2fs_wait_on_page_writeback(page, DATA, true, true);
	zero_user(page, start, len);
	set_page_dirty(page);
	f2fs_put_page(page, 1);
	return 0;
}

int f2fs_truncate_hole(struct inode *inode, pgoff_t pg_start, pgoff_t pg_end)
{
	int err;

	while (pg_start < pg_end) {
		struct dnode_of_data dn;
		pgoff_t end_offset, count;

		set_new_dnode(&dn, inode, NULL, NULL, 0);
		err = f2fs_get_dnode_of_data(&dn, pg_start, LOOKUP_NODE);
		if (err) {
			if (err == -ENOENT) {
				pg_start = f2fs_get_next_page_offset(&dn,
								pg_start);
				continue;
			}
			return err;
		}

		end_offset = ADDRS_PER_PAGE(dn.node_page, inode);
		count = min(end_offset - dn.ofs_in_node, pg_end - pg_start);

		f2fs_bug_on(F2FS_I_SB(inode), count == 0 || count > end_offset);

		f2fs_truncate_data_blocks_range(&dn, count);
		f2fs_put_dnode(&dn);

		pg_start += count;
	}
	return 0;
}

static int punch_hole(struct inode *inode, loff_t offset, loff_t len)
{
	pgoff_t pg_start, pg_end;
	loff_t off_start, off_end;
	int ret;

	ret = f2fs_convert_inline_inode(inode);
	if (ret)
		return ret;

	pg_start = ((unsigned long long) offset) >> PAGE_SHIFT;
	pg_end = ((unsigned long long) offset + len) >> PAGE_SHIFT;

	off_start = offset & (PAGE_SIZE - 1);
	off_end = (offset + len) & (PAGE_SIZE - 1);

	if (pg_start == pg_end) {
		ret = fill_zero(inode, pg_start, off_start,
						off_end - off_start);
		if (ret)
			return ret;
	} else {
		if (off_start) {
			ret = fill_zero(inode, pg_start++, off_start,
						PAGE_SIZE - off_start);
			if (ret)
				return ret;
		}
		if (off_end) {
			ret = fill_zero(inode, pg_end, 0, off_end);
			if (ret)
				return ret;
		}

		if (pg_start < pg_end) {
			loff_t blk_start, blk_end;
			struct f2fs_sb_info *sbi = F2FS_I_SB(inode);

			f2fs_balance_fs(sbi, true);

			blk_start = (loff_t)pg_start << PAGE_SHIFT;
			blk_end = (loff_t)pg_end << PAGE_SHIFT;

			f2fs_down_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);
			f2fs_down_write(&F2FS_I(inode)->i_mmap_sem);

			truncate_pagecache_range(inode, blk_start, blk_end - 1);

			f2fs_lock_op(sbi);
			ret = f2fs_truncate_hole(inode, pg_start, pg_end);
			f2fs_unlock_op(sbi);

			f2fs_up_write(&F2FS_I(inode)->i_mmap_sem);
			f2fs_up_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);
		}
	}

	return ret;
}

static int __read_out_blkaddrs(struct inode *inode, block_t *blkaddr,
				int *do_replace, pgoff_t off, pgoff_t len)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct dnode_of_data dn;
	int ret, done, i;

next_dnode:
	set_new_dnode(&dn, inode, NULL, NULL, 0);
	ret = f2fs_get_dnode_of_data(&dn, off, LOOKUP_NODE_RA);
	if (ret && ret != -ENOENT) {
		return ret;
	} else if (ret == -ENOENT) {
		if (dn.max_level == 0)
			return -ENOENT;
		done = min((pgoff_t)ADDRS_PER_BLOCK(inode) -
						dn.ofs_in_node, len);
		blkaddr += done;
		do_replace += done;
		goto next;
	}

	done = min((pgoff_t)ADDRS_PER_PAGE(dn.node_page, inode) -
							dn.ofs_in_node, len);
	for (i = 0; i < done; i++, blkaddr++, do_replace++, dn.ofs_in_node++) {
		*blkaddr = f2fs_data_blkaddr(&dn);

		if (__is_valid_data_blkaddr(*blkaddr) &&
			!f2fs_is_valid_blkaddr(sbi, *blkaddr,
					DATA_GENERIC_ENHANCE)) {
			f2fs_put_dnode(&dn);
			return -EFSCORRUPTED;
		}

		if (!f2fs_is_checkpointed_data(sbi, *blkaddr)) {

			if (f2fs_lfs_mode(sbi)) {
				f2fs_put_dnode(&dn);
				return -EOPNOTSUPP;
			}

			/* do not invalidate this block address */
			f2fs_update_data_blkaddr(&dn, NULL_ADDR);
			*do_replace = 1;
		}
	}
	f2fs_put_dnode(&dn);
next:
	len -= done;
	off += done;
	if (len)
		goto next_dnode;
	return 0;
}

static int __roll_back_blkaddrs(struct inode *inode, block_t *blkaddr,
				int *do_replace, pgoff_t off, int len)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct dnode_of_data dn;
	int ret, i;

	for (i = 0; i < len; i++, do_replace++, blkaddr++) {
		if (*do_replace == 0)
			continue;

		set_new_dnode(&dn, inode, NULL, NULL, 0);
		ret = f2fs_get_dnode_of_data(&dn, off + i, LOOKUP_NODE_RA);
		if (ret) {
			dec_valid_block_count(sbi, inode, 1);
			f2fs_invalidate_blocks(sbi, *blkaddr);
		} else {
			f2fs_update_data_blkaddr(&dn, *blkaddr);
		}
		f2fs_put_dnode(&dn);
	}
	return 0;
}

static int __clone_blkaddrs(struct inode *src_inode, struct inode *dst_inode,
			block_t *blkaddr, int *do_replace,
			pgoff_t src, pgoff_t dst, pgoff_t len, bool full)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(src_inode);
	pgoff_t i = 0;
	int ret;

	while (i < len) {
		if (blkaddr[i] == NULL_ADDR && !full) {
			i++;
			continue;
		}

		if (do_replace[i] || blkaddr[i] == NULL_ADDR) {
			struct dnode_of_data dn;
			struct node_info ni;
			size_t new_size;
			pgoff_t ilen;

			set_new_dnode(&dn, dst_inode, NULL, NULL, 0);
			ret = f2fs_get_dnode_of_data(&dn, dst + i, ALLOC_NODE);
			if (ret)
				return ret;

			ret = f2fs_get_node_info(sbi, dn.nid, &ni, false);
			if (ret) {
				f2fs_put_dnode(&dn);
				return ret;
			}

			ilen = min((pgoff_t)
				ADDRS_PER_PAGE(dn.node_page, dst_inode) -
						dn.ofs_in_node, len - i);
			do {
				dn.data_blkaddr = f2fs_data_blkaddr(&dn);
				f2fs_truncate_data_blocks_range(&dn, 1);

				if (do_replace[i]) {
					f2fs_i_blocks_write(src_inode,
							1, false, false);
					f2fs_i_blocks_write(dst_inode,
							1, true, false);
					f2fs_replace_block(sbi, &dn, dn.data_blkaddr,
					blkaddr[i], ni.version, true, false);

					do_replace[i] = 0;
				}
				dn.ofs_in_node++;
				i++;
				new_size = (loff_t)(dst + i) << PAGE_SHIFT;
				if (dst_inode->i_size < new_size)
					f2fs_i_size_write(dst_inode, new_size);
			} while (--ilen && (do_replace[i] || blkaddr[i] == NULL_ADDR));

			f2fs_put_dnode(&dn);
		} else {
			struct page *psrc, *pdst;

			psrc = f2fs_get_lock_data_page(src_inode,
							src + i, true);
			if (IS_ERR(psrc))
				return PTR_ERR(psrc);
			pdst = f2fs_get_new_data_page(dst_inode, NULL, dst + i,
								true);
			if (IS_ERR(pdst)) {
				f2fs_put_page(psrc, 1);
				return PTR_ERR(pdst);
			}
			f2fs_copy_page(psrc, pdst);
			set_page_dirty(pdst);
			f2fs_put_page(pdst, 1);
			f2fs_put_page(psrc, 1);

			ret = f2fs_truncate_hole(src_inode,
						src + i, src + i + 1);
			if (ret)
				return ret;
			i++;
		}
	}
	return 0;
}

static int __exchange_data_block(struct inode *src_inode,
			struct inode *dst_inode, pgoff_t src, pgoff_t dst,
			pgoff_t len, bool full)
{
	block_t *src_blkaddr;
	int *do_replace;
	pgoff_t olen;
	int ret;

	while (len) {
		olen = min((pgoff_t)4 * ADDRS_PER_BLOCK(src_inode), len);

		src_blkaddr = f2fs_kvzalloc(F2FS_I_SB(src_inode),
					array_size(olen, sizeof(block_t)),
					GFP_NOFS);
		if (!src_blkaddr)
			return -ENOMEM;

		do_replace = f2fs_kvzalloc(F2FS_I_SB(src_inode),
					array_size(olen, sizeof(int)),
					GFP_NOFS);
		if (!do_replace) {
			kvfree(src_blkaddr);
			return -ENOMEM;
		}

		ret = __read_out_blkaddrs(src_inode, src_blkaddr,
					do_replace, src, olen);
		if (ret)
			goto roll_back;

		ret = __clone_blkaddrs(src_inode, dst_inode, src_blkaddr,
					do_replace, src, dst, olen, full);
		if (ret)
			goto roll_back;

		src += olen;
		dst += olen;
		len -= olen;

		kvfree(src_blkaddr);
		kvfree(do_replace);
	}
	return 0;

roll_back:
	__roll_back_blkaddrs(src_inode, src_blkaddr, do_replace, src, olen);
	kvfree(src_blkaddr);
	kvfree(do_replace);
	return ret;
}

static int f2fs_do_collapse(struct inode *inode, loff_t offset, loff_t len)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	pgoff_t nrpages = DIV_ROUND_UP(i_size_read(inode), PAGE_SIZE);
	pgoff_t start = offset >> PAGE_SHIFT;
	pgoff_t end = (offset + len) >> PAGE_SHIFT;
	int ret;

	f2fs_balance_fs(sbi, true);

	/* avoid gc operation during block exchange */
	f2fs_down_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);
	f2fs_down_write(&F2FS_I(inode)->i_mmap_sem);

	f2fs_lock_op(sbi);
	f2fs_drop_extent_tree(inode);
	truncate_pagecache(inode, offset);
	ret = __exchange_data_block(inode, inode, end, start, nrpages - end, true);
	f2fs_unlock_op(sbi);

	f2fs_up_write(&F2FS_I(inode)->i_mmap_sem);
	f2fs_up_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);
	return ret;
}

static int f2fs_collapse_range(struct inode *inode, loff_t offset, loff_t len)
{
	loff_t new_size;
	int ret;

	if (offset + len >= i_size_read(inode))
		return -EINVAL;

	/* collapse range should be aligned to block size of f2fs. */
	if (offset & (F2FS_BLKSIZE - 1) || len & (F2FS_BLKSIZE - 1))
		return -EINVAL;

	ret = f2fs_convert_inline_inode(inode);
	if (ret)
		return ret;

	/* write out all dirty pages from offset */
	ret = filemap_write_and_wait_range(inode->i_mapping, offset, LLONG_MAX);
	if (ret)
		return ret;

	ret = f2fs_do_collapse(inode, offset, len);
	if (ret)
		return ret;

	/* write out all moved pages, if possible */
	f2fs_down_write(&F2FS_I(inode)->i_mmap_sem);
	filemap_write_and_wait_range(inode->i_mapping, offset, LLONG_MAX);
	truncate_pagecache(inode, offset);

	new_size = i_size_read(inode) - len;
	ret = f2fs_truncate_blocks(inode, new_size, true);
	f2fs_up_write(&F2FS_I(inode)->i_mmap_sem);
	if (!ret)
		f2fs_i_size_write(inode, new_size);
	return ret;
}

static int f2fs_do_zero_range(struct dnode_of_data *dn, pgoff_t start,
								pgoff_t end)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(dn->inode);
	pgoff_t index = start;
	unsigned int ofs_in_node = dn->ofs_in_node;
	blkcnt_t count = 0;
	int ret;

	for (; index < end; index++, dn->ofs_in_node++) {
		if (f2fs_data_blkaddr(dn) == NULL_ADDR)
			count++;
	}

	dn->ofs_in_node = ofs_in_node;
	ret = f2fs_reserve_new_blocks(dn, count);
	if (ret)
		return ret;

	dn->ofs_in_node = ofs_in_node;
	for (index = start; index < end; index++, dn->ofs_in_node++) {
		dn->data_blkaddr = f2fs_data_blkaddr(dn);
		/*
		 * f2fs_reserve_new_blocks will not guarantee entire block
		 * allocation.
		 */
		if (dn->data_blkaddr == NULL_ADDR) {
			ret = -ENOSPC;
			break;
		}

		if (dn->data_blkaddr == NEW_ADDR)
			continue;

		if (!f2fs_is_valid_blkaddr(sbi, dn->data_blkaddr,
					DATA_GENERIC_ENHANCE)) {
			ret = -EFSCORRUPTED;
			break;
		}

		f2fs_invalidate_blocks(sbi, dn->data_blkaddr);
		dn->data_blkaddr = NEW_ADDR;
		f2fs_set_data_blkaddr(dn);
	}

	f2fs_update_read_extent_cache_range(dn, start, 0, index - start);

	return ret;
}

static int f2fs_zero_range(struct inode *inode, loff_t offset, loff_t len,
								int mode)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct address_space *mapping = inode->i_mapping;
	pgoff_t index, pg_start, pg_end;
	loff_t new_size = i_size_read(inode);
	loff_t off_start, off_end;
	int ret = 0;

	ret = inode_newsize_ok(inode, (len + offset));
	if (ret)
		return ret;

	ret = f2fs_convert_inline_inode(inode);
	if (ret)
		return ret;

	ret = filemap_write_and_wait_range(mapping, offset, offset + len - 1);
	if (ret)
		return ret;

	pg_start = ((unsigned long long) offset) >> PAGE_SHIFT;
	pg_end = ((unsigned long long) offset + len) >> PAGE_SHIFT;

	off_start = offset & (PAGE_SIZE - 1);
	off_end = (offset + len) & (PAGE_SIZE - 1);

	if (pg_start == pg_end) {
		ret = fill_zero(inode, pg_start, off_start,
						off_end - off_start);
		if (ret)
			return ret;

		new_size = max_t(loff_t, new_size, offset + len);
	} else {
		if (off_start) {
			ret = fill_zero(inode, pg_start++, off_start,
						PAGE_SIZE - off_start);
			if (ret)
				return ret;

			new_size = max_t(loff_t, new_size,
					(loff_t)pg_start << PAGE_SHIFT);
		}

		for (index = pg_start; index < pg_end;) {
			struct dnode_of_data dn;
			unsigned int end_offset;
			pgoff_t end;

			f2fs_down_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);
			f2fs_down_write(&F2FS_I(inode)->i_mmap_sem);

			truncate_pagecache_range(inode,
				(loff_t)index << PAGE_SHIFT,
				((loff_t)pg_end << PAGE_SHIFT) - 1);

			f2fs_lock_op(sbi);

			set_new_dnode(&dn, inode, NULL, NULL, 0);
			ret = f2fs_get_dnode_of_data(&dn, index, ALLOC_NODE);
			if (ret) {
				f2fs_unlock_op(sbi);
				f2fs_up_write(&F2FS_I(inode)->i_mmap_sem);
				f2fs_up_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);
				goto out;
			}

			end_offset = ADDRS_PER_PAGE(dn.node_page, inode);
			end = min(pg_end, end_offset - dn.ofs_in_node + index);

			ret = f2fs_do_zero_range(&dn, index, end);
			f2fs_put_dnode(&dn);

			f2fs_unlock_op(sbi);
			f2fs_up_write(&F2FS_I(inode)->i_mmap_sem);
			f2fs_up_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);

			f2fs_balance_fs(sbi, dn.node_changed);

			if (ret)
				goto out;

			index = end;
			new_size = max_t(loff_t, new_size,
					(loff_t)index << PAGE_SHIFT);
		}

		if (off_end) {
			ret = fill_zero(inode, pg_end, 0, off_end);
			if (ret)
				goto out;

			new_size = max_t(loff_t, new_size, offset + len);
		}
	}

out:
	if (new_size > i_size_read(inode)) {
		if (mode & FALLOC_FL_KEEP_SIZE)
			file_set_keep_isize(inode);
		else
			f2fs_i_size_write(inode, new_size);
	}
	return ret;
}

static int f2fs_insert_range(struct inode *inode, loff_t offset, loff_t len)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	pgoff_t nr, pg_start, pg_end, delta, idx;
	loff_t new_size;
	int ret = 0;

	new_size = i_size_read(inode) + len;
	ret = inode_newsize_ok(inode, new_size);
	if (ret)
		return ret;

	if (offset >= i_size_read(inode))
		return -EINVAL;

	/* insert range should be aligned to block size of f2fs. */
	if (offset & (F2FS_BLKSIZE - 1) || len & (F2FS_BLKSIZE - 1))
		return -EINVAL;

	ret = f2fs_convert_inline_inode(inode);
	if (ret)
		return ret;

	f2fs_balance_fs(sbi, true);

	f2fs_down_write(&F2FS_I(inode)->i_mmap_sem);
	ret = f2fs_truncate_blocks(inode, i_size_read(inode), true);
	f2fs_up_write(&F2FS_I(inode)->i_mmap_sem);
	if (ret)
		return ret;

	/* write out all dirty pages from offset */
	ret = filemap_write_and_wait_range(inode->i_mapping, offset, LLONG_MAX);
	if (ret)
		return ret;

	pg_start = offset >> PAGE_SHIFT;
	pg_end = (offset + len) >> PAGE_SHIFT;
	delta = pg_end - pg_start;
	idx = DIV_ROUND_UP(i_size_read(inode), PAGE_SIZE);

	/* avoid gc operation during block exchange */
	f2fs_down_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);
	f2fs_down_write(&F2FS_I(inode)->i_mmap_sem);
	truncate_pagecache(inode, offset);

	while (!ret && idx > pg_start) {
		nr = idx - pg_start;
		if (nr > delta)
			nr = delta;
		idx -= nr;

		f2fs_lock_op(sbi);
		f2fs_drop_extent_tree(inode);

		ret = __exchange_data_block(inode, inode, idx,
					idx + delta, nr, false);
		f2fs_unlock_op(sbi);
	}
	f2fs_up_write(&F2FS_I(inode)->i_mmap_sem);
	f2fs_up_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);

	/* write out all moved pages, if possible */
	f2fs_down_write(&F2FS_I(inode)->i_mmap_sem);
	filemap_write_and_wait_range(inode->i_mapping, offset, LLONG_MAX);
	truncate_pagecache(inode, offset);
	f2fs_up_write(&F2FS_I(inode)->i_mmap_sem);

	if (!ret)
		f2fs_i_size_write(inode, new_size);
	return ret;
}

static int expand_inode_data(struct inode *inode, loff_t offset,
					loff_t len, int mode)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct f2fs_map_blocks map = { .m_next_pgofs = NULL,
			.m_next_extent = NULL, .m_seg_type = NO_CHECK_TYPE,
			.m_may_create = true };
	pgoff_t pg_start, pg_end;
	loff_t new_size = i_size_read(inode);
	loff_t off_end;
	block_t expanded = 0;
	int err;

	err = inode_newsize_ok(inode, (len + offset));
	if (err)
		return err;

	err = f2fs_convert_inline_inode(inode);
	if (err)
		return err;

	f2fs_balance_fs(sbi, true);

	pg_start = ((unsigned long long)offset) >> PAGE_SHIFT;
	pg_end = ((unsigned long long)offset + len) >> PAGE_SHIFT;
	off_end = (offset + len) & (PAGE_SIZE - 1);

	map.m_lblk = pg_start;
	map.m_len = pg_end - pg_start;
	if (off_end)
		map.m_len++;

	if (!map.m_len)
		return 0;

	if (f2fs_is_pinned_file(inode)) {
		block_t sec_blks = BLKS_PER_SEC(sbi);
		block_t sec_len = roundup(map.m_len, sec_blks);

		map.m_len = sec_blks;
next_alloc:
		if (has_not_enough_free_secs(sbi, 0,
			GET_SEC_FROM_SEG(sbi, overprovision_segments(sbi)))) {
			f2fs_down_write(&sbi->gc_lock);
			err = f2fs_gc(sbi, true, false, false, NULL_SEGNO);
			if (err && err != -ENODATA && err != -EAGAIN)
				goto out_err;
		}

		f2fs_down_write(&sbi->pin_sem);

		f2fs_lock_op(sbi);
		f2fs_allocate_new_section(sbi, CURSEG_COLD_DATA_PINNED, false);
		f2fs_unlock_op(sbi);

		map.m_seg_type = CURSEG_COLD_DATA_PINNED;
		err = f2fs_map_blocks(inode, &map, 1, F2FS_GET_BLOCK_PRE_DIO);

		f2fs_up_write(&sbi->pin_sem);

		expanded += map.m_len;
		sec_len -= map.m_len;
		map.m_lblk += map.m_len;
		if (!err && sec_len)
			goto next_alloc;

		map.m_len = expanded;
	} else {
		err = f2fs_map_blocks(inode, &map, 1, F2FS_GET_BLOCK_PRE_AIO);
		expanded = map.m_len;
	}
out_err:
	if (err) {
		pgoff_t last_off;

		if (!expanded)
			return err;

		last_off = pg_start + expanded - 1;

		/* update new size to the failed position */
		new_size = (last_off == pg_end) ? offset + len :
					(loff_t)(last_off + 1) << PAGE_SHIFT;
	} else {
		new_size = ((loff_t)pg_end << PAGE_SHIFT) + off_end;
	}

	if (new_size > i_size_read(inode)) {
		if (mode & FALLOC_FL_KEEP_SIZE)
			file_set_keep_isize(inode);
		else
			f2fs_i_size_write(inode, new_size);
	}

	return err;
}

static long f2fs_fallocate(struct file *file, int mode,
				loff_t offset, loff_t len)
{
	struct inode *inode = file_inode(file);
	long ret = 0;

	if (unlikely(f2fs_cp_error(F2FS_I_SB(inode))))
		return -EIO;
	if (!f2fs_is_checkpoint_ready(F2FS_I_SB(inode)))
		return -ENOSPC;
	if (!f2fs_is_compress_backend_ready(inode))
		return -EOPNOTSUPP;

	/* f2fs only support ->fallocate for regular file */
	if (!S_ISREG(inode->i_mode))
		return -EINVAL;

	if (IS_ENCRYPTED(inode) &&
		(mode & (FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_INSERT_RANGE)))
		return -EOPNOTSUPP;

#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
	file_start_write(file);
#endif
	inode_lock(inode);

#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
	if (f2fs_compressed_file(inode)) {
		ret = f2fs_do_decompress_file(inode, DECOMP_FALLOCATE);
		if(ret)
			goto out;
	}
#endif

    	/*
	 * Pinned file should not support partial trucation since the block
	 * can be used by applications.
	 */
	if ((f2fs_compressed_file(inode) || f2fs_is_pinned_file(inode)) &&
		(mode & (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_COLLAPSE_RANGE |
			FALLOC_FL_ZERO_RANGE | FALLOC_FL_INSERT_RANGE))) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	if (mode & ~(FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE |
			FALLOC_FL_COLLAPSE_RANGE | FALLOC_FL_ZERO_RANGE |
			FALLOC_FL_INSERT_RANGE)) {
		ret = -EOPNOTSUPP;
		goto out;
	}

#ifdef CONFIG_F2FS_FS_SIS_DISK
	remove_data_coincide_flag(inode);
	if (f2fs_is_dummy_inode(inode) &&
			f2fs_recover_sis_inode(inode, __func__)) {
		ret = -EIO;
		goto out;
	}
#endif

	ret = file_modified(file);
	if (ret)
		goto out;

	if (mode & FALLOC_FL_PUNCH_HOLE) {
		if (offset >= inode->i_size)
			goto out;

		ret = punch_hole(inode, offset, len);
	} else if (mode & FALLOC_FL_COLLAPSE_RANGE) {
		ret = f2fs_collapse_range(inode, offset, len);
	} else if (mode & FALLOC_FL_ZERO_RANGE) {
		ret = f2fs_zero_range(inode, offset, len, mode);
	} else if (mode & FALLOC_FL_INSERT_RANGE) {
		ret = f2fs_insert_range(inode, offset, len);
	} else {
		ret = expand_inode_data(inode, offset, len, mode);
	}

	if (!ret) {
		inode->i_mtime = inode->i_ctime = current_time(inode);
		f2fs_mark_inode_dirty_sync(inode, false);
		f2fs_update_time(F2FS_I_SB(inode), REQ_TIME);
	}

out:
	inode_unlock(inode);
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
	file_end_write(file);
#endif

	trace_f2fs_fallocate(inode, mode, offset, len, ret);
	return ret;
}

static int f2fs_release_file(struct inode *inode, struct file *filp)
{
	/*
	 * f2fs_relase_file is called at every close calls. So we should
	 * not drop any inmemory pages by close called by other process.
	 */
	if (!(filp->f_mode & FMODE_WRITE) ||
			atomic_read(&inode->i_writecount) != 1)
		return 0;

	/* some remained atomic pages should discarded */
	if (f2fs_is_atomic_file(inode))
		f2fs_drop_inmem_pages(inode);
	if (f2fs_is_volatile_file(inode)) {
		set_inode_flag(inode, FI_DROP_CACHE);
		filemap_fdatawrite(inode->i_mapping);
		clear_inode_flag(inode, FI_DROP_CACHE);
		clear_inode_flag(inode, FI_VOLATILE_FILE);
		stat_dec_volatile_write(inode);
	}
	return 0;
}

static int f2fs_file_flush(struct file *file, fl_owner_t id)
{
	struct inode *inode = file_inode(file);

	/*
	 * If the process doing a transaction is crashed, we should do
	 * roll-back. Otherwise, other reader/write can see corrupted database
	 * until all the writers close its file. Since this should be done
	 * before dropping file lock, it needs to do in ->flush.
	 */
	if (f2fs_is_atomic_file(inode) &&
			F2FS_I(inode)->inmem_task == current)
		f2fs_drop_inmem_pages(inode);
	return 0;
}

static int f2fs_setflags_common(struct inode *inode, u32 iflags, u32 mask)
{
	struct f2fs_inode_info *fi = F2FS_I(inode);
	u32 masked_flags = fi->i_flags & mask;

	/* mask can be shrunk by flags_valid selector */
	iflags &= mask;

	/* Is it quota file? Do not allow user to mess with it */
	if (IS_NOQUOTA(inode))
		return -EPERM;

	if ((iflags ^ masked_flags) & F2FS_CASEFOLD_FL) {
		if (!f2fs_sb_has_casefold(F2FS_I_SB(inode)))
			return -EOPNOTSUPP;
		if (!f2fs_empty_dir(inode))
			return -ENOTEMPTY;
	}

	if (iflags & (F2FS_COMPR_FL | F2FS_NOCOMP_FL)) {
		if (!f2fs_sb_has_compression(F2FS_I_SB(inode)))
			return -EOPNOTSUPP;
		if ((iflags & F2FS_COMPR_FL) && (iflags & F2FS_NOCOMP_FL))
			return -EINVAL;
	}

	if ((iflags ^ masked_flags) & F2FS_COMPR_FL) {
		if (masked_flags & F2FS_COMPR_FL) {
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
			if (filemap_write_and_wait_range(inode->i_mapping, 0, LLONG_MAX)) {
				f2fs_compress_err("wait write failed, ino %lu", inode->i_ino);
				return -EINVAL;
			}
#endif
			if (!f2fs_disable_compressed_file(inode))
				return -EINVAL;
		} else {
			if (!f2fs_may_compress(inode))
				return -EINVAL;

#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
			if (filemap_write_and_wait_range(inode->i_mapping, 0, LLONG_MAX)) {
				f2fs_compress_err("wait write failed, ino %lu", inode->i_ino);
				return -EINVAL;
			}
			if(f2fs_down_write_trylock(&fi->i_compress_sem)) {
				if (set_compress_context(inode)) {
					f2fs_up_write(&fi->i_compress_sem);
					return -EOPNOTSUPP;
				}
				f2fs_up_write(&fi->i_compress_sem);
			} else {
				return -EBUSY;
			}

			f2fs_lock_op(F2FS_I_SB(inode));
			f2fs_drop_extent_tree(inode);
			f2fs_unlock_op(F2FS_I_SB(inode));
#else
			if (S_ISREG(inode->i_mode) && inode->i_size)
				return -EINVAL;
			if (set_compress_context(inode))
				return -EOPNOTSUPP;
#endif
		}
	}

	fi->i_flags = iflags | (fi->i_flags & ~mask);
	f2fs_bug_on(F2FS_I_SB(inode), (fi->i_flags & F2FS_COMPR_FL) &&
					(fi->i_flags & F2FS_NOCOMP_FL));

	if (fi->i_flags & F2FS_PROJINHERIT_FL)
		set_inode_flag(inode, FI_PROJ_INHERIT);
	else
		clear_inode_flag(inode, FI_PROJ_INHERIT);

	inode->i_ctime = current_time(inode);
	f2fs_set_inode_flags(inode);
	f2fs_mark_inode_dirty_sync(inode, true);
	return 0;
}

/* FS_IOC_GETFLAGS and FS_IOC_SETFLAGS support */

/*
 * To make a new on-disk f2fs i_flag gettable via FS_IOC_GETFLAGS, add an entry
 * for it to f2fs_fsflags_map[], and add its FS_*_FL equivalent to
 * F2FS_GETTABLE_FS_FL.  To also make it settable via FS_IOC_SETFLAGS, also add
 * its FS_*_FL equivalent to F2FS_SETTABLE_FS_FL.
 */

static const struct {
	u32 iflag;
	u32 fsflag;
} f2fs_fsflags_map[] = {
	{ F2FS_COMPR_FL,	FS_COMPR_FL },
	{ F2FS_SYNC_FL,		FS_SYNC_FL },
	{ F2FS_IMMUTABLE_FL,	FS_IMMUTABLE_FL },
	{ F2FS_APPEND_FL,	FS_APPEND_FL },
	{ F2FS_NODUMP_FL,	FS_NODUMP_FL },
	{ F2FS_NOATIME_FL,	FS_NOATIME_FL },
	{ F2FS_NOCOMP_FL,	FS_NOCOMP_FL },
	{ F2FS_INDEX_FL,	FS_INDEX_FL },
	{ F2FS_DIRSYNC_FL,	FS_DIRSYNC_FL },
	{ F2FS_PROJINHERIT_FL,	FS_PROJINHERIT_FL },
	{ F2FS_CASEFOLD_FL,	FS_CASEFOLD_FL },
};

#define F2FS_GETTABLE_FS_FL (		\
		FS_COMPR_FL |		\
		FS_SYNC_FL |		\
		FS_IMMUTABLE_FL |	\
		FS_APPEND_FL |		\
		FS_NODUMP_FL |		\
		FS_NOATIME_FL |		\
		FS_NOCOMP_FL |		\
		FS_INDEX_FL |		\
		FS_DIRSYNC_FL |		\
		FS_PROJINHERIT_FL |	\
		FS_ENCRYPT_FL |		\
		FS_INLINE_DATA_FL |	\
		FS_NOCOW_FL |		\
		FS_VERITY_FL |		\
		FS_CASEFOLD_FL)

#define F2FS_SETTABLE_FS_FL (		\
		FS_COMPR_FL |		\
		FS_SYNC_FL |		\
		FS_IMMUTABLE_FL |	\
		FS_APPEND_FL |		\
		FS_NODUMP_FL |		\
		FS_NOATIME_FL |		\
		FS_NOCOMP_FL |		\
		FS_DIRSYNC_FL |		\
		FS_PROJINHERIT_FL |	\
		FS_CASEFOLD_FL)

/* Convert f2fs on-disk i_flags to FS_IOC_{GET,SET}FLAGS flags */
static inline u32 f2fs_iflags_to_fsflags(u32 iflags)
{
	u32 fsflags = 0;
	int i;

	for (i = 0; i < ARRAY_SIZE(f2fs_fsflags_map); i++)
		if (iflags & f2fs_fsflags_map[i].iflag)
			fsflags |= f2fs_fsflags_map[i].fsflag;

	return fsflags;
}

/* Convert FS_IOC_{GET,SET}FLAGS flags to f2fs on-disk i_flags */
static inline u32 f2fs_fsflags_to_iflags(u32 fsflags)
{
	u32 iflags = 0;
	int i;

	for (i = 0; i < ARRAY_SIZE(f2fs_fsflags_map); i++)
		if (fsflags & f2fs_fsflags_map[i].fsflag)
			iflags |= f2fs_fsflags_map[i].iflag;

	return iflags;
}

static int f2fs_ioc_getflags(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct f2fs_inode_info *fi = F2FS_I(inode);
	u32 fsflags = f2fs_iflags_to_fsflags(fi->i_flags);

	if (IS_ENCRYPTED(inode))
		fsflags |= FS_ENCRYPT_FL;
	if (IS_VERITY(inode))
		fsflags |= FS_VERITY_FL;
	if (f2fs_has_inline_data(inode) || f2fs_has_inline_dentry(inode))
		fsflags |= FS_INLINE_DATA_FL;
	if (is_inode_flag_set(inode, FI_PIN_FILE))
		fsflags |= FS_NOCOW_FL;

	fsflags &= F2FS_GETTABLE_FS_FL;

	return put_user(fsflags, (int __user *)arg);
}

static int f2fs_ioc_setflags(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct f2fs_inode_info *fi = F2FS_I(inode);
	u32 fsflags, old_fsflags;
	u32 iflags;
	int ret;

	if (!inode_owner_or_capable(inode))
		return -EACCES;

	if (get_user(fsflags, (int __user *)arg))
		return -EFAULT;

	if (fsflags & ~F2FS_GETTABLE_FS_FL)
		return -EOPNOTSUPP;
	fsflags &= F2FS_SETTABLE_FS_FL;

	iflags = f2fs_fsflags_to_iflags(fsflags);
	if (f2fs_mask_flags(inode->i_mode, iflags) != iflags)
		return -EOPNOTSUPP;

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	inode_lock(inode);

	old_fsflags = f2fs_iflags_to_fsflags(fi->i_flags);
	ret = vfs_ioc_setflags_prepare(inode, old_fsflags, fsflags);
	if (ret)
		goto out;

	ret = f2fs_setflags_common(inode, iflags,
			f2fs_fsflags_to_iflags(F2FS_SETTABLE_FS_FL));
out:
	inode_unlock(inode);
	mnt_drop_write_file(filp);
	return ret;
}

static int f2fs_ioc_getversion(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);

	return put_user(inode->i_generation, (int __user *)arg);
}

static int f2fs_ioc_start_atomic_write(struct file *filp)
{
	struct inode *inode = file_inode(filp);
	struct f2fs_inode_info *fi = F2FS_I(inode);
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	int ret;

	if (!inode_owner_or_capable(inode))
		return -EACCES;

	if (!S_ISREG(inode->i_mode))
		return -EINVAL;

	if (filp->f_flags & O_DIRECT)
		return -EINVAL;

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	inode_lock(inode);

#ifdef CONFIG_F2FS_FS_SIS_DISK
	remove_data_coincide_flag(inode);
	if (f2fs_is_dummy_inode(inode)) {
		ret = f2fs_recover_sis_inode(inode, __func__);
		if (ret) {
			f2fs_err(F2FS_I_SB(inode), "[sis]: inode[%lu], recover err, "
				"err = %d", inode->i_ino, ret);
			goto out;
		}
	}
#endif

#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
	if (f2fs_compressed_file(inode)) {
		ret = f2fs_do_decompress_file(inode, DECOMP_ATOMIC_WRITE);
		if (ret)
			goto out;
	}
#else
	if (!f2fs_disable_compressed_file(inode)) {
		ret = -EINVAL;
		goto out;
	}
#endif

	if (f2fs_is_atomic_file(inode)) {
		if (is_inode_flag_set(inode, FI_ATOMIC_REVOKE_REQUEST))
			ret = -EINVAL;
		goto out;
	}

	ret = f2fs_convert_inline_inode(inode);
	if (ret)
		goto out;

	f2fs_down_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);

	/*
	 * Should wait end_io to count F2FS_WB_CP_DATA correctly by
	 * f2fs_is_atomic_file.
	 */
	if (get_dirty_pages(inode))
		f2fs_warn(F2FS_I_SB(inode), "Unexpected flush for atomic writes: ino=%lu, npages=%u",
			  inode->i_ino, get_dirty_pages(inode));
	ret = filemap_write_and_wait_range(inode->i_mapping, 0, LLONG_MAX);
	if (ret) {
		f2fs_up_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);
		goto out;
	}

	spin_lock(&sbi->inode_lock[ATOMIC_FILE]);
	if (list_empty(&fi->inmem_ilist))
		list_add_tail(&fi->inmem_ilist, &sbi->inode_list[ATOMIC_FILE]);
	sbi->atomic_files++;
	spin_unlock(&sbi->inode_lock[ATOMIC_FILE]);

	/* add inode in inmem_list first and set atomic_file */
	set_inode_flag(inode, FI_ATOMIC_FILE);
	clear_inode_flag(inode, FI_ATOMIC_REVOKE_REQUEST);
	f2fs_up_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);

	f2fs_update_time(F2FS_I_SB(inode), REQ_TIME);
	F2FS_I(inode)->inmem_task = current;
	stat_update_max_atomic_write(inode);
out:
	inode_unlock(inode);
	mnt_drop_write_file(filp);
	return ret;
}

static int f2fs_ioc_commit_atomic_write(struct file *filp)
{
	struct inode *inode = file_inode(filp);
	int ret;

	if (!inode_owner_or_capable(inode))
		return -EACCES;

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	f2fs_balance_fs(F2FS_I_SB(inode), true);

	inode_lock(inode);

	if (f2fs_is_volatile_file(inode)) {
		ret = -EINVAL;
		goto err_out;
	}

	if (f2fs_is_atomic_file(inode)) {
		ret = f2fs_commit_inmem_pages(inode);
		if (ret)
			goto err_out;

		ret = f2fs_do_sync_file(filp, 0, LLONG_MAX, 0, true);
		if (!ret)
			f2fs_drop_inmem_pages(inode);
	} else {
		ret = f2fs_do_sync_file(filp, 0, LLONG_MAX, 1, false);
	}
err_out:
	if (is_inode_flag_set(inode, FI_ATOMIC_REVOKE_REQUEST)) {
		clear_inode_flag(inode, FI_ATOMIC_REVOKE_REQUEST);
		ret = -EINVAL;
	}
	inode_unlock(inode);
	mnt_drop_write_file(filp);
	return ret;
}

static int f2fs_ioc_start_volatile_write(struct file *filp)
{
	struct inode *inode = file_inode(filp);
	int ret;

	if (!inode_owner_or_capable(inode))
		return -EACCES;

	if (!S_ISREG(inode->i_mode))
		return -EINVAL;

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	inode_lock(inode);
#ifdef CONFIG_F2FS_FS_SIS_DISK
	remove_data_coincide_flag(inode);
	if (f2fs_is_dummy_inode(inode)) {
		ret = f2fs_recover_sis_inode(inode, __func__);
		if (ret) {
			f2fs_err(F2FS_I_SB(inode), "[sis]: inode[%lu], recover err, "
				"err = %d", inode->i_ino, ret);
			goto out;
		}
	}
#endif

#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
		if (f2fs_compressed_file(inode)) {
			ret = f2fs_do_decompress_file(inode, DECOMP_VOLATILE_WRITE);
			if (ret)
				goto out;
		}
#endif

	if (f2fs_is_volatile_file(inode))
		goto out;

	ret = f2fs_convert_inline_inode(inode);
	if (ret)
		goto out;

	stat_inc_volatile_write(inode);
	stat_update_max_volatile_write(inode);

	set_inode_flag(inode, FI_VOLATILE_FILE);
	f2fs_update_time(F2FS_I_SB(inode), REQ_TIME);
out:
	inode_unlock(inode);
	mnt_drop_write_file(filp);
	return ret;
}

static int f2fs_ioc_release_volatile_write(struct file *filp)
{
	struct inode *inode = file_inode(filp);
	int ret;

	if (!inode_owner_or_capable(inode))
		return -EACCES;

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	inode_lock(inode);

	if (!f2fs_is_volatile_file(inode))
		goto out;

	if (!f2fs_is_first_block_written(inode)) {
		ret = truncate_partial_data_page(inode, 0, true);
		goto out;
	}

	ret = punch_hole(inode, 0, F2FS_BLKSIZE);
out:
	inode_unlock(inode);
	mnt_drop_write_file(filp);
	return ret;
}

static int f2fs_ioc_abort_volatile_write(struct file *filp)
{
	struct inode *inode = file_inode(filp);
	int ret;

	if (!inode_owner_or_capable(inode))
		return -EACCES;

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	inode_lock(inode);

	if (f2fs_is_atomic_file(inode))
		f2fs_drop_inmem_pages(inode);
	if (f2fs_is_volatile_file(inode)) {
		clear_inode_flag(inode, FI_VOLATILE_FILE);
		stat_dec_volatile_write(inode);
		ret = f2fs_do_sync_file(filp, 0, LLONG_MAX, 0, true);
	}

	clear_inode_flag(inode, FI_ATOMIC_REVOKE_REQUEST);

	inode_unlock(inode);

	mnt_drop_write_file(filp);
	f2fs_update_time(F2FS_I_SB(inode), REQ_TIME);
	return ret;
}

static int f2fs_ioc_shutdown(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct super_block *sb = sbi->sb;
	__u32 in;
	int ret = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (get_user(in, (__u32 __user *)arg))
		return -EFAULT;

	if (in != F2FS_GOING_DOWN_FULLSYNC) {
		ret = mnt_want_write_file(filp);
		if (ret) {
			if (ret == -EROFS) {
				ret = 0;
				f2fs_stop_checkpoint(sbi, false,
						STOP_CP_REASON_SHUTDOWN);
				set_sbi_flag(sbi, SBI_IS_SHUTDOWN);
				trace_f2fs_shutdown(sbi, in, ret);
			}
			return ret;
		}
	}

	switch (in) {
	case F2FS_GOING_DOWN_FULLSYNC:
		ret = freeze_bdev(sb->s_bdev);
		if (ret)
			goto out;
		f2fs_stop_checkpoint(sbi, false, STOP_CP_REASON_SHUTDOWN);
		set_sbi_flag(sbi, SBI_IS_SHUTDOWN);
		thaw_bdev(sb->s_bdev);
		break;
	case F2FS_GOING_DOWN_METASYNC:
		/* do checkpoint only */
		ret = f2fs_sync_fs(sb, 1);
		if (ret)
			goto out;
		f2fs_stop_checkpoint(sbi, false, STOP_CP_REASON_SHUTDOWN);
		set_sbi_flag(sbi, SBI_IS_SHUTDOWN);
		break;
	case F2FS_GOING_DOWN_NOSYNC:
		f2fs_stop_checkpoint(sbi, false, STOP_CP_REASON_SHUTDOWN);
		set_sbi_flag(sbi, SBI_IS_SHUTDOWN);
		break;
	case F2FS_GOING_DOWN_METAFLUSH:
		f2fs_sync_meta_pages(sbi, META, LONG_MAX, FS_META_IO);
		f2fs_stop_checkpoint(sbi, false, STOP_CP_REASON_SHUTDOWN);
		set_sbi_flag(sbi, SBI_IS_SHUTDOWN);
		break;
	case F2FS_GOING_DOWN_NEED_FSCK:
		set_sbi_flag(sbi, SBI_NEED_FSCK);
		set_sbi_flag(sbi, SBI_CP_DISABLED_QUICK);
		set_sbi_flag(sbi, SBI_IS_DIRTY);
		/* do checkpoint only */
		ret = f2fs_sync_fs(sb, 1);
		goto out;
	default:
		ret = -EINVAL;
		goto out;
	}

	f2fs_stop_gc_thread(sbi);
	f2fs_stop_discard_thread(sbi);

	f2fs_drop_discard_cmd(sbi);
	clear_opt(sbi, DISCARD);

	f2fs_update_time(sbi, REQ_TIME);
out:
	if (in != F2FS_GOING_DOWN_FULLSYNC)
		mnt_drop_write_file(filp);

	trace_f2fs_shutdown(sbi, in, ret);

	return ret;
}

static int f2fs_ioc_fitrim(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct super_block *sb = inode->i_sb;
	struct request_queue *q = bdev_get_queue(sb->s_bdev);
	struct fstrim_range range;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (!f2fs_hw_support_discard(F2FS_SB(sb)))
		return -EOPNOTSUPP;

	if (copy_from_user(&range, (struct fstrim_range __user *)arg,
				sizeof(range)))
		return -EFAULT;

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	range.minlen = max((unsigned int)range.minlen,
				q->limits.discard_granularity);
	ret = f2fs_trim_fs(F2FS_SB(sb), &range);
	mnt_drop_write_file(filp);
	if (ret < 0)
		return ret;

	if (copy_to_user((struct fstrim_range __user *)arg, &range,
				sizeof(range)))
		return -EFAULT;
	f2fs_update_time(F2FS_I_SB(inode), REQ_TIME);
	return 0;
}

static bool uuid_is_nonzero(__u8 u[16])
{
	int i;

	for (i = 0; i < 16; i++)
		if (u[i])
			return true;
	return false;
}

static int f2fs_ioc_set_encryption_policy(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);

	if (!f2fs_sb_has_encrypt(F2FS_I_SB(inode)))
		return -EOPNOTSUPP;

	f2fs_update_time(F2FS_I_SB(inode), REQ_TIME);

	return fscrypt_ioctl_set_policy(filp, (const void __user *)arg);
}

static int f2fs_ioc_get_encryption_policy(struct file *filp, unsigned long arg)
{
	if (!f2fs_sb_has_encrypt(F2FS_I_SB(file_inode(filp))))
		return -EOPNOTSUPP;
	return fscrypt_ioctl_get_policy(filp, (void __user *)arg);
}

static int f2fs_ioc_get_encryption_pwsalt(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	int err;

	if (!f2fs_sb_has_encrypt(sbi))
		return -EOPNOTSUPP;

	err = mnt_want_write_file(filp);
	if (err)
		return err;

	f2fs_down_write(&sbi->sb_lock);

	if (uuid_is_nonzero(sbi->raw_super->encrypt_pw_salt))
		goto got_it;

	/* update superblock with uuid */
	generate_random_uuid(sbi->raw_super->encrypt_pw_salt);

	err = f2fs_commit_super(sbi, false);
	if (err) {
		/* undo new data */
		memset(sbi->raw_super->encrypt_pw_salt, 0, 16);
		goto out_err;
	}
got_it:
	if (copy_to_user((__u8 __user *)arg, sbi->raw_super->encrypt_pw_salt,
									16))
		err = -EFAULT;
out_err:
	f2fs_up_write(&sbi->sb_lock);
	mnt_drop_write_file(filp);
	return err;
}

static int f2fs_ioc_get_encryption_policy_ex(struct file *filp,
					     unsigned long arg)
{
	if (!f2fs_sb_has_encrypt(F2FS_I_SB(file_inode(filp))))
		return -EOPNOTSUPP;

	return fscrypt_ioctl_get_policy_ex(filp, (void __user *)arg);
}

static int f2fs_ioc_add_encryption_key(struct file *filp, unsigned long arg)
{
	if (!f2fs_sb_has_encrypt(F2FS_I_SB(file_inode(filp))))
		return -EOPNOTSUPP;

	return fscrypt_ioctl_add_key(filp, (void __user *)arg);
}

static int f2fs_ioc_remove_encryption_key(struct file *filp, unsigned long arg)
{
	if (!f2fs_sb_has_encrypt(F2FS_I_SB(file_inode(filp))))
		return -EOPNOTSUPP;

	return fscrypt_ioctl_remove_key(filp, (void __user *)arg);
}

static int f2fs_ioc_remove_encryption_key_all_users(struct file *filp,
						    unsigned long arg)
{
	if (!f2fs_sb_has_encrypt(F2FS_I_SB(file_inode(filp))))
		return -EOPNOTSUPP;

	return fscrypt_ioctl_remove_key_all_users(filp, (void __user *)arg);
}

static int f2fs_ioc_get_encryption_key_status(struct file *filp,
					      unsigned long arg)
{
	if (!f2fs_sb_has_encrypt(F2FS_I_SB(file_inode(filp))))
		return -EOPNOTSUPP;

	return fscrypt_ioctl_get_key_status(filp, (void __user *)arg);
}

static int f2fs_ioc_get_encryption_nonce(struct file *filp, unsigned long arg)
{
	if (!f2fs_sb_has_encrypt(F2FS_I_SB(file_inode(filp))))
		return -EOPNOTSUPP;

	return fscrypt_ioctl_get_nonce(filp, (void __user *)arg);
}

static int f2fs_ioc_gc(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	__u32 sync;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (get_user(sync, (__u32 __user *)arg))
		return -EFAULT;

	if (f2fs_readonly(sbi->sb))
		return -EROFS;

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	if (!sync) {
		if (!f2fs_down_write_trylock(&sbi->gc_lock)) {
			ret = -EBUSY;
			goto out;
		}
	} else {
		f2fs_down_write(&sbi->gc_lock);
	}
#ifdef CONFIG_BLK_CGROUP_IOSMART
	current->flags |= PF_MUTEX_GC;
	ret = f2fs_gc(sbi, sync, true, false, NULL_SEGNO);
	current->flags &= (~PF_MUTEX_GC);
#else
	ret = f2fs_gc(sbi, sync, true, false, NULL_SEGNO);
#endif
out:
	mnt_drop_write_file(filp);
	return ret;
}

static int __f2fs_ioc_gc_range(struct file *filp, struct f2fs_gc_range *range)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(file_inode(filp));
	u64 end;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;
	if (f2fs_readonly(sbi->sb))
		return -EROFS;

	end = range->start + range->len;
	if (end < range->start || range->start < MAIN_BLKADDR(sbi) ||
					end >= MAX_BLKADDR(sbi))
		return -EINVAL;

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

do_more:
	if (!range->sync) {
		if (!f2fs_down_write_trylock(&sbi->gc_lock)) {
			ret = -EBUSY;
			goto out;
		}
	} else {
		f2fs_down_write(&sbi->gc_lock);
	}
#ifdef CONFIG_BLK_CGROUP_IOSMART
	current->flags |= PF_MUTEX_GC;
	ret = f2fs_gc(sbi, range->sync, true, false,
				GET_SEGNO(sbi, range->start));
		current->flags &= (~PF_MUTEX_GC);
#else
	ret = f2fs_gc(sbi, range->sync, true, false,
				GET_SEGNO(sbi, range->start));
#endif
	if (ret) {
		if (ret == -EBUSY)
			ret = -EAGAIN;
		goto out;
	}
	range->start += BLKS_PER_SEC(sbi);
	if (range->start <= end)
		goto do_more;
out:
	mnt_drop_write_file(filp);
	return ret;
}

static int f2fs_ioc_gc_range(struct file *filp, unsigned long arg)
{
	struct f2fs_gc_range range;

	if (copy_from_user(&range, (struct f2fs_gc_range __user *)arg,
							sizeof(range)))
		return -EFAULT;
	return __f2fs_ioc_gc_range(filp, &range);
}

static int f2fs_ioc_write_checkpoint(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (f2fs_readonly(sbi->sb))
		return -EROFS;

	if (unlikely(is_sbi_flag_set(sbi, SBI_CP_DISABLED))) {
		f2fs_info(sbi, "Skipping Checkpoint. Checkpoints currently disabled.");
		return -EINVAL;
	}

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	ret = f2fs_sync_fs(sbi->sb, 1);

	mnt_drop_write_file(filp);
	return ret;
}

static int f2fs_defragment_range(struct f2fs_sb_info *sbi,
					struct file *filp,
					struct f2fs_defragment *range)
{
	struct inode *inode = file_inode(filp);
	struct f2fs_map_blocks map = { .m_next_extent = NULL,
					.m_seg_type = NO_CHECK_TYPE,
					.m_may_create = false };
	struct extent_info ei = {};
	pgoff_t pg_start, pg_end, next_pgofs;
	unsigned int blk_per_seg = sbi->blocks_per_seg;
	unsigned int total = 0, sec_num;
	block_t blk_end = 0;
	bool fragmented = false;
	int err;

	pg_start = range->start >> PAGE_SHIFT;
	pg_end = (range->start + range->len) >> PAGE_SHIFT;

	f2fs_balance_fs(sbi, true);

	inode_lock(inode);

	/* if in-place-update policy is enabled, don't waste time here */
	set_inode_flag(inode, FI_OPU_WRITE);
	if (f2fs_should_update_inplace(inode, NULL)) {
		err = -EINVAL;
		goto out;
	}

#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
	if (is_inode_flag_set(inode, FI_COMPRESS_RELEASED)) {
		err = f2fs_do_reserve_compress_blocks(inode, COMP_DEFRAGMENT);
		if (err) {
			f2fs_compress_err("reserve file failed, ino %lu, ret %d", inode->i_ino, err);
			goto out;
		}
	}
#endif


#ifdef CONFIG_F2FS_FS_SIS_DISK
	remove_data_coincide_flag(inode);
	if (f2fs_is_dummy_inode(inode)) {
		err = f2fs_recover_sis_inode(inode, __func__);
		if (err) {
			f2fs_err(F2FS_I_SB(inode), "[sis]: inode[%lu], recover err,"
				"err = %d", inode->i_ino, err);
			goto out;
		}
	}
#endif

	/* writeback all dirty pages in the range */
	err = filemap_write_and_wait_range(inode->i_mapping, range->start,
						range->start + range->len - 1);
	if (err)
		goto out;

	/*
	 * lookup mapping info in extent cache, skip defragmenting if physical
	 * block addresses are continuous.
	 */
	if (f2fs_lookup_read_extent_cache(inode, pg_start, &ei)) {
		if (ei.fofs + ei.len >= pg_end)
			goto out;
	}

	map.m_lblk = pg_start;
	map.m_next_pgofs = &next_pgofs;

	/*
	 * lookup mapping info in dnode page cache, skip defragmenting if all
	 * physical block addresses are continuous even if there are hole(s)
	 * in logical blocks.
	 */
	while (map.m_lblk < pg_end) {
		map.m_len = pg_end - map.m_lblk;
		err = f2fs_map_blocks(inode, &map, 0, F2FS_GET_BLOCK_DEFAULT);
		if (err)
			goto out;

		if (!(map.m_flags & F2FS_MAP_FLAGS)) {
			map.m_lblk = next_pgofs;
			continue;
		}

		if (blk_end && blk_end != map.m_pblk)
			fragmented = true;

		/* record total count of block that we're going to move */
		total += map.m_len;

		blk_end = map.m_pblk + map.m_len;

		map.m_lblk += map.m_len;
	}

	if (!fragmented) {
		total = 0;
		goto out;
	}

	sec_num = DIV_ROUND_UP(total, BLKS_PER_SEC(sbi));

	/*
	 * make sure there are enough free section for LFS allocation, this can
	 * avoid defragment running in SSR mode when free section are allocated
	 * intensively
	 */
	if (has_not_enough_free_secs(sbi, 0, sec_num)) {
		err = -EAGAIN;
		goto out;
	}

	map.m_lblk = pg_start;
	map.m_len = pg_end - pg_start;
	total = 0;

	while (map.m_lblk < pg_end) {
		pgoff_t idx;
		int cnt = 0;

do_map:
		map.m_len = pg_end - map.m_lblk;
		err = f2fs_map_blocks(inode, &map, 0, F2FS_GET_BLOCK_DEFAULT);
		if (err)
			goto clear_out;

		if (!(map.m_flags & F2FS_MAP_FLAGS)) {
			map.m_lblk = next_pgofs;
			goto check;
		}

		set_inode_flag(inode, FI_SKIP_WRITES);

		idx = map.m_lblk;
		while (idx < map.m_lblk + map.m_len && cnt < blk_per_seg) {
			struct page *page;

			page = f2fs_get_lock_data_page(inode, idx, true);
			if (IS_ERR(page)) {
				err = PTR_ERR(page);
				goto clear_out;
			}

			set_page_dirty(page);
			f2fs_put_page(page, 1);

			idx++;
			cnt++;
			total++;
		}

		map.m_lblk = idx;
check:
		if (map.m_lblk < pg_end && cnt < blk_per_seg)
			goto do_map;

		clear_inode_flag(inode, FI_SKIP_WRITES);

		err = filemap_fdatawrite(inode->i_mapping);
		if (err)
			goto out;
	}
clear_out:
	clear_inode_flag(inode, FI_SKIP_WRITES);
out:
	clear_inode_flag(inode, FI_OPU_WRITE);
	inode_unlock(inode);
	if (!err)
		range->len = (u64)total << PAGE_SHIFT;
	return err;
}

static int f2fs_ioc_defragment(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct f2fs_defragment range;
	int err;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (!S_ISREG(inode->i_mode) || f2fs_is_atomic_file(inode))
		return -EINVAL;

	if (f2fs_readonly(sbi->sb))
		return -EROFS;

	if (copy_from_user(&range, (struct f2fs_defragment __user *)arg,
							sizeof(range)))
		return -EFAULT;

	/* verify alignment of offset & size */
	if (range.start & (F2FS_BLKSIZE - 1) || range.len & (F2FS_BLKSIZE - 1))
		return -EINVAL;

	if (unlikely((range.start + range.len) >> PAGE_SHIFT >
					max_file_blocks(inode)))
		return -EINVAL;

	err = mnt_want_write_file(filp);
	if (err)
		return err;

	err = f2fs_defragment_range(sbi, filp, &range);
	mnt_drop_write_file(filp);

	f2fs_update_time(sbi, REQ_TIME);
	if (err < 0)
		return err;

	if (copy_to_user((struct f2fs_defragment __user *)arg, &range,
							sizeof(range)))
		return -EFAULT;

	return 0;
}

static int f2fs_move_file_range(struct file *file_in, loff_t pos_in,
			struct file *file_out, loff_t pos_out, size_t len)
{
	struct inode *src = file_inode(file_in);
	struct inode *dst = file_inode(file_out);
	struct f2fs_sb_info *sbi = F2FS_I_SB(src);
	size_t olen = len, dst_max_i_size = 0;
	size_t dst_osize;
	int ret;

	if (file_in->f_path.mnt != file_out->f_path.mnt ||
				src->i_sb != dst->i_sb)
		return -EXDEV;

	if (unlikely(f2fs_readonly(src->i_sb)))
		return -EROFS;

	if (!S_ISREG(src->i_mode) || !S_ISREG(dst->i_mode))
		return -EINVAL;

	if (IS_ENCRYPTED(src) || IS_ENCRYPTED(dst))
		return -EOPNOTSUPP;

	if (pos_out < 0 || pos_in < 0)
		return -EINVAL;

	if (src == dst) {
		if (pos_in == pos_out)
			return 0;
		if (pos_out > pos_in && pos_out < pos_in + len)
			return -EINVAL;
	}

	inode_lock(src);
	if (src != dst) {
		ret = -EBUSY;
		if (!inode_trylock(dst))
			goto out;
	}

#ifdef CONFIG_F2FS_FS_SIS_DISK
	remove_data_coincide_flag(src);
	if (f2fs_is_dummy_inode(src)) {
		ret = f2fs_recover_sis_inode(src, __func__);
		if (ret) {
			f2fs_err(F2FS_I_SB(src), "[sis]: inode_src[%lu], recover err, "
				"err = %d", src->i_ino, ret);
			goto out_unlock;
		}
	}

	remove_data_coincide_flag(dst);
	if (f2fs_is_dummy_inode(dst)) {
		ret = f2fs_recover_sis_inode(dst, __func__);
		if (ret) {
			f2fs_err(F2FS_I_SB(dst), "[sis]: inode_dst[%lu], recover err, "
				"err = %d", dst->i_ino, ret);
			goto out_unlock;
		}
	}
#endif

#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
	if (f2fs_compressed_file(src)) {
		ret = f2fs_do_decompress_file(src, DECOMP_MOVE_SRC);
		if (ret)
			goto out_unlock;
	}

	if (f2fs_compressed_file(dst)) {
		ret = f2fs_do_decompress_file(dst, DECOMP_MOVE_DST);
		if (ret)
			goto out_unlock;
	}
#endif

	ret = -EINVAL;
	if (pos_in + len > src->i_size || pos_in + len < pos_in)
		goto out_unlock;
	if (len == 0)
		olen = len = src->i_size - pos_in;
	if (pos_in + len == src->i_size)
		len = ALIGN(src->i_size, F2FS_BLKSIZE) - pos_in;
	if (len == 0) {
		ret = 0;
		goto out_unlock;
	}

	dst_osize = dst->i_size;
	if (pos_out + olen > dst->i_size)
		dst_max_i_size = pos_out + olen;

	/* verify the end result is block aligned */
	if (!IS_ALIGNED(pos_in, F2FS_BLKSIZE) ||
			!IS_ALIGNED(pos_in + len, F2FS_BLKSIZE) ||
			!IS_ALIGNED(pos_out, F2FS_BLKSIZE))
		goto out_unlock;

	ret = f2fs_convert_inline_inode(src);
	if (ret)
		goto out_unlock;

	ret = f2fs_convert_inline_inode(dst);
	if (ret)
		goto out_unlock;

	/* write out all dirty pages from offset */
	ret = filemap_write_and_wait_range(src->i_mapping,
					pos_in, pos_in + len);
	if (ret)
		goto out_unlock;

	ret = filemap_write_and_wait_range(dst->i_mapping,
					pos_out, pos_out + len);
	if (ret)
		goto out_unlock;

	f2fs_balance_fs(sbi, true);

	f2fs_down_write(&F2FS_I(src)->i_gc_rwsem[WRITE]);
	if (src != dst) {
		ret = -EBUSY;
		if (!f2fs_down_write_trylock(&F2FS_I(dst)->i_gc_rwsem[WRITE]))
			goto out_src;
	}

	f2fs_lock_op(sbi);
	ret = __exchange_data_block(src, dst, pos_in >> F2FS_BLKSIZE_BITS,
				pos_out >> F2FS_BLKSIZE_BITS,
				len >> F2FS_BLKSIZE_BITS, false);

	if (!ret) {
		if (dst_max_i_size)
			f2fs_i_size_write(dst, dst_max_i_size);
		else if (dst_osize != dst->i_size)
			f2fs_i_size_write(dst, dst_osize);
	}
	f2fs_unlock_op(sbi);

	if (src != dst)
		f2fs_up_write(&F2FS_I(dst)->i_gc_rwsem[WRITE]);
out_src:
	f2fs_up_write(&F2FS_I(src)->i_gc_rwsem[WRITE]);
out_unlock:
	if (src != dst)
		inode_unlock(dst);
out:
	inode_unlock(src);
	return ret;
}

static int __f2fs_ioc_move_range(struct file *filp,
				struct f2fs_move_range *range)
{
	struct fd dst;
	int err;

	if (!(filp->f_mode & FMODE_READ) ||
			!(filp->f_mode & FMODE_WRITE))
		return -EBADF;

	dst = fdget(range->dst_fd);
	if (!dst.file)
		return -EBADF;

	if (!(dst.file->f_mode & FMODE_WRITE)) {
		err = -EBADF;
		goto err_out;
	}

	err = mnt_want_write_file(filp);
	if (err)
		goto err_out;

	err = f2fs_move_file_range(filp, range->pos_in, dst.file,
					range->pos_out, range->len);

	mnt_drop_write_file(filp);
err_out:
	fdput(dst);
	return err;
}

static int f2fs_ioc_move_range(struct file *filp, unsigned long arg)
{
	struct f2fs_move_range range;

	if (copy_from_user(&range, (struct f2fs_move_range __user *)arg,
							sizeof(range)))
		return -EFAULT;
	return __f2fs_ioc_move_range(filp, &range);
}

static int f2fs_ioc_flush_device(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct sit_info *sm = SIT_I(sbi);
	unsigned int start_segno = 0, end_segno = 0;
	unsigned int dev_start_segno = 0, dev_end_segno = 0;
	struct f2fs_flush_device range;
	int ret;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (f2fs_readonly(sbi->sb))
		return -EROFS;

	if (unlikely(is_sbi_flag_set(sbi, SBI_CP_DISABLED)))
		return -EINVAL;

	if (copy_from_user(&range, (struct f2fs_flush_device __user *)arg,
							sizeof(range)))
		return -EFAULT;

	if (!f2fs_is_multi_device(sbi) || sbi->s_ndevs - 1 <= range.dev_num ||
			__is_large_section(sbi)) {
		f2fs_warn(sbi, "Can't flush %u in %d for segs_per_sec %u != 1",
			  range.dev_num, sbi->s_ndevs, sbi->segs_per_sec);
		return -EINVAL;
	}

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	if (range.dev_num != 0)
		dev_start_segno = GET_SEGNO(sbi, FDEV(range.dev_num).start_blk);
	dev_end_segno = GET_SEGNO(sbi, FDEV(range.dev_num).end_blk);

	start_segno = sm->last_victim[FLUSH_DEVICE];
	if (start_segno < dev_start_segno || start_segno >= dev_end_segno)
		start_segno = dev_start_segno;
	end_segno = min(start_segno + range.segments, dev_end_segno);

	while (start_segno < end_segno) {
		if (!f2fs_down_write_trylock(&sbi->gc_lock)) {
			ret = -EBUSY;
			goto out;
		}
		sm->last_victim[GC_CB] = end_segno + 1;
		sm->last_victim[GC_GREEDY] = end_segno + 1;
		sm->last_victim[ALLOC_NEXT] = end_segno + 1;
#ifdef CONFIG_BLK_CGROUP_IOSMART
		current->flags |= PF_MUTEX_GC;
		ret = f2fs_gc(sbi, true, true, true, start_segno);
		current->flags &= (~PF_MUTEX_GC);
#else
		ret = f2fs_gc(sbi, true, true, true, start_segno);
#endif
		if (ret == -EAGAIN)
			ret = 0;
		else if (ret < 0)
			break;
		start_segno++;
	}
out:
	mnt_drop_write_file(filp);
	return ret;
}

static int f2fs_ioc_get_features(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	u32 sb_feature = le32_to_cpu(F2FS_I_SB(inode)->raw_super->feature);

	/* Must validate to set it with SQLite behavior in Android. */
	sb_feature |= F2FS_FEATURE_ATOMIC_WRITE;

	return put_user(sb_feature, (u32 __user *)arg);
}

#ifdef CONFIG_QUOTA
int f2fs_transfer_project_quota(struct inode *inode, kprojid_t kprojid)
{
	struct dquot *transfer_to[MAXQUOTAS] = {};
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct super_block *sb = sbi->sb;
	int err = 0;

	transfer_to[PRJQUOTA] = dqget(sb, make_kqid_projid(kprojid));
	if (!IS_ERR(transfer_to[PRJQUOTA])) {
		err = __dquot_transfer(inode, transfer_to);
		if (err)
			set_sbi_flag(sbi, SBI_QUOTA_NEED_REPAIR);
		dqput(transfer_to[PRJQUOTA]);
	}
	return err;
}

static int f2fs_ioc_setproject(struct file *filp, __u32 projid)
{
	struct inode *inode = file_inode(filp);
	struct f2fs_inode_info *fi = F2FS_I(inode);
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct page *ipage;
	kprojid_t kprojid;
	int err;

	if (!f2fs_sb_has_project_quota(sbi)) {
		if (projid != F2FS_DEF_PROJID)
			return -EOPNOTSUPP;
		else
			return 0;
	}

	if (!f2fs_has_extra_attr(inode))
		return -EOPNOTSUPP;

	kprojid = make_kprojid(&init_user_ns, (projid_t)projid);

	if (projid_eq(kprojid, F2FS_I(inode)->i_projid))
		return 0;

	err = -EPERM;
	/* Is it quota file? Do not allow user to mess with it */
	if (IS_NOQUOTA(inode))
		return err;

	ipage = f2fs_get_node_page(sbi, inode->i_ino);
	if (IS_ERR(ipage))
		return PTR_ERR(ipage);

	if (!F2FS_FITS_IN_INODE(F2FS_INODE(ipage), fi->i_extra_isize,
								i_projid)) {
		err = -EOVERFLOW;
		f2fs_put_page(ipage, 1);
		return err;
	}
	f2fs_put_page(ipage, 1);

	err = dquot_initialize(inode);
	if (err)
		return err;

	f2fs_lock_op(sbi);
	err = f2fs_transfer_project_quota(inode, kprojid);
	if (err)
		goto out_unlock;

	F2FS_I(inode)->i_projid = kprojid;
	inode->i_ctime = current_time(inode);
	f2fs_mark_inode_dirty_sync(inode, true);
out_unlock:
	f2fs_unlock_op(sbi);
	return err;
}
#else
int f2fs_transfer_project_quota(struct inode *inode, kprojid_t kprojid)
{
	return 0;
}

static int f2fs_ioc_setproject(struct file *filp, __u32 projid)
{
	if (projid != F2FS_DEF_PROJID)
		return -EOPNOTSUPP;
	return 0;
}
#endif

/* FS_IOC_FSGETXATTR and FS_IOC_FSSETXATTR support */

/*
 * To make a new on-disk f2fs i_flag gettable via FS_IOC_FSGETXATTR and settable
 * via FS_IOC_FSSETXATTR, add an entry for it to f2fs_xflags_map[], and add its
 * FS_XFLAG_* equivalent to F2FS_SUPPORTED_XFLAGS.
 */

static const struct {
	u32 iflag;
	u32 xflag;
} f2fs_xflags_map[] = {
	{ F2FS_SYNC_FL,		FS_XFLAG_SYNC },
	{ F2FS_IMMUTABLE_FL,	FS_XFLAG_IMMUTABLE },
	{ F2FS_APPEND_FL,	FS_XFLAG_APPEND },
	{ F2FS_NODUMP_FL,	FS_XFLAG_NODUMP },
	{ F2FS_NOATIME_FL,	FS_XFLAG_NOATIME },
	{ F2FS_PROJINHERIT_FL,	FS_XFLAG_PROJINHERIT },
};

#define F2FS_SUPPORTED_XFLAGS (		\
		FS_XFLAG_SYNC |		\
		FS_XFLAG_IMMUTABLE |	\
		FS_XFLAG_APPEND |	\
		FS_XFLAG_NODUMP |	\
		FS_XFLAG_NOATIME |	\
		FS_XFLAG_PROJINHERIT)

/* Convert f2fs on-disk i_flags to FS_IOC_FS{GET,SET}XATTR flags */
static inline u32 f2fs_iflags_to_xflags(u32 iflags)
{
	u32 xflags = 0;
	int i;

	for (i = 0; i < ARRAY_SIZE(f2fs_xflags_map); i++)
		if (iflags & f2fs_xflags_map[i].iflag)
			xflags |= f2fs_xflags_map[i].xflag;

	return xflags;
}

/* Convert FS_IOC_FS{GET,SET}XATTR flags to f2fs on-disk i_flags */
static inline u32 f2fs_xflags_to_iflags(u32 xflags)
{
	u32 iflags = 0;
	int i;

	for (i = 0; i < ARRAY_SIZE(f2fs_xflags_map); i++)
		if (xflags & f2fs_xflags_map[i].xflag)
			iflags |= f2fs_xflags_map[i].iflag;

	return iflags;
}

static void f2fs_fill_fsxattr(struct inode *inode, struct fsxattr *fa)
{
	struct f2fs_inode_info *fi = F2FS_I(inode);

	simple_fill_fsxattr(fa, f2fs_iflags_to_xflags(fi->i_flags));

	if (f2fs_sb_has_project_quota(F2FS_I_SB(inode)))
		fa->fsx_projid = from_kprojid(&init_user_ns, fi->i_projid);
}

static int f2fs_ioc_fsgetxattr(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct fsxattr fa;

	f2fs_fill_fsxattr(inode, &fa);

	if (copy_to_user((struct fsxattr __user *)arg, &fa, sizeof(fa)))
		return -EFAULT;
	return 0;
}

static int f2fs_ioc_fssetxattr(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct fsxattr fa, old_fa;
	u32 iflags;
	int err;

	if (copy_from_user(&fa, (struct fsxattr __user *)arg, sizeof(fa)))
		return -EFAULT;

	/* Make sure caller has proper permission */
	if (!inode_owner_or_capable(inode))
		return -EACCES;

	if (fa.fsx_xflags & ~F2FS_SUPPORTED_XFLAGS)
		return -EOPNOTSUPP;

	iflags = f2fs_xflags_to_iflags(fa.fsx_xflags);
	if (f2fs_mask_flags(inode->i_mode, iflags) != iflags)
		return -EOPNOTSUPP;

	err = mnt_want_write_file(filp);
	if (err)
		return err;

	inode_lock(inode);

	f2fs_fill_fsxattr(inode, &old_fa);
	err = vfs_ioc_fssetxattr_check(inode, &old_fa, &fa);
	if (err)
		goto out;

	err = f2fs_setflags_common(inode, iflags,
			f2fs_xflags_to_iflags(F2FS_SUPPORTED_XFLAGS));
	if (err)
		goto out;

	err = f2fs_ioc_setproject(filp, fa.fsx_projid);
out:
	inode_unlock(inode);
	mnt_drop_write_file(filp);
	return err;
}

int f2fs_pin_file_control(struct inode *inode, bool inc)
{
	struct f2fs_inode_info *fi = F2FS_I(inode);
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);

	/* Use i_gc_failures for normal file as a risk signal. */
	if (inc)
		f2fs_i_gc_failures_write(inode,
				fi->i_gc_failures[GC_FAILURE_PIN] + 1);

	if (fi->i_gc_failures[GC_FAILURE_PIN] > sbi->gc_pin_file_threshold) {
		f2fs_warn(sbi, "%s: Enable GC = ino %lx after %x GC trials",
			  __func__, inode->i_ino,
			  fi->i_gc_failures[GC_FAILURE_PIN]);
		clear_inode_flag(inode, FI_PIN_FILE);
		return -EAGAIN;
	}
	return 0;
}

static int f2fs_ioc_set_pin_file(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	__u32 pin;
	int ret = 0;

	if (get_user(pin, (__u32 __user *)arg))
		return -EFAULT;

	if (!S_ISREG(inode->i_mode))
		return -EINVAL;

	if (f2fs_readonly(F2FS_I_SB(inode)->sb))
		return -EROFS;

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	inode_lock(inode);

#ifdef CONFIG_F2FS_FS_SIS_DISK
	remove_data_coincide_flag(inode);
	if (f2fs_is_dummy_inode(inode)) {
		ret = f2fs_recover_sis_inode(inode, __func__);
		if (ret) {
			f2fs_err(F2FS_I_SB(inode), "[sis]: inode[%lu], recover err, "
				"err = %d", inode->i_ino, ret);
			goto out;
		}
	}
#endif
	if (!pin) {
		clear_inode_flag(inode, FI_PIN_FILE);
		f2fs_i_gc_failures_write(inode, 0);
		goto done;
	}

	if (f2fs_should_update_outplace(inode, NULL)) {
		ret = -EINVAL;
		goto out;
	}

	if (f2fs_pin_file_control(inode, false)) {
		ret = -EAGAIN;
		goto out;
	}

	ret = f2fs_convert_inline_inode(inode);
	if (ret)
		goto out;
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
	if (f2fs_compressed_file(inode))
		f2fs_do_decompress_file(inode, DECOMP_PIN_FILE);
#endif

	if (!f2fs_disable_compressed_file(inode)) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	set_inode_flag(inode, FI_PIN_FILE);
	ret = F2FS_I(inode)->i_gc_failures[GC_FAILURE_PIN];
done:
	f2fs_update_time(F2FS_I_SB(inode), REQ_TIME);
out:
	inode_unlock(inode);
	mnt_drop_write_file(filp);
	return ret;
}

static int f2fs_ioc_get_pin_file(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	__u32 pin = 0;

	if (is_inode_flag_set(inode, FI_PIN_FILE))
		pin = F2FS_I(inode)->i_gc_failures[GC_FAILURE_PIN];
	return put_user(pin, (u32 __user *)arg);
}

int f2fs_precache_extents(struct inode *inode)
{
	struct f2fs_inode_info *fi = F2FS_I(inode);
	struct f2fs_map_blocks map;
	pgoff_t m_next_extent;
	loff_t end;
	int err;

	if (is_inode_flag_set(inode, FI_NO_EXTENT))
		return -EOPNOTSUPP;

	map.m_lblk = 0;
	map.m_next_pgofs = NULL;
	map.m_next_extent = &m_next_extent;
	map.m_seg_type = NO_CHECK_TYPE;
	map.m_may_create = false;
	end = max_file_blocks(inode);

	while (map.m_lblk < end) {
		map.m_len = end - map.m_lblk;

		f2fs_down_write(&fi->i_gc_rwsem[WRITE]);
		err = f2fs_map_blocks(inode, &map, 0, F2FS_GET_BLOCK_PRECACHE);
		f2fs_up_write(&fi->i_gc_rwsem[WRITE]);
		if (err)
			return err;

		map.m_lblk = m_next_extent;
	}

	return 0;
}

static int f2fs_ioc_precache_extents(struct file *filp, unsigned long arg)
{
	return f2fs_precache_extents(file_inode(filp));
}

static int f2fs_ioc_resize_fs(struct file *filp, unsigned long arg)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(file_inode(filp));
	__u64 block_count;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	if (f2fs_readonly(sbi->sb))
		return -EROFS;

	if (copy_from_user(&block_count, (void __user *)arg,
			   sizeof(block_count)))
		return -EFAULT;

	return f2fs_resize_fs(filp, block_count);
}

static int f2fs_ioc_enable_verity(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);

	f2fs_update_time(F2FS_I_SB(inode), REQ_TIME);

	if (!f2fs_sb_has_verity(F2FS_I_SB(inode))) {
		f2fs_warn(F2FS_I_SB(inode),
			  "Can't enable fs-verity on inode %lu: the verity feature is not enabled on this filesystem",
			  inode->i_ino);
		return -EOPNOTSUPP;
	}

	return fsverity_ioctl_enable(filp, (const void __user *)arg);
}

static int f2fs_ioc_measure_verity(struct file *filp, unsigned long arg)
{
	if (!f2fs_sb_has_verity(F2FS_I_SB(file_inode(filp))))
		return -EOPNOTSUPP;

	return fsverity_ioctl_measure(filp, (void __user *)arg);
}

static int f2fs_ioc_read_verity_metadata(struct file *filp, unsigned long arg)
{
	if (!f2fs_sb_has_verity(F2FS_I_SB(file_inode(filp))))
		return -EOPNOTSUPP;

	return fsverity_ioctl_read_metadata(filp, (const void __user *)arg);
}

static int f2fs_ioc_getfslabel(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	char *vbuf;
	int count;
	int err = 0;

	vbuf = f2fs_kzalloc(sbi, MAX_VOLUME_NAME, GFP_KERNEL);
	if (!vbuf)
		return -ENOMEM;

	f2fs_down_read(&sbi->sb_lock);
	count = utf16s_to_utf8s(sbi->raw_super->volume_name,
			ARRAY_SIZE(sbi->raw_super->volume_name),
			UTF16_LITTLE_ENDIAN, vbuf, MAX_VOLUME_NAME);
	f2fs_up_read(&sbi->sb_lock);

	if (copy_to_user((char __user *)arg, vbuf,
				min(FSLABEL_MAX, count)))
		err = -EFAULT;

	kfree(vbuf);
	return err;
}

static int f2fs_ioc_setfslabel(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	char *vbuf;
	int err = 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	vbuf = strndup_user((const char __user *)arg, FSLABEL_MAX);
	if (IS_ERR(vbuf))
		return PTR_ERR(vbuf);

	err = mnt_want_write_file(filp);
	if (err)
		goto out;

	f2fs_down_write(&sbi->sb_lock);

	memset(sbi->raw_super->volume_name, 0,
			sizeof(sbi->raw_super->volume_name));
	utf8s_to_utf16s(vbuf, strlen(vbuf), UTF16_LITTLE_ENDIAN,
			sbi->raw_super->volume_name,
			ARRAY_SIZE(sbi->raw_super->volume_name));

	err = f2fs_commit_super(sbi, false);

	f2fs_up_write(&sbi->sb_lock);

	mnt_drop_write_file(filp);
out:
	kfree(vbuf);
	return err;
}

#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
void f2fs_bd_compr_op_record(struct inode *inode, enum COMP_OPER op, int scense, bool is_err)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);

	bd_lock(sbi->compr_info);
	if (op == F2FS_RESERVE && scense < COMP_RESV_MAX)
		inc_cbd_array_val_check(sbi, compr_info, resv, scense, 1, is_err);
	else if (op == F2FS_DECOMPR && scense < DECOMP_USAGE_MAX)
		inc_cbd_array_val_check(sbi, compr_info, decomp, scense, 1, is_err);
	bd_unlock(sbi->compr_info);
}

static void f2fs_compress_bd_report(struct f2fs_sb_info *sbi, struct inode *inode,
						enum COMP_BD_SCENE scene, int usage, int result)
{
	struct hiview_hievent *hi_event = NULL;
	unsigned int ret = 0;
	char info[COMP_BD_INFO_SIZE] = {0};
	char phen[COMP_BD_INFO_SIZE] = {0};

	hi_event = hiview_hievent_create(COMP_BD_ID);
	if (!hi_event) {
		f2fs_warn(sbi, "%s:create eventobj failed", __func__);
		return;
	}

	scnprintf(info, sizeof(info), "errno:%d, usage:%d, inode:%lu, "
		"iblocks:%lu, cblocks:%lu, status:%d", result, usage, inode->i_ino,
		inode->i_blocks, atomic_read(&F2FS_I(inode)->i_compr_blocks),
		is_inode_flag_set(inode, FI_COMPRESS_RELEASED));

	scnprintf(phen, sizeof(phen), "compress %d", scene);

	ret = ret | hiview_hievent_put_string(hi_event, "CONTENT", info);
	ret = ret | hiview_hievent_put_string(hi_event, "FAULT_PHENOMENON", phen);

	if (ret)
		goto out;

	ret = hiview_hievent_report(hi_event);
out:
	if (ret < 0)
		f2fs_warn(sbi, "%s scene[%u] send hievent failed, err:%d", __func__, scene, ret);
	else
		f2fs_info(sbi, "%s scene[%u] send hievent ok", __func__, scene);
	hiview_hievent_destroy(hi_event);
}
#endif

static int f2fs_get_compress_blocks(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	__u64 blocks;

	if (!f2fs_sb_has_compression(F2FS_I_SB(inode)))
		return -EOPNOTSUPP;

#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
	f2fs_down_read(&F2FS_I(inode)->i_compress_sem);
#endif
	if (!f2fs_compressed_file(inode)) {
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
		f2fs_compress_err("not compress, ino %lu, file %s",
			inode->i_ino, filp->f_path.dentry->d_name.name);
		f2fs_up_read(&F2FS_I(inode)->i_compress_sem);
#endif
		return -EINVAL;
	}

	blocks = atomic_read(&F2FS_I(inode)->i_compr_blocks);
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
	f2fs_up_read(&F2FS_I(inode)->i_compress_sem);
#endif
	return put_user(blocks, (u64 __user *)arg);
}

static int release_compress_blocks(struct dnode_of_data *dn, pgoff_t count)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(dn->inode);
	unsigned int released_blocks = 0;
	int cluster_size = F2FS_I(dn->inode)->i_cluster_size;
	block_t blkaddr;
	int i;

	for (i = 0; i < count; i++) {
		blkaddr = data_blkaddr(dn->inode, dn->node_page,
						dn->ofs_in_node + i);

		if (!__is_valid_data_blkaddr(blkaddr))
			continue;
		if (unlikely(!f2fs_is_valid_blkaddr(sbi, blkaddr,
					DATA_GENERIC_ENHANCE)))
			return -EFSCORRUPTED;
	}

	while (count) {
		int compr_blocks = 0;

		for (i = 0; i < cluster_size; i++, dn->ofs_in_node++) {
			blkaddr = f2fs_data_blkaddr(dn);

			if (i == 0) {
				if (blkaddr == COMPRESS_ADDR)
					continue;
				dn->ofs_in_node += cluster_size;
				goto next;
			}

			if (__is_valid_data_blkaddr(blkaddr))
				compr_blocks++;

			if (blkaddr != NEW_ADDR)
				continue;

			dn->data_blkaddr = NULL_ADDR;
			f2fs_set_data_blkaddr(dn);
		}

		f2fs_i_compr_blocks_update(dn->inode, compr_blocks, false);
		dec_valid_block_count(sbi, dn->inode,
					cluster_size - compr_blocks);

		released_blocks += cluster_size - compr_blocks;
next:
		count -= cluster_size;
	}

	return released_blocks;
}

static int f2fs_release_compress_blocks(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	pgoff_t page_idx = 0, last_idx;
	unsigned int released_blocks = 0;
	int ret;
	int writecount;

	if (!f2fs_sb_has_compression(F2FS_I_SB(inode)))
		return -EOPNOTSUPP;

	if (!f2fs_compressed_file(inode))
		return -EINVAL;

	if (f2fs_readonly(sbi->sb))
		return -EROFS;

#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
	ret = dquot_initialize(inode);
	if (ret) {
		f2fs_compress_err("dquot init failed, ino %lu, file %s",
			inode->i_ino, filp->f_path.dentry->d_name.name);
		return ret;
	}
#endif

	ret = mnt_want_write_file(filp);
	if (ret) {
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
		f2fs_compress_err("want write file failed, ino %lu, ret %d, "
			"file %s", inode->i_ino, ret, filp->f_path.dentry->d_name.name);
#endif
		return ret;
	}

	f2fs_balance_fs(F2FS_I_SB(inode), true);

	inode_lock(inode);

	writecount = atomic_read(&inode->i_writecount);
	if ((filp->f_mode & FMODE_WRITE && writecount != 1) ||
			(!(filp->f_mode & FMODE_WRITE) && writecount)) {
		ret = -EBUSY;
		goto out;
	}

	if (is_inode_flag_set(inode, FI_COMPRESS_RELEASED)) {
		ret = -EINVAL;
		goto out;
	}

	ret = filemap_write_and_wait_range(inode->i_mapping, 0, LLONG_MAX);
	if (ret) {
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
		f2fs_compress_err("wait write failed, ino %lu, ret %d,"
			" file %s", inode->i_ino, ret, filp->f_path.dentry->d_name.name);
#endif
		goto out;
	}

	f2fs_down_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);
	f2fs_down_write(&F2FS_I(inode)->i_mmap_sem);
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
	f2fs_lock_op(sbi);
#endif

	set_inode_flag(inode, FI_COMPRESS_RELEASED);
	inode->i_ctime = current_time(inode);
	f2fs_mark_inode_dirty_sync(inode, true);

	if (!atomic_read(&F2FS_I(inode)->i_compr_blocks))
		goto unlock;

	last_idx = DIV_ROUND_UP(i_size_read(inode), PAGE_SIZE);

	while (page_idx < last_idx) {
		struct dnode_of_data dn;
		pgoff_t end_offset, count;

		set_new_dnode(&dn, inode, NULL, NULL, 0);
		ret = f2fs_get_dnode_of_data(&dn, page_idx, LOOKUP_NODE);
		if (ret) {
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
			f2fs_compress_info("get dnode info failed, ino %lu, idx %lu, file %s",
				inode->i_ino, page_idx, filp->f_path.dentry->d_name.name);
#endif
			if (ret == -ENOENT) {
				page_idx = f2fs_get_next_page_offset(&dn,
								page_idx);
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
				page_idx = round_up(page_idx, F2FS_I(inode)->i_cluster_size);
				f2fs_compress_info("hole addr goto next, ino %lu, idx %lu, file %s",
					inode->i_ino, page_idx, filp->f_path.dentry->d_name.name);
#endif
				ret = 0;
				continue;
			}
			break;
		}

		end_offset = ADDRS_PER_PAGE(dn.node_page, inode);
		count = min(end_offset - dn.ofs_in_node, last_idx - page_idx);
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
		count = round_down(count, F2FS_I(inode)->i_cluster_size);
#else
		count = round_up(count, F2FS_I(inode)->i_cluster_size);
#endif
		ret = release_compress_blocks(&dn, count);

		f2fs_put_dnode(&dn);

		if (ret < 0)
			break;

#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
		if (count != 0)
			page_idx += count;
		else
			page_idx += F2FS_I(inode)->i_cluster_size;
#else
		page_idx += count;
#endif
		released_blocks += ret;
	}

unlock:
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
	f2fs_unlock_op(sbi);
#endif
	f2fs_up_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);
	f2fs_up_write(&F2FS_I(inode)->i_mmap_sem);
out:
	inode_unlock(inode);

	mnt_drop_write_file(filp);
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
	bd_lock(sbi->compr_info);
	inc_cbd_val(sbi, compr_info, excute_cnt, 1);
	bd_unlock(sbi->compr_info);
#endif

	if (ret >= 0) {
		ret = put_user(released_blocks, (u64 __user *)arg);
	} else if (released_blocks &&
			atomic_read(&F2FS_I(inode)->i_compr_blocks)) {
		set_sbi_flag(sbi, SBI_NEED_FSCK);
		f2fs_warn(sbi, "%s: partial blocks were released i_ino=%lx "
			"iblocks=%llu, released=%u, compr_blocks=%u, "
			"run fsck to fix.",
			__func__, inode->i_ino, inode->i_blocks,
			released_blocks,
			atomic_read(&F2FS_I(inode)->i_compr_blocks));
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
		f2fs_compress_err("partial released, ino %lu, iblks %llu, rel %u, cblk %u, file %s,"
			" run fsck to fix",inode->i_ino, SECTOR_TO_BLOCK(inode->i_blocks), released_blocks,
			atomic_read(&F2FS_I(inode)->i_compr_blocks), filp->f_path.dentry->d_name.name);
		f2fs_compress_bd_report(sbi, inode, BD_RELS, 0, ret);
#endif
	}

	return ret;
}

static int reserve_compress_blocks(struct dnode_of_data *dn, pgoff_t count)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(dn->inode);
	unsigned int reserved_blocks = 0;
	int cluster_size = F2FS_I(dn->inode)->i_cluster_size;
	block_t blkaddr;
	int i;
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
	unsigned int ofs_in_node_start = dn->ofs_in_node;
#endif

	for (i = 0; i < count; i++) {
		blkaddr = data_blkaddr(dn->inode, dn->node_page,
						dn->ofs_in_node + i);

		if (!__is_valid_data_blkaddr(blkaddr))
			continue;
		if (unlikely(!f2fs_is_valid_blkaddr(sbi, blkaddr,
					DATA_GENERIC_ENHANCE))) {
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
			f2fs_compress_err("invalid blkaddr %u, ino %lu", blkaddr, dn->inode->i_ino);
#endif
			return -EFSCORRUPTED;
		}
	}

	while (count) {
		int compr_blocks = 0;
		blkcnt_t reserved;
		int ret;
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
		unsigned int ofs_in_node = dn->ofs_in_node;
#endif

		for (i = 0; i < cluster_size; i++, dn->ofs_in_node++) {
			blkaddr = f2fs_data_blkaddr(dn);

			if (i == 0) {
				if (blkaddr == COMPRESS_ADDR)
					continue;
				dn->ofs_in_node += cluster_size;
				goto next;
			}

			if (__is_valid_data_blkaddr(blkaddr)) {
				compr_blocks++;
				continue;
			}

#ifndef CONFIG_F2FS_FS_COMPRESSION_OPTM
			dn->data_blkaddr = NEW_ADDR;
			f2fs_set_data_blkaddr(dn);
#endif
		}

		reserved = cluster_size - compr_blocks;
		ret = inc_valid_block_count(sbi, dn->inode, &reserved);
		if (ret) {
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
			f2fs_compress_err("inc iblock failed, ino %lu, ret %d, i_blocks %llu",
				dn->inode->i_ino, ret, SECTOR_TO_BLOCK(dn->inode->i_blocks) + 1);
			dn->ofs_in_node = ofs_in_node_start;
			release_compress_blocks(dn, ofs_in_node - ofs_in_node_start);
#endif
			return ret;
		}

		if (reserved != cluster_size - compr_blocks) {
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
			f2fs_compress_err("space not enough, ino %lu, i_blocks %llu, compr_blocks %d, reserved %llu ",
				dn->inode->i_ino, SECTOR_TO_BLOCK(dn->inode->i_blocks) + 1, compr_blocks, reserved);
			dec_valid_block_count(sbi, dn->inode, reserved);
			dn->ofs_in_node = ofs_in_node_start;
			release_compress_blocks(dn, ofs_in_node - ofs_in_node_start);
#endif
			return -ENOSPC;
		}

		f2fs_i_compr_blocks_update(dn->inode, compr_blocks, true);
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
		dn->ofs_in_node = ofs_in_node;
		for (i = 0; i < cluster_size; i++, dn->ofs_in_node++) {
			blkaddr = f2fs_data_blkaddr(dn);

			if (i == 0) {
				if (blkaddr == COMPRESS_ADDR)
					continue;
				dn->ofs_in_node += cluster_size;
				goto next;
			}

			if (__is_valid_data_blkaddr(blkaddr))
				continue;

			dn->data_blkaddr = NEW_ADDR;
			f2fs_set_data_blkaddr(dn);
		}
#endif
		reserved_blocks += reserved;
next:
		count -= cluster_size;
	}

	return reserved_blocks;
}

#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
static int f2fs_recover_reserved_blocks(struct inode *inode, pgoff_t recover_idx, pgoff_t recover_extend)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	pgoff_t page_idx = 0, page_end = 0;
	unsigned int released_blocks = 0;
	unsigned int recover_extend_blocks = 0;
	int ret = 0;

	page_end = min(recover_idx + recover_extend, (unsigned long)
			DIV_ROUND_UP(i_size_read(inode), PAGE_SIZE));

	while (page_idx < page_end) {
		pgoff_t end_offset, count;
		struct dnode_of_data dn;

		set_new_dnode(&dn, inode, NULL, NULL, 0);
		ret = f2fs_get_dnode_of_data(&dn, page_idx, LOOKUP_NODE);
		if (ret) {
			if (ret == -ENOENT) {
				page_idx = f2fs_get_next_page_offset(&dn, page_idx);
				page_idx = round_up(page_idx, F2FS_I(inode)->i_cluster_size);
				ret = 0;
				continue;
			}
			break;
		}
		end_offset = ADDRS_PER_PAGE(dn.node_page, inode);
		count = min(end_offset - dn.ofs_in_node, page_end - page_idx);
		count = round_down(count, F2FS_I(inode)->i_cluster_size);

		ret = release_compress_blocks(&dn, count);
		f2fs_put_dnode(&dn);
		f2fs_bug_on(sbi, ret < 0);

		if (page_idx >= recover_idx)
			recover_extend_blocks += ret;

		if (count != 0)
			page_idx += count;
		else
			page_idx += F2FS_I(inode)->i_cluster_size;

		released_blocks += ret;
	}

	f2fs_compress_err("recover reserve blocks, ino %lu, ridx %lu, rblk %u, "
		"eidx %lu, eblk %u, cblk %u", inode->i_ino, recover_idx, released_blocks,
		page_end, recover_extend_blocks, atomic_read(&F2FS_I(inode)->i_compr_blocks));

	return released_blocks - recover_extend_blocks;
}
#endif

#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
int f2fs_do_reserve_compress_blocks(struct inode *inode, enum COMP_RESV_USAGE usage)
{
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	pgoff_t page_idx = 0, page_end;
	unsigned int reserved_blocks = 0;
	int ret = 0;

	if (!f2fs_sb_has_compression(F2FS_I_SB(inode)))
		return -EOPNOTSUPP;

	if (f2fs_readonly(sbi->sb))
		return -EROFS;

	if (!f2fs_compressed_file(inode))
		return -EINVAL;

	f2fs_compress_info("start, ino %lu, cblk %u, iblk %llu, usage %u",
		inode->i_ino, atomic_read(&F2FS_I(inode)->i_compr_blocks), inode->i_blocks, usage);

	if (atomic_read(&F2FS_I(inode)->i_compr_blocks))
		goto out;

	f2fs_balance_fs(F2FS_I_SB(inode), true);

	if (!is_inode_flag_set(inode, FI_COMPRESS_RELEASED)) {
		ret = -EINVAL;
		goto out;
	}

	f2fs_down_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);
	f2fs_down_write(&F2FS_I(inode)->i_mmap_sem);
	f2fs_lock_op(sbi);

	page_end = DIV_ROUND_UP(i_size_read(inode), PAGE_SIZE);
	while (page_idx < page_end) {
		pgoff_t end_offset, count;
		struct dnode_of_data dn;

		set_new_dnode(&dn, inode, NULL, NULL, 0);
		ret = f2fs_get_dnode_of_data(&dn, page_idx, LOOKUP_NODE);
		if (ret) {
			if (ret == -ENOENT) {
				page_idx = f2fs_get_next_page_offset(&dn, page_idx);
				page_idx = round_up(page_idx, F2FS_I(inode)->i_cluster_size);
				ret = 0;
				continue;
			}
			break;
		}

		end_offset = ADDRS_PER_PAGE(dn.node_page, inode);
		count = min(end_offset - dn.ofs_in_node, page_end - page_idx);
		count = round_down(count, F2FS_I(inode)->i_cluster_size);

		ret = reserve_compress_blocks(&dn, count);
		f2fs_put_dnode(&dn);

		if (ret < 0)
			break;

		if (count != 0)
			page_idx += count;
		else
			page_idx += F2FS_I(inode)->i_cluster_size;

		reserved_blocks += ret;
	}

	if (ret < 0 && reserved_blocks && atomic_read(&F2FS_I(inode)->i_compr_blocks))
		reserved_blocks -= f2fs_recover_reserved_blocks(inode, page_idx, 0);

	if (ret >= 0) {
		clear_inode_flag(inode, FI_COMPRESS_RELEASED);
		inode->i_ctime = current_time(inode);
		f2fs_mark_inode_dirty_sync(inode, true);
	}

	f2fs_unlock_op(sbi);
	f2fs_up_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);
	f2fs_up_write(&F2FS_I(inode)->i_mmap_sem);

out:
	f2fs_bd_compr_op_record(inode, F2FS_RESERVE, usage, (ret < 0));
	if (ret >= 0) {
		f2fs_compress_info("end, ino %lu, cblk %u, iblk %llu, usage %u, ret %d",inode->i_ino,
			atomic_read(&F2FS_I(inode)->i_compr_blocks), inode->i_blocks, usage, ret);
		ret = 0;
	} else if (reserved_blocks &&
			atomic_read(&F2FS_I(inode)->i_compr_blocks)) {
		set_sbi_flag(sbi, SBI_NEED_FSCK);
		f2fs_warn(sbi, "%s: partial blocks were released i_ino=%lx "
			"iblocks=%llu, reserved=%u, compr_blocks=%u, "
			"run fsck to fix.",
			__func__, inode->i_ino, inode->i_blocks,
			reserved_blocks,
			atomic_read(&F2FS_I(inode)->i_compr_blocks));
		f2fs_compress_err("partial released, ino %lu, iblk %llu, rev %u, "
			"cblk %u, usage %u", inode->i_ino,SECTOR_TO_BLOCK(inode->i_blocks),
			reserved_blocks, atomic_read(&F2FS_I(inode)->i_compr_blocks), usage);
		f2fs_compress_bd_report(sbi, inode, BD_RESV, usage, ret);
	}

	return ret;
}
#endif

static int f2fs_reserve_compress_blocks(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	pgoff_t page_idx = 0, last_idx;
	unsigned int reserved_blocks = 0;
	int ret;

	if (!f2fs_sb_has_compression(F2FS_I_SB(inode)))
		return -EOPNOTSUPP;

	if (!f2fs_compressed_file(inode))
		return -EINVAL;

	if (f2fs_readonly(sbi->sb))
		return -EROFS;

#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
	ret = dquot_initialize(inode);
	if (ret) {
		f2fs_compress_err("dquot init failed, ino %lu, file %s",
			inode->i_ino, filp->f_path.dentry->d_name.name);
		return ret;
	}
#endif

	ret = mnt_want_write_file(filp);
	if (ret)
		return ret;

	if (atomic_read(&F2FS_I(inode)->i_compr_blocks))
		goto out;

	f2fs_balance_fs(F2FS_I_SB(inode), true);

	inode_lock(inode);

	if (!is_inode_flag_set(inode, FI_COMPRESS_RELEASED)) {
		ret = -EINVAL;
		goto unlock_inode;
	}

	f2fs_down_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);
	f2fs_down_write(&F2FS_I(inode)->i_mmap_sem);
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
	f2fs_lock_op(sbi);
#endif

	last_idx = DIV_ROUND_UP(i_size_read(inode), PAGE_SIZE);

	while (page_idx < last_idx) {
		struct dnode_of_data dn;
		pgoff_t end_offset, count;

		set_new_dnode(&dn, inode, NULL, NULL, 0);
		ret = f2fs_get_dnode_of_data(&dn, page_idx, LOOKUP_NODE);
		if (ret) {
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
			f2fs_compress_info("get dnode info failed, ino %lu, idx %lu, ret %d, file %s",
				inode->i_ino, page_idx, ret, filp->f_path.dentry->d_name.name);
#endif

			if (ret == -ENOENT) {
				page_idx = f2fs_get_next_page_offset(&dn,
								page_idx);
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
				page_idx = round_up(page_idx, F2FS_I(inode)->i_cluster_size);
				f2fs_compress_info("hole addr goto next, ino %lu, next_idx %lu, file %s",
					inode->i_ino, page_idx, filp->f_path.dentry->d_name.name);
#endif
				ret = 0;
				continue;
			}
			break;
		}

		end_offset = ADDRS_PER_PAGE(dn.node_page, inode);
		count = min(end_offset - dn.ofs_in_node, last_idx - page_idx);
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
		count = round_down(count, F2FS_I(inode)->i_cluster_size);
#else
		count = round_up(count, F2FS_I(inode)->i_cluster_size);
#endif

		ret = reserve_compress_blocks(&dn, count);
		f2fs_put_dnode(&dn);

		if (ret < 0)
			break;
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
		if (count != 0)
			page_idx += count;
		else
			page_idx += F2FS_I(inode)->i_cluster_size;
#else
		page_idx += count;
#endif
		reserved_blocks += ret;
	}

#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
	if (ret < 0 && reserved_blocks && atomic_read(&F2FS_I(inode)->i_compr_blocks))
		reserved_blocks -= f2fs_recover_reserved_blocks(inode, page_idx, 0);
#endif

	if (ret >= 0) {
		clear_inode_flag(inode, FI_COMPRESS_RELEASED);
		inode->i_ctime = current_time(inode);
		f2fs_mark_inode_dirty_sync(inode, true);
	}

#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
	f2fs_unlock_op(sbi);
#endif
	f2fs_up_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);
	f2fs_up_write(&F2FS_I(inode)->i_mmap_sem);


unlock_inode:
	inode_unlock(inode);
out:
	mnt_drop_write_file(filp);

	if (ret >= 0) {
		ret = put_user(reserved_blocks, (u64 __user *)arg);
	} else if (reserved_blocks &&
			atomic_read(&F2FS_I(inode)->i_compr_blocks)) {
		set_sbi_flag(sbi, SBI_NEED_FSCK);
		f2fs_warn(sbi, "%s: partial blocks were released i_ino=%lx "
			"iblocks=%llu, reserved=%u, compr_blocks=%u, "
			"run fsck to fix.",
			__func__, inode->i_ino, inode->i_blocks,
			reserved_blocks,
			atomic_read(&F2FS_I(inode)->i_compr_blocks));
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
		f2fs_compress_err("partial released, ino %lu, iblk %llu, rev %u, "
			"cblk %u, file %s", inode->i_ino,SECTOR_TO_BLOCK(inode->i_blocks),
			reserved_blocks, atomic_read(&F2FS_I(inode)->i_compr_blocks),
			filp->f_path.dentry->d_name.name);
		f2fs_compress_bd_report(sbi, inode, BD_RESV, 0, ret);
#endif
	}

	return ret;
}

static int f2fs_secure_erase(struct block_device *bdev, struct inode *inode,
		pgoff_t off, block_t block, block_t len, u32 flags)
{
	struct request_queue *q = bdev_get_queue(bdev);
	sector_t sector = SECTOR_FROM_BLOCK(block);
	sector_t nr_sects = SECTOR_FROM_BLOCK(len);
	int ret = 0;

	if (!q)
		return -ENXIO;

	if (flags & F2FS_TRIM_FILE_DISCARD)
		ret = blkdev_issue_discard(bdev, sector, nr_sects, GFP_NOFS,
						blk_queue_secure_erase(q) ?
						BLKDEV_DISCARD_SECURE : 0);

	if (!ret && (flags & F2FS_TRIM_FILE_ZEROOUT)) {
		if (IS_ENCRYPTED(inode))
			ret = fscrypt_zeroout_range(inode, off, block, len);
		else
			ret = blkdev_issue_zeroout(bdev, sector, nr_sects,
					GFP_NOFS, 0);
	}

	return ret;
}

static int f2fs_sec_trim_file(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct address_space *mapping = inode->i_mapping;
	struct block_device *prev_bdev = NULL;
	struct f2fs_sectrim_range range;
	pgoff_t index, pg_end, prev_index = 0;
	block_t prev_block = 0, len = 0;
	loff_t end_addr;
	bool to_end = false;
	int ret = 0;

	if (!(filp->f_mode & FMODE_WRITE))
		return -EBADF;

	if (copy_from_user(&range, (struct f2fs_sectrim_range __user *)arg,
				sizeof(range)))
		return -EFAULT;

	if (range.flags == 0 || (range.flags & ~F2FS_TRIM_FILE_MASK) ||
			!S_ISREG(inode->i_mode))
		return -EINVAL;

	if (((range.flags & F2FS_TRIM_FILE_DISCARD) &&
			!f2fs_hw_support_discard(sbi)) ||
			((range.flags & F2FS_TRIM_FILE_ZEROOUT) &&
			 IS_ENCRYPTED(inode) && f2fs_is_multi_device(sbi)))
		return -EOPNOTSUPP;

	file_start_write(filp);
	inode_lock(inode);

#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
	if (f2fs_compressed_file(inode))
		f2fs_do_decompress_file(inode, DECOMP_SEC_TRIM_FILE);
#endif

	if (f2fs_is_atomic_file(inode) || f2fs_compressed_file(inode) ||
			range.start >= inode->i_size) {
		ret = -EINVAL;
		goto err;
	}

#ifdef CONFIG_F2FS_FS_SIS_DISK
	remove_data_coincide_flag(inode);
	if (f2fs_is_dummy_inode(inode)) {
		ret = f2fs_recover_sis_inode(inode, __func__);
		if (ret) {
			f2fs_err(F2FS_I_SB(inode), "[sis]: inode[%lu], recover err, "
				"err = %d", inode->i_ino, ret);
			goto out;
		}
	}
#endif

	if (range.len == 0)
		goto err;

	if (inode->i_size - range.start > range.len) {
		end_addr = range.start + range.len;
	} else {
		end_addr = range.len == (u64)-1 ?
			sbi->sb->s_maxbytes : inode->i_size;
		to_end = true;
	}

	if (!IS_ALIGNED(range.start, F2FS_BLKSIZE) ||
			(!to_end && !IS_ALIGNED(end_addr, F2FS_BLKSIZE))) {
		ret = -EINVAL;
		goto err;
	}

	index = F2FS_BYTES_TO_BLK(range.start);
	pg_end = DIV_ROUND_UP(end_addr, F2FS_BLKSIZE);

	ret = f2fs_convert_inline_inode(inode);
	if (ret)
		goto err;

	f2fs_down_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);
	f2fs_down_write(&F2FS_I(inode)->i_mmap_sem);

	ret = filemap_write_and_wait_range(mapping, range.start,
			to_end ? LLONG_MAX : end_addr - 1);
	if (ret)
		goto out;

	truncate_inode_pages_range(mapping, range.start,
			to_end ? -1 : end_addr - 1);

	while (index < pg_end) {
		struct dnode_of_data dn;
		pgoff_t end_offset, count;
		int i;

		set_new_dnode(&dn, inode, NULL, NULL, 0);
		ret = f2fs_get_dnode_of_data(&dn, index, LOOKUP_NODE);
		if (ret) {
			if (ret == -ENOENT) {
				index = f2fs_get_next_page_offset(&dn, index);
				continue;
			}
			goto out;
		}

		end_offset = ADDRS_PER_PAGE(dn.node_page, inode);
		count = min(end_offset - dn.ofs_in_node, pg_end - index);
		for (i = 0; i < count; i++, index++, dn.ofs_in_node++) {
			struct block_device *cur_bdev;
			block_t blkaddr = f2fs_data_blkaddr(&dn);

			if (!__is_valid_data_blkaddr(blkaddr))
				continue;

			if (!f2fs_is_valid_blkaddr(sbi, blkaddr,
						DATA_GENERIC_ENHANCE)) {
				ret = -EFSCORRUPTED;
				f2fs_put_dnode(&dn);
				goto out;
			}

			cur_bdev = f2fs_target_device(sbi, blkaddr, NULL);
			if (f2fs_is_multi_device(sbi)) {
				int di = f2fs_target_device_index(sbi, blkaddr);

				blkaddr -= FDEV(di).start_blk;
			}

			if (len) {
				if (prev_bdev == cur_bdev &&
						index == prev_index + len &&
						blkaddr == prev_block + len) {
					len++;
				} else {
					ret = f2fs_secure_erase(prev_bdev,
						inode, prev_index, prev_block,
						len, range.flags);
					if (ret) {
						f2fs_put_dnode(&dn);
						goto out;
					}

					len = 0;
				}
			}

			if (!len) {
				prev_bdev = cur_bdev;
				prev_index = index;
				prev_block = blkaddr;
				len = 1;
			}
		}

		f2fs_put_dnode(&dn);

		if (fatal_signal_pending(current)) {
			ret = -EINTR;
			goto out;
		}
		cond_resched();
	}

	if (len)
		ret = f2fs_secure_erase(prev_bdev, inode, prev_index,
				prev_block, len, range.flags);
out:
	f2fs_up_write(&F2FS_I(inode)->i_mmap_sem);
	f2fs_up_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);
err:
	inode_unlock(inode);
	file_end_write(filp);

	return ret;
}

static int f2fs_ioc_get_compress_option(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct f2fs_comp_option option;

	if (!f2fs_sb_has_compression(F2FS_I_SB(inode)))
		return -EOPNOTSUPP;

	inode_lock_shared(inode);

	if (!f2fs_compressed_file(inode)) {
		inode_unlock_shared(inode);
		return -ENODATA;
	}

	option.algorithm = F2FS_I(inode)->i_compress_algorithm;
	option.log_cluster_size = F2FS_I(inode)->i_log_cluster_size;

	inode_unlock_shared(inode);

	if (copy_to_user((struct f2fs_comp_option __user *)arg, &option,
				sizeof(option)))
		return -EFAULT;

	return 0;
}

static int f2fs_ioc_set_compress_option(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct f2fs_comp_option option;
	int ret = 0;

	if (!f2fs_sb_has_compression(sbi))
		return -EOPNOTSUPP;

	if (!(filp->f_mode & FMODE_WRITE))
		return -EBADF;

	if (copy_from_user(&option, (struct f2fs_comp_option __user *)arg,
				sizeof(option)))
		return -EFAULT;

	if (option.log_cluster_size < MIN_COMPRESS_LOG_SIZE ||
			option.log_cluster_size > MAX_COMPRESS_LOG_SIZE ||
			option.algorithm >= COMPRESS_MAX)
		return -EINVAL;

	file_start_write(filp);
	inode_lock(inode);

#ifdef CONFIG_F2FS_FS_SIS_DISK
	if (f2fs_is_sis_inode(inode)) {
		ret = -EACCES;
		goto out;
	}
#endif

#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
	if ((f2fs_compressed_file(inode) && (F2FS_HAS_BLOCKS(inode) ||
		f2fs_is_mmap_file(inode) || get_dirty_pages(inode))) ||
		is_inode_flag_set(inode, FI_COMPRESS_RELEASED) ||
		atomic_read(&F2FS_I(inode)->i_compr_blocks)) {
		ret =  -EINVAL;
		goto out;
	}
#else
	if (f2fs_is_mmap_file(inode) || get_dirty_pages(inode)) {
		ret = -EBUSY;
		goto out;
	}

	if (inode->i_size != 0) {
		ret = -EFBIG;
		goto out;
	}
#endif

	F2FS_I(inode)->i_compress_algorithm = option.algorithm;
	F2FS_I(inode)->i_log_cluster_size = option.log_cluster_size;
	F2FS_I(inode)->i_cluster_size = 1 << option.log_cluster_size;
	f2fs_mark_inode_dirty_sync(inode, true);

	if (!f2fs_is_compress_backend_ready(inode))
		f2fs_warn(sbi, "compression algorithm is successfully set, "
			"but current kernel doesn't support this algorithm.");
out:
	inode_unlock(inode);
	file_end_write(filp);

	return ret;
}

static int redirty_blocks(struct inode *inode, pgoff_t page_idx, int len)
{
	DEFINE_READAHEAD(ractl, NULL, inode->i_mapping, page_idx);
	struct address_space *mapping = inode->i_mapping;
	struct page *page;
	pgoff_t redirty_idx = page_idx;
	int i, page_len = 0, ret = 0;

	page_cache_ra_unbounded(&ractl, len, 0);

	for (i = 0; i < len; i++, page_idx++) {
		page = read_cache_page(mapping, page_idx, NULL, NULL);
		if (IS_ERR(page)) {
			ret = PTR_ERR(page);
			break;
		}
		page_len++;
	}

	for (i = 0; i < page_len; i++, redirty_idx++) {
		page = find_lock_page(mapping, redirty_idx);
		if (!page) {
			ret = -ENOMEM;
			break;
		}
		set_page_dirty(page);
		f2fs_put_page(page, 1);
		f2fs_put_page(page, 0);
	}

	return ret;
}

#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
int f2fs_decompress_inode(struct inode *inode)
{
	int ret = 0, count = 0;
	pgoff_t page_idx = 0, last_idx;
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct f2fs_inode_info *fi = F2FS_I(inode);
	int cluster_size = F2FS_I(inode)->i_cluster_size;
	unsigned int blk_per_seg = sbi->blocks_per_seg;

	ret = filemap_write_and_wait_range(inode->i_mapping, 0, LLONG_MAX);
	if (ret)
		return ret;

	if (!atomic_read(&fi->i_compr_blocks) ||
		is_inode_flag_set(inode, FI_COMPRESS_RELEASED))
		return 0;

	page_idx = 0;
	last_idx = DIV_ROUND_UP(i_size_read(inode), PAGE_SIZE);

	count = last_idx - page_idx;
	while (count) {
		int len = min(cluster_size, count);
		ret = redirty_blocks(inode, page_idx, len);

		if (ret < 0) {
			f2fs_compress_err("redirty blocks failed, ino %lu, idx %lu,"
						" len %u, ret %d", inode->i_ino, page_idx, len, ret);
			break;
		}

		if (get_dirty_pages(inode) >= blk_per_seg)
			filemap_fdatawrite(inode->i_mapping);

		count -= len;
		page_idx += len;
	}
	if (!ret)
		ret = filemap_write_and_wait_range(inode->i_mapping, 0, LLONG_MAX);

	return ret;
}


int f2fs_do_decompress_file(struct inode *inode, enum DECOMPR_USAGE usage)
{
	int ret = 0;
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);

	if (!f2fs_sb_has_compression(sbi) ||
		F2FS_OPTION(sbi).compress_mode != COMPR_MODE_USER)
		return -EOPNOTSUPP;

	f2fs_compress_info("start, ino %lu, cblk %u, iblk %llu, comp %d, rel %d, usage %u",
			inode->i_ino, atomic_read(&F2FS_I(inode)->i_compr_blocks), inode->i_blocks,
			is_inode_flag_set(inode, FI_COMPRESSED_FILE),
			is_inode_flag_set(inode, FI_COMPRESS_RELEASED), usage);

	f2fs_balance_fs(F2FS_I_SB(inode), true);

	if (is_inode_flag_set(inode, FI_COMPRESS_RELEASED)) {
		ret = f2fs_do_reserve_compress_blocks(inode, COMP_DECOMPRESS);
		if (ret < 0)
			goto out;
	}

	ret = f2fs_decompress_inode(inode);
	if (ret) {
		f2fs_compress_bd_report(sbi, inode, BD_DECOMP, 0, ret);
		goto out;
	}

	if(!f2fs_disable_compressed_file(inode)) {
		f2fs_compress_err("disable compress failed, ino %lu, dirty %u,"
			"cblks %u, rel %u", inode->i_ino, get_dirty_pages(inode),
			atomic_read(&F2FS_I(inode)->i_compr_blocks),
			is_inode_flag_set(inode, FI_COMPRESS_RELEASED));
		f2fs_compress_bd_report(sbi, inode, BD_DECOMP, 0, 0);
		ret = -EIO;
	}

out:
	f2fs_bd_compr_op_record(inode, F2FS_DECOMPR, usage, (ret < 0));
	f2fs_compress_info("end, ino %lu, cblk %u, iblk %llu, comp %d, rel %d, usage %u, ret %d",
			inode->i_ino, atomic_read(&F2FS_I(inode)->i_compr_blocks), inode->i_blocks,
			is_inode_flag_set(inode, FI_COMPRESSED_FILE),
			is_inode_flag_set(inode, FI_COMPRESS_RELEASED), usage, ret);

	return ret;
}
#endif

static int f2fs_ioc_decompress_file(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct f2fs_inode_info *fi = F2FS_I(inode);
	pgoff_t page_idx = 0, last_idx;
	unsigned int blk_per_seg = sbi->blocks_per_seg;
	int cluster_size = F2FS_I(inode)->i_cluster_size;
	int count, ret;

	if (!f2fs_sb_has_compression(sbi) ||
			F2FS_OPTION(sbi).compress_mode != COMPR_MODE_USER)
		return -EOPNOTSUPP;

	if (!(filp->f_mode & FMODE_WRITE))
		return -EBADF;

	if (!f2fs_compressed_file(inode))
		return -EINVAL;

	f2fs_balance_fs(F2FS_I_SB(inode), true);

	file_start_write(filp);
	inode_lock(inode);

#ifdef CONFIG_F2FS_FS_SIS_DISK
	if (f2fs_is_sis_inode(inode)) {
		ret = -EACCES;
		goto out;
	}
#endif

	if (!f2fs_is_compress_backend_ready(inode)) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	if (is_inode_flag_set(inode, FI_COMPRESS_RELEASED)) {
		ret = -EINVAL;
		goto out;
	}

	ret = filemap_write_and_wait_range(inode->i_mapping, 0, LLONG_MAX);
	if (ret) {
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
		f2fs_compress_err("wait write failed, ino %lu, ret %d, file %s",
			inode->i_ino, ret, filp->f_path.dentry->d_name.name);
#endif
		goto out;
	}

	if (!atomic_read(&fi->i_compr_blocks))
		goto out;

	last_idx = DIV_ROUND_UP(i_size_read(inode), PAGE_SIZE);

	count = last_idx - page_idx;
	while (count) {
		int len = min(cluster_size, count);

		ret = redirty_blocks(inode, page_idx, len);
		if (ret < 0) {
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
			f2fs_compress_err("redirty blocks failed, ino %lu, ret %d, file %s",
				inode->i_ino, ret, filp->f_path.dentry->d_name.name);
#endif
			break;
		}

		if (get_dirty_pages(inode) >= blk_per_seg)
			filemap_fdatawrite(inode->i_mapping);

		count -= len;
		page_idx += len;
	}

	if (!ret) {
		ret = filemap_write_and_wait_range(inode->i_mapping, 0,
							LLONG_MAX);
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
		if (ret)
			f2fs_compress_err("redirty wait write failed, ino %lu, ret %d, file %s",
					inode->i_ino, ret, filp->f_path.dentry->d_name.name);
#endif
	}

	if (ret) {
		f2fs_warn(sbi, "%s: The file might be partially decompressed (errno=%d). Please delete the file.",
			  __func__, ret);
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
		f2fs_compress_err("partially decompress, ino %lu, ret %d, file %s",
			inode->i_ino, ret, filp->f_path.dentry->d_name.name);
		f2fs_compress_bd_report(sbi, inode, BD_DECOMP, 0, ret);
#endif
	}
out:
	inode_unlock(inode);
	file_end_write(filp);

	return ret;
}

static int f2fs_ioc_compress_file(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	pgoff_t page_idx = 0, last_idx;
	unsigned int blk_per_seg = sbi->blocks_per_seg;
	int cluster_size = F2FS_I(inode)->i_cluster_size;
	int count, ret;

	if (!f2fs_sb_has_compression(sbi) ||
			F2FS_OPTION(sbi).compress_mode != COMPR_MODE_USER)
		return -EOPNOTSUPP;

	if (!(filp->f_mode & FMODE_WRITE))
		return -EBADF;

	if (!f2fs_compressed_file(inode))
		return -EINVAL;

	f2fs_balance_fs(F2FS_I_SB(inode), true);

	file_start_write(filp);
	inode_lock(inode);

#ifdef CONFIG_F2FS_FS_SIS_DISK
	if (f2fs_is_sis_inode(inode)) {
		ret = -EACCES;
		goto out;
	}
#endif

	if (!f2fs_is_compress_backend_ready(inode)) {
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
		f2fs_compress_err("not support algorithm, ino %lu, file %s",
			inode->i_ino, filp->f_path.dentry->d_name.name);
#endif
		ret = -EOPNOTSUPP;
		goto out;
	}

	if (is_inode_flag_set(inode, FI_COMPRESS_RELEASED)) {
		ret = -EINVAL;
		goto out;
	}

	ret = filemap_write_and_wait_range(inode->i_mapping, 0, LLONG_MAX);
	if (ret) {
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
		f2fs_compress_err("wait write failed, ino %lu, file %s",
			inode->i_ino, filp->f_path.dentry->d_name.name);
#endif
		goto out;
	}

	set_inode_flag(inode, FI_ENABLE_COMPRESS);

	last_idx = DIV_ROUND_UP(i_size_read(inode), PAGE_SIZE);

	count = last_idx - page_idx;
	while (count) {
		int len = min(cluster_size, count);

		ret = redirty_blocks(inode, page_idx, len);
		if (ret < 0) {
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
			f2fs_compress_err("redirty blocks failed, ino %lu, ret %d, file %s",
				inode->i_ino, ret, filp->f_path.dentry->d_name.name);
#endif
			break;
		}

		if (get_dirty_pages(inode) >= blk_per_seg)
			filemap_fdatawrite(inode->i_mapping);

		count -= len;
		page_idx += len;
	}

	if (!ret) {
		ret = filemap_write_and_wait_range(inode->i_mapping, 0,
							LLONG_MAX);
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
		if (ret)
			f2fs_compress_err("redirty wait write failed, ino %lu, ret %d, file %s",
				inode->i_ino, ret, filp->f_path.dentry->d_name.name);
#endif
	}

	clear_inode_flag(inode, FI_ENABLE_COMPRESS);

	if (ret) {
		f2fs_warn(sbi, "%s: The file might be partially compressed (errno=%d). Please delete the file.",
			  __func__, ret);
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
		f2fs_compress_err("partially compressed, ino %lu, ret %d, file %s",
				inode->i_ino, ret, filp->f_path.dentry->d_name.name);
		f2fs_compress_bd_report(sbi, inode, BD_COMP, 0, ret);
#endif
	}
out:
	inode_unlock(inode);
	file_end_write(filp);

	return ret;
}

#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
static int f2fs_ioc_get_inode_struct(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct f2fs_inode_struct istruct;

	if (!f2fs_sb_has_compression(F2FS_I_SB(inode)))
		return -EOPNOTSUPP;

	inode_lock_shared(inode);

	istruct.addrs_per_inode = ADDRS_PER_INODE(inode);
	istruct.addrs_per_dnode = ADDRS_PER_BLOCK(inode);

	inode_unlock_shared(inode);

	if (copy_to_user((struct f2fs_inode_struct __user *)arg,
				&istruct, sizeof(istruct)))
		return -EFAULT;

	return 0;
}

static int f2fs_ioc_estimate_compress_rate(struct file *filp, unsigned long arg)
{
	struct inode *inode = file_inode(filp);
	struct f2fs_sb_info *sbi = F2FS_I_SB(inode);
	struct f2fs_comp_estimate estimate;
	unsigned long nr_cluster, cluster_idx, mask;
	block_t start, i, k;
	int ret = 0, saved_blocks = 0;
	struct page *page;
	DEFINE_READAHEAD(ractl, NULL, inode->i_mapping, 0);
	struct compress_ctx cc = {
		.inode = inode,
		.log_cluster_size = 0,
		.cluster_size = 0,
		.cluster_idx = NULL_CLUSTER,
		.rpages = NULL,
		.nr_rpages = 0,
		.cpages = NULL,
		.rbuf = NULL,
		.cbuf = NULL,
		.rlen = 0,
		.private = NULL,
	};

	if (!f2fs_sb_has_compression(sbi))
		return -EOPNOTSUPP;
	if (f2fs_compressed_file(inode))
		return -EBADF;
	if (copy_from_user(&estimate, (struct f2fs_comp_estimate __user *)arg,
		sizeof(struct f2fs_comp_estimate)))
		return -EFAULT;
	if (estimate.log_cluster_size < MIN_COMPRESS_LOG_SIZE ||
		estimate.log_cluster_size > MAX_COMPRESS_LOG_SIZE ||
		estimate.algorithm >= COMPRESS_MAX)
		return -EINVAL;

	cc.log_cluster_size = estimate.log_cluster_size;
	cc.cluster_size = 1 << estimate.log_cluster_size;
	cc.rlen = 1 << (PAGE_SHIFT + estimate.log_cluster_size);

	nr_cluster = (i_size_read(inode) + F2FS_BLKSIZE - 1) >>
			(F2FS_BLKSIZE_BITS + estimate.log_cluster_size);
	mask = (1 << estimate.log_sample_density) - 1;
	if (!(nr_cluster >> (1 + estimate.log_sample_density))) {
		estimate.compress_rate = 0;
		ret = -E2BIG;
		goto out_ret;
	}

	if (f2fs_init_compress_ctx(&cc))
		return -ENOMEM;

	inode_lock(inode);
	F2FS_I(inode)->i_compress_algorithm = estimate.algorithm;

	for (cluster_idx = 0; cluster_idx < nr_cluster;
		cluster_idx += (nr_cluster >> estimate.log_sample_density)) {
		start = cluster_idx << estimate.log_cluster_size;
		ractl._index = start;
		page_cache_ra_unbounded(&ractl, cc.cluster_size, 0);

		for (i = 0; i < cc.cluster_size; ++i) {
			page = read_cache_page(inode->i_mapping, start + i, NULL, NULL);
			if (IS_ERR(page)) {
				ret = PTR_ERR(page);
				goto err_out;
			}
			f2fs_compress_ctx_add_page(&cc, page);
		}

		ret = f2fs_compress_pages(&cc);
		if (ret) {
			if (ret == -EAGAIN)
				goto free_rpages;
			else
				goto err_out;
		}

		saved_blocks += cc.cluster_size - cc.valid_nr_cpages;

		for (k = 0; k < cc.nr_cpages; ++k) {
			f2fs_compress_free_page(cc.cpages[k]);
			cc.cpages[k] = NULL;
		}

		page_array_free(cc.inode, cc.cpages, cc.nr_cpages);
free_rpages:
		for (i = 0; i < cc.cluster_size; ++i) {
			page = cc.rpages[i];
			put_page(page);
			cc.rpages[i] = NULL;
		}
		cc.nr_rpages = 0;
		cc.cluster_idx = NULL_CLUSTER;
	}

	F2FS_I(inode)->i_compress_algorithm = 0;
	inode_unlock(inode);

	f2fs_destroy_compress_ctx(&cc, false);
	estimate.compress_rate = DIV_ROUND_UP_ULL(saved_blocks << 14,
			cc.cluster_size * (!!(nr_cluster & mask) + (1 << estimate.log_sample_density)));

out_ret:
	if (copy_to_user((struct f2fs_comp_estimate __user *)arg, &estimate,
		sizeof(struct f2fs_comp_estimate)))
		return -EFAULT;
	return ret;

err_out:
	F2FS_I(inode)->i_compress_algorithm = 0;
	inode_unlock(inode);
	for (k = 0; k < i; ++k) {
		page = cc.rpages[k];
		put_page(page);
	}
	f2fs_destroy_compress_ctx(&cc, false);

	return ret;
}
#endif

static long __f2fs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case FS_IOC_GETFLAGS:
		return f2fs_ioc_getflags(filp, arg);
	case FS_IOC_SETFLAGS:
		return f2fs_ioc_setflags(filp, arg);
	case FS_IOC_GETVERSION:
		return f2fs_ioc_getversion(filp, arg);
	case F2FS_IOC_START_ATOMIC_WRITE:
		return f2fs_ioc_start_atomic_write(filp);
	case F2FS_IOC_COMMIT_ATOMIC_WRITE:
		return f2fs_ioc_commit_atomic_write(filp);
	case F2FS_IOC_START_VOLATILE_WRITE:
		return f2fs_ioc_start_volatile_write(filp);
	case F2FS_IOC_RELEASE_VOLATILE_WRITE:
		return f2fs_ioc_release_volatile_write(filp);
	case F2FS_IOC_ABORT_VOLATILE_WRITE:
		return f2fs_ioc_abort_volatile_write(filp);
	case F2FS_IOC_SHUTDOWN:
		return f2fs_ioc_shutdown(filp, arg);
	case FITRIM:
		return f2fs_ioc_fitrim(filp, arg);
	case FS_IOC_SET_ENCRYPTION_POLICY:
		return f2fs_ioc_set_encryption_policy(filp, arg);
	case FS_IOC_GET_ENCRYPTION_POLICY:
		return f2fs_ioc_get_encryption_policy(filp, arg);
	case FS_IOC_GET_ENCRYPTION_PWSALT:
		return f2fs_ioc_get_encryption_pwsalt(filp, arg);
	case FS_IOC_GET_ENCRYPTION_POLICY_EX:
		return f2fs_ioc_get_encryption_policy_ex(filp, arg);
	case FS_IOC_ADD_ENCRYPTION_KEY:
		return f2fs_ioc_add_encryption_key(filp, arg);
	case FS_IOC_REMOVE_ENCRYPTION_KEY:
		return f2fs_ioc_remove_encryption_key(filp, arg);
	case FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS:
		return f2fs_ioc_remove_encryption_key_all_users(filp, arg);
	case FS_IOC_GET_ENCRYPTION_KEY_STATUS:
		return f2fs_ioc_get_encryption_key_status(filp, arg);
	case FS_IOC_GET_ENCRYPTION_NONCE:
		return f2fs_ioc_get_encryption_nonce(filp, arg);
	case F2FS_IOC_GARBAGE_COLLECT:
		return f2fs_ioc_gc(filp, arg);
	case F2FS_IOC_GARBAGE_COLLECT_RANGE:
		return f2fs_ioc_gc_range(filp, arg);
	case F2FS_IOC_WRITE_CHECKPOINT:
		return f2fs_ioc_write_checkpoint(filp, arg);
	case F2FS_IOC_DEFRAGMENT:
		return f2fs_ioc_defragment(filp, arg);
	case F2FS_IOC_MOVE_RANGE:
		return f2fs_ioc_move_range(filp, arg);
	case F2FS_IOC_FLUSH_DEVICE:
		return f2fs_ioc_flush_device(filp, arg);
	case F2FS_IOC_GET_FEATURES:
		return f2fs_ioc_get_features(filp, arg);
	case FS_IOC_FSGETXATTR:
		return f2fs_ioc_fsgetxattr(filp, arg);
	case FS_IOC_FSSETXATTR:
		return f2fs_ioc_fssetxattr(filp, arg);
	case F2FS_IOC_GET_PIN_FILE:
		return f2fs_ioc_get_pin_file(filp, arg);
	case F2FS_IOC_SET_PIN_FILE:
		return f2fs_ioc_set_pin_file(filp, arg);
	case F2FS_IOC_PRECACHE_EXTENTS:
		return f2fs_ioc_precache_extents(filp, arg);
	case F2FS_IOC_RESIZE_FS:
		return f2fs_ioc_resize_fs(filp, arg);
	case FS_IOC_ENABLE_VERITY:
		return f2fs_ioc_enable_verity(filp, arg);
	case FS_IOC_MEASURE_VERITY:
		return f2fs_ioc_measure_verity(filp, arg);
	case FS_IOC_READ_VERITY_METADATA:
		return f2fs_ioc_read_verity_metadata(filp, arg);
	case FS_IOC_GETFSLABEL:
		return f2fs_ioc_getfslabel(filp, arg);
	case FS_IOC_SETFSLABEL:
		return f2fs_ioc_setfslabel(filp, arg);
	case F2FS_IOC_GET_COMPRESS_BLOCKS:
		return f2fs_get_compress_blocks(filp, arg);
	case F2FS_IOC_RELEASE_COMPRESS_BLOCKS:
		return f2fs_release_compress_blocks(filp, arg);
	case F2FS_IOC_RESERVE_COMPRESS_BLOCKS:
		return f2fs_reserve_compress_blocks(filp, arg);
	case F2FS_IOC_SEC_TRIM_FILE:
		return f2fs_sec_trim_file(filp, arg);
	case F2FS_IOC_GET_COMPRESS_OPTION:
		return f2fs_ioc_get_compress_option(filp, arg);
	case F2FS_IOC_SET_COMPRESS_OPTION:
		return f2fs_ioc_set_compress_option(filp, arg);
	case F2FS_IOC_DECOMPRESS_FILE:
		return f2fs_ioc_decompress_file(filp, arg);
	case F2FS_IOC_COMPRESS_FILE:
		return f2fs_ioc_compress_file(filp, arg);
#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
	case F2FS_IOC_ESTIMATE_COMPRESS_RATE:
		return f2fs_ioc_estimate_compress_rate(filp, arg);
	case F2FS_IOC_GET_INODE_STRUCT:
		return f2fs_ioc_get_inode_struct(filp, arg);
#endif
#ifdef CONFIG_F2FS_FS_SIS_DISK
	case F2FS_IOC_SIS_CONNECT:
		return f2fs_ioc_sis_connect_hidden(filp, arg);
	case F2FS_IOC_SIS_DEDUP:
		return f2fs_ioc_sis_dedup_file(filp, arg);
	case F2FS_IOC_SIS_RECOVER:
		return f2fs_ioc_sis_recover_file(filp, arg);
	case F2FS_IOC_SIS_DUP:
		return f2fs_ioc_dup_file(filp, arg);
	case F2FS_IOC_SIS_COINCIDE_FLAG:
		return f2fs_ioc_coincide_flag(filp, arg);
	case F2FS_IOC_SIS_PRE_CHECK:
		return f2fs_ioc_sis_pre_check(filp, arg);
	case F2FS_IOC_SIS_GET_FILE_INFO:
		return f2fs_ioc_sis_get_file_info(filp, arg);
#endif
	default:
		return -ENOTTY;
	}
}

long f2fs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	if (unlikely(f2fs_cp_error(F2FS_I_SB(file_inode(filp)))))
		return -EIO;
	if (!f2fs_is_checkpoint_ready(F2FS_I_SB(file_inode(filp))))
		return -ENOSPC;

	return __f2fs_ioctl(filp, cmd, arg);
}

static ssize_t f2fs_file_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	int ret;

#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
	if (f2fs_compressed_file(inode))
		inc_cbd_val(F2FS_I_SB(inode), compr_info, access_cnt, 1);
#endif
	if (!f2fs_is_compress_backend_ready(inode))
		return -EOPNOTSUPP;

	ret = generic_file_read_iter(iocb, iter);

	if (ret > 0)
		f2fs_update_iostat(F2FS_I_SB(inode), APP_READ_IO, ret);

	return ret;
}

static ssize_t f2fs_file_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct file *file = iocb->ki_filp;
	struct inode *inode = file_inode(file);
	ssize_t ret;

	if (unlikely(f2fs_cp_error(F2FS_I_SB(inode)))) {
		ret = -EIO;
		goto out;
	}

	if (!f2fs_is_compress_backend_ready(inode)) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	if (iocb->ki_flags & IOCB_NOWAIT) {
		if (!inode_trylock(inode)) {
			ret = -EAGAIN;
			goto out;
		}
	} else {
		inode_lock(inode);
	}

	if (unlikely(IS_IMMUTABLE(inode))) {
		ret = -EPERM;
		goto unlock;
	}

#ifdef CONFIG_F2FS_FS_COMPRESSION_OPTM
	if (is_inode_flag_set(inode, FI_COMPRESS_RELEASED)) {
		ret = f2fs_do_reserve_compress_blocks(inode, COMP_FILE_WRITE);

		if (is_inode_flag_set(inode, FI_COMPRESS_RELEASED))
			BUG_ON(atomic_read(&F2FS_I(inode)->i_compr_blocks));

		if (ret < 0) {
			f2fs_compress_err("reserve file failed, ino %lu, ret %d", inode->i_ino, ret);
			goto unlock;
		}
	}
#else
	if (is_inode_flag_set(inode, FI_COMPRESS_RELEASED)) {
		ret = -EPERM;
		goto unlock;
	}
#endif

#ifdef CONFIG_F2FS_FS_SIS_DISK
	remove_data_coincide_flag(inode);
	if (f2fs_is_dummy_inode(inode)) {
		ret = f2fs_recover_sis_inode(inode, __func__);
		if (ret) {
			f2fs_err(F2FS_I_SB(inode), "[sis]: inode[%lu], recover err, err = %d", inode->i_ino, ret);
			inode_unlock(inode);
			goto out;
		}
	}
#endif


	ret = generic_write_checks(iocb, from);
	if (ret > 0) {
		bool preallocated = false;
		size_t target_size = 0;
		int err;

		if (iov_iter_fault_in_readable(from, iov_iter_count(from)))
			set_inode_flag(inode, FI_NO_PREALLOC);

		if ((iocb->ki_flags & IOCB_NOWAIT)) {
			if (!f2fs_overwrite_io(inode, iocb->ki_pos,
						iov_iter_count(from)) ||
				f2fs_has_inline_data(inode) ||
				f2fs_force_buffered_io(inode, iocb, from)) {
				clear_inode_flag(inode, FI_NO_PREALLOC);
				inode_unlock(inode);
				ret = -EAGAIN;
				goto out;
			}
			goto write;
		}

		if (is_inode_flag_set(inode, FI_NO_PREALLOC))
			goto write;

		if (iocb->ki_flags & IOCB_DIRECT) {
			/*
			 * Convert inline data for Direct I/O before entering
			 * f2fs_direct_IO().
			 */
			err = f2fs_convert_inline_inode(inode);
			if (err)
				goto out_err;
			/*
			 * If force_buffere_io() is true, we have to allocate
			 * blocks all the time, since f2fs_direct_IO will fall
			 * back to buffered IO.
			 */
			if (!f2fs_force_buffered_io(inode, iocb, from) &&
					allow_outplace_dio(inode, iocb, from))
				goto write;
		}
		preallocated = true;
		target_size = iocb->ki_pos + iov_iter_count(from);

		err = f2fs_preallocate_blocks(iocb, from);
		if (err) {
out_err:
			clear_inode_flag(inode, FI_NO_PREALLOC);
			inode_unlock(inode);
			ret = err;
			goto out;
		}
write:
		ret = __generic_file_write_iter(iocb, from);
		clear_inode_flag(inode, FI_NO_PREALLOC);

		/* if we couldn't write data, we should deallocate blocks. */
		if (preallocated && i_size_read(inode) < target_size) {
			f2fs_down_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);
			f2fs_down_write(&F2FS_I(inode)->i_mmap_sem);
			f2fs_truncate(inode);
			f2fs_up_write(&F2FS_I(inode)->i_mmap_sem);
			f2fs_up_write(&F2FS_I(inode)->i_gc_rwsem[WRITE]);
		}

		if (ret > 0)
			f2fs_update_iostat(F2FS_I_SB(inode), APP_WRITE_IO, ret);
	}
unlock:
	inode_unlock(inode);
out:
	trace_f2fs_file_write_iter(inode, iocb->ki_pos,
					iov_iter_count(from), ret);
	if (ret > 0)
		ret = generic_write_sync(iocb, ret);
	return ret;
}

#ifdef CONFIG_COMPAT
struct compat_f2fs_gc_range {
	u32 sync;
	compat_u64 start;
	compat_u64 len;
};
#define F2FS_IOC32_GARBAGE_COLLECT_RANGE	_IOW(F2FS_IOCTL_MAGIC, 11,\
						struct compat_f2fs_gc_range)

static int f2fs_compat_ioc_gc_range(struct file *file, unsigned long arg)
{
	struct compat_f2fs_gc_range __user *urange;
	struct f2fs_gc_range range;
	int err;

	urange = compat_ptr(arg);
	err = get_user(range.sync, &urange->sync);
	err |= get_user(range.start, &urange->start);
	err |= get_user(range.len, &urange->len);
	if (err)
		return -EFAULT;

	return __f2fs_ioc_gc_range(file, &range);
}

struct compat_f2fs_move_range {
	u32 dst_fd;
	compat_u64 pos_in;
	compat_u64 pos_out;
	compat_u64 len;
};
#define F2FS_IOC32_MOVE_RANGE		_IOWR(F2FS_IOCTL_MAGIC, 9,	\
					struct compat_f2fs_move_range)

static int f2fs_compat_ioc_move_range(struct file *file, unsigned long arg)
{
	struct compat_f2fs_move_range __user *urange;
	struct f2fs_move_range range;
	int err;

	urange = compat_ptr(arg);
	err = get_user(range.dst_fd, &urange->dst_fd);
	err |= get_user(range.pos_in, &urange->pos_in);
	err |= get_user(range.pos_out, &urange->pos_out);
	err |= get_user(range.len, &urange->len);
	if (err)
		return -EFAULT;

	return __f2fs_ioc_move_range(file, &range);
}

long f2fs_compat_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	if (unlikely(f2fs_cp_error(F2FS_I_SB(file_inode(file)))))
		return -EIO;
	if (!f2fs_is_checkpoint_ready(F2FS_I_SB(file_inode(file))))
		return -ENOSPC;

	switch (cmd) {
	case FS_IOC32_GETFLAGS:
		cmd = FS_IOC_GETFLAGS;
		break;
	case FS_IOC32_SETFLAGS:
		cmd = FS_IOC_SETFLAGS;
		break;
	case FS_IOC32_GETVERSION:
		cmd = FS_IOC_GETVERSION;
		break;
	case F2FS_IOC32_GARBAGE_COLLECT_RANGE:
		return f2fs_compat_ioc_gc_range(file, arg);
	case F2FS_IOC32_MOVE_RANGE:
		return f2fs_compat_ioc_move_range(file, arg);
	case F2FS_IOC_START_ATOMIC_WRITE:
	case F2FS_IOC_COMMIT_ATOMIC_WRITE:
	case F2FS_IOC_START_VOLATILE_WRITE:
	case F2FS_IOC_RELEASE_VOLATILE_WRITE:
	case F2FS_IOC_ABORT_VOLATILE_WRITE:
	case F2FS_IOC_SHUTDOWN:
	case FITRIM:
	case FS_IOC_SET_ENCRYPTION_POLICY:
	case FS_IOC_GET_ENCRYPTION_PWSALT:
	case FS_IOC_GET_ENCRYPTION_POLICY:
	case FS_IOC_GET_ENCRYPTION_POLICY_EX:
	case FS_IOC_ADD_ENCRYPTION_KEY:
	case FS_IOC_REMOVE_ENCRYPTION_KEY:
	case FS_IOC_REMOVE_ENCRYPTION_KEY_ALL_USERS:
	case FS_IOC_GET_ENCRYPTION_KEY_STATUS:
	case FS_IOC_GET_ENCRYPTION_NONCE:
	case F2FS_IOC_GARBAGE_COLLECT:
	case F2FS_IOC_WRITE_CHECKPOINT:
	case F2FS_IOC_DEFRAGMENT:
	case F2FS_IOC_FLUSH_DEVICE:
	case F2FS_IOC_GET_FEATURES:
	case FS_IOC_FSGETXATTR:
	case FS_IOC_FSSETXATTR:
	case F2FS_IOC_GET_PIN_FILE:
	case F2FS_IOC_SET_PIN_FILE:
	case F2FS_IOC_PRECACHE_EXTENTS:
	case F2FS_IOC_RESIZE_FS:
	case FS_IOC_ENABLE_VERITY:
	case FS_IOC_MEASURE_VERITY:
	case FS_IOC_READ_VERITY_METADATA:
	case FS_IOC_GETFSLABEL:
	case FS_IOC_SETFSLABEL:
	case F2FS_IOC_GET_COMPRESS_BLOCKS:
	case F2FS_IOC_RELEASE_COMPRESS_BLOCKS:
	case F2FS_IOC_RESERVE_COMPRESS_BLOCKS:
	case F2FS_IOC_SEC_TRIM_FILE:
	case F2FS_IOC_GET_COMPRESS_OPTION:
	case F2FS_IOC_SET_COMPRESS_OPTION:
	case F2FS_IOC_DECOMPRESS_FILE:
	case F2FS_IOC_COMPRESS_FILE:
		break;
	default:
		return -ENOIOCTLCMD;
	}
	return __f2fs_ioctl(file, cmd, (unsigned long) compat_ptr(arg));
}
#endif

const struct file_operations f2fs_file_operations = {
	.llseek		= f2fs_llseek,
	.read_iter	= f2fs_file_read_iter,
	.write_iter	= f2fs_file_write_iter,
	.open		= f2fs_file_open,
	.release	= f2fs_release_file,
	.mmap		= f2fs_file_mmap,
	.flush		= f2fs_file_flush,
	.fsync		= f2fs_sync_file,
	.fallocate	= f2fs_fallocate,
	.unlocked_ioctl	= f2fs_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= f2fs_compat_ioctl,
#endif
	.splice_read	= generic_file_splice_read,
	.splice_write	= iter_file_splice_write,
};
