// SPDX-License-Identifier: GPL-2.0
// Copyright (C) 2020 Intel Corporation

#include <linux/debugfs.h>

#include "ufs-debugfs.h"
#include "ufshcd.h"

static struct dentry *ufs_debugfs_root;

void __init ufs_debugfs_init(void)
{
	ufs_debugfs_root = debugfs_create_dir("ufshcd", NULL);
}

void __exit ufs_debugfs_exit(void)
{
	debugfs_remove_recursive(ufs_debugfs_root);
}

static int ufs_debugfs_stats_show(struct seq_file *s, void *data)
{
	struct ufs_hba *hba = s->private;
	struct ufs_event_hist *e = hba->ufs_stats.event;

#define PRT(fmt, typ) \
	seq_printf(s, fmt, e[UFS_EVT_ ## typ].cnt)

	PRT("PHY Adapter Layer errors (except LINERESET): %llu\n", PA_ERR);
	PRT("Data Link Layer errors: %llu\n", DL_ERR);
	PRT("Network Layer errors: %llu\n", NL_ERR);
	PRT("Transport Layer errors: %llu\n", TL_ERR);
	PRT("Generic DME errors: %llu\n", DME_ERR);
	PRT("Auto-hibernate errors: %llu\n", AUTO_HIBERN8_ERR);
	PRT("IS Fatal errors (CEFES, SBFES, HCFES, DFES): %llu\n", FATAL_ERR);
	PRT("DME Link Startup errors: %llu\n", LINK_STARTUP_FAIL);
	PRT("PM Resume errors: %llu\n", RESUME_ERR);
	PRT("PM Suspend errors : %llu\n", SUSPEND_ERR);
	PRT("Logical Unit Resets: %llu\n", DEV_RESET);
	PRT("Host Resets: %llu\n", HOST_RESET);
	PRT("SCSI command aborts: %llu\n", ABORT);
#undef PRT
	return 0;
}
DEFINE_SHOW_ATTRIBUTE(ufs_debugfs_stats);

#ifdef CONFIG_HONOR_UFS_DSM
#undef CREATE_TRACE_POINTS
#include <trace/hooks/ufshcd.h>

#define FLAG_DSM_UFS_UIC_CMD_ERR                                0x80000000
#define FLAG_DSM_UFS_ENTER_OR_EXIT_H8_ERR                       0x40000000
#define FLAG_DSM_UFS_UTP_ERR                                    0x20000000
#define FLAG_DSM_UFS_UIC_TRANS_ERR                              0x10000000
#define FLAG_DSM_UFS_LINKUP_ERR                                 0x08000000
#define FLAG_DSM_UFS_TIMEOUT_ERR                                0x04000000
#define FLAG_DSM_UFS_TIMEOUT_SERIOUS                            0x02000000
#define FLAG_DSM_UFS_SCSI_CMD_ERR                               0x01000000
#define FLAG_DSM_UFS_DEV_INTERNEL_ERR                           0x00800000
#define FLAG_DSM_UFS_HARDWARE_ERR                               0x00400000
#define FLAG_DSM_UFS_IO_TIMEOUT                                 0x00200000

static int dsm_ufs_show(struct seq_file *s, void *data)
{
	struct ufs_hba *hba = s->private;

	if (!hba)
		return -1;

	seq_printf(s, "DSM_UFS_TIMEOUT_ERR:928008007\n");
	hba->errors |= FLAG_DSM_UFS_TIMEOUT_ERR;
	seq_printf(s, "DSM_UFS_TIMEOUT_SERIOUS:928008014\n");
	hba->errors |= FLAG_DSM_UFS_TIMEOUT_SERIOUS;
	seq_printf(s, "DSM_UFS_UTP_ERR:928008008\n");
	hba->errors |= FLAG_DSM_UFS_UTP_ERR;
	seq_printf(s, "DSM_UFS_SCSI_CMD_ERR:928008009\n");
	hba->errors |= FLAG_DSM_UFS_SCSI_CMD_ERR;
	seq_printf(s, "DSM_UFS_DEV_INTERNEL_ERR:928008015\n");
	hba->errors |= FLAG_DSM_UFS_DEV_INTERNEL_ERR;
	seq_printf(s, "DSM_UFS_HARDWARE_ERR:928008018\n");
	hba->errors |= FLAG_DSM_UFS_HARDWARE_ERR;
	seq_printf(s, "DSM_UFS_LINKUP_ERR:928008011\n");
	hba->errors |= FLAG_DSM_UFS_LINKUP_ERR;
	seq_printf(s, "DSM_UFS_ENTER_OR_EXIT_H8_ERR:928008012\n");
	hba->errors |= FLAG_DSM_UFS_ENTER_OR_EXIT_H8_ERR;
	seq_printf(s, "DSM_UFS_IO_TIMEOUT:928008027\n");
	hba->errors |= FLAG_DSM_UFS_IO_TIMEOUT;

	trace_android_vh_ufs_check_int_errors(hba, true);

	return 0;
}

DEFINE_SHOW_ATTRIBUTE(dsm_ufs);
#endif

void ufs_debugfs_hba_init(struct ufs_hba *hba)
{
	hba->debugfs_root = debugfs_create_dir(dev_name(hba->dev), ufs_debugfs_root);
	debugfs_create_file("stats", 0400, hba->debugfs_root, hba, &ufs_debugfs_stats_fops);
#ifdef CONFIG_HONOR_UFS_DSM
	debugfs_create_file("dsm_ufs", 0400, hba->debugfs_root, hba, &dsm_ufs_fops);
#endif
}

void ufs_debugfs_hba_exit(struct ufs_hba *hba)
{
	debugfs_remove_recursive(hba->debugfs_root);
}
