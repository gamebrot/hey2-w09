/*
 * Copyright (c) Honor Device Co., Ltd. 2023-2023. All rights reserved.
 * Description: Get Storage Device Information
 * Author: Sun Xu
 * Create: 2023-03-10
 */

#include <micro_dump.h>
#include <linux/ctype.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/mm.h>

#define STG_TYPE_LENGTH 1
#define EMMC_MANFID_LENGTH 2
#define UFS_VER_LENGTH 4
#define EMMC_VER_LENGTH 6
#define UFS_MANFID_LENGTH 8
#define UFS_SIZE_LENGTH 9
#define DDR_INFO_LENGTH 20

static const char *MANFID_PATH = "/proc/bootdevice/manfid";
static const char *DEV_TYPR_PATH = "/proc/bootdevice/type";
static const char *EMMC_VER_PATH = "/sys/class/mmc_host/mmc0/mmc0:0001/fwrev";
static const char *UFS_VER_PATH = "/sys/class/scsi_device/0:0:0:0/device/rev";
static const char *UFS_SIZE_PATH = "/proc/bootdevice/size";
static const char *DDR_INFO_PATH = "/proc/ddr_info";
static const char *DDR_INFO_KEY = "0x";

static int get_node_info(const char *path, char *buf, int len)
{
	long fd;
	ssize_t ret;

	set_fs(KERNEL_DS);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,10,0)
	fd = micro_ksys_open(path, O_RDONLY, 0);
#else
	fd = micro_do_sys_open(AT_FDCWD, path, O_RDONLY, 0);
#endif
	if (fd < 0) {
		MD_PRINT("%s: open file %s fail. fd = %ld", __func__, path, fd);
		set_fs(KERNEL_DS);
		return -1;
	}

	ret = micro_ksys_read(fd, buf, len);
	if (ret < 0)
		MD_PRINT("%s: read file %s fail. ret = %d", __func__, path, ret);

	ksys_close(fd);
	set_fs(KERNEL_DS);
	return (ret < 0) ? -1 : 0;
}

void dump_stg_info()
{
	int ret = 0;
	int size = 0;
	char *ddr_info = NULL;
	char stg_type[STG_TYPE_LENGTH + 1] = {0};
	char stg_manfid[UFS_MANFID_LENGTH + 1] = {0};
	char stg_size[UFS_SIZE_LENGTH + 1] = {0};
	char stg_version[UFS_VER_LENGTH +1] = {0};
	char ddr_node_info[DDR_INFO_LENGTH + 1] = {0};

	ret = get_node_info(DEV_TYPR_PATH, stg_type, STG_TYPE_LENGTH);
	if (ret < 0)
		MD_PRINT("%s: Get Storage Type failed, ret = %d", __func__, ret);

	if (strcmp(stg_type, "0") == 0)
		ret = get_node_info(MANFID_PATH, stg_manfid, EMMC_MANFID_LENGTH);
	else
		ret = get_node_info(MANFID_PATH, stg_manfid, UFS_MANFID_LENGTH);

	if (ret < 0)
		MD_PRINT("%s: Get Storage Manfid failed, ret = %d.", __func__, ret);

	ret = get_node_info(UFS_SIZE_PATH, stg_size, UFS_SIZE_LENGTH);
	if (ret < 0)
		MD_PRINT("%s: Get Storage Size failed, ret = %d.", __func__, ret);

	/* sector to MB */
	size = ((int)simple_strtoul(stg_size, NULL, 10)) / 2 / 1024;

	if (strcmp(stg_type, "0") == 0)
		ret = get_node_info(EMMC_VER_PATH, stg_version, EMMC_VER_LENGTH);
	else
		ret = get_node_info(UFS_VER_PATH, stg_version, UFS_VER_LENGTH);

	if (ret < 0)
		MD_PRINT("%s: Get Storage Version failed, ret = %d.", __func__, ret);

	ret = get_node_info(DDR_INFO_PATH, ddr_node_info, DDR_INFO_LENGTH);
	if (ret < 0)
		MD_PRINT("%s: Get Ddr Info failed, ret = %d", __func__, ret);

	ddr_info = strstr(ddr_node_info, DDR_INFO_KEY);
	MD_PRINT("info: %s, %s, %d, %s, %s", stg_type, stg_manfid, size, stg_version,
			(ddr_info == NULL) ? "unknow" : ddr_info);
}
