/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */

#ifndef _UAPI_LINUX_F2FS_H
#define _UAPI_LINUX_F2FS_H
#include <linux/types.h>
#include <linux/ioctl.h>

/*
 * f2fs-specific ioctl commands
 */
#define F2FS_IOCTL_MAGIC		0xf5
#define F2FS_IOC_START_ATOMIC_WRITE	_IO(F2FS_IOCTL_MAGIC, 1)
#define F2FS_IOC_COMMIT_ATOMIC_WRITE	_IO(F2FS_IOCTL_MAGIC, 2)
#define F2FS_IOC_START_VOLATILE_WRITE	_IO(F2FS_IOCTL_MAGIC, 3)
#define F2FS_IOC_RELEASE_VOLATILE_WRITE	_IO(F2FS_IOCTL_MAGIC, 4)
#define F2FS_IOC_ABORT_VOLATILE_WRITE	_IO(F2FS_IOCTL_MAGIC, 5)
#define F2FS_IOC_GARBAGE_COLLECT	_IOW(F2FS_IOCTL_MAGIC, 6, __u32)
#define F2FS_IOC_WRITE_CHECKPOINT	_IO(F2FS_IOCTL_MAGIC, 7)
#define F2FS_IOC_DEFRAGMENT		_IOWR(F2FS_IOCTL_MAGIC, 8,	\
						struct f2fs_defragment)
#define F2FS_IOC_MOVE_RANGE		_IOWR(F2FS_IOCTL_MAGIC, 9,	\
						struct f2fs_move_range)
#define F2FS_IOC_FLUSH_DEVICE		_IOW(F2FS_IOCTL_MAGIC, 10,	\
						struct f2fs_flush_device)
#define F2FS_IOC_GARBAGE_COLLECT_RANGE	_IOW(F2FS_IOCTL_MAGIC, 11,	\
						struct f2fs_gc_range)
#define F2FS_IOC_GET_FEATURES		_IOR(F2FS_IOCTL_MAGIC, 12, __u32)
#define F2FS_IOC_SET_PIN_FILE		_IOW(F2FS_IOCTL_MAGIC, 13, __u32)
#define F2FS_IOC_GET_PIN_FILE		_IOR(F2FS_IOCTL_MAGIC, 14, __u32)
#define F2FS_IOC_PRECACHE_EXTENTS	_IO(F2FS_IOCTL_MAGIC, 15)
#define F2FS_IOC_RESIZE_FS		_IOW(F2FS_IOCTL_MAGIC, 16, __u64)
#define F2FS_IOC_GET_COMPRESS_BLOCKS	_IOR(F2FS_IOCTL_MAGIC, 17, __u64)
#define F2FS_IOC_RELEASE_COMPRESS_BLOCKS				\
					_IOR(F2FS_IOCTL_MAGIC, 18, __u64)
#define F2FS_IOC_RESERVE_COMPRESS_BLOCKS				\
					_IOR(F2FS_IOCTL_MAGIC, 19, __u64)
#define F2FS_IOC_SEC_TRIM_FILE		_IOW(F2FS_IOCTL_MAGIC, 20,	\
						struct f2fs_sectrim_range)
#define F2FS_IOC_GET_COMPRESS_OPTION	_IOR(F2FS_IOCTL_MAGIC, 21,	\
						struct f2fs_comp_option)
#define F2FS_IOC_SET_COMPRESS_OPTION	_IOW(F2FS_IOCTL_MAGIC, 22,	\
						struct f2fs_comp_option)
#define F2FS_IOC_DECOMPRESS_FILE	_IO(F2FS_IOCTL_MAGIC, 23)
#define F2FS_IOC_COMPRESS_FILE		_IO(F2FS_IOCTL_MAGIC, 24)

#define F2FS_COMPR_OPTM_IOC_BASE	45
#define F2FS_IOC_ESTIMATE_COMPRESS_RATE _IOWR(F2FS_IOCTL_MAGIC,	\
					F2FS_COMPR_OPTM_IOC_BASE + 0, struct f2fs_comp_estimate)
#define F2FS_IOC_GET_INODE_STRUCT	_IOR(F2FS_IOCTL_MAGIC,	\
					F2FS_COMPR_OPTM_IOC_BASE + 1, struct f2fs_inode_struct)

#define F2FS_SIS_IOC_BASE	50
#define F2FS_IOC_SIS_CONNECT		_IOW(F2FS_IOCTL_MAGIC,	\
					F2FS_SIS_IOC_BASE + 0, struct f2fs_sis_hidden_fd)
#define F2FS_IOC_SIS_DEDUP		_IOW(F2FS_IOCTL_MAGIC,	\
					F2FS_SIS_IOC_BASE + 1, struct f2fs_sis_src_fd)
#define F2FS_IOC_SIS_RECOVER		_IOW(F2FS_IOCTL_MAGIC,	\
					F2FS_SIS_IOC_BASE + 2, struct f2fs_sis_recover_fd)
#define F2FS_IOC_SIS_GET_FILE_INFO	_IOR(F2FS_IOCTL_MAGIC,	\
					F2FS_SIS_IOC_BASE + 3, struct f2fs_sis_file_info)
#define F2FS_IOC_SIS_GET_SYS_INFO	_IOR(F2FS_IOCTL_MAGIC,	\
					F2FS_SIS_IOC_BASE + 4, struct f2fs_sis_sys_info)

#define F2FS_IOC_SIS_DUP		_IOW(F2FS_IOCTL_MAGIC,	\
					F2FS_SIS_IOC_BASE + 5, struct f2fs_sis_src_info)
#define F2FS_IOC_SIS_COINCIDE_FLAG	_IOWR(F2FS_IOCTL_MAGIC,	\
					F2FS_SIS_IOC_BASE + 6, struct f2fs_sis_coincide_info)
#define F2FS_IOC_SIS_PRE_CHECK \
			_IO(F2FS_IOCTL_MAGIC, F2FS_SIS_IOC_BASE + 7)
/*
 * should be same as XFS_IOC_GOINGDOWN.
 * Flags for going down operation used by FS_IOC_GOINGDOWN
 */
#define F2FS_IOC_SHUTDOWN	_IOR('X', 125, __u32)	/* Shutdown */
#define F2FS_GOING_DOWN_FULLSYNC	0x0	/* going down with full sync */
#define F2FS_GOING_DOWN_METASYNC	0x1	/* going down with metadata */
#define F2FS_GOING_DOWN_NOSYNC		0x2	/* going down */
#define F2FS_GOING_DOWN_METAFLUSH	0x3	/* going down with meta flush */
#define F2FS_GOING_DOWN_NEED_FSCK	0x4	/* going down to trigger fsck */

/*
 * Flags used by F2FS_IOC_SEC_TRIM_FILE
 */
#define F2FS_TRIM_FILE_DISCARD		0x1	/* send discard command */
#define F2FS_TRIM_FILE_ZEROOUT		0x2	/* zero out */
#define F2FS_TRIM_FILE_MASK		0x3

struct f2fs_gc_range {
	__u32 sync;
	__u64 start;
	__u64 len;
};

struct f2fs_defragment {
	__u64 start;
	__u64 len;
};

struct f2fs_move_range {
	__u32 dst_fd;		/* destination fd */
	__u64 pos_in;		/* start position in src_fd */
	__u64 pos_out;		/* start position in dst_fd */
	__u64 len;		/* size to move */
};

struct f2fs_flush_device {
	__u32 dev_num;		/* device number to flush */
	__u32 segments;		/* # of segments to flush */
};

struct f2fs_sectrim_range {
	__u64 start;
	__u64 len;
	__u64 flags;
};

struct f2fs_comp_option {
	__u8 algorithm;
	__u8 log_cluster_size;
};

struct f2fs_comp_estimate {
	union {
		struct {
			__u8 algorithm;
			__u8 log_cluster_size;
			__u16 log_sample_density;
		};
		__u32 compress_rate;
	};
};

struct f2fs_inode_struct {
	__u32 addrs_per_inode;
	__u32 addrs_per_dnode;
};

/* F2FS_IOC_SIS_CONNECT */
struct f2fs_sis_hidden_fd {
	int hidden_fd;
};

enum {
	SIS_FILE = 0,
	RAPID_COPY,
	SIS_MODE_MAX
};

/* F2FS_IOC_SIS_FILE */
struct f2fs_sis_src_fd {
	int base_fd;
	int sis_mode;
};

/* F2FS_IOC_SIS_REVOKE */
struct f2fs_sis_recover_fd {
	int recover_fd;
};

/* F2FS_IOC_SIS_GET_FILE_INFO */
struct f2fs_sis_file_info {
	bool is_deduped;
	bool is_connected;
	int hidden_ino;
};

/* F2FS_IOC_SIS_GET_SYS_INFO */
struct f2fs_sis_sys_info {
	u64 file_count;
	u64 file_space;		/* MB */
};

struct f2fs_sis_src_info {
	int src_fd;
	int flags;	/* meta/data index */
};

struct f2fs_sis_coincide_info {
	int flag;	/* data/meta */
	int mode;	/* set/get/clear */
};

#endif /* _UAPI_LINUX_F2FS_H */
