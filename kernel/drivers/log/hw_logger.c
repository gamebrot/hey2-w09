/*
 * drivers/misc/logger.c
 *
 * A Logging Subsystem
 *
 * Copyright (C) 2007-2008 Google, Inc.
 *
 * Robert Love <rlove@google.com>
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#define pr_fmt(fmt) "logger: " fmt

#include "log/hw_logger.h"
#include <linux/notifier.h>
#include <asm/ioctls.h>
#include <linux/aio.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/poll.h>
#include <linux/printk.h>
#include <linux/ratelimit.h>
#include <linux/slab.h>
#include <linux/time.h>
#include <linux/uaccess.h>
#include <linux/uio.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <uapi/linux/uio.h>
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0))
#include <linux/sched/signal.h>
#endif
#ifdef CONFIG_HN_FDLEAK
#include <chipset_common/hwfdleak/fdleak.h>
#endif
#ifdef CONFIG_HN_ERECOVERY
#include <chipset_common/hwerecovery/erecovery.h>
#endif
#ifdef CONFIG_HN_MEMCHECK
#include <chipset_common/hwmemcheck/memcheck.h>
#endif
#include <asm/ioctls.h>

#include "log/log_usertype.h"
#include "log/hwlog_kernel.h"

#define LOGGER_LOG_EXCEPTION_BUF_SIZE (128 * 1024)
#define LOGGER_LOG_JANK_BUF_SIZE	(64 * 1024)
#define LOGGER_LOG_DUBAI_BUF_SIZE	(256 * 1024)
#define ZRHUNG_CMD_INVALID 		0xFF
// nofity callback is null,skip errno of system.
#define ERR_ZRHUNG_NOTIFY_CALLBACK_NULL -300

extern int reboot_wdt_module_init(void);
extern void reboot_wdt_module_exit(void);
static int calc_iovc_ki_left(const struct iovec *iov, int nr_segs);

/*
 * struct logger_log - represents a specific log, such as 'main' or 'radio'
 * @buffer:	The actual ring buffer
 * @misc:	The "misc" device representing the log
 * @wq:		The wait queue for @readers
 * @readers:	This log's readers
 * @mutex:	The mutex that protects the @buffer
 * @w_off:	The current write head offset
 * @head:	The head, or location that readers start reading at.
 * @size:	The size of the log
 * @logs:	The list of log channels
 *
 * This structure lives from module insertion until module removal, so it does
 * not need additional reference counting. The structure is protected by the
 * mutex 'mutex'.
 */
struct logger_log {
	unsigned char *buffer;
	struct miscdevice misc;
	wait_queue_head_t wq;
	struct list_head readers;
	struct mutex mutex;
	size_t w_off;
	size_t head;
	size_t size;
	struct list_head logs;
};

static LIST_HEAD(log_list);

/*
 * struct logger_reader - a logging device open for reading
 * @log:	The associated log
 * @list:	The associated entry in @logger_log's list
 * @r_off:	The current read head offset.
 * @r_all:	Reader can read all entries
 * @r_ver:	Reader ABI version
 *
 * This object lives from open to release, so we don't need additional
 * reference counting. The structure is protected by log->mutex.
 */
struct logger_reader {
	struct logger_log *log;
	struct list_head list;
	size_t r_off;
	bool r_all;
	int r_ver;
};

struct logger_ioctl_struct{
	struct file *file;
	unsigned int cmd;
	uintptr_t arg;
	long *ret;
};

BLOCKING_NOTIFIER_HEAD(logger_notifier_list);
EXPORT_SYMBOL(logger_notifier_list);

/* logger_offset - returns index 'n' into the log via (optimized) modulus */
static size_t logger_offset(struct logger_log *log, size_t n)
{
	return n & (log->size - 1);
}

/*
 * file_get_log - Given a file structure, return the associated log
 *
 * This isn't aesthetic. We have several goals:
 *
 *	1) Need to quickly obtain the associated log during an I/O operation
 *	2) Readers need to maintain state (logger_reader)
 *	3) Writers need to be very fast (open() should be a near no-op)
 *
 * In the reader case, we can trivially go file->logger_reader->logger_log.
 * For a writer, we don't want to maintain a logger_reader, so we just go
 * file->logger_log. Thus what file->private_data points at depends on whether
 * or not the file was opened for reading. This function hides that dirtiness.
 */
static inline struct logger_log *file_get_log(struct file *file)
{
	if (file->f_mode & FMODE_READ) {
		struct logger_reader *reader = file->private_data;

		return reader->log;
	} else {
		return file->private_data;
	}
}

/*
 * get_entry_header - returns a pointer to the logger_entry header within
 * 'log' starting at offset 'off'. A temporary logger_entry 'scratch' must
 * be provided. Typically the return value will be a pointer within
 * 'logger->buf'.  However, a pointer to 'scratch' may be returned if
 * the log entry spans the end and beginning of the circular buffer.
 */
static struct logger_entry *get_entry_header(struct logger_log *log,
					     size_t off,
					     struct logger_entry *scratch)
{
	size_t len = min(sizeof(*scratch), log->size - off);

	if (len != sizeof(*scratch)) {
		memcpy(((void *)scratch), log->buffer + off, len);
		memcpy(((void *)scratch) + len, log->buffer,
		       sizeof(*scratch) - len);
		return scratch;
	}

	return (struct logger_entry *)(log->buffer + off);
}

/*
 * get_entry_msg_len - Grabs the length of the message of the entry
 * starting from from 'off'.
 *
 * An entry length is 2 bytes (16 bits) in host endian order.
 * In the log, the length does not include the size of the log entry structure.
 * This function returns the size including the log entry structure.
 *
 * Caller needs to hold log->mutex.
 */
static __u32 get_entry_msg_len(struct logger_log *log, size_t off)
{
	struct logger_entry scratch;
	struct logger_entry *entry = NULL;

	entry = get_entry_header(log, off, &scratch);
	return entry->len;
}

static size_t get_user_hdr_len(int ver)
{
	if (ver < 2)
		return sizeof(struct user_logger_entry_compat);
	else
		return sizeof(struct logger_entry);
}

static ssize_t copy_header_to_user(int ver, struct logger_entry *entry,
				   char __user *buf)
{
	void *hdr = NULL;
	size_t hdr_len;
	struct user_logger_entry_compat v1;

	if (ver < 2) {
		v1.len = entry->len;
		v1.__pad = 0;
		v1.pid = entry->pid;
		v1.tid = entry->tid;
		v1.sec = entry->sec;
		v1.nsec = entry->nsec;
		hdr = &v1;
		hdr_len = sizeof(struct user_logger_entry_compat);
	} else {
		hdr = entry;
		hdr_len = sizeof(struct logger_entry);
	}

	return copy_to_user(buf, hdr, hdr_len);
}

/*
 * do_read_log_to_user - reads exactly 'count' bytes from 'log' into the
 * user-space buffer 'buf'. Returns 'count' on success.
 *
 * Caller must hold log->mutex.
 */
static ssize_t do_read_log_to_user(struct logger_log *log,
				   struct logger_reader *reader,
				   char __user *buf, size_t count)
{
	struct logger_entry scratch;
	struct logger_entry *entry = NULL;
	size_t len;
	size_t msg_start;

	/*
	 * First, copy the header to userspace, using the version of
	 * the header requested
	 */
	entry = get_entry_header(log, reader->r_off, &scratch);
	if (copy_header_to_user(reader->r_ver, entry, buf))
		return -EFAULT;

	count -= get_user_hdr_len(reader->r_ver);
	buf += get_user_hdr_len(reader->r_ver);
	msg_start = logger_offset(log,
				  reader->r_off + sizeof(struct logger_entry));

	/*
	 * We read from the msg in two disjoint operations. First, we read from
	 * the current msg head offset up to 'count' bytes or to the end of
	 * the log, whichever comes first.
	 */
	len = min(count, log->size - msg_start);
	if (copy_to_user(buf, log->buffer + msg_start, len))
		return -EFAULT;

	/*
	 * Second, we read any remaining bytes, starting back at the head of
	 * the log.
	 */
	if (count != len)
		if (copy_to_user(buf + len, log->buffer, count - len))
			return -EFAULT;

	reader->r_off = logger_offset(log, reader->r_off +
				      sizeof(struct logger_entry) + count);

	return count + get_user_hdr_len(reader->r_ver);
}

/*
 * get_next_entry_by_uid - Starting at 'off', returns an offset into
 * 'log->buffer' which contains the first entry readable by 'euid'
 */
static size_t get_next_entry_by_uid(struct logger_log *log,
				    size_t off, kuid_t euid)
{
	while (off != log->w_off) {
		struct logger_entry *entry = NULL;
		struct logger_entry scratch;
		size_t next_len;

		entry = get_entry_header(log, off, &scratch);

		if (uid_eq(entry->euid, euid))
			return off;

		next_len = sizeof(struct logger_entry) + entry->len;
		off = logger_offset(log, off + next_len);
	}

	return off;
}

static inline int is_between_revers(size_t a, size_t b, size_t c)
{
	if (a < b) {
		if ((a <= c) && (c < b))
			return 1;
	} else {
		if ((c < b) || (a <= c))
			return 1;
	}

	return 0;
}

/*
 * logger_read - our log's read() method
 *
 * Behavior:
 *
 *	- O_NONBLOCK works
 *	- If there are no log entries to read, blocks until log is written to
 *	- Atomically reads exactly one log entry
 *
 * Will set errno to EINVAL if read
 * buffer is insufficient to hold next entry.
 */
static ssize_t logger_read(struct file *file, char __user *buf,
			   size_t count, loff_t *pos)
{
	struct logger_reader *reader = file->private_data;
	struct logger_log *log = reader->log;
	struct logger_reader *other_reader = NULL;
	ssize_t ret;
	DEFINE_WAIT(wait);

start:
	while (1) {
		mutex_lock(&log->mutex);

		prepare_to_wait(&log->wq, &wait, TASK_INTERRUPTIBLE);

		ret = (log->w_off == reader->r_off);
		mutex_unlock(&log->mutex);
		if (!ret)
			break;

		if (file->f_flags & O_NONBLOCK) {
			ret = -EAGAIN;
			break;
		}

		if (signal_pending(current)) {
			ret = -EINTR;
			break;
		}

		schedule();
	}

	finish_wait(&log->wq, &wait);
	if (ret)
		return ret;

	mutex_lock(&log->mutex);

	if (!reader->r_all)
		reader->r_off = get_next_entry_by_uid(log, reader->r_off,
						      current_euid());

	/* is there still something to read or did we race? */
	if (unlikely(log->w_off == reader->r_off)) {
		mutex_unlock(&log->mutex);
		goto start;
	}

	/* get the size of the next entry */
	ret = get_user_hdr_len(reader->r_ver) +
	    get_entry_msg_len(log, reader->r_off);
	if (count < ret) {
		ret = -EINVAL;
		goto out;
	}

	/* get exactly one entry from the log */
	ret = do_read_log_to_user(log, reader, buf, ret);
	if (file->f_flags & O_HWLOGGER_RDDEL) {
		list_for_each_entry(other_reader, &log->readers, list)
			if (is_between_revers(log->head, reader->r_off,
					      other_reader->r_off))
				other_reader->r_off = reader->r_off;
		log->head = reader->r_off;
	}

out:
	mutex_unlock(&log->mutex);

	return ret;
}

/*
 * get_next_entry - return the offset of the first valid entry at least 'len'
 * bytes after 'off'.
 *
 * Caller must hold log->mutex.
 */
static size_t get_next_entry(struct logger_log *log, size_t off, size_t len)
{
	size_t count = 0;

	do {
		size_t nr = sizeof(struct logger_entry) +
			get_entry_msg_len(log, off);
		off = logger_offset(log, off + nr);
		count += nr;
	} while (count < len);

	return off;
}

/*
 * is_between - is a < c < b, accounting for wrapping of a, b, and c
 *    positions in the buffer
 *
 * That is, if a<b, check for c between a and b
 * and if a>b, check for c outside (not between) a and b
 *
 * |------- a xxxxxxxx b --------|
 *               c^
 *
 * |xxxxx b --------- a xxxxxxxxx|
 *    c^
 *  or                    c^
 */
static inline int is_between(size_t a, size_t b, size_t c)
{
	if (a < b) {
		if ((a < c) && (c <= b))
			return 1;
	} else {
		if ((c <= b) || (a < c))
			return 1;
	}

	return 0;
}

/*
 * fix_up_readers - walk the list of all readers and "fix up" any who were
 * lapped by the writer; also do the same for the default "start head".
 * We do this by "pulling forward" the readers and start head to the first
 * entry after the new write head.
 *
 * The caller needs to hold log->mutex.
 */
static void fix_up_readers(struct logger_log *log, size_t len)
{
	size_t old = log->w_off;
	size_t new = logger_offset(log, old + len);
	struct logger_reader *reader = NULL;

	if (is_between(old, new, log->head))
		log->head = get_next_entry(log, log->head, len);

	list_for_each_entry(reader, &log->readers, list)
		if (is_between(old, new, reader->r_off))
			reader->r_off = get_next_entry(log, reader->r_off, len);
}

/*
 * do_write_log - writes 'len' bytes from 'buf' to 'log'
 *
 * The caller needs to hold log->mutex.
 */
static void do_write_log(struct logger_log *log, const void *buf, size_t count)
{
	size_t len;

	len = min(count, log->size - log->w_off);
	memcpy(log->buffer + log->w_off, buf, len);

	if (count != len)
		memcpy(log->buffer, buf + len, count - len);

	log->w_off = logger_offset(log, log->w_off + count);

}

/*
 * do_write_log_user - writes 'len' bytes from the user-space buffer 'buf' to
 * the log 'log'
 *
 * The caller needs to hold log->mutex.
 *
 * Returns 'count' on success, negative error code on failure.
 */
static ssize_t do_write_log_from_user(struct logger_log *log,
				      const void __user *buf, size_t count)
{
	size_t len;

	len = min(count, log->size - log->w_off);
	if (len && copy_from_user(log->buffer + log->w_off, buf, len))
		return -EFAULT;

	if (count != len)
		if (copy_from_user(log->buffer, buf + len, count - len))
			/*
			 * Note that by not updating w_off, this abandons the
			 * portion of the new entry that *was* successfully
			 * copied, just above.  This is intentional to avoid
			 * message corruption from missing fragments.
			 */
			return -EFAULT;

	log->w_off = logger_offset(log, log->w_off + count);

	return count;
}

static ssize_t hw_logger_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	struct logger_log *log = file_get_log(iocb->ki_filp);
	size_t orig = log->w_off;
	struct logger_entry header;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
	struct timespec64 now;
#else
	struct timespec now;
#endif
	ssize_t ret = 0;
	unsigned long nr_segs = from->nr_segs;
	const struct iovec *iov = from->iov;
	int invaliddata = 0;

	if (unlikely(nr_segs < 1)) {
		invaliddata = EVecSeg;
	} else if (unlikely(iov[0].iov_len != sizeof(int))) {
		invaliddata = EVecLen;
	} else {
		int code = 0;

		if (copy_from_user(&code, iov[0].iov_base, sizeof(code))) {
			invaliddata = EVecCopy;
		} else if (unlikely(code != LOGGER_CHECK_MAGIC)) {
			invaliddata = EVecCode;
		} else {
			nr_segs--;
			iov++;
		}
	}

	if (unlikely(invaliddata)) {
		pr_err_ratelimited("%s: invalid log data, error code is %d\n",
				   log->misc.name, invaliddata);
		return -EINVAL;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
	ktime_get_coarse_real_ts64(&now);
#else
	now = current_kernel_time();
#endif

	header.pid = current->tgid;
	header.tid = current->pid;
	header.sec = now.tv_sec;
	header.nsec = now.tv_nsec;
	header.euid = current_euid();
	header.len = min_t(size_t, calc_iovc_ki_left(iov, nr_segs),
			   LOGGER_ENTRY_MAX_PAYLOAD);
	header.hdr_size = sizeof(struct logger_entry);

	/* null writes succeed */
	if (unlikely(!header.len))
		return 0;

	mutex_lock(&log->mutex);

	/*
	 * Fix up any readers, pulling them forward to the first readable
	 * entry after (what will be) the new write offset. We do this now
	 * because if we partially fail, we can end up with clobbered log
	 * entries that encroach on readable buffer.
	 */
	fix_up_readers(log, sizeof(struct logger_entry) + header.len);

	do_write_log(log, &header, sizeof(struct logger_entry));

	while (nr_segs-- > 0) {
		size_t len;
		ssize_t nr;

		/* figure out how much of this vector we can keep */
		len = min_t(size_t, iov->iov_len, header.len - ret);

		/* write out this segment's payload */
		nr = do_write_log_from_user(log, iov->iov_base, len);
		if (unlikely(nr < 0)) {
			log->w_off = orig;
			mutex_unlock(&log->mutex);
			return nr;
		}

		iov++;
		ret += nr;
	}

	mutex_unlock(&log->mutex);

	/* wake up any blocked readers */
	wake_up_interruptible(&log->wq);

	return ret;
}

static struct logger_log *get_log_from_minor(int minor)
{
	struct logger_log *log = NULL;

	list_for_each_entry(log, &log_list, logs)
		if (log->misc.minor == minor)
			return log;
	return NULL;
}

/*
 * logger_open - the log's open() file operation
 *
 * Note how near a no-op this is in the write-only case. Keep it that way!
 */
static int logger_open(struct inode *inode, struct file *file)
{
	struct logger_log *log = NULL;
	int ret;

	ret = nonseekable_open(inode, file);
	if (ret)
		return ret;

	log = get_log_from_minor(MINOR(inode->i_rdev));
	if (!log)
		return -ENODEV;

	if (file->f_mode & FMODE_READ) {
		struct logger_reader *reader = kmalloc(sizeof(*reader), GFP_KERNEL);

		if (!reader)
			return -ENOMEM;

		reader->log = log;
		reader->r_ver = 1;
		reader->r_all = in_egroup_p(inode->i_gid) ||
		    capable(CAP_SYSLOG);

		INIT_LIST_HEAD(&reader->list);

		mutex_lock(&log->mutex);
		reader->r_off = log->head;
		list_add_tail(&reader->list, &log->readers);
		mutex_unlock(&log->mutex);

		file->private_data = reader;
	} else {
		file->private_data = log;
	}

	return 0;
}

/*
 * logger_release - the log's release file operation
 *
 * Note this is a total no-op in the write-only case. Keep it that way!
 */
static int logger_release(struct inode *ignored, struct file *file)
{
	if (file->f_mode & FMODE_READ) {
		struct logger_reader *reader = file->private_data;
		struct logger_log *log = reader->log;

		mutex_lock(&log->mutex);
		list_del(&reader->list);
		mutex_unlock(&log->mutex);

		kfree(reader);
	}

	return 0;
}

/*
 * logger_poll - the log's poll file operation, for poll/select/epoll
 *
 * Note we always return POLLOUT, because you can always write() to the log.
 * Note also that, strictly speaking, a return value of POLLIN does not
 * guarantee that the log is readable without blocking, as there is a small
 * chance that the writer can lap the reader in the interim between poll()
 * returning and the read() request.
 */
static unsigned int logger_poll(struct file *file, poll_table *wait)
{
	struct logger_reader *reader = NULL;
	struct logger_log *log = NULL;
	unsigned int ret = POLLOUT | POLLWRNORM;

	if (!(file->f_mode & FMODE_READ))
		return ret;

	reader = file->private_data;
	log = reader->log;

	poll_wait(file, &log->wq, wait);

	mutex_lock(&log->mutex);
	if (!reader->r_all)
		reader->r_off = get_next_entry_by_uid(log, reader->r_off,
						      current_euid());

	if (log->w_off != reader->r_off)
		ret |= POLLIN | POLLRDNORM;
	mutex_unlock(&log->mutex);

	return ret;
}

// For GKI2.0 adjust, to avoid circular dependencies between zrhung and logger.
static long zrhung_ioctl_notify(struct file *file, unsigned int cmd, unsigned long arg)
{
	long ret = ERR_ZRHUNG_NOTIFY_CALLBACK_NULL;
	struct logger_ioctl_struct ioctl_entry;

	ioctl_entry.file = file;
	ioctl_entry.cmd = cmd;
	ioctl_entry.arg = arg;
	ioctl_entry.ret = &ret;
	blocking_notifier_call_chain(&logger_notifier_list, (unsigned long)&ioctl_entry, NULL);

	return ret;
}

static long logger_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct logger_log *log = file_get_log(file);
	struct logger_reader *reader = NULL;
	long ret = -EINVAL;
	long ret_zrhung;

	ret_zrhung = zrhung_ioctl_notify(file, cmd, arg);
	if (ret_zrhung != ERR_ZRHUNG_NOTIFY_CALLBACK_NULL) { // zrhung enable.
		ret = ret_zrhung;
		if (ret != ZRHUNG_CMD_INVALID)
			return ret;
	}

#ifdef CONFIG_HN_FDLEAK
	ret = fdleak_ioctl(file, cmd, arg);
	if (ret != FDLEAK_CMD_INVALID)
		return ret;
#endif
#ifdef CONFIG_HN_ERECOVERY
	ret = erecovery_ioctl(file, cmd, arg);
	if (ret != ERECOVERY_CMD_INVALID)
		return ret;
#endif
#ifdef CONFIG_HN_MEMCHECK
	ret = memcheck_ioctl(file, cmd, arg);
	if(ret != MEMCHECK_CMD_INVALID) {
		return ret;
	}
#endif
	mutex_lock(&log->mutex);

	switch (cmd) {
	case LOGGER_GET_LOG_BUF_SIZE:
		ret = log->size;
		break;
	case LOGGER_GET_LOG_LEN:
		if (!(file->f_mode & FMODE_READ)) {
			ret = -EBADF;
			break;
		}
		reader = file->private_data;
		if (log->w_off >= reader->r_off)
			ret = log->w_off - reader->r_off;
		else
			ret = (log->size - reader->r_off) + log->w_off;
		break;
	case LOGGER_GET_NEXT_ENTRY_LEN:
		if (!(file->f_mode & FMODE_READ)) {
			ret = -EBADF;
			break;
		}
		reader = file->private_data;

		if (!reader->r_all)
			reader->r_off = get_next_entry_by_uid(log,
				reader->r_off, current_euid());

		if (log->w_off != reader->r_off)
			ret = get_user_hdr_len(reader->r_ver) +
			    get_entry_msg_len(log, reader->r_off);
		else
			ret = 0;
		break;
	case LOGGER_FLUSH_LOG:
		if (!(file->f_mode & FMODE_WRITE)) {
			ret = -EBADF;
			break;
		}
		if (!(in_egroup_p(file->f_path.dentry->d_inode->i_gid) ||
		      capable(CAP_SYSLOG))) {
			ret = -EPERM;
			break;
		}
		list_for_each_entry(reader, &log->readers, list)
			reader->r_off = log->w_off;
		log->head = log->w_off;
		ret = 0;
		break;
	case LOGGER_SET_RDDEL:
		if (!(file->f_mode & FMODE_READ)) {
			ret = -EBADF;
			break;
		}
		file->f_flags |= O_HWLOGGER_RDDEL;
		ret = 0;
		break;
	case LOGGER_RESET_RDDEL:
		if (!(file->f_mode & FMODE_READ)) {
			ret = -EBADF;
			break;
		}
		file->f_flags &= (~O_HWLOGGER_RDDEL);
		ret = 0;
		break;
	case FIONREAD:
		if (!strncmp(log->misc.name, LOGGER_LOG_JANK, strlen(LOGGER_LOG_JANK)) ||
		    !strncmp(log->misc.name, LOGGER_LOG_DUBAI, strlen(LOGGER_LOG_DUBAI)))
			ret = -ENOTTY;
		break;
	default:
		break;
	}

	mutex_unlock(&log->mutex);

	return ret;
}

static const struct file_operations logger_fops = {
	.owner = THIS_MODULE,
	.read = logger_read,
	.write_iter = hw_logger_write_iter,
	.poll = logger_poll,
	.unlocked_ioctl = logger_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = logger_ioctl,
#endif
	.open = logger_open,
	.release = logger_release,
};

/*
 * Log size must must be a power of two, and greater than
 * (LOGGER_ENTRY_MAX_PAYLOAD + sizeof(struct logger_entry)).
 */
static int __init create_log(char *log_name, int size)
{
	int ret;
	struct logger_log *log = NULL;
	unsigned char *buffer = NULL;

	if (size <= 0)
		return -EINVAL;
	buffer = vmalloc(size);
	if (!buffer)
		return -ENOMEM;
	memset(buffer, 0, size);

	log = kzalloc(sizeof(*log), GFP_KERNEL);
	if (!log) {
		ret = -ENOMEM;
		goto out_free_buffer;
	}
	log->buffer = buffer;

	log->misc.minor = MISC_DYNAMIC_MINOR;
	log->misc.name = kstrdup(log_name, GFP_KERNEL);
	if (!log->misc.name) {
		ret = -ENOMEM;
		goto out_free_log;
	}

	log->misc.fops = &logger_fops;
	log->misc.parent = NULL;

	init_waitqueue_head(&log->wq);
	INIT_LIST_HEAD(&log->readers);
	mutex_init(&log->mutex);
	log->w_off = 0;
	log->head = 0;
	log->size = size;

	INIT_LIST_HEAD(&log->logs);
	list_add_tail(&log->logs, &log_list);

	/* finally, initialize the misc device for this log */
	ret = misc_register(&log->misc);
	if (unlikely(ret)) {
		pr_err("failed to register misc device for log '%s'!\n",
		       log->misc.name);
		goto out_free_log;
	}

	pr_info("created %luK log '%s'\n",
		(unsigned long)log->size >> 10, log->misc.name);
	return 0;

out_free_log:
	kfree(log);

out_free_buffer:
	vfree(buffer);
	return ret;
}

static int __init logger_init(void)
{
	int ret;

	/* must modified with EXCEPTION_LOG_BUF_LEN */
	ret = create_log(LOGGER_LOG_EXCEPTION, LOGGER_LOG_EXCEPTION_BUF_SIZE);
	if (unlikely(ret))
		goto out;
#if defined CONFIG_LOG_KERNEL
	ret = create_log(LOGGER_LOG_JANK, LOGGER_LOG_JANK_BUF_SIZE);
	if (unlikely(ret))
		goto out;
	ret = create_log(LOGGER_LOG_DUBAI, LOGGER_LOG_DUBAI_BUF_SIZE);
	if (unlikely(ret))
		goto out;
#endif
	hwlog_wq_init();
	log_usertype_proc_init();
	reboot_wdt_module_init();
out:
	return ret;
}

static void __exit logger_exit(void)
{
	struct logger_log *current_log = NULL;
	struct logger_log *next_log = NULL;

	list_for_each_entry_safe(current_log, next_log, &log_list, logs) {
		/* we have to delete all the entry inside log_list */
		misc_deregister(&current_log->misc);
		if (current_log->buffer) {
			vfree(current_log->buffer);
			current_log->buffer = NULL;
		}
		kfree(current_log->misc.name);
		current_log->misc.name = NULL;
		list_del(&current_log->logs);
		kfree(current_log);
		current_log = NULL;
	}
	hwlog_wq_destroy();
	log_usertype_proc_exit();
	reboot_wdt_module_exit();
}

static struct logger_log *get_log_from_name(const char *name)
{
	struct logger_log *log = NULL;

	list_for_each_entry(log, &log_list, logs)
		if (!strcmp(log->misc.name, name))
			return log;
	return NULL;
}

static int calc_iovc_ki_left(const struct iovec *iov, int nr_segs)
{
	int ret = 0;
	int seg;
	ssize_t len;

	for (seg = 0; seg < nr_segs; seg++) {
		len = (ssize_t) iov[seg].iov_len;
		ret += len;
	}
	return ret;
}

static void init_header(struct logger_entry *header)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
	struct timespec64 now;
	ktime_get_coarse_real_ts64(&now);
#else
	struct timespec now = current_kernel_time();
#endif
	header->pid = current->tgid;
	header->tid = current->pid;
	header->sec = now.tv_sec;
	header->nsec = now.tv_nsec;
	header->euid = current_euid();
	header->len = 0;
	header->hdr_size = sizeof(struct logger_entry);
}

ssize_t send_hievent_vector(const char *category, struct iovec *vec,
							ssize_t vec_size)
{
	int code;
	ssize_t ret = 0;
	struct iovec *iov = vec;
	struct logger_log *log;
	struct logger_entry header;

	log = get_log_from_name(category);
	if (unlikely(log == NULL || vec_size < 1))
		return -EINVAL;
	if (unlikely(iov[0].iov_len != sizeof(int)))
		return -EINVAL;
	memcpy(&code, iov[0].iov_base, sizeof(int));

	if (unlikely(code != LOGGER_CHECK_MAGIC))
		return -EINVAL;

	vec_size--;
	iov++;

	init_header(&header);
	header.len = min(calc_iovc_ki_left(iov, vec_size),
					 LOGGER_ENTRY_MAX_PAYLOAD);
	if (unlikely(!header.len)) {
		return 0;
	}

	mutex_lock(&log->mutex);
	/*
	 * Fix up any readers, pulling them forward to the first readable
	 * entry after (what will be) the new write offset. We do this now
	 * because if we partially fail, we can end up with clobbered log
	 * entries that encroach on readable buffer.
	 */
	fix_up_readers(log, sizeof(struct logger_entry) + header.len);

	do_write_log(log, &header, sizeof(struct logger_entry));

	while (vec_size-- > 0) {
		/* figure out how much of this vector we can keep */
		size_t len = min_t(size_t, iov->iov_len, header.len - ret);

		/* write out this segment's payload */
		do_write_log(log, iov->iov_base, len);

		iov++;
		ret += len;
	}
	mutex_unlock(&log->mutex);

	/* wake up any blocked readers */
	wake_up_interruptible(&log->wq);
	return ret;
}
EXPORT_SYMBOL(send_hievent_vector);

module_init(logger_init);
module_exit(logger_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Robert Love, <rlove@google.com>");
MODULE_DESCRIPTION("Android Logger");
