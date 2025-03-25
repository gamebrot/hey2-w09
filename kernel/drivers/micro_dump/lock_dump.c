/*
 * Copyright (c) Honor Device Co., Ltd. 2022-2022. All rights reserved.
 * Description:dump hungtask lock
 * Author: mahulin
 * Create: 2022-10-26
 */

#include <micro_dump.h>
#include <linux/kmsg_dump.h>

#define FLAG_MASK 0x07
#define MAX_CHECK_DEEP 5
#define HUNG_PANIC_LOG "120s is causing panic"
#define STACK_OFF_BASE 0x10 /* see rwsem_down_write_slowpath, how save x19 ~ x28 */

enum lock_type {
	RW_SEM = 0,
	MUTEX,
	UNKNOWN,
};

struct lock_info {
	enum lock_type type;
	char *lock_symbol;
};

static const struct lock_info g_lock_list[] = {
	{RW_SEM,	"down_read"},
	{RW_SEM,	"down_write"},
	{MUTEX,		"mutex_lock"},
};

static pid_t get_hung_pid(void)
{
	pid_t pid;
	char *ptr;
	static char line[1024];
	unsigned long len;

	struct kmsg_dumper dumper;
	dumper.active = true;
	kmsg_dump_rewind(&dumper);
	while (kmsg_dump_get_line(&dumper, true, line, sizeof(line), &len)) {
		line[len] = '\0';
		ptr = strstr(line, HUNG_PANIC_LOG);
		if (ptr)
			break;
	}

	if (!ptr) {
		MD_PRINT("Unable to locate string:120s is causing panic\n");
		return -1;
	}

	/* find pid from such info "Thread-31:3315 blocked for 120s is causing panic" */
	ptr = strrchr(line, ':');
	pid = (pid_t)simple_strtoul(++ptr, NULL, 10);
	if (!pid) {
		MD_PRINT("Unable to convert out correct pid, maybe no pid info\n");
		return -1;
	}

	return pid;
}

static struct task_struct *get_hung_task(pid_t pid)
{
	struct task_struct *g, *p;

	for_each_process_thread(g, p)
		if (p->pid == pid)
			return p;

	return NULL;
}

void microdump_hungtask_stack(void)
{
	pid_t pid;
	struct task_struct *task;

	pid = get_hung_pid();
	if (pid < 0) {
		MD_PRINT("get hung pid failed\n");
		return;
	}

	task = get_hung_task(pid);
	if (!task) {
		MD_PRINT("get hung task struct failed\n");
		return;
	}

	MD_PRINT("hungtask pid:%d, name:%s\n", pid, task->comm);
	common_show_stack(task, NULL, KERN_INFO);
}

static unsigned long get_rwsem_addr(struct stackframe frame, unsigned long last_fp)
{
	unsigned long addr = 0;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0))
	unsigned int inst;
	unsigned char reg;

	/*
	 * down_write caller have such characteristics generally:
	 * .../AA1403E0/AA1303E0/    mov     x0 x28/.../x20/x19
	 * 941A65F8                  bl      0xFFFFFFC011A07B0C   ; down_write
	 * so we identify lock calls with this characteristic, inst means (mov x0, x19) or
	 * (mov x0, x20)..., x19/x20/... is the key data for traversing the stack.
	 * AA1303E0
	 *   ||--> These two bits represent the register.
	 */
	frame.pc = READ_ONCE_NOCHECK(*(unsigned long *)(uintptr_t)(frame.fp + 8)); /* get caller */
	inst = *(unsigned int *)(uintptr_t)(frame.pc - 8);
	if ((inst & 0xff00ffff) == 0xaa0003e0) {
		reg = inst >> 16;
		/*
		 * The principle of the following code comes from rwsem_down_write_slowpath:
		 * sub     SP,SP,#0x150     ; SP,SP,#336
		 * ...
		 * stp     x29,x30,[SP,#0xF0]   ; x29,x30,[SP,#240]
		 * ...
		 * stp     x20,x19,[SP,#0x140]   ; x20,x19,[SP,#320]
		 * add     x29,SP,#0xF0          ; x29,SP,#240
		 * x19 ~ x28 have fixed stack storage address, offset is 0x58 ~ 0x10.
		 */
		if ((reg >= 19) && (reg <= 28))
			addr = *(unsigned long *)(uintptr_t)(last_fp + (STACK_OFF_BASE +
				(28 - reg) * sizeof(unsigned long)));
	}
#else
	addr = *(unsigned long *)(uintptr_t)(frame.fp - 8);
#endif
	return addr;
}

static unsigned long get_mutex_addr(struct stackframe frame, unsigned long last_fp)
{
	unsigned long addr = 0;
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0))
	unsigned int inst;
	unsigned char reg;

	/*
	 * mutex_lock caller have such characteristics generally:
	 * .../AA1403E0/AA1303E0/    mov     x0 x28/.../x20/x19
	 * 941A65F8                  bl      0xFFFFFFC011A07B0C   ; mutex_lock
	 * so we identify lock calls with this characteristic, inst means (mov x0, x19) or
	 * (mov x0, x20)..., x19/x20/... is the key data for traversing the stack.
	 * AA1303E0
	 *   ||--> These two bits represent the register.
	 */
	frame.pc = READ_ONCE_NOCHECK(*(unsigned long *)(uintptr_t)(frame.fp + 8)); /* get caller */
	inst = *(unsigned int *)(uintptr_t)(frame.pc - 8);
	if ((inst & 0xff00ffff) == 0xaa0003e0) {
		reg = inst >> 16;
		/*
		 * The principle of the following code comes from __mutex_lock:
		 * sub     SP,SP,#0xA0      ; SP,SP,#160
		 * ...
		 * stp     x29,x30,[SP,#0x40]   ; x29,x30,[SP,#64]
		 * ...
		 * stp     x20,x19,[SP,#0x90]   ; x20,x19,[SP,#144]
		 * add     x29,SP,#0x40     ; x29,SP,#64
		 * x19 ~ x28 have fixed stack storage address.
		 */
		if ((reg >= 19) && (reg <= 28))
			/* It is different from rwsem data search method */
			addr = *(unsigned long *)(uintptr_t)(last_fp -
				(reg - 18) * sizeof(unsigned long));
	}
#else
	addr = *(unsigned long *)(uintptr_t)(last_fp - 8);
#endif
	return addr;
}

/*
 * 0xFFFFFF8018D69BC0:FFFFFFA2DF7A1000 FFFFFFC25E4B2110 <-lock:sem/mutex
 * 0xFFFFFF8018D69BD0:FFFFFF8018D69BE0 FFFFFFA2DDB2E630 <-func:down_read/mutex_lock/...
 *     |                 |                |
 *    \|/               \|/              \|/
 *  last_fp           frame.fp         frame.pc
 * we can get :sem/mutex = *(last_fp +(-) some offset) or *(frame.fp +(-) some offset)
 */
static unsigned long get_lock_addr(struct task_struct *task, enum lock_type type)
{
	struct stackframe frame;
	unsigned long lock_addr;
	unsigned long last_fp;
	char buf[64] = {0};
	int i;

	frame.fp = thread_saved_fp(task);
	frame.pc = thread_saved_pc(task);
	last_fp = frame.fp;
	do {
		sprintf_s(buf, sizeof(buf), "%ps", (void *)(uintptr_t)frame.pc);
		for (i = 0; i < ARRAY_SIZE(g_lock_list); i++) {
			if (!strcmp(buf, g_lock_list[i].lock_symbol))
				break;
		}

		if (i != ARRAY_SIZE(g_lock_list)) {
			switch (type) {
			case RW_SEM:
				lock_addr = get_rwsem_addr(frame, last_fp);
				break;
			case MUTEX:
				lock_addr = get_mutex_addr(frame, last_fp);
				break;
			default:
				lock_addr = 0;
				break;
			}

			if (!microdump_check_addr_valid(lock_addr)) {
				MD_PRINT("address %016llx invalid\n", lock_addr);
				return 0;
			}

			MD_PRINT("task %s:0x%016lx is doing %s lock:0x%016lx",
				 task->comm, task, g_lock_list[i].lock_symbol, lock_addr);
			return lock_addr;

		}
		last_fp = frame.fp;
	} while (!common_unwind_frame(task, &frame));

	return 0;
}

static enum lock_type get_lock_type(struct task_struct *task)
{
	struct stackframe frame;
	unsigned long last_fp;
	enum lock_type type = UNKNOWN;
	char buf[64] = {0};
	int i;

	frame.fp = thread_saved_fp(task);
	frame.pc = thread_saved_pc(task);
	do {
		sprintf_s(buf, sizeof(buf), "%ps", (void *)(uintptr_t)frame.pc);
		for (i = 0; i < ARRAY_SIZE(g_lock_list); i++) {
			if (!strcmp(buf, g_lock_list[i].lock_symbol))
				break;
		}
		if (i != ARRAY_SIZE(g_lock_list))
			type = g_lock_list[i].type;

		last_fp = frame.fp;
	} while (!common_unwind_frame(task, &frame));

	return type;
}

static unsigned long identify_lock_holder(unsigned long lock_addr, enum lock_type type)
{
	unsigned long holder;
	struct mutex *mutex;
	struct rw_semaphore *rw_sem;

	switch (type) {
	case RW_SEM:
		rw_sem = (struct rw_semaphore *)(uintptr_t)lock_addr;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
		holder = atomic_long_read(&rw_sem->owner);
#else
		holder = (unsigned long)rw_sem->owner;
#endif
		holder = holder & ~FLAG_MASK;
		break;
	case MUTEX:
		mutex = (struct mutex *)(uintptr_t)lock_addr;
		holder = atomic_long_read(&mutex->owner);
		holder = holder & ~FLAG_MASK;
		break;
	default:
		holder = 0;
		break;
	}

	return holder;
}

static unsigned long get_lock_holder(struct task_struct *task)
{
	unsigned long lock_addr;
	unsigned long holder;
	enum lock_type type;

	type = get_lock_type(task);
	if (type == UNKNOWN) {
		pr_debug("task %s don't involve lock waiting\n", task->comm);
		return 0;
	}

	lock_addr = get_lock_addr(task, type);
	if (!lock_addr) {
		pr_debug("unable to get lock address\n");
		return 0;
	}

	holder = identify_lock_holder(lock_addr, type);
	if (!holder) {
		MD_PRINT("lock struct don't have owner or lock holder is NULL\n");
		return 0;
	}

	if (!microdump_check_addr_valid(holder)) {
		MD_PRINT("holder is invalid\n");
		return 0;
	}

	return holder;
}

static void traverse_lock_holders(struct task_struct *entry_task)
{
	int i;
	struct task_struct *task = entry_task;
	unsigned int p_state;

	for (i = 0; i < MAX_CHECK_DEEP; i++) {
		pr_debug("now traverse task %s:0x%016lx\n", task->comm, task);
		task = (struct task_struct *)(uintptr_t)get_lock_holder(task);
		if (!task)
			return;
		p_state = READ_ONCE(task->state);
		MD_PRINT("lock:%d holder info task_addr:0x%016lx, name:%s, pid:%d, tgid:%d, state:%d\n",
			 i, task, task->comm, task->pid, task->tgid, p_state);

		if (p_state == TASK_UNINTERRUPTIBLE || p_state == TASK_INTERRUPTIBLE)
			common_show_stack(task, NULL, KERN_INFO);
	}
}

void microdump_hungtask_lock_dump(void)
{
	struct task_struct *hung_task;
	struct task_struct *g, *task;
	struct task_struct *holder;
	char task_state;
	pid_t pid;

	pid = get_hung_pid();
	if (pid < 0) {
		MD_PRINT("get hung pid failed\n");
		return;
	}

	hung_task = get_hung_task(pid);
	if (!hung_task) {
		MD_PRINT("get hung task struct failed\n");
		return;
	}
	MD_PRINT("hung task info name:%s, pid:%d, tgid:%d, state:%d\n",
		 hung_task->comm, hung_task->pid, hung_task->tgid, hung_task->state);
	traverse_lock_holders(hung_task);

	MD_PRINT("now traverse all D-state task are waiting which lock\n");
	for_each_process_thread(g, task) {
		task_state = task_state_to_char(task);
		if (task_state == 'D') {
			holder = (struct task_struct *)(uintptr_t)get_lock_holder(task);
			if (holder)
				pr_cont(" held by %s\n", holder->comm);
		}
	}
}
MODULE_LICENSE("GPL v2");
