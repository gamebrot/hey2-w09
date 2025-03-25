#include <linux/kthread.h>
#include "linux/moduleparam.h"
#include "linux/delay.h"
#include "linux/mutex.h"
#include "linux/rwsem.h"
#include "linux/init.h"
#include "linux/module.h"
#include "linux/sched/clock.h"

static int para_mutex = 0;
static int para_mutexA = 0;
module_param(para_mutex, int, 0644);
module_param(para_mutexA, int, 0644);
static struct mutex mutexA;
static struct mutex mutexB;
static struct task_struct *task_mutex;
static struct task_struct *task_mutexA;
static struct task_struct *task_mutexB;

static int para_rwsem = 0;
static int para_rwsemA = 0;
module_param(para_rwsem, int, 0644);
module_param(para_rwsemA, int, 0644);
static struct rw_semaphore rw_semA;
static struct rw_semaphore rw_semB;
static struct task_struct *task_rwsem;
static struct task_struct *task_rwsemA;
static struct task_struct *task_rwsemB;

static int test_mutex(void *dummy)
{
	for (;;) {
		if (para_mutex)
			mutex_lock(&mutexA);

		schedule_timeout_interruptible(3);
	}
}

void noinline _get_mutexA(void)
{
	pr_info("_get_rwsemA\n");
	mutex_lock(&mutexA);
}
EXPORT_SYMBOL(_get_mutexA);

void noinline get_mutexA(void)
{
	pr_info("_get_rwsemA\n");
	_get_mutexA();
}
EXPORT_SYMBOL(get_mutexA);

static int test_mutexA(void *dummy)
{
	static int temp = 1;
	for (;;) {
		if (para_mutexA) {
			pr_info("hungtask:%016llx, %016llx\n", &mutexA, &mutexB);
			get_mutexA();
			mutex_lock(&mutexB);
			temp = 0;
		}
		schedule_timeout_interruptible(3);
	}
}

static int test_mutexB(void *dummy)
{
	static int temp = 1;
	for (;;) {
		if (temp) {
			mutex_lock(&mutexB);
			temp = 0;
		}
		schedule_timeout_interruptible(3);
	}
}


static int test_rwsem(void *dummy)
{
	for (;;) {
		if (para_rwsem)
			down_write(&rw_semA);

		schedule_timeout_interruptible(3);
	}
}

void noinline _get_rwsemA(void)
{
	pr_info("_get_rwsemA\n");
	down_write(&rw_semA);
}

void noinline get_rwsemA(void)
{
	pr_info("get_rwsemA\n");
	_get_rwsemA();
}

static int test_rwsemA(void *dummy)
{
	for (;;) {
		if (para_rwsemA) {
			get_rwsemA();
			pr_info("hungtask:%016llx, %016llx\n", &rw_semA, &rw_semB);
			down_write(&rw_semB);
		}
		schedule_timeout_interruptible(3);
	}
}

static int test_rwsemB(void *dummy)
{
	static int temp = 0;
	for (;;) {
		if (!temp) {
			down_write(&rw_semB);
			temp = 1;
		}
		schedule_timeout_interruptible(3);
	}
}

static int lock_test_init(void)
{
	mutex_init(&mutexA);
	mutex_init(&mutexB);
	task_mutex = kthread_run(test_mutex, NULL, "test_mutex");
	task_mutexA = kthread_run(test_mutexA, NULL, "test_mutexA");
	task_mutexB = kthread_run(test_mutexB, NULL, "test_mutexB");

	init_rwsem(&rw_semA);
	init_rwsem(&rw_semB);
	task_rwsem = kthread_run(test_rwsem, NULL, "test_rwsem");
	task_rwsemA = kthread_run(test_rwsemA, NULL, "test_rwsemA");
	task_rwsemB = kthread_run(test_rwsemB, NULL, "test_rwsemB");

	return 0;
}
subsys_initcall(lock_test_init);
MODULE_LICENSE("GPL v2");
