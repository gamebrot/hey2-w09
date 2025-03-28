/*
 * Copyright (c) Honor Device Co., Ltd. 2021-2021. All rights reserved.
 * Description: the hn_kernel_stp_scanner.c for kernel stp
 * Author: jiayunlong <jiayunlong@hihonor.com>
 * Create: 2021-08-30
 */

#include "hn_kernel_stp_scanner.h"

static const char *TAG = "kernel_stp_scanner";

struct kernel_stp_scanner_node g_stp_scanner_node;

struct workqueue_struct *g_kernel_stp_scan_wq;

static DEFINE_MUTEX(stp_scanner_list_lock);

static int g_scanner_list_init = KSTP_SCAN_LIST_UNINIT;

int kernel_stp_scanner_register(stp_cb callbackfunc)
{
	struct kernel_stp_scanner_node *listnode = NULL;
	struct kernel_stp_scanner_node *p = NULL;
	int repeat_count = 0;

	if (g_scanner_list_init == KSTP_SCAN_LIST_UNINIT) {
		INIT_LIST_HEAD(&g_stp_scanner_node.stp_scanner_list);
		g_scanner_list_init = KSTP_SCAN_LIST_INIT;
		KSTPLogTrace(TAG, "kernel stp scanner init success at register.");
	}

	listnode = kzalloc(sizeof(struct kernel_stp_scanner_node),
							GFP_KERNEL);
	if (listnode == NULL) {
		KSTPLogError(TAG, "listnode init failed");
		return KSTP_ERRCODE;
	}

	listnode->callbackfunc = callbackfunc;

	mutex_lock(&stp_scanner_list_lock);
	list_for_each_entry(p, &g_stp_scanner_node.stp_scanner_list, stp_scanner_list) {
		if (listnode->callbackfunc == p->callbackfunc) {
			repeat_count++;
			KSTPLogDebug(TAG, "callbackfunc has in scanner list,no need add again!");
			break;
		}
	}
	mutex_unlock(&stp_scanner_list_lock);

	if (repeat_count == 0) {
		mutex_lock(&stp_scanner_list_lock);
		list_add_tail(&listnode->stp_scanner_list,
			&g_stp_scanner_node.stp_scanner_list);
		mutex_unlock(&stp_scanner_list_lock);

		KSTPLogTrace(TAG, "kernel stp scanner list add node success.");
	}

	return 0;
}
EXPORT_SYMBOL(kernel_stp_scanner_register);

static void kernel_stp_do_callback(struct work_struct *data)
{
	int ret;
	struct kernel_stp_scan_work *work_node = container_of(data,
					struct kernel_stp_scan_work, work);

	ret = work_node->callbackfunc();
	if (ret != 0)
		KSTPLogError(TAG, "kernel stp do callbackfunc failed!");
	kfree(work_node);
}

void kernel_stp_scanner(void)
{
	struct kernel_stp_scanner_node *p = NULL;

	mutex_lock(&stp_scanner_list_lock);
	list_for_each_entry(p, &g_stp_scanner_node.stp_scanner_list, stp_scanner_list) {
		struct kernel_stp_scan_work *work_node = NULL;

		work_node = kzalloc(sizeof(struct kernel_stp_scan_work), GFP_KERNEL);
		if (work_node == NULL) {
			KSTPLogError(TAG, "work_node init failed");
			continue;
		}

		work_node->callbackfunc = p->callbackfunc;

		INIT_WORK(&work_node->work, kernel_stp_do_callback);
		queue_work(g_kernel_stp_scan_wq, &work_node->work);
	}
	mutex_unlock(&stp_scanner_list_lock);
}


int kernel_stp_scanner_init(void)
{
	g_kernel_stp_scan_wq = create_singlethread_workqueue("HN_KERNEL_STP_SCANNER");
	if (g_kernel_stp_scan_wq == NULL) {
		KSTPLogError(TAG, "kernel stp scanner wq error, no mem");
		return -ENOMEM;
	}

	if (g_scanner_list_init == KSTP_SCAN_LIST_UNINIT) {
		INIT_LIST_HEAD(&g_stp_scanner_node.stp_scanner_list);
		g_scanner_list_init = KSTP_SCAN_LIST_INIT;
		KSTPLogTrace(TAG, "kernel stp scanner init success.");
		return 0;
	}

	KSTPLogTrace(TAG, "kernel stp scanner has init success at register");
	return 0;
}

void kernel_stp_scanner_exit(void)
{
	struct kernel_stp_scanner_node *pos = NULL;
	struct kernel_stp_scanner_node *next = NULL;

	if (g_kernel_stp_scan_wq != NULL) {
		destroy_workqueue(g_kernel_stp_scan_wq);
		g_kernel_stp_scan_wq = NULL;
	}

	mutex_lock(&stp_scanner_list_lock);
	list_for_each_entry_safe(pos, next, &g_stp_scanner_node.stp_scanner_list,
				stp_scanner_list) {
		list_del(&pos->stp_scanner_list);
		kfree(pos);
		pos = NULL;
	}
	mutex_unlock(&stp_scanner_list_lock);

	KSTPLogTrace(TAG, "stp_scanner_list cleanup success");
}
