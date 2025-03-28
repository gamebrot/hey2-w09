// SPDX-License-Identifier: GPL-2.0
/*
 * This program is used for create hook in dubai.
 *
 * HONOR POWER
 */

#ifndef DUBAI_VENDOR_HOOK_H
#define DUBAI_VENDOR_HOOK_H

#include <linux/device.h>
#include <linux/slab.h>
#include <linux/sched/signal.h>
#include <linux/capability.h>

typedef void(*dubaiLogIrqWakeup)(const char *);
typedef void(*dubaiSetRtcTimer)(const char *, int);
typedef void(*dubaiUpdateSuspend)(const char *);
typedef void(*dubaiLogUevent)(const char *, unsigned int);
typedef void(*dubaiLogKworker)(unsigned long, unsigned long long);
typedef void(*dubaiLogBinderStats)(int, uid_t, int, uid_t, int);

void dubai_log_irq_wakeup_hook(dubaiLogIrqWakeup dubaiWakeupHook);
void dubai_set_rtc_timer_hook(dubaiSetRtcTimer dubaiAlarmtimerHook);
void dubai_update_suspend_abort_reason_hook(dubaiUpdateSuspend dubaiWakeupReasonHook);
void dubai_log_uevent_hook(dubaiLogUevent dubaiKobjectHook);
void dubai_log_kworker_hook(dubaiLogKworker dubaiWorkqueueHook);
void dubai_log_binder_stats_hook(dubaiLogBinderStats dubaiBinderHook);

extern dubaiLogIrqWakeup kernelWakeupHook;
extern dubaiSetRtcTimer kernelAlarmtimerHook;
extern dubaiUpdateSuspend kernelWakeupReasonHook;
extern dubaiLogUevent kernelKobjectHook;
extern dubaiLogKworker kernelWorkqueueHook;
extern dubaiLogBinderStats kernelBinderHook;

#endif // DUBAI_VENDOR_HOOK_H
