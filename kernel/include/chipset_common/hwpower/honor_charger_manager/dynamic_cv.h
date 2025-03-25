#include <linux/version.h>
#include <linux/workqueue.h>
#include <linux/notifier.h>
#include <linux/power_supply.h>
#include <linux/alarmtimer.h>
#include <linux/pm_wakeup.h>
#include <linux/time.h>

#ifndef _DYNAMIC_CV_H_
#define _DYNAMIC_CV_H_

struct dynamic_cv_config
{
	int volt_th_high;
	int volt_th_low;
	int cv_step;
	int vbat_th;
	int ibat_high;
	int ibat_low;
	int isys_th;
};

enum DYNAMIC_CV_STATE {
	DYNAMIC_CV_DEFAULT = 0,
	DYNAMIC_CV_CHECK_SLOW,
	DYNAMIC_CV_CHECK_FAST,
	DYNAMIC_CV_READY,
	DYNAMIC_CV_RUNNING,
	DYNAMIC_CV_DONE,
	DYNAMIC_CV_FAIL,
};

struct dynamic_cv_info {
	struct dynamic_cv_config dynamic_cv_conf;
	int cv_increase_cnt;
	int cv_decrease_cnt;
	int status;
	struct delayed_work cv_work;
	int ibat_stable_cnt;
};

void dynamic_cv_init(struct buck_charge_device_info *di);
void dynamic_cv_start(struct buck_charge_device_info *di);
void dynamic_cv_exit(void);
#endif /* _DYNAMIC_CV_H_ */