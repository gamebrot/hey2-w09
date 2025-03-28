/*
 * Copyright (c) Honor Device Co., Ltd. 2018-2018. All rights reserved.
 * Description: the hw_rscan_whitelist.h for set default root procs
 * Author: ducuixia <ducuixia.>
 * Create: 2018-01-19
 */

#ifndef _HW_RSCAN_WHITELIST_H_
#define _HW_RSCAN_WHITELIST_H_
#define RPROC_WHITE_LIST_STR                                               \
        "/apex/com.android.adbd/bin/adbd:"                                \
        "/apex/com.android.conscrypt/bin/boringssl_self_test32:"           \
        "/apex/com.android.conscrypt/bin/boringssl_self_test64:"           \
        "/eng/init:"                                                       \
        "/init:"                                                           \
        "/product/bin/qvirtmgr:"                                           \
        "/sbin/charger:"                                                   \
        "/sbin/hwservicemanager:"                                          \
        "/sbin/ueventd:"                                                   \
        "/system/bin/NORMAL:"                                              \
        "/system/bin/apexd:"                                               \
        "/system/bin/app_process:"                                         \
        "/system/bin/app_process32:"                                       \
        "/system/bin/app_process64:"                                       \
        "/system/bin/atrace:"                                              \
        "/system/bin/bastetd:"                                             \
        "/system/bin/bootstat:"                                            \
        "/system/bin/bugreport:"                                           \
        "/system/bin/check_longpress:"                                     \
        "/system/bin/cust_init:"                                           \
        "/system/bin/debuggerd:"                                           \
        "/system/bin/debuggerd64:"                                         \
        "/system/bin/distributedfiledaemon:"                               \
        "/system/bin/dmabuf_dump:"                                         \
        "/system/bin/do_ddrtest:"                                          \
        "/system/bin/dubaid:"                                              \
        "/system/bin/dumpstate:"                                           \
        "/system/bin/dumpsys:"                                             \
        "/system/bin/emcomd:"                                              \
        "/system/bin/factory_log_service:"                                 \
        "/system/bin/filebackup:"                                          \
        "/system/bin/fsck.exfat:"                                          \
        "/system/bin/fsck_msdos:"                                          \
        "/system/bin/goldeneye:"                                           \
        "/system/bin/gzip:"                                                \
        "/system/bin/hdbd:"                                                \
        "/system/bin/healthd:"                                             \
        "/system/bin/hilogcat:"                                            \
        "/system/bin/hiview:"                                              \
        "/system/bin/hw_cdmamodem_service:"                                \
        "/system/bin/hwnffserver:"                                         \
        "/system/bin/hwpged:"                                              \
        "/system/bin/hwpged_m:"                                            \
        "/system/bin/init:"                                                \
        "/system/bin/install-recovery.sh:"                                 \
        "/system/bin/installd:"                                            \
        "/system/bin/ip:"                                                  \
        "/system/bin/ip6tables:"                                           \
        "/system/bin/iptables:"                                            \
        "/system/bin/limit_current:"                                       \
        "/system/bin/lmkd:"                                                \
        "/system/bin/logcat:"                                              \
        "/system/bin/logcatz:"                                             \
        "/system/bin/logd:"                                                \
        "/system/bin/logserver:"                                           \
        "/system/bin/mobicache:"                                           \
        "/system/bin/netd:"                                                \
        "/system/bin/ntfs-3g:"                                             \
        "/system/bin/patchoat:"                                            \
        "/system/bin/pmom_cat:"                                            \
        "/system/bin/powerlogd:"                                           \
        "/system/bin/racoon:"                                              \
        "/system/bin/sample:"                                              \
        "/system/bin/screencap:"                                           \
        "/system/bin/screenrecord:"                                        \
        "/system/bin/sh:"                                                  \
        "/system/bin/shs:"                                                 \
        "/system/bin/statusd:"                                             \
        "/system/bin/storaged:"                                            \
        "/system/bin/system_teecd:"                                        \
        "/system/bin/tee_auth_daemon:"                                     \
        "/system/bin/thermalserviced:"                                     \
        "/system/bin/toolbox:"                                             \
        "/system/bin/toybox:"                                              \
        "/system/bin/tui_daemon:"                                          \
        "/system/bin/uncrypt:"                                             \
        "/system/bin/update_engine:"                                       \
        "/system/bin/usbd:"                                                \
        "/system/bin/vdc:"                                                 \
        "/system/bin/vold:"                                                \
        "/system/bin/vold_prepare_subdirs:"                                \
        "/system/bin/xlogcat:"                                             \
        "/system/vendor/bin/aptouch_daemon:"                               \
        "/system/vendor/bin/cs-set:"                                       \
        "/system/vendor/bin/hilogcat:"                                     \
        "/system/vendor/bin/hinetmanager:"                                 \
        "/system/vendor/bin/hiscoutmanager:"                               \
        "/system/vendor/bin/iked:"                                         \
        "/system/vendor/bin/shs:"                                          \
        "/system_ext/bin/hilogcat-early:"                                  \
        "/system_ext/bin/hwnffserver:"                                     \
        "/system_ext/bin/qcrosvm:"                                         \
        "/vendor/bin/aee_aedv64_v2:"                                       \
        "/vendor/bin/aptouch_daemon:"                                      \
        "/vendor/bin/atcmdserver:"                                         \
        "/vendor/bin/blkid:"                                               \
        "/vendor/bin/dhcp6s:"                                              \
        "/vendor/bin/diagserver:"                                          \
        "/vendor/bin/exfatfsck:"                                           \
        "/vendor/bin/fcs:"                                                 \
        "/vendor/bin/fingerprint_log:"                                     \
        "/vendor/bin/fmd:"                                                 \
        "/vendor/bin/fsck_msdos:"                                          \
        "/vendor/bin/fulldump_store:"                                      \
        "/vendor/bin/gcovd:"                                               \
        "/vendor/bin/gpsdaemon:"                                           \
        "/vendor/bin/hinetmanager:"                                        \
        "/vendor/bin/hn_aee:"                                              \
        "/vendor/bin/hw/android.hardware.boot@1.2-service:"                \
        "/vendor/bin/hw/android.hardware.thermal@2.0-service.qti-v2:"      \
        "/vendor/bin/hw/android.hardware.usb@1.0-service:"                 \
        "/vendor/bin/hw/android.hardware.usb@1.2-service-qti:"             \
        "/vendor/bin/hw/android.hardware.usb@1.2-service-mediatekv2:"      \
        "/vendor/bin/hw/rild:"                                             \
        "/vendor/bin/hw/vendor.honor.hardware.hnchipsrv@service:"          \
        "/vendor/bin/hw/vendor.honor.hardware.hwfactoryinterface@1.1-service:"    \
        "/vendor/bin/hw/vendor.honor.hardware.hwfs@1.0-service:"           \
        "/vendor/bin/hw/vendor.honor.hardware.hwhiview.service:"           \
        "/vendor/bin/hw/vendor.honor.hardware.hwhiview@1.0-service:"       \
        "/vendor/bin/hw/vendor.honor.hardware.hwsched@1.0-service:"        \
        "/vendor/bin/hw/vendor.honor.hardware.hwupdate@1.0-service:"       \
        "/vendor/bin/hw/vendor.honor.hardware.hyperhold@1.0-service:"      \
        "/vendor/bin/hw/vendor.qti.camera.provider-service_64:"            \
        "/vendor/bin/hw/vendor.qti.hardware.perf-hal-service:"             \
        "/vendor/bin/hw/wpa_supplicant:"                                   \
        "/vendor/bin/hw_diag_server:"                                      \
        "/vendor/bin/hwemerffu:"                                           \
        "/vendor/bin/iked:"                                                \
        "/vendor/bin/irqbalance:"                                          \
        "/vendor/bin/isplogcat:"                                           \
        "/vendor/bin/libqmi_oem_main:"                                     \
        "/vendor/bin/mac_addr_normalization:"                              \
        "/vendor/bin/modemchr:"                                            \
        "/vendor/bin/modemlogcat_lte:"                                     \
        "/vendor/bin/modemlogcat_via:"                                     \
        "/vendor/bin/msm_irqbalance:"                                      \
        "/vendor/bin/nvram_daemon:"                                        \
        "/vendor/bin/oeminfo_nvm_server:"                                  \
        "/vendor/bin/poweropt-service:"                                    \
        "/vendor/bin/qcom-system-daemon:"                                  \
        "/vendor/bin/radvd:"                                               \
        "/vendor/bin/sh:"                                                  \
        "/vendor/bin/smithloader:"                                         \
        "/vendor/bin/statusd:"                                             \
        "/vendor/bin/storage_info:"                                        \
        "/vendor/bin/teecd:"                                               \
        "/vendor/bin/thermal-engine-v2:"                                   \
        "/vendor/bin/thermal_core:"                                        \
        "/vendor/bin/tlogcat:"                                             \
        "/vendor/bin/toolbox:"                                             \
        "/vendor/bin/toybox_vendor:"                                       \
        "/vendor/bin/unrmd:"                                               \
        "/vendor/vin/ntfs/3g"
#endif

