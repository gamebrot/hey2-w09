# SPDX-License-Identifier: GPL-2.0
#
# Makefile for the kernel security code
#

obj-$(CONFIG_KEYS)			+= keys/
subdir-$(CONFIG_SECURITY_SELINUX)	+= selinux
subdir-$(CONFIG_SECURITY_SMACK)		+= smack
subdir-$(CONFIG_SECURITY_TOMOYO)        += tomoyo
subdir-$(CONFIG_SECURITY_APPARMOR)	+= apparmor
subdir-$(CONFIG_SECURITY_YAMA)		+= yama
subdir-$(CONFIG_SECURITY_LOADPIN)	+= loadpin
subdir-$(CONFIG_SECURITY_SAFESETID)    += safesetid
subdir-$(CONFIG_SECURITY_LOCKDOWN_LSM)	+= lockdown
subdir-$(CONFIG_BPF_LSM)		+= bpf

# always enable default capabilities
obj-y					+= commoncap.o
obj-$(CONFIG_MMU)			+= min_addr.o

# Object file lists
obj-$(CONFIG_SECURITY)			+= security.o
obj-$(CONFIG_SECURITYFS)		+= inode.o
obj-$(CONFIG_SECURITY_SELINUX)		+= selinux/
obj-$(CONFIG_SECURITY_SMACK)		+= smack/
obj-$(CONFIG_SECURITY)			+= lsm_audit.o
obj-$(CONFIG_SECURITY_TOMOYO)		+= tomoyo/
obj-$(CONFIG_SECURITY_APPARMOR)		+= apparmor/
obj-$(CONFIG_SECURITY_YAMA)		+= yama/
obj-$(CONFIG_SECURITY_LOADPIN)		+= loadpin/
obj-$(CONFIG_SECURITY_SAFESETID)       += safesetid/
obj-$(CONFIG_SECURITY_LOCKDOWN_LSM)	+= lockdown/
obj-$(CONFIG_CGROUPS)			+= device_cgroup.o
obj-$(CONFIG_BPF_LSM)			+= bpf/

# Object integrity file lists
subdir-$(CONFIG_INTEGRITY)		+= integrity
obj-$(CONFIG_INTEGRITY)			+= integrity/

# RY security file lists
obj-$(CONFIG_HONOR_SOP)        += sop/
obj-$(CONFIG_HN_ROOT_SCAN)     +=hw_root_scan/

# Object root_scan
obj-$(CONFIG_HONOR_EIMA)     +=eima/

# os security kernel_harden file lists
include security/kernel_harden/Makefile
obj-$(CONFIG_KERNEL_HARDEN_DEBUG)       += kernel_harden_test/

# Object kernel_stp file
obj-$(CONFIG_HN_KERNEL_STP)			+= kernel_stp/

# Object check_root file
obj-$(CONFIG_HONOR_PROC_CHECK_ROOT)     +=check_root/
