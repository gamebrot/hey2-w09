obj-$(CONFIG_HN_MEMCHECK) += memcheck_ioctl.o memcheck_memstat.o memcheck_bufmgr.o memcheck_interface.o memory_report_notify.o
ifeq ($(CONFIG_HONOR_PAGE_TRACE)$(CONFIG_MM_PAGE_TRACE),)
obj-$(CONFIG_HN_MEMCHECK) += memcheck_ion.o
endif
