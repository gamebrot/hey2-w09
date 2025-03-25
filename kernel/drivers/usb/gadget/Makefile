# SPDX-License-Identifier: GPL-2.0
#
# USB peripheral controller drivers
#
subdir-ccflags-$(CONFIG_USB_GADGET_DEBUG)	:= -DDEBUG
subdir-ccflags-$(CONFIG_USB_GADGET_VERBOSE)	+= -DVERBOSE_DEBUG
ifneq (,$(filter parrot sm6450,$(KERNEL_TARGET)))
ifneq (,$(filter tablet,$(PRODUCT_TYPE)))
subdir-ccflags-y += -DCONFIG_HONOR_DIGITAL_PAD
endif
endif
ccflags-y				+= -I$(srctree)/drivers/usb/gadget/udc

obj-$(CONFIG_USB_LIBCOMPOSITE)	+= libcomposite.o
libcomposite-y			:= usbstring.o config.o epautoconf.o
libcomposite-y			+= composite.o functions.o configfs.o u_f.o

obj-$(CONFIG_USB_GADGET)	+= udc/ function/ legacy/
