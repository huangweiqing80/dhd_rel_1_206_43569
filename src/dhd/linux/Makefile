
# GNU Makefile for Broadcom Dongle Host Driver
#
# Copyright (C) 2014, Broadcom Corporation. All Rights Reserved.
# 
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
# 
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
# SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
# OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
#
# $Id: Makefile 477914 2014-05-15 01:24:48Z $
#
# **********  LINUX KERNEL FOR panda  ***************
# Standard preamble work.
WLAN_ComponentsInUse += bcmwifi ppr dongle
include $(dir $(lastword $(MAKEFILE_LIST)))/../../makefiles/WLAN_Common.mk

# Root name for object dir - could be just a prefix, could be a directory.
ObjPfx := dhd-

# This should be the standard but it seems to break something
# in the android/panda build so turned off for now.
#SHELL := /bin/bash

# Try a couple of places for LINUXDIR if not specified
ifeq ($(LINUXDIR),)
    ifeq ($(LINUXVER),)
        # Neither one is specified, use uname for version
        LINUXVER := $(shell uname -r)
    endif
    ifneq ($(wildcard /lib/modules/$(LINUXVER)/build/include/linux/version.h),)
        LINUXDIR := /lib/modules/$(LINUXVER)/build
    else ifneq ($(wildcard /tools/linux/src/linux-$(LINUXVER)/include/linux/version.h),)
        LINUXDIR := /tools/linux/src/linux-$(LINUXVER)
    else ifneq ($(wildcard /lib/modules/$(LINUXVER)/build/include/generated/uapi/linux/version.h),)
        # Linux 3.7+ has moved version.h to include/generated/uapi/linux.
        # If native host matches LINUXVER, then use local LINUXDIR
        LINUXDIR := /lib/modules/$(LINUXVER)/build
    else ifneq ($(wildcard /tools/linux/src/linux-$(LINUXVER)/include/generated/uapi/linux/version.h),)
        # Linux 3.7+ has moved version.h to include/generated/uapi/linux.
        LINUXDIR := /tools/linux/src/linux-$(LINUXVER)
    else
        LINUXDIR := /usr/src/linux
    endif
endif

# Derive Linux version
LINUXSRC := $(LINUXDIR)
# Try to fix for not local build
ifneq ($(wildcard $(LINUXSRC)/source), )
LINUXSRC := $(LINUXDIR)/source
endif
VERSION = $(shell grep "^VERSION =" $(LINUXSRC)/Makefile | cut -d " " -f 3)
PATCHLEVEL = $(shell grep "^PATCHLEVEL =" $(LINUXSRC)/Makefile | cut -d " " -f 3)
SUBLEVEL = $(shell grep "^SUBLEVEL =" $(LINUXSRC)/Makefile | cut -d " " -f 3)
BCM_KVERSIONSTRING := $(VERSION)$(if $(PATCHLEVEL),.$(PATCHLEVEL)$(if $(SUBLEVEL),.$(SUBLEVEL)))
UTS_RELEASE_PATH := $(LINUXDIR)/include/generated/utsrelease.h
ifeq ($(wildcard $(UTS_RELEASE_PATH)), )
UTS_RELEASE_PATH := $(LINUXDIR)/include/linux/utsrelease.h
endif
ifeq ($(wildcard $(UTS_RELEASE_PATH)), )
$(error Could not find utsrelease.h)
endif
# No need to require a kernel version when cleaning.
ifeq (,$(findstring clean,$(MAKECMDGOALS)))
LINUXVER = $(shell grep "UTS_RELEASE" $(UTS_RELEASE_PATH) | cut -d " " -f 3 | sed "s/\"//g")
$(warning Building for $(BCM_KVERSIONSTRING) Kernel, UTS_RELEASE "$(LINUXVER)")
endif

# dumb proof for 32 bit build on 64 bit machine
ifndef GCCVER_FIX_PROCESSED
 export GCCVER_FIX_PROCESSED:=1
 GCCVER ?= 4.8.2
 ifeq ($(shell uname -m), x86_64)
   ifeq (,$(shell test -f $(LINUXDIR)/.config || echo N))
     ifeq (,$(shell cat $(LINUXDIR)/.config | grep CONFIG_X86_64 -w | awk -F= '{print $$2}'))
          export 32ON64:=1
     endif
   endif
   ifneq (,$(findstring i386,$(LINUXVER))$(findstring i686,$(LINUXVER)))
     export 32ON64:=1
   endif
 endif
 ifneq (,$(filter %-32,$(GCCVER)))
  export 32ON64:=1
  override GCCVER := $(patsubst %-32,%,$(GCCVER))
 endif
endif

# Require LINUXVER to have at least 3 fields (x.y.z).
ifeq (,$(findstring clean,$(MAKECMDGOALS)))
ifeq (,$(word 3,$(subst .,$(space),$(BCM_KVERSIONSTRING))))
     $(error LINUXVER bad format: "$(LINUXVER)")
endif
endif

# Allow CROSS_COMPILE to specify compiler base
CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)ld
NM := $(CROSS_COMPILE)nm
OBJCOPY := $(CROSS_COMPILE)objcopy
STRIP := $(CROSS_COMPILE)strip

vpath %.c $(addprefix $(WLAN_SrcBaseR)/,dhd/sys dhd/debugger bcmsdio/sys) \
		$(WLAN_StdSrcDirsR) $(WLAN_ComponentSrcDirsR)


## Initialize DFLAGS
DFLAGS :=
CFILES :=

# basic options (defines in DFLAGS, includes in IFLAGS)
DFLAGS += -DLINUX -DSRCBASE=\"$(WLAN_SrcBaseA)\" -DBCMDRIVER -DBCMDONGLEHOST
DFLAGS += -DUNRELEASEDCHIP -DBCMDMA32
DFLAGS += -DBCMFILEIMAGE
ifeq ($(BCMQT),1)
	DFLAGS += -DBCMSLTGT -DBCMQT
endif
ifeq ($(WLTEST),1)
	DFLAGS += -DWLTEST -DIOCTL_RESP_TIMEOUT=20000
	DFLAGS += -DDHD_SPROM
endif

ifeq ($(TARGETLINUXOS),ubuntu)
	DFLAGS += -DLINUX_OS_UBUNTU
endif

# Past 2.6.29 kernels, arch specific bits are re-organized in linux kernel. So
# append new include paths to existing ones to get 2.6.29+ kernels compile

# Default DHDARCH is x86
ifdef ARCH
   DHDARCH ?= $(ARCH)
else
   DHDARCH ?= x86
endif
ifneq ($(findstring native,$(TARGET)),)
   DHDARCH = x86
endif
ifneq ($(findstring mips,$(TARGET)),)
   DHDARCH = mips
endif
ifneq ($(findstring arm,$(TARGET)),)
   DHDARCH = arm
endif

# First include from linux kernel dirs
IFLAGS := -I$(LINUXDIR)/include
IFLAGS += -I$(LINUXDIR)/include/asm/mach-default
# Followed by 2.6.29+ specific paths
IFLAGS += -I$(LINUXDIR)/arch/$(DHDARCH)/include
IFLAGS += -I$(LINUXDIR)/arch/$(DHDARCH)/include/asm/mach-default

# From current workspace
IFLAGS += -I.
IFLAGS += -I$(WLAN_SrcBaseA)/dhd/sys
IFLAGS += -I$(WLAN_SrcBaseA)/dhd/debugger
IFLAGS += $(WLAN_ComponentIncPath)
IFLAGS += $(WLAN_IncPathA)
# REMOVE when BISON is no longer auto merged from trunk
IFLAGS += -I$(WLAN_SrcBaseA)/dongle

ifneq ($(wildcard $(LINUXDIR)/.config),)
include $(LINUXDIR)/.config
else
# This is dangerous, since we don't know if they are really configured.
CONFIG_WIRELESS_EXT=y
DFLAGS += -DCONFIG_WIRELESS_EXT
endif

ifeq ($(CONFIG_MMC_MSM7X00A),y)
DFLAGS += -Dlinux
DFLAGS += -DDHD_SDALIGN=64 -DMAX_HDR_READ=64 -DDHD_FIRSTREAD=64
endif

WFLAGS := -Wall -Wstrict-prototypes
ifeq (,$(findstring 2.4.18,$(LINUXVER)))
  WFLAGS += -Werror
endif

#disabled# # Kernel starting from fc15 need a gcc 4.6.+ compiler that is more stricter
#disabled# # and doesn't allow warnings pass compilation step.
#disabled# # Development group requested that fixing FC15+ warnings takes few weeks
#disabled# # hence for now suppress those warnings, but do NOT let them linger for too
#disabled# # long as this may mask real sloppy compilation mistakes.

#disabled# ifeq ($(filter arm% mips%,$(TARGETARCH))$(filter arm% mips%,$(ARCH)),)
#disabled#   ifneq ($(filter 2.6.38% 2.6.39% 2.6.40%,$(LINUXVER)),)
#disabled#     WFLAGS += -Wno-unused-but-set-variable
#disabled#     WFLAGS += -Wno-unused-but-set-parameter
#disabled#     WFLAGS += -Wframe-larger-than=1024
#disabled#     WFLAGS += -maccumulate-outgoing-args
#disabled#   endif # LINUXVER
#disabled# endif # TARGETARCH

CFILES += dhd_linux.c dhd_linux_sched.c linux_osl.c bcmutils.c hnd_pktq.c hnd_pktpool.c bcmevent.c dhd_common.c dhd_ip.c dhd_linux_platdev.c dhd_linux_wq.c
CFILES += dhd_custom_gpio.c

ifeq ($(findstring -usb-,-$(TARGET)-),)
CFILES += siutils.c sbutils.c aiutils.c hndpmu.c
ifeq ($(WLTEST),1)
	CFILES += bcmsrom.c bcmotp.c
endif
else
  ifeq ($(findstring -notxthread-,-$(TARGET)-),)
    #Enable separate USB TX thread. This also allows synchronous USB resumes.
    DFLAGS += -DUSBOS_TX_THREAD
  endif
endif

# Building hsic for 43239, 43236, 4330 and 4334
ifneq ($(findstring -hsic-,-$(TARGET)-),)
DFLAGS += -DEXTENDED_VID_PID=' { USB_DEVICE(0x0a5c, 0xbd1b) }, \
                               { USB_DEVICE(0x0a5c, 0xbd17) }, \
                               { USB_DEVICE(0x0a5c, 0xbd19) }, \
                               { USB_DEVICE(0x0a5c, 0xbd1c) }, \
                                { USB_DEVICE(0x0a5c, 0xbd1a) }'
#Enable interrupt ep support for HSIC driver
DFLAGS += -DINTR_EP_ENABLE
endif

# FullDongle Usb aggregation
ifneq ($(findstring -fdaggr-,-$(TARGET)-),)
CFILES += bcm_rpc_tp_dbus.c linux_rpc_osl.c
DFLAGS += -DBCM_FD_AGGR
endif

ifneq ($(findstring -urblim-,-$(TARGET)-),)
	DFLAGS += -DBCM_MAX_URB_LEN=1920
	ifneq ($(findstring -fdaggr-,-$(TARGET)-),)
		$(error cannot have urblimit and fdaddr)
	endif
endif

OFILES=$(CFILES:.c=.o)

# Make debug a separate option
ifneq ($(findstring -debug-,-$(TARGET)-),)
DFLAGS += -DDHD_DEBUG -DSDTEST
endif

# Enable the WAR for SDIO hang
ifneq ($(findstring -regonbphangfix-,-$(TARGET)-),)
DFLAGS += -DREGON_BP_HANG_FIX
endif

# enable queuing in host
ifneq ($(findstring -sdstd-,-$(TARGET)-),)
ifeq ($(findstring -noproptxstatus-,-$(TARGET)-),)
DFLAGS += -DPROP_TXSTATUS
endif
ifneq ($(findstring -dbgwlfc-,-$(TARGET)-),)
DFLAGS += -DPROP_TXSTATUS_DEBUG
endif
endif

# Make big-endian a separate option
ifneq ($(findstring -be-,-$(TARGET)-),)
DFLAGS += -DIL_BIGENDIAN
endif

ifneq ($(findstring -qmon-,$(TARGET)-),)
DFLAGS += -DQMONITOR
CFILES += dhd_qmon.c
endif

ifneq ($(findstring -dnglimage-,-$(TARGET)-),)
## Embeddable dongle image name
DNGL_IMAGE_NAME?=
DFLAGS += -DBCM_DNGL_EMBEDIMAGE -DEMBED_IMAGE_GENERIC
IFLAGS += -I$(WLAN_SrcBaseA)/../build/dongle/$(DNGL_IMAGE_NAME)
IFLAGS += -I$(WLAN_SrcBaseA)/shared/zlib
endif

ifneq ($(findstring -cdc-,-$(TARGET)-),)
DFLAGS += -DBDC -DTOE
DFLAGS += -DDHD_BCMEVENTS -DSHOW_EVENTS
CFILES += dhd_cdc.c dhd_wlfc.c
endif

ifneq ($(findstring -dbususb-,-$(TARGET)-),)
DFLAGS += -DBCMDHDUSB -DBCMDBUS
CFILES += dbus.c dbus_usb.c dbus_usb_linux.c
endif
ifneq ($(findstring -dbususb-dnglimage-,-$(TARGET)-),)
DFLAGS += -DBCMDHDUSB -DBCMDBUS
DFLAGS += -DBCM_DNGL_EMBEDIMAGE
CFILES += dbus.c dbus_usb.c dbus_usb_linux.c
endif
ifneq ($(findstring -usb-,-$(TARGET)-),)
DFLAGS += -DBCMDHDUSB -DBCMDBUS -DBCMTRXV2
CFILES += dbus.c dbus_usb.c dbus_usb_linux.c
endif
ifneq ($(findstring -dbus-,$(TARGET)-),)
DFLAGS += -DBCMDBUS -DBCMSDIO
CFILES += dbus.c dbus_sdh.c dbus_sdh_linux.c
endif
ifneq ($(findstring -dbussdstd-,$(TARGET)-),)
DFLAGS += -DBCMSDIO -DBCMSDIOH_STD
CFILES += bcmsdh.c bcmsdstd.c bcmsdstd_linux.c bcmsdh_linux.c
DFLAGS += -DBCMDBUS
CFILES += dbus.c dbus_sdh.c dbus_sdh_linux.c
endif
ifneq ($(findstring -sdio-,-$(TARGET)-),)
DFLAGS += -DBCMSDIO
CFILES += dhd_sdio.c
endif
ifneq ($(findstring -sdbcm-,$(TARGET)-),)
DFLAGS += -DBCMSDIO -DBCMSDIOH_BCM -DTESTDONGLE
CFILES += dhd_sdio.c bcmsdh.c bcmsdbrcm.c bcmsdbrcm_linux.c bcmsdh_linux.c hnddma.c
endif
ifneq ($(findstring -sdstd-,$(TARGET)-),)
DFLAGS += -DBCMSDIO -DBCMSDIOH_STD -DBCMSDIOH_TXGLOM
DFLAGS += -DRXFRAME_THREAD
CFILES += dhd_sdio.c bcmsdh.c bcmsdstd.c bcmsdstd_linux.c bcmsdh_linux.c
ifneq ($(findstring -hc3-,$(TARGET)-),)
DFLAGS += -DSDHOST3=1
endif
endif
ifneq ($(findstring -rxf-,$(TARGET)-),)
DFLAGS += -DRXFRAME_THREAD
endif

ifneq ($(findstring -sdmmc-,-$(TARGET)-),)
ifeq ($(findstring -noproptxstatus-,-$(TARGET)-),)
  DFLAGS += -DPROP_TXSTATUS
endif
  DFLAGS += -DBCMSDIO -DBCMLXSDMMC
  CFILES += dhd_sdio.c bcmsdh_sdmmc.c bcmsdh.c bcmsdh_linux.c bcmsdh_sdmmc_linux.c
endif

ifneq ($(findstring -tacksup-,$(TARGET)-),)
DFLAGS += -DDHDTCPACK_SUPPRESS
endif

ifeq ($(call wlan_version_ge,$(BCM_KVERSIONSTRING),2.6.35),TRUE)
DFLAGS += -DARP_OFFLOAD_SUPPORT
endif
ifneq ($(findstring -android-,-$(TARGET)-),)
  DFLAGS += -DOEM_ANDROID -Dlinux -DBCMDBG
  DFLAGS += -DCUSTOMER_HW2 -DEMBEDDED_PLATFORM -DKEEP_ALIVE
  DFLAGS += -DPKT_FILTER_SUPPORT -DPNO_SUPPORT -DDUAL_STA
  CFILES += wl_android.c wldev_common.c bcmwifi_channels.c dhd_pno.c
  ifeq ($(call wlan_version_ge,$(BCM_KVERSIONSTRING),2.6.35),TRUE)
    DFLAGS += -DCSCAN
  endif
  # Enable Hotspot2.0
  # ... except on USB.
  ifeq ($(findstring -usb-,-$(TARGET)-),)
    DFLAGS += -DWL11U
  endif
endif

ifneq ($(findstring -debugger-,-$(TARGET)-),)
  DFLAGS += -DDEBUGGER
  CFILES += debugger_arm.c debugger_ui.c debugger_gdb.c debugger_linux.c arm_disassembler.c
endif

ifneq ($(findstring -cfg80211-,-$(TARGET)-),)
  ifndef COMPAT_WIRELESS
    ifneq ($(call wlan_version_ge,$(BCM_KVERSIONSTRING),2.6.38),TRUE)
      $(warning : Kernel < 2.6.38 needs compat-wireless****)
      COMPAT_WIRELESS=/projects/hnd/tools/linuxwireless/compat-wireless
      export COMPAT_WIRELESS
    endif
  endif
  ifdef COMPAT_WIRELESS
    DFLAGS += -DWL_COMPAT_WIRELESS -DWL_SUPPORT_BACKPORTED_KPATCHES
  endif
  DFLAGS += -DWL_CFG80211 -DWLP2P -DWIFI_ACT_FRAME -DESCAN_RESULT_PATCH
# DFLAGS += -DPNO_SUPPORT
  CFILES += wl_cfg80211.c wl_cfgp2p.c dhd_cfg80211.c wl_cfg_btcoex.c wl_cfgvendor.c
  CFILES += wl_linux_mon.c wldev_common.c bcmwifi_channels.c

  ifndef CONFIG_NL80211_TESTMODE
    $(warning kernel does not support nl80211 testmode API)
  endif
else
  ifeq ($(CONFIG_WIRELESS_EXT),y)
    # Do not use the flag defined in the kernel config file(CONFIG_WIRELESS_EXT),
    # Instead, use driver-wide flag(WL_WIRELESS_EXT).
    CFILES += wl_iw.c bcmwifi_channels.c
    DFLAGS += -DWL_WIRELESS_EXT -DWLLXIW -DUSE_IW
    DFLAGS += -DSOFTAP
#    DFLAGS += -DBCMFW_ROAM_ENABLE_WEXT
  endif
endif

ifneq ($(findstring -usb,-$(TARGET)-),)
ifeq ($(findstring -noproptxstatus-,-$(TARGET)-),)
DFLAGS += -DPROP_TXSTATUS
endif
ifneq ($(findstring -dbgwlfc-,-$(TARGET)-),)
DFLAGS += -DPROP_TXSTATUS_DEBUG
endif
endif


ifneq ($(findstring -oob-,-$(TARGET)-),)
  DFLAGS += -DOOB_INTR_ONLY
  DFLAGS += -DMMC_SDIO_ABORT
  ifeq ($(call wlan_version_ge,$(BCM_KVERSIONSTRING),2.6.35),TRUE)
    DFLAGS += -DHW_OOB
  endif
else
  ifneq ($(findstring -swoob-,-$(TARGET)-),)
    DFLAGS += -DOOB_INTR_ONLY
    DFLAGS += -DMMC_SDIO_ABORT
  else
    ifneq ($(findstring -sdmmc-,-$(TARGET)-),)
      DFLAGS += -DSDIO_ISR_THREAD
    endif
  endif
endif

# *** PLEASE try not to overwirte the common -sdmmc- settings in your build.
# if all builds (nexus, panda etc) have its special settings, we will end up having \
	many
# duplicate flags/files in DFLAGS, CFILES

ifneq ($(findstring -nexus-,-$(TARGET)-),)
  DFLAGS += -DDHD_USE_STATIC_BUF -DCUSTOM_OOB_GPIO_NUM=299
endif

ifneq ($(findstring -p2p-,-$(TARGET)-),)
DFLAGS += -DWL_IFACE_COMB_NUM_CHANNELS
	ifeq ($(call wlan_version_ge,$(BCM_KVERSIONSTRING),3.8.0),FALSE)
# Make sure that Kernel has the required patches for p2p operation. Refer to
# http://hwnbu-twiki.sj.broadcom.com/bin/view/Mwgroup/P2pWpaSupplicant#Kernel
#_Patches_Applied_on_Proxim
		DFLAGS += -DWL_SUPPORT_BACKPORTED_KPATCHES
	endif
DFLAGS += -DHT40_GO -DWL_SDO -DVSDB -DWL_CFG80211_VSDB_PRIORITIZE_SCAN_REQUEST
DFLAGS += -DWL_CFG80211_STA_EVENT -DWL_IFACE_COMB_NUM_CHANNELS
DFLAGS += -DSUPPORT_PM2_ONLY -DAMPDU_HOSTREORDER
DFLAGS += -DDHD_USE_IDLECOUNT
# This define is for SoftAP. But assuming that the platform using P2P might use SoftAP as well.
DFLAGS += -DSET_RANDOM_MAC_SOFTAP
endif

ifneq ($(findstring -htc-,-$(TARGET)-),)
DFLAGS += -DBCMWAPI_WPI -DBCMWAPI_WAI -DCUSTOM_OOB_GPIO_NUM=299 -DWL_ENABLE_P2P_IF -DWL_CFG80211_STA_EVENT
DFLAGS += -DWL_CFG80211_VSDB_PRIORITIZE_SCAN_REQUEST -DHT40_G -DBCMCCX -DHTC_KlocWork -DHTC_TX_TRACKING
DFLAGS += -DUSE_DYNAMIC_MAXPKT_RXGLOM
endif

ifneq ($(findstring -usb-android-cfg80211-jellybean-,-$(TARGET)-),)
  DFLAGS += -DWL_ENABLE_P2P_IF -DWL_CFG80211_STA_EVENT
endif

ifneq ($(findstring -panda-,-$(TARGET)-),)
$(warning : =====> Panda build <======)
DFLAGS += -DBCMWAPI_WPI -DBCMWAPI_WAI -DBCM_REQUEST_FW
DFLAGS += -DCUSTOM_OOB_GPIO_NUM=138 -DDHD_USE_EARLYSUSPEND -DBOARD_PANDA \
    -DNEW_COMPAT_WIRELESS -DWL_CFG80211_STA_EVENT -DWL_SUPPORT_BACKPORTED_KPATCHES -DMFP
DFLAGS += -DWL_CFG80211_VSDB_PRIORITIZE_SCAN_REQUEST -DWL_SDO
# Supplicant >= 77 requires WL_IFACE_COMB_NUM_CHANNELS for enabling multichannel concurrency
DFLAGS += -DWL_IFACE_COMB_NUM_CHANNELS
DFLAGS += -DVSDB
DFLAGS += -DBCMCCX
#BT/WiFi handover/tunneling
DFLAGS += -DBT_WIFI_HANDOVER
#add roaming features
#DFLAGS += -DROAM_ENABLE
DFLAGS += -DWL_ENABLE_P2P_IF
# Enable Voice Enterprise/802.11r (FBT) by default.
# Note that these changes require a modified version of linux/cfg80211.
# Those linux changes will be submitted upstream but for now only work
# under panda-ics-1.5.0.
# WLFBT only controls whether the dhd understands the new 802.11r FBT AKM
# suites.
DFLAGS += -DWLFBT
# Uncomment this for run-time selection of FBT-lite/heavy mode based on module
# parameter "dhd_use_idsup".
# -(FBT-heavy) When dhd_use_idsup=1, dhd attempts to turn on the in-dongle supplicant
# if supported by the firmware so that it will perform the 4-way handshake. This
# mode requires support from firmware and external supplicant so only enable this
# if you know what you're doing.
# -(FBT-lite) When dhd_use_idsup=0 or not passed (default), external supplicant will
# do the 4-way handshake.
# Commented means that external supplicant will do the 4-way handshake.
DFLAGS += -DBCMSUP_4WAY_HANDSHAKE
# Enable driver based roaming
#DFLAGS += -DBCMFW_ROAM_ENABLE
# --- turn off ht clock when idle ---
DFLAGS += -DDHD_USE_IDLECOUNT
DFLAGS += -DWLAIBSS -DCUSTOM_IBSS_AMPDU_BA_WSIZE=16
  ifeq ($(CONFIG_WIRELESS_EXT),y)
    DFLAGS :=$(filter-out -DCSCAN,$(DFLAGS))
  endif
  ifneq ($(findstring -hsic-android-,-$(TARGET)-),)
    DFLAGS :=$(filter-out -DWL_ENABLE_P2P_IF,$(DFLAGS))
  endif
endif

ifneq ($(findstring -manta-,-$(TARGET)-),)
$(info : =====> MANTA CFG Kernel 3.4 build <=====)
DFLAGS :=$(filter-out -DSOFTAP,$(DFLAGS))
DFLAGS :=$(filter-out -DSDIO_ISR_THREAD,$(DFLAGS))
DFLAGS :=$(filter-out -DCUSTOMER_HW4,$(DFLAGS))
DFLAGS += -DSET_RANDOM_MAC_SOFTAP
DFLAGS += -DDHD_USE_IDLECOUNT -DWL_HOST_BAND_MGMT
DFLAGS += -DVSDB
DFLAGS += -DCUSTOM_ROAM_TRIGGER_SETTING=-65
DFLAGS += -DCUSTOM_ROAM_DELTA_SETTING=15
DFLAGS += -DWL_CFG80211_VSDB_PRIORITIZE_SCAN_REQUEST
DFLAGS += -DAMPDU_HOSTREORDER
DFLAGS += -DUSE_SDIOFIFO_IOVAR
DFLAGS += -DDCUSTOM_SDIO_F2_BLKSIZE=128
DFLAGS += -DSUPPORT_PM2_ONLY
DFLAGS += -DCUSTOM_KEEP_ALIVE_SETTING=28000
DFLAGS += -DCUSTOM_PNO_EVENT_LOCK_xTIME=7
DFLAGS += -Dlinux -DBCMDRIVER                                          \
	-DBCMDONGLEHOST -DUNRELEASEDCHIP -DBCMDMA32 -DBCMFILEIMAGE            \
	-DDHD_DEBUG -DSDTEST -DBDC -DTOE                          \
	-DDHD_BCMEVENTS -DSHOW_EVENTS -DPROP_TXSTATUS -DBCMDBG                \
	-DCUSTOMER_HW2 -DOOB_INTR_ONLY -DHW_OOB                               \
	-DMMC_SDIO_ABORT -DBCMSDIO -DBCMLXSDMMC -DWLP2P     \
	-DWIFI_ACT_FRAME -DARP_OFFLOAD_SUPPORT                                \
	-DKEEP_ALIVE -DGET_CUSTOM_MAC_ENABLE -DPKT_FILTER_SUPPORT             \
	-DEMBEDDED_PLATFORM -DENABLE_INSMOD_NO_FW_LOAD -DPNO_SUPPORT 	      \
	-DDHD_DONOT_FORWARD_BCMEVENT_AS_NETWORK_PKT
# Jellybean build
DFLAGS += -DWL_CFG80211 -DWL_CFG80211_STA_EVENT
DFLAGS += -DWL_ENABLE_P2P_IF
endif

ifneq ($(findstring -prime-,-$(TARGET)-),)
$(info : =====> prime build <=====)
DFLAGS :=$(filter-out -DSOFTAP,$(DFLAGS))
DFLAGS :=$(filter-out -DSDIO_ISR_THREAD,$(DFLAGS))
CFILES += dhd_bta.c
DFLAGS += -DCUSTOM_GLOM_SETTING=0
DFLAGS += -DCUSTOM_ROAM_TRIGGER_SETTING=-65
DFLAGS += -DCUSTOM_ROAM_DELTA_SETTING=15
DFLAGS += -DHD_GPL -DDHD_SCHED -DCUSTOMER_HW2 -DNEW_COMPAT_WIRELESS -DWIFI_ACT_FRAME 	\
    -DGET_CUSTOM_MAC_ENABLE -DPKT_FILTER_SUPPORT -DENABLE_INSMOD_NO_FW_LOAD				\
    -DPNO_SUPPORT -DWLBTAMP -DOOB_INTR_ONLY -DMMC_SDIO_ABORT -DHW_OOB -DWIFI_ACT_FRAME	\
    -DSDTEST -DDHD_USE_EARLYSUSPEND -DCUSTOM_OOB_GPIO_NUM=2 -DWL_ENABLE_P2P_IF			\
    -DWL_CFG80211_STA_EVENT
	ifneq ($(findstring -lungo-,-$(TARGET)-),)
     $(info : =====> lungo build <=====)
			DFLAGS += -fno-pic
			DFLAGS :=$(filter-out -DENABLE_INSMOD_NO_FW_LOAD,$(DFLAGS))
	endif
	ifneq ($(findstring -jellybean-,-$(TARGET)-),)
     $(warning : ***** Jellybean build *****)
			DFLAGS += -DSET_RANDOM_MAC_SOFTAP
			DFLAGS += -DWL_SCHED_SCAN
	endif
endif

ifneq ($(findstring -mfp-,-$(TARGET)-),)
  DFLAGS += -DMFP
endif

ifneq ($(findstring -stb-,-$(TARGET)-),)
$(info : =====> stb build <=====)

  ifneq ($(findstring -jellybean-,-$(TARGET)-),)
  $(warning : ***** Jellybean build *****)
    DFLAGS += -DSET_RANDOM_MAC_SOFTAP
    DFLAGS += -DWL_SCHED_SCAN
    DFLAGS += -DWL_CFG80211
    ifneq ($(call wlan_version_ge,$(BCM_KVERSIONSTRING),3.6.0),TRUE)
      DFLAGS += -DWL_SUPPORT_BACKPORTED_KPATCHES
    endif
    ifneq ($(call wlan_version_ge,$(BCM_KVERSIONSTRING),3.8.0),TRUE)
      DFLAGS += -DWL_ENABLE_P2P_IF
    endif
    DFLAGS += -DWL_CFG80211_STA_EVENT
    #add p2p features
    DFLAGS += -DWL_CFG80211_GON_COLLISION
  endif

endif   # stb

# ======================= mps platforms =================================
ifneq ($(findstring -capri_ap-,-$(TARGET)-),)
$(warning : =====> MPS capri_ap build <======)
	# --- common chip independent flags ---
	DFLAGS += -DCUSTOMER_HW2 -DOOB_INTR_ONLY -DSUPPORT_PM2_ONLY
	DFLAGS += -DPLATFORM_MPS -DDHD_USE_IDLECOUNT -DSUPPORT_MULTIPLE_REVISION -DSUPPORT_MULTIPLE_CHIPS
	DFLAGS += -DCUSTOM_OOB_GPIO_NUM=102 -DDHD_USE_EARLYSUSPEND
	DFLAGS += -DWL_ENABLE_P2P_IF -DNEW_COMPAT_WIRELESS -DWL_CFG80211
	DFLAGS += -DWL_CFG80211_STA_EVENT -DWL_SUPPORT_BACKPORTED_KPATCHES

	# --- current capri kernel defines CONFIG_BCM4334 ---
	# --- force to test other 43xx chips, default 4335  ---
	override CONFIG_BCM4335 :=y
	override CONFIG_BCM43241 :=
	override CONFIG_BCM4334 :=

	ifneq ($(CONFIG_BCM4330),)
	  DFLAGS += -DBCM4330_CHIP
	  DFLAGS += -DMCAST_LIST_ACCUMULATION
	  DFLAGS += -DCONFIG_CONTROL_PM
	endif

	ifneq ($(CONFIG_BCM4334),)
$(warning : ****** COMPILING FOR ====> 4334 chip<==== **********)
		#add BCM4334 features
		DFLAGS += -DBCM4334_CHIP
		#DFLAGS += -DENABLE_INSMOD_NO_FW_LOAD
		DFLAGS += -DVSDB_DYNAMIC_F2_BLKSIZE -DSDIO_F2_BLKSIZE=512 -DVSDB_F2_BLKSIZE=64
		DFLAGS += -DPROP_TXSTATUS
		DFLAGS += -DMAX_CNTL_TIMEOUT=1
		DFLAGS += -DENABLE_BCN_LI_BCN_WAKEUP
		DFLAGS += -DCUSTOM_GLOM_SETTING=5
		DFLAGS += -DWL11U
		DFLAGS += -DVSDB -DHT40_GO -DWL_CFG80211_VSDB_PRIORITIZE_SCAN_REQUEST
	endif

	ifneq ($(CONFIG_BCM4335),)
$(warning : ****** COMPILING FOR ====> 4335 chip<==== **********)
		#-- don't use with capri_ap yet ---
		#DFLAGS += -DENABLE_INSMOD_NO_FW_LOAD
		DFLAGS += -DBCM4335_CHIP
		DFLAGS += -DVSDB -DHT40_GO -DWL_CFG80211_VSDB_PRIORITIZE_SCAN_REQUEST
		DFLAGS += -DMAX_CNTL_TIMEOUT=1
		DFLAGS += -DENABLE_BCN_LI_BCN_WAKEUP
		DFLAGS += -DCUSTOM_GLOM_SETTING=5 -DCUSTOM_RXCHAIN=1
		DFLAGS += -DWL11U
		DFLAGS += -DBCMSDIOH_TXGLOM
		DFLAGS += -DCUSTOM_TXGLOM=1
		DFLAGS += -DBCMSDIOH_TXGLOM_HIGHSPEED
		DFLAGS += -DDHD_SET_FW_HIGHSPEED
		DFLAGS += -DUSE_SDIOFIFO_IOVAR
		DFLAGS += -DCUSTOM_MAX_TXGLOM_SIZE=32
		DFLAGS += -DCUSTOM_DEF_TXGLOM_SIZE=16
		DFLAGS += -DDHD_SDALIGN=64

		DFLAGS :=$(filter-out -DPROP_TXSTATUS, $(DFLAGS))
		DFLAGS :=$(filter-out -DAMPDU_HOSTREORDER, $(DFLAGS))
	endif

	ifneq ($(CONFIG_BCM43241),)
$(warning : ****** COMPILING FOR ====> 43241 chip<==== **********)
	  DFLAGS += -DBCM43241_CHIP
	  DFLAGS += -DMCAST_LIST_ACCUMULATION
	  DFLAGS += -DMIMO_ANT_SETTING
	  DFLAGS += -DAMPDU_HOSTREORDER  -DPROP_TXSTATUS
	  DFLAGS +=	-DDHD_DONOT_FORWARD_BCMEVENT_AS_NETWORK_PKT
	  DFLAGS += -DCUSTOM_SDIO_F2_BLKSIZE=128 -DWL_SDO -DWLTDLS
	  DFLAGS += -Idrivers/net/wireless/bcmdhd	-Idrivers/net/wireless/bcmdhd/include
	  DFLAGS +=	-Idrivers/net/wireless/bcmdhd/common/include
	  ifeq ($(CONFIG_BCM43241),m)
		DHDCFLAGS += -fno-pic
	  endif
	endif

	# ---- wapi: MPS has no kernel support for it yet ---
	#DFLAGS += -DBCMWAPI_WPI -DBCMWAPI_WAI

	# --- flags that must not be defined for capri_ap ---
	DFLAGS :=$(filter-out -DHW_OOB, $(DFLAGS))
	DFLAGS :=$(filter-out -DSDTEST, $(DFLAGS))

	ifneq ($(findstring -jellybean-,-$(TARGET)-),)
     $(warning : ***** Jellybean build *****)
			DFLAGS += -DWL_CFG80211 -DWL_CFG80211_STA_EVENT -DWL_ENABLE_P2P_IF
			DFLAGS += -DSET_RANDOM_MAC_SOFTAP
	endif
endif
# ======================= end of mps platforms =================================

# filter out wapi specific defines for compat-wireless, as corresponding
# defines are not added in cfg80211 and nl80211 files
ifdef COMPAT_WIRELESS
  DFLAGS :=$(filter-out -DBCMWAPI_WPI,$(DFLAGS))
  DFLAGS :=$(filter-out -DBCMWAPI_WAI,$(DFLAGS))
endif

ifneq ($(findstring -sdspi-,$(TARGET)-),)
  DFLAGS += -DBCMSDIO -DBCMSDIOH_SPI -DTESTDONGLE # -DBCMSDYIELD
  CFILES += dhd_sdio.c bcmsdh.c bcmsdspi.c bcmsdspi_linux.c bcmsdh_linux.c
endif
ifneq ($(findstring -gspi-,$(TARGET)-),)
  DFLAGS += -DBCMSDIO -DBCMSPI
  CFILES += dhd_sdio.c bcmsdh.c bcmspibrcm.c bcmsdspi_linux.c bcmsdh_linux.c
  ifneq ($(findstring -android-,$(TARGET)-),)
    DFLAGS += -DBCMSPI_ANDROID
  else
    DFLAGS += -DBCMSDIOH_SPI -DTESTDONGLE
  endif
endif
ifneq ($(findstring -gspibcm,$(TARGET)-),)
  DFLAGS += -DBCMSDIO -DBCMSDIOH_SPI -DTESTDONGLE -DBCMSPI
  CFILES += dhd_sdio.c bcmsdh.c bcmgspi.c bcmsdbrcm_linux.c bcmsdh_linux.c hnddma.c
endif
ifneq ($(findstring -pci-,$(TARGET)-),)
  CFILES += bcmpcispi.c
endif
ifneq ($(findstring -sdext-,$(TARGET)-),)
  DFLAGS += -DBCMSDIO -DTESTDONGLE
  CFILES += dhd_sdio.c
endif

#ifdef WLBTAMP
 ifneq ($(findstring -btamp-,$(TARGET)-),)
  DFLAGS += -DWLBTAMP
  CFILES += dhd_bta.c
endif

#ifdef WIFI_ACT_FRAME
DFLAGS += -DWIFI_ACT_FRAME
#endif
ifneq ($(findstring -comp,-$(TARGET)),)
DFLAGS += -DBCMUSBDEV_COMPOSITE
endif

#
# SAVERESTORE
#
# DFLAGS += -DUSE_CMD14
# Without CMD14, defaults to CMD52 toggle to wakeup device
# Or define this for OOB wakeup
# DFLAGS += -DUSE_OOB_GPIO1

ifneq ($(findstring -reqfw-,$(TARGET)-),)
DFLAGS += -DBCM_REQUEST_FW
endif

ifneq ($(findstring -pciefd-,$(TARGET)-),)
DFLAGS += -DPCIE_FULL_DONGLE
DFLAGS += -DBCMPCIE
DFLAGS += -DCUSTOM_DPC_PRIO_SETTING=-1
DFLAGS += -DSHOW_EVENTS
DFLAGS += -DSHOW_LOGTRACE
CFILES += dhd_pcie.c dhd_pcie_linux.c pcie_core.c dhd_flowring.c
ifneq ($(findstring -msgbuf-,$(TARGET)-),)
CFILES += dhd_msgbuf.c
endif
ifneq ($(findstring -router-,$(TARGET)-),)
# For router specific optimizations
DFLAGS += -DBCM_ROUTER_DHD
endif
# By default r/w pointers(indices) are
# dmaed only via FW/Host agreement
# o/w it is specified via explicit targets
ifneq ($(findstring -indxtcm-,$(TARGET)-),)
# FW gets r/w indices only from its memory
DFLAGS += -DBCM_INDX_TCM
endif
ifneq ($(findstring -indxdma-,$(TARGET)-),)
# FW gets r/w indices only from Host Memory
DFLAGS += -DBCM_INDX_DMA
endif
ifneq ($(findstring -buzzz-,$(TARGET)-),)
# For BUZZZ profiling tools
DFLAGS += -DBCM_BUZZZ
endif
endif

ifneq ($(findstring -wapi-,$(TARGET)-),)
DFLAGS +=-DBCMWAPI_WPI -DBCMWAPI_WAI
endif

ifneq ($(findstring -ccx-,$(TARGET)-),)
DFLAGS +=-DBCMCCX
endif

ifneq ($(findstring -fbt-,$(TARGET)-),)
DFLAGS +=-DWLFBT
endif

# disable 11U for ICS MR1.
ifneq ($(findstring -icsmr1-,-$(TARGET)-),)
  $(warning : ***** IceCream MR1 build *****)
  DFLAGS :=$(filter-out -DWL_ENABLE_P2P_IF,$(DFLAGS))
  DFLAGS :=$(filter-out -DWL_CFG80211_STA_EVENT,$(DFLAGS))
  DFLAGS :=$(filter-out -DWL_SUPPORT_BACKPORTED_KPATCHES,$(DFLAGS))
  DFLAGS :=$(filter-out -DWL11U,$(DFLAGS))
endif

#
# Makefile_hwx target : extract CFLAGS from bcmdhd/Makefile_hwx file
#
# Makefile_xx_xx ignore this file's DFLAGS
# instead of this file's DFLAGS, this will be use Makefile_hw4's defines directly.
ifneq ($(findstring -Makefile,-$(TARGET)-),)
ifeq ($(MAKECMDGOALS), modules)

# find customer's Makefile(ex: Makefile_hw4)
MAKEFILE_HWx = $(filter Makefile%, $(subst -, ,$(TARGET)))
MAKEFILE_HWx_AndVer = $(filter Makefile%, $(subst -, ,$(TARGET)))_$(wordlist 2, 2, \
				$(subst _, ,$(filter android_%, $(subst -, ,$(TARGET)))))

# Merge separated android difinition file into Makefile
# Copy $(MAKEFILE_HWx) to Makefile_base
CMD_MAKEFILE_1 = $(shell cp $(WLAN_SrcBaseR)/bcmdhd/$(MAKEFILE_HWx) ./Makefile_base)

# Merge android definition file($(MAKEFILE_HWx_AndVer)) into Makefile_base and save it as Makefile
ifneq ($(findstring -customer_hw10,-$(TARGET)-),)
CMD_MAKEFILE_2 = $(shell awk -v RS="\0" -v ORS="" 'NR==FNR{r=$$0;next} \
				{gsub(/THIS_STRING_WILL_BE_REPLACED_WITH_ANDROID_DEFINITION/,r)} \
				{gsub(/src\/shared\/bcmwifi\/src\//,"",$$0)} \
				{gsub(/src\/bcmsdio\/sys\//,"",$$0)} \
				{gsub(/src\/dhd\/sys\//,"",$$0)} \
				{gsub(/src\/shared\//,"",$$0)} \
				{gsub(/src\/wl\/sys\//,"",$$0);print $$0}' \
				$(WLAN_SrcBaseR)/bcmdhd/$(MAKEFILE_HWx_AndVer) Makefile_base > Makefile)
else
CMD_MAKEFILE_2 = $(shell awk -v RS="\0" -v ORS="" 'NR==FNR{r=$$0;next}{ \
				sub(/THIS_STRING_WILL_BE_REPLACED_WITH_ANDROID_DEFINITION/,r)}1' \
				$(WLAN_SrcBaseR)/bcmdhd/$(MAKEFILE_HWx_AndVer) Makefile_base > Makefile)
endif # customer_hw10

# trick for print '$' string in echo command
TEXT_DOLLAR = $$

# For extract VARIABLE in Makefile
ADD_MAKEFILE_PRINT_VARIABLE = $(shell \
	echo 'print-%: ' >> Makefile && \
	echo '	@echo $(TEXT_DOLLAR)($(TEXT_DOLLAR)*)' >> Makefile)

# Extract DHDOFILES from Makefile
NOW_DIR = $(shell pwd)
GET_DHDOFILES = $(shell make -C $(LINUXDIR) -f .config -f $(NOW_DIR)/Makefile print-DHDOFILES --no-print-directory)

$(warning DHDOFILES extracted from Makefile $(CMD_MAKEFILE_1) $(CMD_MAKEFILE_2) $(ADD_MAKEFILE_PRINT_VARIABLE))

# override CFILES
CFILES = $(GET_DHDOFILES)

ifneq ($(findstring -android,-$(TARGET)-),)
CFLAGS += -DOEM_ANDROID
endif # android

endif # modules
endif # Makefile


# DFLAGS will be used in Makefile_hwx file
ifneq ($(findstring -Makefile,-$(TARGET)-),)
CFLAGS += -fshort-wchar			$(WFLAGS) $(IFLAGS) $(MY_C_DEFINES)
else
CFLAGS += -fshort-wchar $(DFLAGS) $(WFLAGS) $(IFLAGS) $(MY_C_DEFINES)
endif


LDFLAGS := -r
MODULES := dhd.o
ifeq ($(call wlan_version_ge,$(BCM_KVERSIONSTRING),2.5.0),TRUE)
  ##Kernel module names in 2.6 kernel have .ko suffix
  KMODULES:=dhd.ko
  ifneq ($(findstring -android-,-$(TARGET)-),)
      KMODULES:=bcmdhd.ko
  endif
else
  KMODULES:=$(MODULES)
endif

# host options
HOSTCC := $(CC)
ifeq ($(call wlan_version_ge,$(BCM_KVERSIONSTRING),2.5.0),TRUE)
  HOSTCFLAGS := $(CFLAGS) -D__KERNEL__
  export DHDCFLAGS := $(HOSTCFLAGS) -I$(shell pwd)
  export DHDOFILES := $(OFILES)
else
  HOSTCFLAGS := $(CFLAGS) $(shell $(MAKE) --no-print-directory -s -C $(LINUXDIR) script 'SCRIPT=@echo $$(CFLAGS) $$(MODFLAGS)')
endif

# Please do NOT explicitly specify any -debug build here, the Makefile can handles that postfix.
# That is, -debug can be added to any of the following builds#

TARGETS := \
	msgbuf-pciefd \
	msgbuf-pciefd-mfp \
	msgbuf-pciefd-tacksup \
	msgbuf-pciefd-buzzz \
	msgbuf-pciefd-buzzz-tacksup \
	msgbuf-pciefd-router \
	msgbuf-pciefd-router-tacksup \
	msgbuf-pciefd-indxtcm \
	msgbuf-pciefd-indxdma \
	msgbuf-pciefd-android-cfg80211 \
	msgbuf-pciefd-android-cfg80211-tacksup \
	msgbuf-pciefd-android-cfg80211-wapi-ccx-fbt \
	msgbuf-pciefd-android-cfg80211-wapi-ccx-fbt-tacksup \
	msgbuf-pciefd-android-stb-jellybean-cfg80211 \
	msgbuf-pciefd-android-stb-jellybean-cfg80211-mfp \
	cdc-usb \
	cdc-usb-notxthread \
	cdc-dbususb \
	cdc-dbususb-dnglimage \
	cdc-sdio \
	cdc-dbus \
	cdc-sdbcm \
	cdc-sdstd \
	cdc-sdstd-tacksup \
	cdc-sdstd-qmon \
	cdc-sdstd-qmon-tacksup \
	cdc-dbussdstd \
	cdc-sdspi-pci \
	cdc-sdstd-noproptxstatus \
	cdc-sdstd-noproptxstatus-tacksup \
	cdc-sdmmc-android-nexus\
	cdc-sdmmc-android-nexus-oob\
	cdc-sdmmc-android-nexus-cfg80211\
	cdc-sdmmc-android-nexus-cfg80211-oob\
	cdc-sdmmc-android-panda-oob \
	cdc-sdmmc-android-panda-cfg80211 \
	cdc-sdmmc-android-panda-cfg80211-oob \
	cdc-sdmmc-android-panda-cfg80211-oob-debugger \
	cdc-sdmmc-android-panda-icsmr1-cfg80211 \
	cdc-sdmmc-android-panda-icsmr1-cfg80211-oob \
	cdc-sdmmc-android-panda-icsmr1-cfg80211-swoob \
	cdc-sdmmc-android-htc-cfg80211-oob \
	cdc-sdmmc-android-capri_ap-jellybean-cfg80211-oob \
	cdc-sdmmc-android-prime-cfg80211 \
	cdc-sdmmc-android-prime-icsmr1-cfg80211 \
	cdc-sdmmc-android-prime-cfg80211-gpl \
	cdc-sdmmc-android-prime-cfg80211-oob-gpl \
	cdc-sdmmc-android-prime-jellybean-cfg80211-oob-gpl \
	cdc-sdmmc-android-prime-lungo-cfg80211 \
	cdc-sdmmc-android-prime-lungo-icsmr1-cfg80211 \
	cdc-sdmmc-android-prime-lungo-cfg80211-gpl \
	cdc-sdmmc-android-prime-lungo-cfg80211-oob-gpl \
	cdc-sdmmc-android-prime-lungo-jellybean-cfg80211-oob-gpl \
	cdc-sdmmc-android-manta-jellybean-cfg80211-oob-gpl \
	cdc-sdstd-nothread \
	cdc-sdstd-nothread-tacksup \
	cdc-sdmmc-gpl \
	cdc-sdmmc-cfg80211-gpl \
	cdc-usb-gpl \
	cdc-usb-notxthread-gpl \
	cdc-usb-cfg80211-gpl \
	cdc-usb-notxthread-cfg80211-gpl \
	cdc-usb-reqfw-gpl \
	cdc-usb-notxthread-reqfw-gpl \
	cdc-usb-reqfw-android-cfg80211 \
	cdc-usb-notxthread-reqfw-android-cfg80211 \
	cdc-usb-android-cfg80211-reqfw \
	cdc-usb-android-stb-jellybean-cfg80211 \
	cdc-usb-android-stb-jellybean-cfg80211-comp \
	cdc-usb-android-stb-jellybean-cfg80211-comp-mfp \
	cdc-usb-android-stb-jellybean-cfg80211-noproptxstatus \
	cdc-usb-reqfw-android-stb-jellybean-cfg80211 \
	cdc-usb-reqfw-android-stb-jellybean-cfg80211-comp \
	cdc-usb-reqfw-android-stb-jellybean-cfg80211-comp-mfp \
	cdc-usb-reqfw-android-stb-jellybean-cfg80211-noproptxstatus \
	cdc-usb-notxthread-android-cfg80211-reqfw \
	cdc-usb-android-cfg80211-jellybean-reqfw \
	cdc-usb-notxthread-android-cfg80211-jellybean-reqfw \
	cdc-sdstd-android-cfg80211-p2p \
	cdc-sdstd-android-cfg80211-p2p-tacksup \
	cdc-usb-hsic-android-panda-cfg80211 \
	cdc-usb-notxthread-hsic-android-panda-cfg80211 \
	cdc-usb-reqfw-p2p-android-cfg80211 \
	cdc-usb-notxthread-reqfw-p2p-android-cfg80211 \
	cdc-usb-hsic-p2p-android-cfg80211 \
	cdc-usb-notxthread-hsic-p2p-android-cfg80211 \
	cdc-usb-dnglimage-gpl \
	cdc-usb-notxthread-dnglimage-gpl \
	cdc-usb-fdaggr-gpl \
	cdc-usb-notxthread-fdaggr-gpl \
	cdc-usb-comp \
	cdc-usb-comp-mfp \
	cdc-usb-notxthread-comp \
	cdc-usb-comp-gpl \
	cdc-usb-comp-mfp-gpl \
	cdc-usb-urblim-comp-gpl \
	cdc-usb-notxthread-comp-gpl \
	cdc-sdstd-apsta \
	cdc-sdstd-apsta-tacksup \
	cdc-sdio-dnglimage \
	cdc-sdbcm-dnglimage \
	cdc-sdstd-dnglimage \
	cdc-sdstd-dnglimage-tacksup \
	cdc-dbussdstd-dnglimage \
	cdc-dbus-dnglimage \
	cdc-sdspi-pci-dnglimage \
	cdc-gspi-pci \
	cdc-gspibcm \
	cdc-sdstd-regonbphangfix \
	cdc-sdstd-regonbphangfix-tacksup \
	cdc-sdstd-hc3 \
	cdc-sdstd-hc3-tacksup \
	cdc-sdmmc-p2p-android-cfg80211 \
	Makefile_hw4-android_jb-customer_hw4 \
	Makefile_hw4-android_jbp-customer_hw4 \
	Makefile_hw4-android_kk-customer_hw4 \
	android-Makefile_hw10-android_jb-customer_hw10 \
	android-Makefile_hw10-android_jbp-customer_hw10 \
	android-Makefile_hw10-android_kk-customer_hw10
TARGETS += cdc-sdext-be
TARGETS += cdc-sdext-be-dnglimage
#ifdef WLBTAMP
TARGETS += cdc-sdstd-btamp
#endif

TARGETS := $(addprefix $(ObjPfx),$(TARGETS))
TARGETS += $(foreach tgt, $(TARGETS), $(tgt)-debug)

ifeq ($(BUILD_TAG),TRUNK)
OBJDIR=host/$(TARGET_ARCH)/$(TARGET_OS)/$(TARGET)-$(LINUXVER)$(if $(BCMQT),-bcmqt)
else
OBJDIR=$(TARGET)-$(LINUXVER)$(if $(BCMQT),-bcmqt)
endif

all: $(filter %-sdio %-sdbcm %-sdstd %-usb %sdspi-pci %-sdmmc, $(TARGETS))
sdio: $(filter %-sdio %-sdbcm %-sdstd, $(TARGETS))
usb: $(filter %-usb, $(TARGETS))
sdspi: $(filter %-sdspi-pci, $(TARGETS))

# Allow making target with the LINUXVER suffix already on it.
# (Typical of command line tab completion; trailing slash still not allowed)
%-$(LINUXVER): force
	$(MAKE) $(@:%-$(LINUXVER)=%)

$(TARGETS):
	@echo "MAKING $@"
	$(strip $(MAKE) $(if $(findstring 86,$(DHDARCH)),GCCVER=$(GCCVER)) TARGET=$@ objdir)

# Show compiler version, for the current target build
showenv:
	@echo "CC = $(CC) (ver=`$(CC) -dumpversion`; host=`hostname`; processor=`uname -m`)"
	@echo "HOSTCFLAGS = $(HOSTCFLAGS)"

objdir: showenv
	@echo "Making objdir $(OBJDIR)"
	@echo "TARGET is $(TARGET)"
	mkdir -p $(OBJDIR)
ifneq ($(call wlan_version_ge,$(BCM_KVERSIONSTRING),2.5.0),TRUE)
	$(MAKE) -C $(OBJDIR) -f $(WLAN_Makefile) dep
endif
	$(MAKE) -C $(OBJDIR) -f $(WLAN_Makefile) modules
ifeq ($(call wlan_version_ge,$(BCM_KVERSIONSTRING),2.5.0),TRUE)
	$(STRIP) -g $(OBJDIR)/$(KMODULES) -o $(OBJDIR)/$(KMODULES).stripped
else
	$(OBJCOPY) --strip-unneeded $(OBJDIR)/dhd.o $(OBJDIR)/dhd.o.stripped
endif

dep: $(foreach file,$(CFILES),.$(file).depend)
.%.c.depend: %.c
	$(HOSTCC) $(HOSTCFLAGS) -M $< > $@ || (rm -f $@; exit 1)
.%.c.depend::
	touch $@

ifeq ($(call wlan_version_ge,$(BCM_KVERSIONSTRING),2.5.0),TRUE)
modules: $(OFILES)
# -Makefile_hwx target will be use Makefile_hwx file instead of dhd/linux/Makefile
    ifeq ($(findstring -Makefile,-$(TARGET)-),)
		test -r ./Makefile || ln -s $(WLAN_SrcBaseR)/dhd/linux/makefile.26 ./Makefile
    endif
	$(strip $(MAKE) -C $(LINUXDIR) M=$(shell pwd) $(if $(VERBOSE),V=1) $(WLAN_ShellDebugSHELL) modules)
else
modules: $(MODULES)
endif

$(MODULES): $(OFILES)
	$(LD) $(LDFLAGS) -o $@ $^

ifeq ($(call wlan_version_ge,$(BCM_KVERSIONSTRING),2.5.0),TRUE)
%.o: %.c
  # when make is called from 2.6, vpath doesn't work so we need to link the files.
	test -r ./$(<F) || ln -s $< .
else
%.o: %.c
	$(HOSTCC) $(HOSTCFLAGS) -c -o $@ $<
	@( \
	echo 'ifneq ($$(HOSTCFLAGS),$(HOSTCFLAGS))' ; \
	echo '$@: force' ; \
	echo 'endif' ; \
	) > .$*.c.flags
endif

force:

clean:
ifeq (,$(filter %/,$(ObjPfx)))
	$(RM) -r $(ObjPfx)*
else
	$(RM) -r $(ObjPfx)
endif

-include $(wildcard .*.depend)
-include $(wildcard .*.flags)
