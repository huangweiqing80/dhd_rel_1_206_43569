#
# Linux Makefile for the P2P Sample Application
#
# Copyright (C) 2012, Broadcom Corporation
# All Rights Reserved.
# 
# This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
# the contents of this file may not be disclosed to third parties, copied
# or duplicated in any form, in whole or in part, without the prior
# written permission of Broadcom Corporation.
#
# $Id: Makefile,v 1.100 2011-02-09 18:06:23 $

# This file is present in old branches without WLAN_Common.mk
WLAN_ComponentsInUse := bcmwifi
-include ../../../../makefiles/WLAN_Common.mk

SRCBASE  := ../../../..

#BLDTYPE   := release
BLDTYPE    := debug

# Uncomment this to test a P2P_UPNP_DISCOVERY build
#p2p_upnp := y

# Uncomment this to test a SOFTAP_ONLY build
#softap := y

# Uncomment this to pre-test a WIN32 build from Linux
#win32 := y

# Uncomment this to pre-test a External auth/supp build
#extsec := ""

UNAME        := $(shell uname -a)

# Allow CROSS_COMPILE to specify compiler base
CC         := $(CROSS_COMPILE)gcc
AR         := $(CROSS_COMPILE)ar
LD         := $(CROSS_COMPILE)ld
NM         := $(CROSS_COMPILE)nm
STRIP      := $(CROSS_COMPILE)strip
TARGETARCH ?= x86

ifeq ($(CC), gcc)
  CFLAGS     += -m32
endif

ifeq ($(CC), arm-linux-gcc)
  CFLAGS     += -mstructure-size-boundary=8
  LD         := arm-linux-ld
  CC         := arm-linux-gcc
  NM         := arm-linux-nm
  STRIP      := arm-linux-strip
  TARGETARCH := arm
endif

ifeq ($(CC), mipsel-uclibc-gcc)
  LD         := mipsel-uclibc-ld
  CC         := mipsel-uclibc-gcc
  NM         := mipsel-uclibc-nm
  STRIP      := mipsel-uclibc-strip
  TARGETARCH := mipsel
endif

ifeq ($(CC), mipsel-linux-gcc)
  LD         := mipsel-linux-ld
  CC         := mipsel-linux-gcc
  NM         := mipsel-linux-nm
  STRIP      := mipsel-linux-strip
  TARGETARCH := mipsel
endif

ifeq ($(TARGETARCH), x86_64)
  CFLAGS += -DBN64_BIT
endif

ifeq ($(origin softap),undefined)
  OBJ_SOFTAP :=
  WFDISP_SRCS := p2papp_wfd.c
else
  OBJ_SOFTAP := softap-
  CFLAGS_SOFTAP := -DSOFTAP_ONLY
  WFDISP_SRCS :=
endif

ifeq ($(origin p2p_upnp),undefined)
  OBJ_UPNP :=
  CFLAGS_UPNP :=
  P2PUPNP_SRCS :=
  P2PUPNP_INCLUDES :=
else
  OBJ_UPNP := p2pupnp-
  CFLAGS_UPNP := -DP2P_UPNP_DISCOVERY=1
  P2PUPNP_SRCS  = p2papp_upnp.c
  P2PUPNP_INCLUDES := -I$(SRCBASE)/dlna/AppLibs/dlna/include
endif

ifeq ($(origin extsec),undefined)
  OBJDIR    = obj/$(TARGETARCH)-$(BLDTYPE)-$(OBJ_UPNP)$(OBJ_SOFTAP)intsec
else
  OBJDIR    = obj/$(TARGETARCH)-$(BLDTYPE)-$(OBJ_UPNP)$(OBJ_SOFTAP)extsec
endif

ifeq ($(BLDTYPE),debug)
#  CFLAGS   += -Wall -Wnested-externs -g -DWPS_WIRELESS_ENROLLEE -D_TUDEBUGTRACE -MD -Wformat -Wformat-security -Wformat-nonliteral -Werror
#  CXXFLAGS = -Wall -Wnested-externs -g -DWPS_WIRELESS_ENROLLEE -D_TUDEBUGTRACE -MD -Wformat -Wformat-security -Wformat-nonliteral -Werror
  CFLAGS   += -Wall -Wnested-externs -g -DWPS_WIRELESS_ENROLLEE -D_TUDEBUGTRACE -MD -Wformat -Wformat-security -Wformat-nonliteral
  CXXFLAGS = -Wall -Wnested-externs -g -DWPS_WIRELESS_ENROLLEE -D_TUDEBUGTRACE -MD -Wformat -Wformat-security -Wformat-nonliteral
	ifneq ($(findstring mips,$(CC)),)
		CFLAGS += -gstabs+
	endif
else
#  CFLAGS   += -Wall -Os -Wnested-externs -DWPS_WIRELESS_ENROLLEE -MD -Wformat -Wformat-security -Wformat-nonliteral -Werror
  CFLAGS   += -Wall -Os -Wnested-externs -DWPS_WIRELESS_ENROLLEE -MD -Wformat -Wformat-security -Wformat-nonliteral
endif

# Show passphrase
CFLAGS += -DP2PAPI_ENABLE_DEBUG_SHOWKEY=1

# P2P Library feature options
CFLAGS += -DP2PAPI_ENABLE_WPS=1
CFLAGS += -DP2PAPI_ENABLE_MULTI_CHANNEL=1
CFLAGS += -DP2PAPI_ENABLE_DHCPD=0
ifeq ($(origin softap),undefined)
CFLAGS += -DP2PAPI_ENABLE_SERVICE_DISCOVERY=1
else
CFLAGS += -DP2PAPI_ENABLE_SERVICE_DISCOVERY=0
endif
# Whether to use in-driver or external WPA2-PSK authenticator/supplicant.
ifeq ($(origin extsec),undefined)
	CFLAGS += -DP2PAPI_USE_IDAUTH=1
	CFLAGS += -DP2PAPI_USE_IDSUP=1
	USE_EXT_SECAGENT = 0
else
	CFLAGS += -DP2PAPI_USE_IDAUTH=0
	CFLAGS += -DP2PAPI_USE_IDSUP=0
	USE_EXT_SECAGENT = 1
endif

ifneq ($(findstring mips, $(CC)),)
ifneq ($(findstring 2.6.37, $(UNAME)),)
  CFLAGS += -DTARGETENV_BCMSTB=1
endif
  POSIX_MQUEUE :=0
endif

# Use posix message queues by default for buffering P2P library events. Else
# use internal message queues.
ifeq ($(POSIX_MQUEUE),)
   POSIX_MQUEUE := 1
endif

ifeq ($(POSIX_MQUEUE),1)
  CFLAGS += -DP2P_USE_POSIX_MQUEUE
endif

# Use uClibc embedded C run-time library.
ifeq ($(UCLIBC),1)
  CFLAGS += -DP2P_USE_UCLIBC
endif


CFLAGS += -DBCMP2P -DWLP2P -DWIFI_ACT_FRAME
#CFLAGS += -DNON_11AC_APP
#CFLAGS += -DBCMP2P

CFLAGS += $(CFLAGS_SOFTAP)
CFLAGS += $(CFLAGS_UPNP)

NO_WPS_THREAD = 1

ifeq ($(NO_WPS_THREAD),1)
CFLAGS += -DWPSCLI_NO_WPS_LOOP
endif

# For testing the WIN32 #ifdef from a Linux build
ifeq ($(origin win32),undefined)
else
  CFLAGS += -DWIN32
endif

ifeq ($(BCM_P2P_IOTYPECOMPAT),1)
  CFLAGS += -DBCM_P2P_IOTYPECOMPAT
endif
ifeq ($(BCM_P2P_ACRATES),1)
  CFLAGS += -DBCM_P2P_ACRATES
endif

ifeq ($(BCM_P2P_OPTEXT),1)
  CFLAGS += -DBCM_P2P_OPTEXT
endif

# SRCBASE is the root of the src directory (eg. ~/work/tot/src)
WPSBASE     := $(SRCBASE)/wps
WPSCOMMON   := $(WPSBASE)/common
WPSLINUX    := $(WPSBASE)/linux
WPSCLI      := $(WPSBASE)/wpscli
WPSCLILINUX := $(WPSCLI)/linux
P2PBASE     := $(SRCBASE)/p2p/p2plib
P2PLINUX    := $(P2PBASE)/linux
DHCPDBASE   := $(SRCBASE)/apps/dhcpd
EXTSECBASE  := $(SRCBASE)/security/secfrw
WFDCAPD		:= $(SRCBASE)/apps/wfd_capd
WFDCAPDIELINUX := $(SRCBASE)/apps/wfd_capd/linux/wfd_capd_ie

INCLUDE := -I. \
	-I$(P2PBASE)/include \
	-I$(P2PBASE)/linux \
	-I$(P2PBASE)/common \
	-I$(SRCBASE)/include \
	-I$(SRCBASE)/include/proto \
	-I$(SRCBASE)/common/include \
	-I$(SRCBASE)/common/include/proto \
	-I$(SRCBASE)/include/bcmcrypto \
	$(WLAN_ComponentIncPath) \
	-I$(WPSCLI)/include \
	-I$(WPSBASE)/include \
	-I$(WPSCOMMON)/include \
	-I$(WPSLINUX)/inc \
	-I$(DHCPDBASE)/include \
	-I$(EXTSECBASE)/include \
	-I$(WFDCAPD)/include \
	 $(P2PUPNP_INCLUDES)
#	-I$(SRCBASE)/router/shared

INCLUDE += $(addprefix -I,$(wildcard $(SRCBASE)/shared/bcmwifi/include))

export CFLAGS CXXFLAGS INCLUDE USE_EXT_SECAGENT INCLUDE CFLAGS

P2PAPPSRCS =  p2p_app.c p2p_app_cli.c p2papp_persist_file.c p2papp_linux.c $(WFDISP_SRCS) $(P2PUPNP_SRCS)
ifneq ($(POSIX_MQUEUE),1)
   P2PAPPSRCS += p2papp_queue.c
endif

P2PAPPOBJS =  $(P2PAPPSRCS:%.c=$(OBJDIR)/%.o)
P2PAPPDEPS =  $(wildcard $(OBJDIR)/*.d)

vpath %.c $(P2PLINUX)/sampleapp

P2PAPILIBS := bcmp2p bcmp2psig wpscli wpscliosl wpscore bcmcrypto dhcpd wfdcapdie
ifeq ($(USE_EXT_SECAGENT), 1)
	P2PAPILIBS += hslbcmsec
endif

P2PLDFLAGS := $(P2PAPILIBS:%=-l%)
# If OBJDIR is overriden (like in cases of release builds)
# ensure that it is in libpath
P2PLDFLAGS += -L$(P2PLINUX)/$(OBJDIR)
P2PLDFLAGS += -L$(WPSCLILINUX)/$(OBJDIR)
P2PLDFLAGS += -L$(WFDCAPDIELINUX)/$(OBJDIR)
# Make it backward compatible (if needed) with default object dir format
P2PLDFLAGS += -L$(P2PLINUX)/obj/$(TARGETARCH)-$(BLDTYPE)
P2PLDFLAGS += -L$(WPSCLILINUX)/obj/$(TARGETARCH)-$(BLDTYPE)
P2PLDFLAGS += -L$(WFDCAPDIELINUX)/obj/$(TARGETARCH)-$(BLDTYPE)
P2PLDFLAGS += -lpthread

# Link real-time library by default.
ifeq ($(LINK_REALTIME_LIB),)
   LINK_REALTIME_LIB := 1
endif

ifeq ($(LINK_REALTIME_LIB),1)
   P2PLDFLAGS += -lrt
endif

P2PLDFLAGS += -L$(EXTSECBASE)/$(OBJDIR)
ifeq ($(CC), gcc)
  P2PLDFLAGS += -m32
endif

# Uncomment this line to generate a linker symbols map to stderr.
# To generate a map file, run "make > bcmp2papp.map 2>&1"
#P2PLDFLAGS += -Xlinker -M

LIBTARGETS := wpscli p2plib dhcplib wfdcapdie

# Don't build it if we don't need it
ifeq ($(USE_EXT_SECAGENT), 1)
	LIBTARGETS += hslbcmsec
endif

all: $(OBJDIR)/bcmp2papp

.PHONY: libs
libs: $(LIBTARGETS) $(OBJDIR)/libbcmp2papp.a

hslbcmsec :
	@date "+==== [%D %T] START: Build BCMSEC libraries ===="
	$(MAKE) BLDTYPE=$(BLDTYPE) CC="$(CC)" AR=$(AR) $(if $(V),V=1) \
	TARGETARCH=$(TARGETARCH) OBJDIR=$(OBJDIR) SECFRW_PRINT_TRACE_ENABLED=0 -C $(EXTSECBASE) hslbcmsec
	@date "+==== [%D %T] END  : Build BCMSEC libraries ===="

dhcplib :
	@date "+==== [%D %T] START: Build DHCP libraries ===="
	$(MAKE) BLDTYPE=$(BLDTYPE) CFLAGS="$(CFLAGS)" CC="$(CC)" \
		TARGETARCH=$(TARGETARCH) -C $(P2PLINUX) -f dhcpd.mk
	@date "+==== [%D %T] END  : Build DHCP libraries ===="

wpscli :
	@date "+==== [%D %T] START: Build WPS CLI libraries ===="
	$(MAKE) BLDTYPE=$(BLDTYPE) CC="$(CC)" $(if $(V),V=1) \
		TARGETARCH=$(TARGETARCH) NO_WPS_THREAD=$(NO_WPS_THREAD) \
		-C $(WPSCLILINUX)
	@date "+==== [%D %T] END  : Build WPS CLI libraries ===="

p2plib :
	@date "+==== [%D %T] START: Build P2P libraries ===="
	$(MAKE) BLDTYPE=$(BLDTYPE) CFLAGS="$(CFLAGS)" CC="$(CC)" $(if $(V),V=1) \
		TARGETARCH=$(TARGETARCH) OBJDIR=$(OBJDIR) -C $(P2PBASE)/linux p2plibs
	@date "+==== [%D %T] END  : Build P2P libraries ===="

wfdcapdie :
	@date "+==== [%D %T] START: Build WFD CAPDIE libraries ===="
	$(MAKE) BLDTYPE=$(BLDTYPE) CC="$(CC)" $(if $(V),V=1) \
		TARGETARCH=$(TARGETARCH) -C $(WFDCAPDIELINUX)
	@date "+==== [%D %T] END  : Build WFD CAPDIE libraries ===="

$(OBJDIR)/bcmp2papp:  $(LIBTARGETS) $(OBJDIR)/libbcmp2papp.a $(OBJDIR)/p2p_app_main.o
	$(CC)  $(OBJDIR)/p2p_app_main.o $(OBJDIR)/libbcmp2papp.a $(P2PLDFLAGS) -o $(OBJDIR)/$(@F)
ifeq ($(BLDTYPE),release)
	$(STRIP) $(OBJDIR)/$(@F)
endif

$(OBJDIR)/libbcmp2papp.a: $(LIBTARGETS) $(P2PAPPOBJS)
	@[ -d "$(@D)" ] || mkdir -pv $(@D)
	$(AR) cr$(if $(V),v) $(OBJDIR)/$(@F) $(P2PAPPOBJS)


$(P2PAPPOBJS) $(OBJDIR)/p2p_app_main.o: $(OBJDIR)/%.o : %.c
	@[ -d "$(@D)" ] || mkdir -pv $(@D)
	$(CC) $(if $(V),-H) -c $(CFLAGS) $(INCLUDE) $< -o $@

clean:
	rm -Rf $(OBJDIR)
	$(MAKE) OBJDIR=$(OBJDIR) -C $(P2PBASE)/linux clean
	$(MAKE) -C $(WPSCLILINUX) clean
	$(MAKE) -C $(WFDCAPDIELINUX) clean
ifeq ($(USE_EXT_SECAGENT), 1)
	$(MAKE) -C $(EXTSECBASE) clean
endif

clean_all:
	rm -Rf ./obj
	$(MAKE) OBJDIR=$(OBJDIR) -C $(P2PBASE)/linux clean_all
	$(MAKE) -C $(WPSCLILINUX) clean
	$(MAKE) -C $(WFDCAPDIELINUX) clean
ifeq ($(USE_EXT_SECAGENT), 1)
	$(MAKE) -C $(EXTSECBASE) clean
endif


extract:
	cd $(SRCBASE); cvs co src/p2p/p2plib
	cd $(SRCBASE); cvs co src/bcmcrypto
	cd $(SRCBASE); cvs co src/include/bcmcrypto \
	cd $(SRCBASE); cvs co src/include/wlioctl.h \
	cd $(SRCBASE); cvs co src/include/bcmendian.h \
	cd $(SRCBASE); cvs co src/include/bcmutils.h \
	cd $(SRCBASE); cvs co src/include/bcmip.h \
	cd $(SRCBASE); cvs co src/include/ethernet.h \

.PHONY: p2plib wpscli hslbcmsec wfdcapdie

# Include dependencies.
ifeq ($(strip $(filter clean%, $(MAKECMDGOALS))),)
   ifneq ($(P2PAPPDEPS),)
      include $(P2PAPPDEPS)
   endif
endif
