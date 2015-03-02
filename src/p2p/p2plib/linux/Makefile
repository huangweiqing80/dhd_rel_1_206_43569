
# Linux Makefile to build the P2P API Library
#
# Copyright (C) 2014, Broadcom Corporation
# All Rights Reserved.
# 
# This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
# the contents of this file may not be disclosed to third parties, copied
# or duplicated in any form, in whole or in part, without the prior
# written permission of Broadcom Corporation.
#
# $Id: Makefile,v 1.101 2010-12-21 23:05:42 $

SRCBASE    := ../../..
WLAN_ComponentsInUse := bcmwifi
-include ../../../makefiles/WLAN_Common.mk
#BLDTYPE   := release
BLDTYPE    := debug
# Allow CROSS_COMPILE to specify compiler base
CC         := $(CROSS_COMPILE)gcc
LD         := $(CROSS_COMPILE)ld
AR         := $(CROSS_COMPILE)ar
TARGETARCH ?= x86
UNAME        := $(shell uname -a)

ifeq ($(CC), gcc)
  CFLAGS     += -m32
endif

ifeq ($(CC), arm-linux-gcc)
  CFLAGS     += -mstructure-size-boundary=8
  LD        := arm-linux-ld
  CC        := arm-linux-gcc
  AR        := arm-linux-ar
  TARGETARCH := arm
endif

ifeq ($(CC), mipsel-uclibc-gcc)
  LD        := mipsel-uclibc-ld
  CC        := mipsel-uclibc-gcc
  AR        := mipsel-uclibc-ar
  TARGETARCH := mipsel
endif

ifeq ($(CC), mipsel-linux-gcc)
  LD        := mipsel-linux-ld
  CC        := mipsel-linux-gcc
  AR        := mipsel-linux-ar
  TARGETARCH := mipsel
endif

ifeq ($(origin extsec),undefined)
OBJDIR := obj/x86-debug-intsec
else
OBJDIR := x86-debug-extsec
endif

#OBJDIR    ?= obj/$(TARGETARCH)-$(BLDTYPE)

CFLAGS   += -Wall -Wnested-externs -DWPS_WIRELESS_ENROLLEE -MD -Wformat -Wformat-security -Wformat-nonliteral -Werror
CFLAGS	 += ${EXTERNAL_CFLAGS}
CXXFLAGS += -Wall -Wnested-externs -DWPS_WIRELESS_ENROLLEE -MD -Wformat -Wformat-security -Wformat-nonliteral -Werror

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

ifeq ($(BCMSTB),1)
ifneq ($(findstring 2.6.37,$(UNAME)),)
  CFLAGS += -DTARGETENV_BCMSTB=1
endif
endif

# Add -D_TUDEBUGTRACE to CFLAGS for WPS debug prints
ifeq ($(BLDTYPE),debug)
  CFLAGS   += -g -D_TUDEBUGTRACE
  CXXFLAGS += -g -D_TUDEBUGTRACE
else
  CFLAGS   += -Os
  CXXFLAGS += -Os
endif


CFLAGS += -DBCMP2P -DWLP2P -DWIFI_ACT_FRAME

ifeq ($(WPS_V2),1)
CFLAGS += -DWPSCLI_WSCV2
endif

LDFLAGS = -r -lrt

ifeq ($(CC), gcc)
  LDFLAGS += -m32
endif

# SRCBASE is the root of the src directory (eg. ~/work/tot/src)
WPSBASE     := $(SRCBASE)/wps
WPSCOMMON   := $(WPSBASE)/common
WPSLINUX    := $(WPSBASE)/linux
WPSCLI      := $(WPSBASE)/wpscli
WPSCLILINUX := $(WPSCLI)/linux
DHCPDBASE   := $(SRCBASE)/apps/dhcpd
P2PBASE     := $(SRCBASE)/p2p/p2plib
P2PINC      := $(P2PBASE)/include
P2PCOMMON   := $(P2PBASE)/common
P2PSIG      := $(P2PBASE)/common/p2psig
P2PLINUX    := $(P2PBASE)/linux
EXTSECBASE  := $(SRCBASE)/security/secfrw
BCMCRYPTO   := $(SRCBASE)/bcmcrypto


vpath %.c $(P2PLINUX) $(P2PCOMMON) $(P2PSIG) $(BCMCRYPTO) $(EXTSECBASE)/tmr $(EXTSECBASE)/utils $(WLAN_StdSrcDirsA) $(WLAN_ComponentSrcDirs)

INCLUDE += -I. \
	-I$(P2PBASE)/include \
	-I$(P2PBASE)/linux \
	-I$(P2PBASE)/common \
	-I$(SRCBASE)/include \
	-I$(SRCBASE)/include/proto \
	-I$(SRCBASE)/common/include \
	-I$(SRCBASE)/common/include/proto \
	-I$(SRCBASE)/include/bcmcrypto \
	-I$(WPSBASE)/include \
	-I$(WPSCOMMON)/include \
	-I$(WPSLINUX)/inc \
	-I$(WPSCLI)/include \
	-I$(DHCPDBASE)/include \
	-I$(BCMCRYPTO)/bcmcrypto \
	-I$(EXTSECBASE)/testcli \
	-I$(EXTSECBASE)/include \
	-I$(EXTSECBASE)/tmr \
	-I$(SRCBASE)/supp/include \
	-I$(SRCBASE)/shared/bcmwifi/include



# -I$(SRCBASE)/router/shared
# -I$(P2PBASE)/linux/wps

export CC
export CFLAGS
export CXXFLAGS
export LDFLAGS
export INCLUDE

COMMON_SRCS  = p2plib_misc.c p2plib_dbg.c p2plib_wlu.c p2pwl.c BcmP2PAPI.c
COMMON_SRCS  += p2plib_generic_osl.c
ifeq ($(origin win32),undefined)
  COMMON_SRCS  += p2plib_aftx.c
else
endif
ifeq ($(BCM_P2P_ACRATES),1)
	COMMON_SRCS += bcmwifi_channels.c
endif


P2PSIG_SRCS  =  p2plib_connect.c p2plib_discover.c p2plib_negotiate.c p2plib_dispatch.c
P2PSIG_SRCS  += p2plib_prov_disc.c p2plib_invite.c p2plib_device_disc.c p2plib_presence.c
ifeq ($(origin softap),undefined)
P2PSIG_SRCS   += p2plib_sd.c
endif

LINUX_SRCS   = p2posl_linux.c
ifeq ($(origin extsec),undefined)
BCMCRYPTO_SRCS  = passhash.c prf.c sha1.c
else
BCMCRYPTO_SRCS  =
endif

# Add timer utilites. Steal these from security-framework.
ifeq ($(USE_EXT_SECAGENT), 1)
   # Timer utilities are included as part of security-framework library.
   SECFRW_SRCS  := 
else
   SECFRW_SRCS  := bcmseclib_linux_timer.c bcmseclib_timer.c bcm_llist.c
endif


COMMON_OBJS  = $(COMMON_SRCS:%.c=$(OBJDIR)/%.o)
P2PSIG_OBJS  = $(P2PSIG_SRCS:%.c=$(OBJDIR)/%.o)
LINUX_OBJS   = $(LINUX_SRCS:%.c=$(OBJDIR)/%.o)
BCMCRYPTO_OBJS = $(BCMCRYPTO_SRCS:%.c=$(OBJDIR)/%.o)
SECFRW_OBJS  = $(SECFRW_SRCS:%.c=$(OBJDIR)/%.o)
ALL_OBJS     = $(COMMON_OBJS) $(P2PSIG_OBJS) $(LINUX_OBJS) $(SECFRW_OBJS)
ALL_DEPS     = $(wildcard $(OBJDIR)/*.d)

#all: p2plibdirs dhcpdlib wpsclilib
all: p2plibdirs
all: p2plibs
.PHONY: p2plibs

p2plibs: $(OBJDIR)/libbcmp2psig.a $(OBJDIR)/libbcmp2p.a

$(OBJDIR)/libbcmp2psig.a: $(P2PSIG_OBJS)
	@[ -d "$(@D)" ] || mkdir -pv $(@D)
	$(AR) cr$(if $(V),v) $(OBJDIR)/$(@F) $^

$(OBJDIR)/libbcmp2p.a: $(COMMON_OBJS) $(LINUX_OBJS) $(BCMCRYPTO_OBJS) $(SECFRW_OBJS)
	@[ -d "$(@D)" ] || mkdir -pv $(@D)
	$(AR) cr$(if $(V),v)  $(OBJDIR)/$(@F) $^

$(COMMON_OBJS) $(P2PSIG_OBJS) $(LINUX_OBJS) $(BCMCRYPTO_OBJS): $(OBJDIR)/%.o :  %.c
	@[ -d "$(@D)" ] || mkdir -pv $(@D)
	$(CC) -c $(CFLAGS) $(if $(V),-H) $(INCLUDE) $< -o $@

$(SECFRW_OBJS): $(OBJDIR)/%.o :  %.c
	@[ -d "$(@D)" ] || mkdir -pv $(@D)
	$(CC) -c $(CFLAGS) -DSECFRW_PRINT_TRACE_ENABLED=0 -DDEBUG $(if $(V),-H) $(INCLUDE) $< -o $@

p2plibdirs :
	@[ -d "$(OBJDIR)" ] || mkdir -pv $(OBJDIR)

clean:
	rm -Rf $(OBJDIR)
	rm -Rf obj/$(TARGETARCH)-$(BLDTYPE)

clean_all:
	rm -Rf ./obj


#.PHONY: default p2plibdirs dhcpdlib wpsclilib
.PHONY: default p2plibdirs

# Include dependencies.
ifeq ($(strip $(filter clean%, $(MAKECMDGOALS))),)
   ifneq ($(ALL_DEPS),)
      include $(ALL_DEPS)
   endif
endif
