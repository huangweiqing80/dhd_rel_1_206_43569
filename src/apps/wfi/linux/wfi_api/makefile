#
# Copyright (C) 2014, Broadcom Corporation
# All Rights Reserved.
# 
# This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
# the contents of this file may not be disclosed to third parties, copied
# or duplicated in any form, in whole or in part, without the prior
# written permission of Broadcom Corporation.
#
# $Id: makefile,v 1.10 2010-11-18 18:50:08 $

WLAN_ComponentsInUse := bcmwifi
include ../../../../makefiles/WLAN_Common.mk

BLDTYPE   := release
#BLDTYPE    := debug
# Allow CROSS_COMPILE to specify compiler base
CC         := $(CROSS_COMPILE)gcc
LD         := $(CROSS_COMPILE)ld
STRIP      := $(CROSS_COMPILE)strip
AR         := $(CROSS_COMPILE)ar
TARGETARCH := x86

ifeq ($(CC), arm-linux-gcc)
  CFLAGS     += -mstructure-size-boundary=8
  CC         :=arm-linux-gcc
  LD 	     :=arm-linux-ld
  STRIP      :=arm-linux-strip
  AR         :=arm-linux-ar
  TARGETARCH := arm
endif

ifeq ($(CC), mipsel-uclibc-gcc)
  LD         :=mipsel-uclibc-ld
  AR         :=mipsel-uclibc-ar
  STRIP      :=mipsel-uclibc-strip
  TARGETARCH := mipsel
endif

ifeq ($(CC), mipsel-linux-gcc)
  LD         :=mipsel-linux-ld
  AR         :=mipsel-linux-ar
  STRIP      :=mipsel-linux-strip
  TARGETARCH := mipsel
endif

OBJDIR     ?= obj/$(TARGETARCH)-$(BLDTYPE)
#OBJDIR    ?= obj/$(BLDTYPE)/$(TARGETARCH)

CFLAGS   += -Wall -Wnested-externs -DWPS_WIRELESS_ENROLLEE -fPIC

# Add -D_TUDEBUGTRACE to CFLAGS for WPS debug prints
ifeq ($(BLDTYPE),debug)
  CFLAGS   += -g -DDEBUG -D_TUDEBUGTRACE
else
  CFLAGS   += -Os
endif

ifdef BCMINTERNAL
  CFLAGS   += -DBCMINTERNAL -DBCMDBG
endif


# SRCBASE is the root of the src directory (eg. ~/work/tot/src)
SRCBASE     := $(WLAN_SrcBaseR)
WPSBASE     := $(SRCBASE)/wps
WPSCOMMON   := $(WPSBASE)/common
WPSCLI      := $(WPSBASE)/wpscli
WPSCLILINUX := $(WPSBASE)/wpscli/linux
WFIBASE     := $(SRCBASE)/apps/wfi/linux
WFIAPI      := $(WFIBASE)/wfi_api

INCLUDE += -I. \
	-I$(SRCBASE)/include \
	-I$(SRCBASE)/common/include \
	-I$(SRCBASE)/common/include/proto \
	-I$(WPSBASE)/include \
	-I$(WPSCOMMON)/include \
	-I$(WPSCLI)/include \
	-I$(WPSCLI)/common/include \
	$(WLAN_ComponentIncPathR) \
	-I$(WFIBASE)/include 

export CC
export CFLAGS
export INCLUDE


#flag to create dynamic library
SHARED_LIB ?= 0

#flag to use external OpenSSL
ifeq ($(EXTERNAL_OPENSSL), 1)
EXTERNAL_OPENSSL_BASE ?= /data/openssl/mipsel-uclibc_stage-install/usr/local/
endif

OBJS =   $(OBJDIR)/wfi_api.o $(OBJDIR)/wfi_utils.o 
SAMPLEAPPOBJS = $(OBJDIR)/wfi_api_tester.o


ifneq ($(SHARED_LIB),1)
SAMPLEAPPLIBS = $(WFIAPI)/$(OBJDIR)/libwfiapi.a \
		$(WPSCLILINUX)/$(OBJDIR)/libwpscli.a \
		$(WPSCLILINUX)/$(OBJDIR)/libwpscliosl.a \
		$(WPSCLILINUX)/$(OBJDIR)/libwpscore.a \
		-lpthread \
		-lrt

ifeq ($(EXTERNAL_OPENSSL), 1)
SAMPLEAPPLIBS += $(EXTERNAL_OPENSSL_BASE)/lib/libcrypto.a
else
SAMPLEAPPLIBS += $(WPSCLILINUX)/$(OBJDIR)/libbcmcrypto.a 
endif #EXTERNAL_OPENSSL

else #SHARED_LIB
SAMPLEAPPLIBS = -L$(WFIAPI)/$(OBJDIR) -lwfiapi \
		-L$(WPSCLILINUX)/$(OBJDIR) -lwpscli -lwpscliosl -lwpscore \
		-lpthread \
		-lrt 

ifeq ($(EXTERNAL_OPENSSL), 1)
SAMPLEAPPLIBS += -L$(EXTERNAL_OPENSSL_BASE)/lib -lcrypto
else
SAMPLEAPPLIBS += -L$(WPSCLILINUX)/$(OBJDIR) -lbcmcrypto 
endif #EXTERNAL_OPENSSL

#Add option to link with additional libraries.
SAMPLEAPPLIBS += $(EXTERNAL_LIBS)

endif #SHARED_LIB

default: outdir wpslibs wfiapi wfiapitester

outdir :
	mkdir -p $(OBJDIR)
	
wpslibs :
	$(MAKE) EXTERNAL_OPENSSL=$(EXTERNAL_OPENSSL) EXTERNAL_OPENSSL_BASE=$(EXTERNAL_OPENSSL_BASE) \
	SHARED_LIB=$(SHARED_LIB) BLDTYPE=$(BLDTYPE) CFLAGS="$(CFLAGS)" \
	CC="$(CC)" AR=$(AR) LD=$(LD) EXTERNAL_LIBS=$(EXTERNAL_LIBS) \
	TARGETARCH=$(TARGETARCH) -C $(WPSCLILINUX)

ifneq ($(SHARED_LIB),1)
wfiapi : $(OBJS)
	$(AR) cr $(OBJDIR)/libwfiapi.a $^
else
wfiapi : $(OBJS)
	$(LD) -shared -o $(OBJDIR)/libwfiapi.so $^
endif #SHARED_LIB

ifeq ($(BLDTYPE),debug)
wfiapitester: $(SAMPLEAPPOBJS)
	      $(CC) $(SAMPLEAPPOBJS) $(SAMPLEAPPLIBS) -o $(OBJDIR)/wfiapitester
else
wfiapitester: $(SAMPLEAPPOBJS)
	      $(CC) $(SAMPLEAPPOBJS) $(SAMPLEAPPLIBS) -o $(OBJDIR)/wfiapitester
	      $(STRIP) $(OBJDIR)/wfiapitester
endif

$(OBJDIR)/%.o : %.c
	$(CC) -c $(CFLAGS) $(INCLUDE) $< -o $@

clean:
	find $(WPSCLILINUX)/$(OBJDIR) -name "*.o" | xargs rm -f
	find $(WPSCLILINUX)/$(OBJDIR) -name "*.so" | xargs rm -f
	find $(WPSCLILINUX)/$(OBJDIR) -name "*.a" | xargs rm -f
	find $(OBJDIR) -name "*.o" | xargs rm -f
	find $(OBJDIR) -name "*.so" | xargs rm -f
	find $(OBJDIR) -name "*.a" | xargs rm -f

.PHONY: default wfiapidirs wfilib wpsclilib wfiapitester
