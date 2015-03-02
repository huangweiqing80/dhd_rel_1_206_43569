#
# GNUmakefile for wl/exe
#
# Copyright (c) 2000, Broadcom Corp.
# $Id: GNUmakefile,v 1.5 2010-11-30 23:56:21 $

WLAN_ComponentsInUse += bcmwifi
-include ../../../makefiles/WLAN_Common.mk
SRCBASE ?= $(WLAN_SrcBaseR)

#-----------------------------------------------------------------
# Windows build
# 1) windows, don't include Makerules due to all: conflict

ifdef WLAN_CYGWIN_HOST

include $(WLAN_TreeBaseA)/GNUmakefile.inc

else # WLAN_CYGWIN_HOST

# 2) not windows, need to include first to pick up TARGETENV dependent vars
include $(SRCBASE)/Makerules

#ifdef BCMWPA2
CFLAGS += -DBCMWPA2
#endif

CFLAGS += -DBCMSUP_PSK

#ifdef WLCNT
CFLAGS += -DWLCNT
#endif

#-----------------------------------------------------------------
# Linux build
#
# This should be one of values recognized in src/Makerules

ifneq ($(findstring $(TARGETENV), "linux linuxmips linuxmips_be linuxarm linuxarm_le"),)

# Discard any "MMX" or other qualifications on x86 so that
# any TARGETARCH containing x86 is just "x86"
ifeq ($(findstring x86_mmx,$(TARGETARCH)),x86_mmx)
	TARGETARCH = x86
endif

OBJDIR = $(TARGETARCH)

# $(TARGETARCH) is set based on TARGETENV in src/Makerules.* files
#BWL_OBJS := bwl.o bwl_utils.o bwl_linux.o bwl_wps_enr.o bwltest.o
BWL_OBJS := bwl.o bwl_utils.o bwl_linux.o  
BWL_EXE  := bwl
BWL_LIB	 := lib$(BWL_EXE).so
WLU_OBJS := bcmutils.o bcmwifi_channels.o 
BLD_BWL_VER := bwl_ver

ifeq ($(INCLUDE_WPS),1)
BWL_OBJS += bwl_wps_enr.o 
WPS_TARGET := wps_enr 
WPS_PATH := $(OBJDIR)
WPS_LIBS  = $(WPS_PATH)/libwpsenr.a $(WPS_PATH)/libwpscom.a $(WPS_PATH)/libbcmcrypto.a
WPS_OBJS := wps_linux_hooks.o wl_wps.o
CFLAGS += -DINCLUDE_WPS
LDFLAGS  += -L$(WPS_PATH) 
endif

ifndef BUILD_SHARED_LIB
BWL_OBJS += bwltest.o 
endif

ifneq ($(TARGETARCH),x86)
  BWL_EXE  := $(BWL_EXE)$(TARGETARCH)
  BWL_OBJS := $(BWL_OBJS:%.o=$(OBJDIR)/%.o)
  WLU_OBJS := $(WLU_OBJS:%.o=$(OBJDIR)/%.o)
  WPS_OBJS := $(WPS_OBJS:%.o=$(OBJDIR)/%.o)
endif

###########################
# openssl
###########################
BCM_PARTIAL_CRYPTO = 1
EXTERNAL_OPENSSL = 0

ifdef INCLUDE_WPS
export CFLAGS += -include wps_openssl.h
export CXXFLAGS += -include wps_openssl.h
endif

ifdef INCLUDE_WPS

ifeq ($(BCM_PARTIAL_CRYPTO),1)
  WPS_LIBS += $(WPS_PATH)/libbcmcrypto.a
  LDFLAGS  += -Wl,-static,-lwpsenr,-lwpscom,-lbcmcrypto,-Bsymbolic,-dy,-lstdc++
else
  LDFLAGS  += -Wl,-static,-lwpsenr,-lwpscom,-Bsymbolic,-dy,-lstdc++
  WPS_OBJS += bcmcrypto/rijndael-alg-fst.o bcmcrypto/hmac_sha256.o bcmcrypto/aes.o
endif

export EXTERNAL_OPENSSL_INC = $(EXTERNAL_OPENSSL_BASE)/include
export EXTERNAL_OPENSSL_LIB = $(EXTERNAL_OPENSSL_BASE)/lib/libcrypto.a

ifeq ($(EXTERNAL_OPENSSL), 1)
	export CFLAGS += -DUSE_EXTERNAL_OPENSSL
	export CXXFLAGS += -DUSE_EXTERNAL_OPENSSL
	EXTERNAL_OPENSSL_LIB = $(EXTERNAL_OPENSSL_BASE)/lib/libcrypto.a
	ifeq ($(BCM_PARTIAL_CRYPTO),1)
		CFLAGS += -I$(EXTERNAL_OPENSSL_INC) -I$(EXTERNAL_OPENSSL_INC)/openssl -I$(SRCBASE)/include/bcmcrypto
	else
		CFLAGS += -I$(EXTERNAL_OPENSSL_INC) -I$(EXTERNAL_OPENSSL_INC)/openssl
	endif
else
	CFLAGS += -I$(SRCBASE)/include/bcmcrypto
	EXTERNAL_OPENSSL_LIB =
endif
CFLAGS += -I$(SRCBASE)/wps/common/include
endif

CFLAGS += -DWLPFN
CFLAGS += -DWLC_HIGH
CFLAGS += -I$(SRCBASE)/wl/sys
CFLAGS += -I$(SRCBASE)/wl/exe
CFLAGS += $(WLAN_ComponentIncPathR)

CFLAGS += -fPIC

vpath %.c $(addprefix $(SRCBASE)/,shared wl/sys wl/exe wps/linux/enr wps/common/enrollee) $(WLAN_StdSrcDirsA) $(WLAN_ComponentSrcDirs)

#all: wps_enr $(BWL_EXE)
#all: $(BWL_TARGETS)

ifdef BUILD_SHARED_LIB
CFLAGS += -DBUILD_SHARED_LIB -DBCMSUP_PSK
all: $(BLD_BWL_VER) $(WPS_TARGET) $(BWL_LIB)
else
all: $(BLD_BWL_VER) $(WPS_TARGET) $(BWL_EXE) 
endif

$(BWL_LIB): $(WLU_OBJS) $(WPS_OBJS) $(BWL_OBJS)
	${CC} -shared -o $@  $^ ${LDFLAGS}

$(BWL_EXE): $(WLU_OBJS) $(WPS_OBJS) $(BWL_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(WPS_LIBS) $(EXTERNAL_OPENSSL_LIB)

$(OBJDIR)/%.o: %.c
	@mkdir -p $(OBJDIR)
	$(CC) -c $(CFLAGS) -o $@ $^

wps_enr:
	$(MAKE) -f bwl_wps_libs.mk

bwl_ver:
#	$(MAKE) -f MakeVersion

clean:
	rm -f $(BWL_EXE) $(BWL_OBJS) $(WLU_OBJS) $(WPS_OBJS)
	rm -rf $(OBJDIR)
	$(MAKE) -f bwl_wps_libs.mk clean

.PHONY: all clean

endif # TARGETENV linux


endif # WLAN_CYGWIN_HOST
