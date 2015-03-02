BLDTYPE := debug
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


LIB=lib
DUT=dut
CA=ca
#TC=tc
CLI=cli
UCC=ucc
SCRIPTS=scripts
MAKE=make

LINUXVER := $(shell uname -r)


ifeq ($(origin extsec),undefined)
BINDIR := obj/$(TARGETARCH)-$(BLDTYPE)-intsec
else
BINDIR := obj/$(TARGETARCH)-$(BLDTYPE)-extsec
endif
OBJDIR := obj/$(TARGETARCH)-$(BLDTYPE)

# This is for WMM-PS
#for Ext TG
#CFLAGS += -g -O2 -D_REENTRANT -DWFA_WMM_PS_EXT -Wall -I../inc

## for WMM-AC, WMM-PS and Voice Test-Bed
#CFLAGS += -g -O2 -D_REENTRANT  -DWFA_WMM_PS_EXT -DWFA_WMM_AC -DWFA_VOICE_EXT -DWFA_STA_TB -Wall -I../inc

## for non-Test-Bed WMM-AC, WMM-PS and Voice
CFLAGS += -g -O2 -D_REENTRANT  -DWFA_WMM_PS_EXT -DWFA_WMM_AC -DWFA_VOICE_EXT -Wall -I../inc

## for PC-ENDPOINT
#CFLAGS += -g -O2 -D_REENTRANT  -DWFA_WMM_PS_EXT -DWFA_WMM_AC -DWFA_VOICE_EXT -DWFA_PC_CONSOLE -Wall -I../inc

## for PC-ENDPOINT No Voice
#CFLAGS += -g -O2 -D_REENTRANT  -DWFA_WMM_PS_EXT -DWFA_WMM_AC -DWFA_PC_CONSOLE -Wall -I../inc

# This is for WPA2 as default
#CFLAGS += -g -O2 -D_REENTRANT -Wall -I../inc

ifeq ($(CC), arm-linux-gcc)
  CFLAGS     += -mstructure-size-boundary=8
endif

ifneq ($(findstring mips, $(CC)),)
ifneq ($(findstring 2.6.37,$(UNAME)),)
  CFLAGS += -DTARGETENV_BCMSTB=1
endif
  # Mark mips compiler to produce debugging info that is understood by gdb
  CFLAGS += -gstabs+
endif

# Use uClibc embedded C run-time library.
ifeq ($(UCLIBC),1)
  CFLAGS += -DUSE_UCLIBC
endif

ifeq ($(BCM_P2P_IOTYPECOMPAT),1)
  CFLAGS += -DBCM_P2P_IOTYPECOMPAT
endif

ifeq ($(BCM_P2P_ACRATES),1)
  CFLAGS += -DBCM_P2P_ACRATES
endif
BRCM_SRC_DIR := ../../../../../../src
BRCM_P2P_DIR := ${BRCM_SRC_DIR}/p2p/p2plib
BRCM_WPS_DIR := ${BRCM_SRC_DIR}/wps
BRCM_SECFRW_DIR := ${BRCM_SRC_DIR}/security/secfrw
BRCM_WFDCAPD_DIR := ${BRCM_SRC_DIR}/apps/wfd_capd

BRCM_OBJDIR := $(OBJDIR)
ifeq ($(origin extsec),undefined)
BRCM_P2P_OBJDIR := obj/$(TARGETARCH)-$(BLDTYPE)-intsec
else
BRCM_P2P_OBJDIR := obj/$(TARGETARCH)-$(BLDTYPE)-extsec
endif

BRCM_INCLUDES := -I${BRCM_SRC_DIR}/include  -I${BRCM_SRC_DIR}/common/include -I${BRCM_SRC_DIR}/include/bcmcrypto -I${BRCM_P2P_DIR}/linux/sampleapp -I${BRCM_P2P_DIR}/include
BRCM_INCLUDES += -I${BRCM_P2P_DIR}/common -I${BRCM_SRC_DIR}/include/proto -I${BRCM_SRC_DIR}/common/include/proto -I${BRCM_SRC_DIR}/wps/wpscli/include -I${BRCM_SRC_DIR}/wps/common/include
BRCM_INCLUDES += -I${BRCM_SRC_DIR}/security/secfrw/include
BRCM_INCLUDES += -I${BRCM_SRC_DIR}/shared/bcmwifi/include
BRCM_INCLUDES += -I${BRCM_SRC_DIR}/apps/wfd_capd/include
BRCM_DEFINES := -D BRCM_CUSTOM=1 -D P2PAPI_ENABLE_PERSISTENT_GROUP=1 -D BCMSUP_PSK
CFLAGS += ${BRCM_INCLUDES} ${BRCM_DEFINES}


DUTLIBS = ../lib/$(OBJDIR)/libwfa_dut.a -lpthread
CALIBS = ../lib/$(OBJDIR)/libwfa_ca.a -lpthread
RANLIB = ranlib

LIBWFA_NAME_DUT = libwfa_dut.a
LIBWFA_NAME_CA = libwfa_ca.a
LIBWFA_NAME = libwfa.a

LIB_OBJS = $(OBJDIR)/wfa_sock.o $(OBJDIR)/wfa_tg.o $(OBJDIR)/wfa_cs.o $(OBJDIR)/wfa_ca_resp.o $(OBJDIR)/wfa_tlv.o $(OBJDIR)/wfa_typestr.o $(OBJDIR)/wfa_cmdtbl.o $(OBJDIR)/wfa_cmdproc.o $(OBJDIR)/wfa_miscs.o $(OBJDIR)/wfa_thr.o $(OBJDIR)/wfa_wmmps.o

LIB_OBJS_DUT = wfa_sock.o wfa_tlv.o wfa_tg.o wfa_wfa_cmdtbl.o wfa_miscs.o wfa_thr.o wfa_wmmps.o

LIB_OBJS_CA = $(OBJDIR)/wfa_sock.o $(OBJDIR)/wfa_tlv.o $(OBJDIR)/wfa_ca_resp.o $(OBJDIR)/wfa_cmdproc.o $(OBJDIR)/wfa_miscs.o $(OBJDIR)/wfa_typestr.o

CLEANFILES = core core.* *.core.* *.o *.a $(OBJDIR)

DEP_FILES = $(wildcard $(OBJDIR)/*.d)

# Compilation targets
$(OBJDIR)/%.o : %.c
	@mkdir -pv $(@D)
	$(CC) -c $(CFLAGS) -o $@ $^


## Include dependencies.
#ifeq ($(strip $(filter clean%, $(MAKECMDGOALS))),)
#   ifneq ($(DEP_FILES),)
#      include $(DEP_FILES)
#   endif
#endif
