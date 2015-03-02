#
# Copyright (C) 2011 Broadcom Corporation
#
# Linux Makefile to build wfdcapdie library
#
# $Id: $


SRCBASE    := ../../../..
BLDTYPE   ?= debug
#BLDTYPE    ?= release
CC         ?= gcc
TARGETARCH ?= x86
OBJDIR     ?= obj/$(TARGETARCH)-$(BLDTYPE)

ifeq ($(CC), arm-linux-gcc)
CFLAGS += -mstructure-size-boundary=8
endif

ifeq ($(CC), mipsel-uclibc-gcc)
endif

ifeq ($(CC), gcc)
  CFLAGS += -m32
endif

ifeq ($(BLDTYPE),debug)
  CFLAGS += -Wall -Wnested-externs -g -D_TUDEBUGTRACE
  # Mark mips compiler to produce debugging information that is understood
  # by gdb
  ifneq ($(findstring mips,$(CC)),)
    CFLAGS += -gstabs+
  endif
else
  CFLAGS += -Wall -Os -Wnested-externs
endif

WFDCAPDDIR := $(SRCBASE)/apps/wfd_capd
WFDCAPDCOMMONDIR := $(WFDCAPDDIR)/common
WFDCAPDCOMMONSHAREDDIR := $(WFDCAPDDIR)/common/shared

INCLUDE :=  -I$(SRCBASE)/include \
		-I$(SRCBASE)/include/proto \
		-I$(SRCBASE)/common/include \
		-I$(SRCBASE)/common/include/proto \
		-I$(WFDCAPDDIR)/include \
		-I$(WFDCAPDDIR)/common/shared \
		-I$(SRCBASE)/p2p/p2plib/include \
		-I$(WFDCAPDDIR)/linux/inc


vpath %.c $(WFDCAPDDIR)/common/shared \
	$(WFDCAPDDIR)/common/wfd_capdie

OSISHAREDSRCS = tutrace.c
OSISRCS      = wfd_capdie.c wfd_capdie_proto.c wfadisp.c

OSISHAREDOBJS = $(OSISHAREDSRCS:%.c=$(OBJDIR)/%.o)
OSIOBJS      = $(OSISRCS:%.c=$(OBJDIR)/%.o)

all: objdir 

all: $(OBJDIR)/libwfdcapdie.a 

# create folders to hold objects files of each lib
objdir :
	@[ -d "$(OBJDIR)" ] || mkdir -pv $(OBJDIR)

# wfd_capd_ie lib
libwfdcapdie.a $(OBJDIR)/libwfdcapdie.a : $(OSIOBJS) $(OSISHAREDOBJS)
	@[ -d "$(@D)" ] || mkdir -pv $(@D)
	$(AR) crs$(if $(V),v) $(OBJDIR)/$(@F) $^

$(OSIOBJS) $(OSISHAREDOBJS): $(OBJDIR)/%.o: %.c
	@[ -d "$(@D)" ] || mkdir -pv $(@D)
	$(CC) -c $(CFLAGS) $(if $(V),-H) $(INCLUDE) $< -o $@

# cleanup
clean: cleanfiles cleanfolders

cleanfiles:
	find $(OBJDIR) -name "*.o" | xargs rm -f
	find $(OBJDIR) -name "*.a" | xargs rm -f

cleanfolders:
	@rm -rfv $(OBJDIR)
