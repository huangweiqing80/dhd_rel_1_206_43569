#
# USB Remote Download Makefile - Host linux user mode driver
#
#
# Copyright (C) 2014, Broadcom Corporation
# All Rights Reserved.
# 
# This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
# the contents of this file may not be disclosed to third parties, copied
# or duplicated in any form, in whole or in part, without the prior
# written permission of Broadcom Corporation.
#
# $Id: Makefile 419790 2013-08-22 19:45:37Z $


SRCBASE = ../..
include $(SRCBASE)/Makerules

vpath %.c $(SRCBASE)/shared

CFLAGS= -Wall -Wstrict-prototypes -g -O2 -I$(SRCBASE)/include -I$(SRCBASE)/common/include -I$(SRCBASE)/shared/zlib -DBCMTRXV2

LIBS = -lusb
TARGET = $(ObjPfx)bcmdl
SRCS = bcmdl.c adler32.c inffast.c inflate.c infcodes.c infblock.c inftrees.c infutil.c zutil.c crc32.c bcmutils.c

OBJECTS = $(SRCS:%.c=$(ObjPfx)%.o)

TESTS = tsthwa tstjtag timehwa timejtag

VPATH := $(SRCBASE)/shared/zlib

ifeq ($(TARGETENV), linux)
	OBJECTS += $(ObjPfx)usb_linux.o
	COMPILE = $(CC)
	CLEAN = clean_linux
	CFLAGS += -I../libusb
	LDFLAGS += $(CROSS_LD_PATH)
endif

ifeq ($(TARGETENV), linuxmips_be)
	OBJECTS += $(ObjPfx)usb_linux.o
	COMPILE = mips-linux-gcc
	LIBS := -L$(LIBUSB_PATH)/.libs $(LIBUSB_PATH)/.libs/libusb.a
	CFLAGS += -I$(LIBUSB_PATH) -DIL_BIGENDIAN
endif


ifeq ($(TARGETENV), linuxmips)
	TARGET_PREFIX := mipsel-linux-
	OBJECTS += $(ObjPfx)usb_linux.o
	CFLAGS += -I ../libusb
	COMPILE = mipsel-linux-gcc
	CLEAN = clean_linux
	LDFLAGS += -L$(LIBUSB_PATH)/.libs
	LIBS= ../libusb/.libs/libusb.a
	LIBS := -L$(LIBUSB_PATH)/.libs $(LIBUSB_PATH)/.libs/libusb.a
	CFLAGS += -I$(LIBUSB_PATH)
#It is wrong to put install target here, affect the rest of ifeq tests
#install:
#	cp bcmdl $(SRCBASE)/router/mipsel-uclibc/target/bin
endif

ifeq ($(TARGETENV), linux26mips)
	TARGET_PREFIX := mipsel-uclibc-linux26-
	OBJECTS += $(ObjPfx)usb_linux.o
	CFLAGS += -I ../libusb
	COMPILE = mipsel-uclibc-linux26-gcc
	CLEAN = clean_linux
	LDFLAGS += -L ../libusb/.libs
	LIBS= ../libusb/.libs/libusb.a
#It is wrong to put install target here, affect the rest of ifeq tests
#install:
#	cp bcmdl $(SRCBASE)/router/mipsel-uclibc/target/bin
endif

ifeq ($(TARGETENV), macos)
	TARGET = bcmdl_macos
	CLEAN = clean_macos
	COMPILE = xcodebuild
	PROJECT = bcmdl.xcodeproj
endif

# Have to make sure the TARGETARCH is set when TARGETENV is "linuxmips"
# Whether TARGETARCH or TARGETENV is the main macro doesn't really matter
# What matter is we need uniformity
ifeq ($(TARGETARCH), mips)
	ObjPfx := $(TARGETARCH)/
	OBJECTS := $(SRCS:%.c=$(ObjPfx)%.o)
	OBJECTS += $(ObjPfx)usb_linux.o
	TARGET_PREFIX := mipsel-linux-
	TARGET := $(ObjPfx)bcmdl
	COMPILE := $(CC)
	LDFLAGS += $(CROSS_LD_PATH)
	LDFLAGS += -L$(LIBUSB_PATH)/.libs
	LIBS= ../libusb/.libs/libusb.a
	LIBS := -L$(LIBUSB_PATH)/.libs $(LIBUSB_PATH)/.libs/libusb.a
	CFLAGS += -I ../libusb
	CFLAGS += -I$(LIBUSB_PATH)
endif

ifeq ($(BCMQT),1)
	CFLAGS += -DBCMQT
	TARGET = bcmdl_qt
endif

all: $(TARGET)

tests: $(TESTS)

$(ObjPfx)bcmdl: $(OBJECTS)
	$(COMPILE)  $(OBJECTS)  $(CFLAGS) $(LDFLAGS) $(LIBS)  -o $@

bcmdl_qt: $(OBJECTS)
	$(COMPILE)  $(OBJECTS)  $(CFLAGS) $(LIBS)  -o $@

$(TESTS): %: %.o
	$(COMPILE) $< $(CFLAGS) $(LIBS) -o $@

# Executable is located in build/Debug/bcmdl
#
bcmdl_macos:
	$(COMPILE) -project $(PROJECT) -target $(TARGET) -configuration Debug build

clean_macos:
	$(COMPILE) -project $(PROJECT) -target $(TARGET) -configuration Debug clean

clean_linux:
	rm -rf bcmdl_qt $(TARGET) $(OBJECTS) $(TESTS) $(TESTS:=.o)

clean: $(CLEAN)

$(ObjPfx)%.o: %.c
	@[ -d "$(@D)" ] || mkdir -pv $(@D)
	$(COMPILE) -c $(CFLAGS) -o $@ $<
