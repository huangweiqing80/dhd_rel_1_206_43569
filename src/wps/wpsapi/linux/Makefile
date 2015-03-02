#
# Linux Makefile by using WPS API library.
#
# $Id: Makefile 458775 2014-02-27 20:22:19Z $

WLAN_ComponentsInUse := bcmwifi
-include ../../../makefiles/WLAN_Common.mk
export SRCBASE = $(shell (cd ../../.. && pwd -P))

# Build type
export BLDTYPE = release
#export BLDTYPE = debug

# If cross compile has been set, then CC should inherit it
CC = gcc

ifneq ($(TARGETARCH),)
	ObjPfx  ?= $(BLDTYPE)/$(TARGETARCH)
else
TARGETARCH := x86
ifneq ($(BRAND),)
	ObjPfx  := $(BLDTYPE)/$(TARGETARCH)
else
	ObjPfx  ?= $(notdir $(CC))
endif
endif
ifneq ($(CROSS_COMPILE),)
	CC := $(CROSS_COMPILE)$(CC)
endif
export $(CC)

# Source paths
export WPSSRC = $(SRCBASE)/wps

# Common configuration
export WL_MODE = sta
export WPS_CONF_FILE = wpsconfig_wpsapi_linux
include $(WPSSRC)/common/config/$(WPS_CONF_FILE)
include $(WPSSRC)/common/config/wps.mk
EXTRA_CFLAGS = $(WPS_FLAGS)

# Async mode
ASYNC_MODE ?= 1
# WFA WPS 2.0 Testbed extra caps
WFA_TB ?= 0

# Set CFLAGS
CFLAGS = -Wall -Werror -Wnested-externs -fPIC -fno-strict-aliasing

ifeq ($(TARGETARCH), x86_64)
CFLAGS += -DBN64_BIT
endif

ifeq ($(BLDTYPE),debug)
	CFLAGS += -g -DDEBUG
	# Mark mips compiler to produce debugging information that is understood by gdb
	ifneq ($(findstring mips,$(CC)),)
		CFLAGS += -gstabs+
	endif
else
	CFLAGS += -Os
endif
ifeq ($(WFA_TB), 1)
CFLAGS += -DWFA_WPS_20_TESTBED
endif
ifeq ($(ASYNC_MODE), 1)
CFLAGS += -DASYNC_MODE
endif

ifeq ($(BCM_WPS_IOTYPECOMPAT),1)
  CFLAGS += -DBCM_WPS_IOTYPECOMPAT
endif

# Include path
CFLAGS += -I$(SRCBASE)/include \
	  -I$(SRCBASE)/common/include \
	  $(WLAN_ComponentIncPath) \
	  -I$(SRCBASE)/wps/common/include \
	  -I$(SRCBASE)/wps/wpsapi/common/include

ifeq ($(EXTERNAL_OPENSSL),1)
EXTERNAL_OPENSSL_BASE = $(shell (cd $(SRCBASE)/$(OS)openssl && pwd -P))
EXTERNAL_OPENSSL_INC = $(EXTERNAL_OPENSSL_BASE)/include
EXTERNAL_OPENSSL_LIB = $(EXTERNAL_OPENSSL_BASE)/lib/libcrypto.a
CFLAGS += -include wps_openssl.h -I$(EXTERNAL_OPENSSL_INC) -I$(EXTERNAL_OPENSSL_INC)/openssl
else
CFLAGS += -I$(SRCBASE)/include/bcmcrypto
endif

# Output dir
LIBDIR ?= $(shell pwd)/$(ObjPfx)

# Libraries
WPSLIB = $(LIBDIR)/libwps_sta.a
APILIB = $(LIBDIR)/libwpsapi.a
LIBS = $(APILIB) $(WPSLIB)
ifeq ($(ASYNC_MODE), 1)
LIBS += -lpthread
endif
ifeq ($(EXTERNAL_OPENSSL),1)
LIBS += $(EXTERNAL_OPENSSL_LIB)
endif

STRIP = strip
OS    =

ifeq ($(CC), arm-linux-gcc)
	CFLAGS += -mstructure-size-boundary=8
	STRIP = arm-linux-strip
	OS    = arm-linux_
endif

ifeq ($(CC), mipsel-uclibc-gcc)
	STRIP = mipsel-uclibc-strip
	OS    = mipsel-uclibc_
endif

ifeq ($(CC), mipsel-linux-gcc)
	STRIP = mipsel-linux-strip
	OS    = mipsel-linux_
endif

# WPS common files
WPS_SOURCE := $(WPS_FILES)

# API common files
API_SOURCE  = src/wps/wpsapi/common/wps_api.c
API_SOURCE += src/wps/wpsapi/common/wps_hooks.c
API_SOURCE += src/wps/wpsapi/common/wps_wl.c

# Application files
APP_SOURCE  = src/wps/wpsapi/linux/wps_api_tester.c
APP_SOURCE += src/wps/wpsapi/linux/wps_api_ui.c

ifeq ($(SHARED_LIB),1)
API_SOURCE += src/wps/wpsapi/linux/wps_linux_osl.c
else
APP_SOURCE += src/wps/wpsapi/linux/wps_linux_osl.c
endif

vpath %.c $(SRCBASE)/../

# WPS common objs
WPS_OBJS := $(foreach file, $(WPS_SOURCE), \
	$(patsubst src/%.c, $(LIBDIR)/obj/%.o,$(file)))

WPS_DIRS := $(foreach file, $(WPS_OBJS), \
	$(dir $(file)))

WPS_DIRLIST = $(sort $(WPS_DIRS))

# API common objs
API_OBJS := $(foreach file, $(API_SOURCE), \
	$(patsubst src/%.c, $(LIBDIR)/obj/%.o,$(file)))

API_DIRS := $(foreach file, $(API_OBJS), \
	$(dir $(file)))

API_DIRLIST = $(sort $(API_DIRS))

# Application objs
APP_OBJS := $(foreach file, $(APP_SOURCE), \
	$(patsubst src/%.c, $(LIBDIR)/obj/%.o,$(file)))

APP_DIRS := $(foreach file, $(APP_OBJS), \
	$(dir $(file)))

APP_DIRLIST = $(sort $(APP_DIRS))

ifeq ($(SHARED_LIB),1)
all: $(APILIB)
else
all: $(WPSLIB) $(APILIB) wpsapitester
endif

%_DIRS :
	mkdir -p $($*_DIRLIST)
	@echo "==> $(WPS_CONF_FILE)"

# All objs rule
$(WPS_OBJS) $(API_OBJS) $(APP_OBJS): $(LIBDIR)/obj%.o: $(addprefix $(SRCBASE)/../,src%.c)
	$(CC) -c $(CFLAGS) $(EXTRA_CFLAGS) -o $@ $<

# WPS common library
$(WPSLIB) : WPS_DIRS $(WPS_OBJS)
	$(AR) cr $@ $(WPS_OBJS)
	@date +"%c -- MARK $@ --"

# API common library
$(APILIB) : API_DIRS $(API_OBJS)
ifeq ($(SHARED_LIB),1)
	$(LD) -shared -o $(LIBDIR)/libwpsapi.so $(API_OBJS)
else
	$(AR) cr $@ $(API_OBJS)
endif
	@date +"%c -- MARK $@ --"

# Application
wpsapitester : APP_DIRS $(APP_OBJS) $(LIBS)
	$(CC) $(APP_OBJS) $(LIBS) -o $(LIBDIR)/wpsapitester
ifeq ($(BLDTYPE),release)
	$(STRIP) $(LIBDIR)/wpsapitester
endif
	@cd $(LIBDIR); ln -sf wpsapitester wpsenr
	@cd $(LIBDIR); ln -sf wpsapitester wpsreg
	@date +"%c -- MARK $@ --"

clean:
	@rm -rf $(LIBDIR)/obj
	@rm -f $(LIBDIR)/*.a
	@rm -f $(LIBDIR)/*.so
	@rm -f $(LIBDIR)/wpsapitester
	@rm -f $(LIBDIR)/wpsenr
	@rm -f $(LIBDIR)/wpsreg
	@date +"%c -- MARK $@ --"

phony:
