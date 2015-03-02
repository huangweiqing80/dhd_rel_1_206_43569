# GNUmakefile for secfrw test program driver 
# Setup for building android, linux targets
# RTT 2009-09-30

# Invocations
# For Android:
# gmake TARGETENV=android TARGETARCH=arm_android TARGETOS=unix
# gmake TARGETENV=android TARGETARCH=arm_android TARGETOS=unix clean
#
# For Linux:
# gmake all
# gmake clean
#
# $Id: GNUmakefile,v 1.4 2010-08-26 22:18:31 $

SRCBASE = ../..
include secfrw_defines.mk

SRCS = cli.c

CLI_EXE := testcli

# Android has pthread built into its libc
ifeq ($(findstring linux,$(TARGETENV)), linux)
	THREAD_LIB := -lpthread
endif

LIBS=bcmcrypto cfg disp tmr utils mth userauth usersup linux

LIBS_LIST:=$(foreach lib,$(LIBS),-l$(lib))
LIB_DIRLIST:=$(foreach lib,$(LIBS),-L$(lib)/$(OBJDIR))

LD_GROUP := -Wl,--start-group
LD_GROUP += -Wl,$(subst $(space),$(comma),$(strip $(LIBS_LIST) $(EXT_LIBS)))
LD_GROUP += -Wl,--end-group

# remove unused sections (function/data)
LDFLAGS	+= -Wl,--gc-sections

all: CFLAGS += -DCLI_TESTTOOL
all: build_libs $(OBJS)
#$(CC) -o $(OBJDIR)/$(CLI_EXE) $(LDFLAGS) $(OBJS) $(LIB_DIRLIST) $(LD_GROUP) -lbcmcrypto -lpthread
	echo $(TARGETARCH)
	echo $(TARGETENV)
	$(CC) -o $(OBJDIR)/$(CLI_EXE) $(LDFLAGS) $(OBJS) $(LIB_DIRLIST) $(LD_GROUP) -lbcmcrypto $(THREAD_LIB)
	echo "done"

hslbcmsec: CFLAGS += -DHSL_INTEGRATION
hslbcmsec: build_libs $(OBJS)
	$(AR) rc $(OBJDIR)/lib$@.a $(OBJS) $(LIBS:%=%/$(OBJDIR)/*.o)
	echo "done"

define run-make-on-libs
	for dir in $(sort $(LIBS)); \
		do $(MAKE) -C $$dir $(1); \
		if [ $$? -ne 0 ]; then \
			exit 1; \
		fi; \
	done
endef

build_libs: FORCE
	$(call run-make-on-libs)

vpath %.c testcli

clean: lib-clean

lib-clean: FORCE
	$(call run-make-on-libs,clean)

FORCE:
include secfrw_rules.mk
