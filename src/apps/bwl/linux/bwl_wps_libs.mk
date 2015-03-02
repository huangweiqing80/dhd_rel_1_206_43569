#Linux Makefile

BLDTYPE = release
#BLDTYPE = debug

#-----------------------------------------------------------------
# Linux build
#
# This should be one of values recognized in src/Makerules

# Discard any "MMX" or other qualifications on x86 so that
# any TARGETARCH containing x86 is just "x86"
ifeq ($(findstring x86_mmx,$(TARGETARCH)),x86_mmx)
	TARGETARCH = x86
endif

OBJDIR = $(TARGETARCH)

CC:= gcc
export $(CC)


ifeq ($(BLDTYPE),debug)
CFLAGS = -Wall -Wnested-externs -g -D_TUDEBUGTRACE -DWPS_WIRELESS_ENROLLEE
CXXFLAGS = -Wall -Wnested-externs -g -D_TUDEBUGTRACE -DWPS_WIRELESS_ENROLLEE
else
CFLAGS = -Wall -Os -Wnested-externs -DWPS_WIRELESS_ENROLLEE
endif

CFLAGS += -DBCMWPA2
CFLAGS += -fPIC



ifeq ($(CC), arm-linux-gcc)
CFLAGS += -mstructure-size-boundary=8
STRIP = arm-linux-strip
OS = arm-linux_
endif

ifeq ($(CC), mipsel-uclibc-gcc)
STRIP = mipsel-uclibc-strip
OS = mipsel-uclibc_
endif

ifeq ($(CC), gcc)
STRIP = strip
OS =
endif

ifndef	SRCBASE
	export SRCBASE = $(shell (cd ../../.. && pwd -P))
endif

export INCLUDE =  -I$(SRCBASE)/include -I$(SRCBASE)/wps/common/include

# openssl
export CFLAGS += -include wps_openssl.h
export CXXFLAGS += -include wps_openssl.h

BCM_PARTIAL_CRYPTO = 1
EXTERNAL_OPENSSL = 0

#export EXTERNAL_OPENSSL_BASE = $(shell (cd $(SRCBASE)/$(OS)openssl && pwd -P))
#export EXTERNAL_OPENSSL_BASE = $(shell (cd ../../../../../openssl/$(OS)stage-install/usr/local && pwd -P))

export EXTERNAL_OPENSSL_INC = $(EXTERNAL_OPENSSL_BASE)/include
export EXTERNAL_OPENSSL_LIB = $(EXTERNAL_OPENSSL_BASE)/lib/libcrypto.a

ifeq ($(EXTERNAL_OPENSSL), 1)
export CFLAGS += -DUSE_EXTERNAL_OPENSSL
export CXXFLAGS += -DUSE_EXTERNAL_OPENSSL
ifeq ($(BCM_PARTIAL_CRYPTO),1)
CFLAGS += -I$(EXTERNAL_OPENSSL_INC) -I$(EXTERNAL_OPENSSL_INC)/openssl -I$(SRCBASE)/include/bcmcrypto
else
CFLAGS += -I$(EXTERNAL_OPENSSL_INC) -I$(EXTERNAL_OPENSSL_INC)/openssl
endif
else
CFLAGS += -I$(SRCBASE)/include/bcmcrypto
endif


LIBS = $(OBJDIR)/libwpsenr.a $(OBJDIR)/libwpscom.a

ifeq ($(EXTERNAL_OPENSSL), 1)
LIBS += $(EXTERNAL_OPENSSL_LIB)
ifeq ($(BCM_PARTIAL_CRYPTO),1)
LIBS += $(OBJDIR)/libbcmcrypto.a
endif
else
LIBS += $(OBJDIR)/libbcmcrypto.a
endif

default: libs


libs :
	mkdir -p $(OBJDIR)/bcmcrypto
	mkdir -p $(OBJDIR)/sta
	mkdir -p $(OBJDIR)/enrollee
	mkdir -p $(OBJDIR)/registrar
	mkdir -p $(OBJDIR)/shared
	make BLDTYPE=$(BLDTYPE) EXTERNAL_OPENSSL=$(EXTERNAL_OPENSSL) BCM_PARTIAL_CRYPTO=$(BCM_PARTIAL_CRYPTO) \
		CFLAGS="$(CFLAGS)" CC=$(CC) LIBDIR=$(SRCBASE)/apps/bwl/linux/$(OBJDIR) -C $(SRCBASE)/wps/common -f wps_enr_lib.mk
	make BLDTYPE=$(BLDTYPE) EXTERNAL_OPENSSL=$(EXTERNAL_OPENSSL) CFLAGS="$(CFLAGS)" CC=$(CC) \
		LIBDIR=$(SRCBASE)/apps/bwl/linux/$(OBJDIR) -C $(SRCBASE)/wps/common -f wps_common_lib.mk

clean:
	find -name "*.o" | xargs rm -f
	find -name "*.so" | xargs rm -f
	find -name "*.a" | xargs rm -f

phony:
