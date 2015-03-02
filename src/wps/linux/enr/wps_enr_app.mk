#Linux Makefile

BLDTYPE := release
#BLDTYPE = debug
CC = gcc
STRIP = strip

ObjPfx  ?= $(notdir $(CC))
# If cross compile has been set, then CC should inherit it
ifneq ($(CROSS_COMPILE),)
	CC := $(CROSS_COMPILE)$(CC)
	STRIP := $(CROSS_COMPILE)$(STRIP)
endif

export $(CC)

ifeq ($(BLDTYPE),debug)
	CFLAGS = -Wall -Wnested-externs -g -D_TUDEBUGTRACE -DWPS_WIRELESS_ENROLLEE -DDEBUG
	CXXFLAGS = -Wall -Wnested-externs -g -D_TUDEBUGTRACE -DWPS_WIRELESS_ENROLLEE
	# Mark mips compiler to produce debugging information that is understood
	# by gdb
	ifneq ($(findstring mips,$(CC)),)
		CFLAGS += -gstabs+
	endif
else
	CFLAGS = -Wall -Os -Wnested-externs -DWPS_WIRELESS_ENROLLEE
endif

ifeq ($(CC), gcc)
  CFLAGS     += -m32
  LDFLAGS    += -m32
endif

CFLAGS += -DBCMWPA2 -fPIC
CFLAGS += -fno-strict-aliasing -Werror


ifeq ($(BCM_WPS_IOTYPECOMPAT),1)
  CFLAGS += -DBCM_WPS_IOTYPECOMPAT
endif

# WFA WPS 2.0 Testbed extra caps
#CFLAGS += -DWFA_WPS_20_TESTBED

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

ifeq ($(CC), mips-uclibc-gcc)
	STRIP = mips-uclibc-strip
	OS    = mips-uclibc_
endif

ifeq ($(CC), mips-linux-gcc)
	STRIP = mips-linux-strip
	OS    = mips-linux_
endif


export SRCBASE = $(shell (cd ../../.. && pwd -P))

export INCLUDE =  -I$(SRCBASE)/include -I$(SRCBASE)/common/include -I../../common/include -I../inc -I$(SRCBASE)/shared/bcmwifi/include

#flag to use external openssl library.
EXTERNAL_OPENSSL ?= 0

ifeq ($(EXTERNAL_OPENSSL), 1)
export EXTERNAL_OPENSSL_BASE = $(shell (cd $(SRCBASE)/$(OS)openssl && pwd -P))
export EXTERNAL_OPENSSL_INC = $(EXTERNAL_OPENSSL_BASE)/include
export EXTERNAL_OPENSSL_LIB = $(EXTERNAL_OPENSSL_BASE)/lib/libcrypto.a

export CFLAGS += -DEXTERNAL_OPENSSL -include wps_openssl.h \
	-I$(EXTERNAL_OPENSSL_INC) -I$(EXTERNAL_OPENSSL_INC)/openssl
export CXXFLAGS += -DEXTERNAL_OPENSSL -include wps_openssl.h \
	-I$(EXTERNAL_OPENSSL_INC) -I$(EXTERNAL_OPENSSL_INC)/openssl
else
CFLAGS += -I$(SRCBASE)/include/bcmcrypto
endif

OBJS = $(ObjPfx)/wps_enr.o $(ObjPfx)/wps_linux_hooks.o $(ObjPfx)/wl_wps.o
REGOBJS = $(ObjPfx)/wps_reg.o $(ObjPfx)/wps_linux_hooks.o $(ObjPfx)/wl_wps.o
APIOBJS = $(ObjPfx)/wps_api.o $(ObjPfx)/wps_linux_hooks.o $(ObjPfx)/wl_wps.o
SAMPLEAPPOBJS = $(ObjPfx)/wps_api_tester.o

LIBS = $(ObjPfx)/libwpsenr.a $(ObjPfx)/libwpscom.a
SAMPLEAPPLIBS = $(ObjPfx)/libwpsapi.a $(ObjPfx)/libwpsenr.a $(ObjPfx)/libwpscom.a -lpthread

ifeq ($(EXTERNAL_OPENSSL), 1)
LIBS += $(EXTERNAL_OPENSSL_LIB)
SAMPLEAPPLIBS += $(EXTERNAL_OPENSSL_LIB)
else
LIBS += $(ObjPfx)/libbcmcrypto.a
SAMPLEAPPLIBS += $(ObjPfx)/libbcmcrypto.a
endif

default: libs wpsenr wpsapi wpsreg wpsapitester


libs :
	mkdir -p $(ObjPfx)/bcmcrypto
	mkdir -p $(ObjPfx)/sta
	mkdir -p $(ObjPfx)/enrollee
	mkdir -p $(ObjPfx)/registrar
	mkdir -p $(ObjPfx)/shared
	$(MAKE) BLDTYPE=$(BLDTYPE) EXTERNAL_OPENSSL=$(EXTERNAL_OPENSSL) CFLAGS="$(CFLAGS)" "CC=$(CC)" \
		LIBDIR=$(PWD)/$(ObjPfx) -C ../../common -f wps_enr_lib.mk
	$(MAKE) BLDTYPE=$(BLDTYPE) EXTERNAL_OPENSSL=$(EXTERNAL_OPENSSL) CFLAGS="$(CFLAGS)" "CC=$(CC)" \
		LIBDIR=$(PWD)/$(ObjPfx) -C ../../common -f wps_common_lib.mk

ifeq ($(BLDTYPE),debug)
wpsenr : $(OBJS) $(LIBS)
	$(CC) $(LDFLAGS) $(OBJS) $(LIBS) -o $(ObjPfx)/wpsenr

wpsapi : $(APIOBJS)
	$(AR) cr $(ObjPfx)/libwpsapi.a $^

wpsreg : $(REGOBJS) $(LIBS)
	$(CC) $(LDFLAGS) $(REGOBJS) $(LIBS) -o $(ObjPfx)/wpsreg

wpsapitester : $(SAMPLEAPPOBJS) $(SAMPLEAPPLIBS)
	$(CC) $(LDFLAGS) $(SAMPLEAPPOBJS) $(SAMPLEAPPLIBS) -o $(ObjPfx)/wpsapitester

else
wpsenr : $(OBJS) $(LIBS)
	$(CC) $(LDFLAGS) $(OBJS) $(LIBS) -o $(ObjPfx)/wpsenr
	$(STRIP) $(ObjPfx)/wpsenr

wpsapi : $(APIOBJS)
	$(AR) cr $(ObjPfx)/libwpsapi.a $^

wpsreg : $(REGOBJS) $(LIBS)
	$(CC) $(LDFLAGS) $(REGOBJS) $(LIBS) -o $(ObjPfx)/wpsreg
	$(STRIP) $(ObjPfx)/wpsreg

wpsapitester : $(SAMPLEAPPOBJS) $(SAMPLEAPPLIBS)
	$(CC) $(LDFLAGS) $(SAMPLEAPPOBJS) $(SAMPLEAPPLIBS) -o $(ObjPfx)/wpsapitester
	$(STRIP) $(ObjPfx)/wpsapitester
endif

$(CC)/%.o $(ObjPfx)/%.o : %.c
	$(CC) -c $(CFLAGS) $(INCLUDE) $< -o $@

clean:
	find -name "*.o" | xargs rm -f
	find -name "*.so" | xargs rm -f
	find -name "*.a" | xargs rm -f
	find -name  wpsenr | xargs rm -f
	find -name  wpsapitester | xargs rm -f
	find -name  wpsreg | xargs rm -f

extract:
	cd $(SRCBASE); cvs co src/bcmcrypto
	cd $(SRCBASE); cvs co src/include/bcmcrypto \
	cvs co src/include/bcmcrypto/bcmdefs.h \
	cvs co src/include/bcmcrypto/bcmwifi.h \
	cvs co src/include/bcmcrypto/bcmendian.h \
	cvs co src/include/bcmcrypto/wlioctl.h \
	cvs co src/include/bcmcrypto/proto

phony:
