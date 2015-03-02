# Common defines for secfrw/*/Makefile
#
# $Id: secfrw_defines.mk,v 1.4 2010-08-26 22:16:13 $

BLDTYPE    := debug
# Allow CROSS_COMPILE to specify compiler base
CC         := $(CROSS_COMPILE)gcc
LD         := $(CROSS_COMPILE)ld
NM         := $(CROSS_COMPILE)nm
STRIP      := $(CROSS_COMPILE)strip
AR         := $(CROSS_COMPILE)ar

TARGETARCH := x86

ifeq ($(LINUXVER),)
LINUXVER := $(shell uname -r)
endif

OBJDIR   ?= obj-$(LINUXVER)-$(BLDTYPE)-$(TARGETARCH)

include $(SRCBASE)/Makerules

comma:=,

LCINCS := -I. -I./include -I../include

CFLAGS += -I$(SRCBASE)/supp/include

CFLAGS += -fno-builtin
CFLAGS += -Werror
CFLAGS += -Wall 

ifeq ($(BLDTYPE),debug)
  CFLAGS += -DDEBUG -DBCMDBG -g
else
  CFLAGS += -O2
endif

ifeq ($(WPS),1)
CFLAGS += -DWPS
endif

ifneq ($(SECFRW_PRINT_TRACE_ENABLED),)
   CFLAGS += -DSECFRW_PRINT_TRACE_ENABLED=$(SECFRW_PRINT_TRACE_ENABLED)
endif


OBJS = $(SRCS:%.c=$(OBJDIR)/%.o)
