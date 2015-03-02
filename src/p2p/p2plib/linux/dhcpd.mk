#
# DHDCPD Makefile needed by P2P library
#
# Copyright (C) 2014, Broadcom Corporation
# All Rights Reserved.
# 
# This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
# the contents of this file may not be disclosed to third parties, copied
# or duplicated in any form, in whole or in part, without the prior
# written permission of Broadcom Corporation.
#
# $Id: dhcpd.mk,v 1.8 2010-11-30 02:30:12 $
#

SRCBASE   := ../../..
DHCPDBASE ?= $(SRCBASE)/apps/dhcpd
BLDTYPE   ?= debug
CC        ?= gcc
CC        ?= X86
OBJDIR    ?= obj/$(TARGETARCH)-$(BLDTYPE)

IFLAGS := -I $(DHCPDBASE)/include -I $(SRCBASE)/include -I $(SRCBASE)/common/include

CCFLAGS := 
ifeq ($(CC), gcc)
  CCFLAGS += -m32
endif

DHCPD_SRCS = main.c config.c dhcpsend.c ippool.c mac.c packet.c \
		pktparse.c linuxosl.c linuxsocket.c
DHCPD_OBJS = $(DHCPD_SRCS:%.c=$(OBJDIR)/%.o)

all: libdhcpd.a

vpath %.c $(SRCBASE)/apps/dhcpd/common $(SRCBASE)/apps/dhcpd/linux

$(DHCPD_OBJS): $(OBJDIR)/%.o: %.c
	@[ -d "$(@D)" ] || mkdir -pv $(@D)
	$(CC) -c $(if $(V),-H) $(CCFLAGS) $(IFLAGS) -o $@ $<

#dhcpd: $(DHCPD_OBJS)
#	$(CC) -lc -o $(OBJDIR)/dhcpd $(DHCPD_OBJS)

libdhcpd.a $(OBJDIR)/libdhcpd.a: $(DHCPD_OBJS)
	@[ -d "$(@D)" ] || mkdir -pv $(@D)
	$(AR) cr$(if $(V),v) $(OBJDIR)/$(@F) $^  

clean:
	rm $(DHCPD_OBJS) *.o dhcpd
