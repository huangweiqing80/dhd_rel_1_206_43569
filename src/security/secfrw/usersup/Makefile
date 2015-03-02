#
# Makefile for wpa supplicant library
#
# Copyright (C) 2009 Broadcom Corporation
#
# $Id: Makefile,v 1.4 2010-08-09 18:39:58 $
#

SRCBASE = ../../..
include ../secfrw_defines.mk

# Disable CCX for now: brings us grief with authenticator
#CFLAGS += -DBCMSUP_PSK -DBCMWPA2 -DBCMEXTCCX -DSECFRW 
CFLAGS += -DBCMSUP_PSK -DBCMWPA2 -DSECFRW 

CFLAGS += -DLINUX

LCINCS += -I$(SRCBASE)/supp/include

SUPPFLAGS = -DSTA -DBCMEXTSUP

SRCS= bcm_supenv.c wlc_sup.c bcmwpa.c wpaif.c bcmutils.c

TARGET_LIB=usersup

vpath %.c $(SRCBASE)/supp/usersup $(SRCBASE)/shared

include ../secfrw_rules.mk
# overrides

$(OBJDIR)/wlc_sup.o wlc_sup.o:	CFLAGS += $(SUPPFLAGS)

$(OBJDIR)/bcmwpa.o bcmwpa.o:	CFLAGS += $(SUPPFLAGS)
