#
# Makefile for wpa authenticator library
#
# Copyright (C) 2009 Broadcom Corporation
#
# $Id: Makefile,v 1.3 2010-08-09 18:39:59 $
#

SRCBASE = ../../..
include ../secfrw_defines.mk

CFLAGS += -DBCMAUTH_PSK

AUTHFLAGS = -DBCMSUP_PSK

LCINCS += -I$(SRCBASE)/supp/include

SRCS = wlc_auth.c wpaif_auth.c bcm_authenv.c

TARGET_LIB=userauth

vpath %.c $(SRCBASE)/shared

include ../secfrw_rules.mk
# overrides

$(OBJDIR)/wlc_auth.o wlc_auth.o: CFLAGS += $(AUTHFLAGS)
