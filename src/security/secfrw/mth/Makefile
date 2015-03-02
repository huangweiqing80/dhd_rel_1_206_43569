#
# Makefile for cfg library
#
# Copyright (C) 2009 Broadcom Corporation
#
# $Id: Makefile,v 1.4 2010-08-09 18:50:57 $
#

SRCBASE = ../../..
include ../secfrw_defines.mk

CFLAGS += -I$(SRCBASE)/supp/usersup 
CFLAGS += -DBCMSUP_PSK

SRCS = \
	wpa_sup.c wl.c wl_linux.c wpa_auth.c dev_mth.c hal.c wpa_unpack_cfg.c \
	l2.c wpa_svc.c wpa_svcp.c wpa_sk.c bind_sk.c bta_al.c bta_svc.c \
	common_svc.c

ifeq ($(WPS),1)
CFLAGS += \
	-I$(SRCBASE)/wps/common/include \
	-I$(SRCBASE)/wps/wpscli/include \
	-I$(SRCBASE)/wps/wpscli/common/include
SRCS += \
	wps_svc.c wps_al.c
endif

TARGET_LIB=mth

include ../secfrw_rules.mk
