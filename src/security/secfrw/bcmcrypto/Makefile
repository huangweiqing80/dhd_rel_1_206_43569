#
# Linux router libbcmcrypto Makefile
#
# Copyright (C) 2014, Broadcom Corporation
# All Rights Reserved.
# 
# This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
# the contents of this file may not be disclosed to third parties, copied
# or duplicated in any form, in whole or in part, without the prior
# written permission of Broadcom Corporation.
#
# $Id: Makefile,v 1.2 2010-02-10 22:37:15 $
#

SRCBASE = ../../..
include ../secfrw_defines.mk

#ifdef BCMINTERNALG
ifeq ($(BLDTYPE),debug)
  CFLAGS	+= -DBCMINTERNAL
endif
#endif 

vpath %.c $(SRCBASE)/bcmcrypto

SRCS := aes.c aeskeywrap.c rijndael-alg-fst.c sha1.c passhash.c prf.c md5.c hmac.c rc4.c  tkhash.c tkmic.c wep.c

TARGET_LIB := bcmcrypto

include ../secfrw_rules.mk
