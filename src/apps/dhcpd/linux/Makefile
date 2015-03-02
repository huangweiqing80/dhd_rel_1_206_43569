#
# Copyright 2009, Broadcom, Inc.
#
# $Id: Makefile,v 1.4 2010-11-30 01:08:06 $
#

ifeq ($(SRCBASE),)
SRCBASE := $(shell /bin/pwd)/..
endif

IFLAGS := -I $(SRCBASE)/include

ifeq ($(CC), gcc)
  CFLAGS += -m32
endif


OFILES = main.o config.o dhcpsend.o ippool.o packet.o pktparse.o linuxosl.o linuxsocket.o mac.o test.o
#OFILES=$(CFILES:.c=.o)


vpath %.c ../common

%.o: %.c
	gcc $(IFLAGS) -c $(CFLAGS) -o $@ $<


dhcpd: $(OFILES)
	gcc $(CFLAGS) -lc -o dhcpd $(OFILES)
	
clean:
	rm *.o dhcpd
