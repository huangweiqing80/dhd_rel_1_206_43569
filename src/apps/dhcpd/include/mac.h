/*
 * Broadcom DHCP Server
 * MAC Address definitions. 
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: mac.h,v 1.3 2009-09-10 20:48:35 $
 */

#define MAC_MAGIC	0x3a42da32

#define MACADDRESSLEN 6

struct MAC {
	struct MAC *next;
	struct MAC *last;
	unsigned char macAddress[MACADDRESSLEN];

	unsigned long magic;
};

extern struct MAC gMAC;
extern void *gMacLock;

int MACInit();
int MACDeinit();
int MACFree(unsigned char *pMAC);
int MACAllocate(unsigned char *, struct MAC **ppMAC);
int MACLookup(unsigned char *, struct MAC **ppMAC);
int MACThreadSafeLookup(unsigned char *, struct MAC **ppMAC);
