/*
 * Broadcom DHCP Server
 * IP Address pool definitions. 
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: ippool.h,v 1.4 2009-10-06 18:03:51 $
 */

#define IP_MAGIC	0x4912aa31

struct IP {
	unsigned long IPaddress;
	unsigned char ClientID[6];
	unsigned long timeAllocated;
	unsigned long leaseTime;
	unsigned long magic;
};


int IPInit();
int IPDeinit();
int IPFree(struct IP *pIP);
int IPAllocate(struct IP **ppIP);
int IPValidate(struct parsedPacket *pp);
int IsIPStillValid(struct parsedPacket *pp);
int IPLookup(unsigned long RequestedIP, struct IP **ppIP);
int IPLookupByMAC(char * RequestedMAC, struct IP **ppIP);
