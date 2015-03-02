/*
 * Broadcom DHCP Server
 * DHCP packet handling definitions. 
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: packet.h,v 1.2 2009-06-08 23:04:05 $
 */

#define PACKET_MAGIC	0xa92abb1c

struct Packet {
		int Size;
		int maxSize;
		unsigned char *Data;
		unsigned long magic;
};

int packetAlloc(int Size, struct Packet **p);
int packetFree(struct Packet *p);
int packetDup(struct Packet *From, struct Packet **To);
int packetDupFromTemplate(unsigned char *From, struct Packet **To, int Size);
