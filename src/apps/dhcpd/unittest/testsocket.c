/*
 * Broadcom DHCP Server
 * Socket routines for Win32 
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: testsocket.c,v 1.4 2009-08-17 22:35:46 $
 */

#pragma comment( lib,"ws2_32.lib" )

#include <winsock.h>

#include "dhcp.h"
#include "osl.h"
#include "packet.h"
#include "dhcpdebug.h"

int gSendCount;
struct Packet *gLastPacket = NULL;

int socketInit() {
	if (gLastPacket)
		packetFree(gLastPacket);

	gSendCount = 0;
	gLastPacket = NULL;

	return DDOK;
}

int socketDeinit() {
	return DDOK;
}

int socketSend(struct Packet *p) {
	if (gLastPacket)
		packetFree(gLastPacket);

	gSendCount++;
	packetDup(p, &gLastPacket);
	
	return DDOK;
}
