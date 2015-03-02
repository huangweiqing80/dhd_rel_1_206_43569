/*
 * Broadcom DHCP Server
 * DHCP packet handling routines. 
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: packet.c,v 1.6 2009-10-05 19:13:02 $
 */

#include <malloc.h>
#include <string.h>

#include "dhcp.h"
#include "packet.h"
#include "dhcpdebug.h"
#include "osl.h"

int packetAlloc(int Size, struct Packet **p) {
	ASSERT(p);

	*p = (struct Packet *) malloc(sizeof(struct Packet));

	if (!*p)
		return DDRESOURCES;

	memset(*p, 0, sizeof(struct Packet));

	(*p)->Data = (unsigned char *)malloc(Size);

	if ((*p)->Data == (unsigned char *) NULL)
	{
		free(*p);
		*p = NULL;
		return DDRESOURCES;
	}

	VINIT((*p), PACKET);

	(*p)->maxSize = Size;						// max size of the allocated buffer
	memset((*p)->Data, 0, (*p)->maxSize);		// clear the buffer

	return DDOK;
}

int packetFree(struct Packet *p) {
	VALIDATE(p ,PACKET);

	VDEINIT(p, PACKET);

	if (p->Data)
		free(p->Data);

	free(p);

	return DDOK;
}

int packetDup(struct Packet *From, struct Packet **To) {
	int rVal;

	ASSERT(From);
	ASSERT(To);

	if (DDOK != (rVal = packetAlloc(From->maxSize, To)))	// always allocate a max-size
		return rVal;

	memcpy((*To)->Data, From->Data, From->Size);
	(*To)->Size = From->Size;							// only copy the 'current size'

	return DDOK;
}

int packetDupFromTemplate(unsigned char *From, struct Packet **To, int Size) {
	int rVal;

	ASSERT(From);
	ASSERT(To);

	if (DDOK != (rVal = packetAlloc(Size, To)))
		return rVal;

	memcpy((*To)->Data, From, Size);
	(*To)->Size = Size;

	return DDOK;
}
