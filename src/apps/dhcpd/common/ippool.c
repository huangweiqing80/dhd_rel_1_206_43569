/*
 * Broadcom DHCP Server
 * IP Address management routines
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: ippool.c,v 1.12 2010-09-03 08:47:15 $
 */

#include <stdio.h>
#include <string.h>
#include <malloc.h>
#ifdef WIN32
#include <winsock.h>
#endif
#ifdef TARGETOS_symbian
#include <typedefs.h>
#include <netinet/in.h>
#endif

#include "dhcp.h"
#include "pktparse.h"
#include "ippool.h"
#include "config.h"
#include "osl.h"
#include "dhcpdebug.h"

static struct IP **IPPool = NULL;
static int IPPoolSize = 0;

struct IP *newIP(int i);


int IPInit() {
	ASSERT( (int)gConfig.EndingIP - (int)gConfig.StartingIP > 0);

	IPPoolSize = gConfig.EndingIP - gConfig.StartingIP;
	IPPool = (struct IP **)malloc(sizeof(struct IP *) * IPPoolSize);

	if (!IPPool)
		return DDRESOURCES;

	memset(IPPool, 0,sizeof(struct IP *) * IPPoolSize);

	return DDOK;
}

int IPDeinit(){
	int i;
	struct IP **pIP = (struct IP **) IPPool;
	
	ASSERT(IPPool && IPPoolSize);

	for (i = 0; i < IPPoolSize; i++, pIP++) {
		if (*pIP)
			IPFree(*pIP);
	}

	free(IPPool);

	IPPool = NULL;
	IPPoolSize = 0;

	return DDOK;
}

int IPFree(struct IP *pIP){
	ASSERT(pIP);

	free(pIP);
	return DDOK;
}

struct IP *newIP(int i) {
	struct IP *pIP = (struct IP *)malloc(sizeof(struct IP));

	if (!pIP)
		return NULL;

	memset(pIP, 0, sizeof(struct IP));

	VINIT(pIP, IP);

	pIP->IPaddress = gConfig.Subnet + gConfig.StartingIP + i;
	pIP->leaseTime = gConfig.LeaseTime;
	pIP->timeAllocated = OslGetSeconds();
	DHCPLOG(("DHCP newIP: subnet=0x%08x i=0x%08x IP=0x%08x\n",
		gConfig.Subnet, gConfig.StartingIP + i, pIP->IPaddress));

	return pIP;
}



int IPAllocate(struct IP **ppIP) {
	int i;
	struct IP **pIP = (struct IP **) IPPool;

	ASSERT(ppIP);

	for (i = 0; i < IPPoolSize; i++, pIP++) {
		if (gConfig.GateWay == (gConfig.Subnet + gConfig.StartingIP + i))
			/* Skip this element as Gateway must not be assigned */
			continue;
		
		if (!(*pIP)) {
			if (!(*pIP = newIP(i)))
				return DDRESOURCES;

			*ppIP = *pIP;
			return DDOK;
		} else {
			VALIDATE((*pIP), IP);

			if ((*pIP)->timeAllocated + (*pIP)->leaseTime < OslGetSeconds()) {
				// lease for the IP has expired, reissue it to another client

				*ppIP = *pIP;
				return DDOK;
			}
		}
	}

	return DDRESOURCES;
}

int IPLookup(unsigned long RequestedIP, struct IP **ppIP) {
	int i;
	struct IP **pIP = (struct IP **) IPPool;

	ASSERT(pIP);
	ASSERT(RequestedIP);
	ASSERT(ppIP);
	ASSERT(IPPoolSize);

	for (i = 0; i < IPPoolSize; i++, pIP++) {

		if (*pIP)
		{
			VALIDATE((*pIP), IP);
		}

		if (*pIP && (*pIP)->IPaddress == RequestedIP) {
			*ppIP = *pIP;
			DHCPLOG(("DHCP IPLookup: found IP 0x%08x\n", RequestedIP));
			return DDOK;
		}
	}

	DHCPLOG(("DHCP IPLookup: IP 0x%08x not found\n", RequestedIP));
	return DDNOTFOUND;
}

int IPLookupByMAC(char * RequestedMAC, struct IP **ppIP) {
	int i;
	struct IP **pIP = (struct IP **) IPPool;

	ASSERT(pIP);
	ASSERT(ppIP);
	ASSERT(IPPoolSize);

	for (i = 0; i < IPPoolSize; i++, pIP++) {

		if (*pIP)
		{
			VALIDATE((*pIP), IP);
		}

		if (*pIP && !memcmp(RequestedMAC, (const char *) &(*pIP)->ClientID, 6)) {
			*ppIP = *pIP;
			return DDOK;
		}
	}

	return DDNOTFOUND;
}

int IPValidate(struct parsedPacket *pp) {
	struct IP *pIP;

	if (!pp->RequestedIP)
		return DDINVALID;

	if (DDOK == IPLookup(ntohl(pp->RequestedIP), &pIP)) {
		if (!memcmp((const char *)pp->ClientID, (const char *) &pIP->ClientID, 6)) {
			// Assigned to another Client
			// Check if lease expired

			if ( (pIP->timeAllocated + pIP->leaseTime) < OslGetSeconds())
				return DDOK; // Lease expired, give to requestor

			// Lease still valid, another client owns the IP
			return DDINVALID;
		}
		// Requestor has lease on IP
		// Update the lease

		pIP->timeAllocated = OslGetSeconds();

		return DDOK;
	}

	if (!(DDOK == IPAllocate(&pIP))) {
		// out of IP Addresses
		return DDRESOURCES;
	}

	ASSERT(pp->ClientMAC);
	memcpy(&pIP->ClientID, pp->ClientMAC, 6);

	return DDOK;
}

//
int IsIPStillValid(struct parsedPacket *pp) {
	struct IP *pIP;
	unsigned char *pClientMAC;

	if (!pp->RequestedIP)
		return DDINVALID;
	pClientMAC = (pp->ClientMAC != NULL) ? pp->ClientMAC : pp->ClientID;
	if (pClientMAC == NULL)
		return DDINVALID;

	// locate the IP entry
	if (DDOK != IPLookup(ntohl(pp->RequestedIP), &pIP))
		return DDINVALID;

	// make sure this entry is not used by another
	if (memcmp(pClientMAC, &pIP->ClientID, sizeof(pIP->ClientID)) != 0)
		return DDINVALID;

	// check if lease expired
	if ( (pIP->timeAllocated + pIP->leaseTime) < OslGetSeconds())
		return DDINVALID; // Lease expired

	return DDOK;
	
}
