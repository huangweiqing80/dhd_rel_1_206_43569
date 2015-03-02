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
 * $Id: mac.c,v 1.8 2009-11-30 23:07:56 $
 */

#include <stdio.h>
#include <string.h>
#include <malloc.h>

#include "dhcp.h"
#include "config.h"
#include "osl.h"
#include "dhcpdebug.h"
#include "mac.h"

void *gMacLock = NULL;
struct MAC gMAC;

int MACInit() {

	DHCPLOG(("DHCP: enter MACInit\n"));

	memset(&gMAC, 0, sizeof(struct MAC));

	gMacLock = OslCreateLock();

	gMAC.magic = MAC_MAGIC;

	return DDOK;
}

int MACDeinit() {
	struct MAC *pMAC;
	struct MAC *pMACNext;

	ASSERT(gMAC.magic == MAC_MAGIC);

	DHCPLOG(("DHCP: enter MACDeinit\n"));

	OslLock(gMacLock);

	pMAC = gMAC.next;

	while (pMAC) {
		VALIDATE(pMAC, MAC);

		pMACNext = pMAC->next;

		VDEINIT(pMAC, MAC);
		free(pMAC);

		pMAC = pMACNext;
	}

	memset(&gMAC, 0, sizeof(struct MAC));	// gMAC.magic = (unsigned long) NULL;
	OslUnlock(gMacLock);

	OslDeleteLock(gMacLock);
	gMacLock = NULL;

	return DDOK;
}


int MACAllocate(unsigned char *mac, struct MAC **ppMAC) {
	struct MAC *pMAC;

	ASSERT(gMAC.magic == MAC_MAGIC);

	/* allocate a new one */
	pMAC = (struct MAC *) malloc(sizeof(struct MAC));

	if (!pMAC)
		return DDRESOURCES;

	memset(pMAC, 0, sizeof(struct MAC));

	VINIT(pMAC, MAC);

	memcpy(&pMAC->macAddress, mac, MACADDRESSLEN);

	/* add it to the end of the link-list */
	OslLock(gMacLock);

	if (gMAC.last) {
		VALIDATE(gMAC.last, MAC);

		gMAC.last->next = pMAC;
		pMAC->last = gMAC.last;
		pMAC->next = (struct MAC *) NULL;
	} else {
		gMAC.next = pMAC;
	}

	gMAC.last = pMAC;

	if (ppMAC)
		*ppMAC = pMAC;

	OslUnlock(gMacLock);

	return DDOK;
}

// Note: It is not safe to return a pointer to a MAC entry to the caller,
//       so caller should always pass a NULL as the 2nd parameter
//       e.g.
//            MACThreadSafeLookup(..., NULL);
int MACThreadSafeLookup(unsigned char *mac, struct MAC **ppMAC) {
	int rVal;

	OslLock(gMacLock);
	rVal = MACLookup(mac, ppMAC);
	OslUnlock(gMacLock);

	return rVal;
}

int MACLookup(unsigned char *mac, struct MAC **ppMAC) {
	struct MAC *pMAC;

	ASSERT(gMAC.magic == MAC_MAGIC);

	pMAC = gMAC.next;
/*	DHCPLOG(("  MACLookup: mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])); */

	while (pMAC) {
		VALIDATE(pMAC, MAC);
/*		DHCPLOG(("    MACLookup: cmp pMAC=%02x:%02x:%02x:%02x:%02x:%02x\n",
			pMAC->macAddress[0], pMAC->macAddress[1], pMAC->macAddress[2],
			pMAC->macAddress[3], pMAC->macAddress[4], pMAC->macAddress[5])); */
		if (memcmp(pMAC->macAddress, mac, MACADDRESSLEN) == 0) {
/*			DHCPLOG(("  MACLookup: found\n")); */
			if (ppMAC)
				*ppMAC = pMAC;
			return DDOK;
		}

		pMAC = pMAC->next;
	}

/*	DHCPLOG(("  MACLookup: not found\n")); */
	return DDNOTFOUND;
}

int MACFree(unsigned char *mac) {
	int rVal = DDOK;
	struct MAC *pMAC;

	OslLock(gMacLock);

	rVal = MACLookup(mac, &pMAC);

	if (rVal != DDOK)
		goto done;

	if (gMAC.next == pMAC)
		gMAC.next = pMAC->next;

	if (gMAC.last == pMAC)
		gMAC.last = pMAC->last;

	if (pMAC->last) {
		VALIDATE(pMAC->last, MAC);

		pMAC->last->next = pMAC->next;
	}

	if (pMAC->next) {
		VALIDATE(pMAC->next, MAC);

		pMAC->next->last = pMAC->last;
	}

	VDEINIT(pMAC, MAC);
	free(pMAC);

done:
	OslUnlock(gMacLock);
	return rVal;
}
