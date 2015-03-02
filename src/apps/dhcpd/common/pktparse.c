/*
 * Broadcom DHCP Server
 * DHCP packet parsing routines
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: pktparse.c,v 1.12 2009-12-23 15:58:01 $
 */

#include <assert.h>
#include <string.h>
#include <malloc.h>

#include "dhcp.h"
#include "packet.h"
#include "pktparse.h"
#include "ippool.h"
#include "config.h"
#include "dhcpdebug.h"
#include "osl.h"

#ifdef TARGETENV_android
	unsigned int req_ip; 
#endif /* TARGETENV_android */

static int parseOptions(struct parsedPacket *pp, unsigned char *pOpts, int optBytesRemaining) {
	int maxOpts = 255;	// Add max count or malformed packet could make us loop forever

	ASSERT(optBytesRemaining < MAXBUFFERSIZE);
	
	// Initialize the variables
	pp->RequestedIP = 0;
	pp->optServerID = 0;

	while (optBytesRemaining > 0 && maxOpts--) {
		int optLen = 0;
		int bFixedLengthOption;	
		int optType = *pOpts++;
		optBytesRemaining--;

		// check for a fixed-length option
		// Only options 0 and 255 are fixed length. It contains only a tag octet, no data associated
		bFixedLengthOption = (optType == OPT_END || optType == OPT_PADDING);	
		
		if (!bFixedLengthOption)
		{	// get the 'length' for a variable-length option
			optLen = *pOpts++;
			optBytesRemaining--;
		}

		switch (optType) {
			case OPT_REQUESTDIP:
				if (optLen != 4)
					return DDBADPACKET;

				memcpy(&pp->RequestedIP, pOpts, sizeof(unsigned long));

				DHCPLOG(("DHCP : found DHCP RequestdIP option\n"));
				break;

			case OPT_DHCPMESSAGE:
				if (optLen != 1)
					return DDBADPACKET;

				if (*pOpts == DHCP_MSG_TYPE_DISCOVER)
					pp->packetType = PKT_DISCOVER;
				else if (*pOpts == DHCP_MSG_TYPE_REQUEST)
					pp->packetType = PKT_REQUEST;
				else if (*pOpts == DHCP_MSG_TYPE_DECLINE)
					pp->packetType = PKT_DECLINE;
				else if (*pOpts == DHCP_MSG_TYPE_INFORM)
					pp->packetType = PKT_INFORM;
				else
					DHCPLOG(("DHCP: ignore parseOption msg(%d)\n", *pOpts));
				break;

			case OPT_END:
				return DDOK;

			case OPT_SERVER_ID:
				if (optLen == 4)
					memcpy(&pp->optServerID, pOpts, (sizeof(unsigned long)));

				break;
			case OPT_PADDING:	// ignore padding
					DHCPLOG(("DHCP : ignore padding option\n"));
				break;
			default:
					DHCPLOG(("DHCP: ignore parseOption option parameter(%d)\n", optType));
				break;
		}

		// move to the next option
		if (!bFixedLengthOption)
		{
			// adjust for 'variable-length' option
			pOpts += optLen;
			optBytesRemaining -= optLen;
		}
	}

	return DDOK;
}

int parseFree(struct parsedPacket *pp) {
	ASSERT(pp);

	VDEINIT(pp, PARSEDPACKET);

	free(pp);
	return DDOK;
}

int parsePacket(struct Packet *p, struct parsedPacket **pp) {
	struct bootp_frame *pRequest;
	unsigned char *pOpts;
	int optBytesRemaining;


	ASSERT(p && pp);

	*pp = NULL;

	if (p->Size < sizeof(struct bootp_frame))
		return DDUNKNOWN;

	pRequest = (struct bootp_frame *) p->Data;
	pOpts = p->Data + sizeof(struct bootp_frame);
	optBytesRemaining = p->Size - sizeof(struct bootp_frame);

	if (optBytesRemaining < 4 || *((unsigned long *) pOpts) != DHCPMAGICCOOKIE)
		return DDUNKNOWN;

	pOpts += sizeof(unsigned long);
	optBytesRemaining -= sizeof(unsigned long);

	// We have a candidate DHCP pkt, allocate parsedPacket struct and process the options

	*pp = (struct parsedPacket *) malloc(sizeof (struct parsedPacket));

	if (!*pp)
		return DDRESOURCES;

	memset(*pp, 0, sizeof(struct parsedPacket));

	VINIT((*pp), PARSEDPACKET);

	(*pp)->packetType = PKT_UNKNOWN;
	(*pp)->TransactionID = &pRequest->xid;
	(*pp)->ClientIP = &pRequest->client_ip;
	(*pp)->ClientMAC = (unsigned char *)&pRequest->client_mac;

	(*pp)->Packet = p;	/* save a reference to the original client msg */

	if (DDOK != parseOptions(*pp, pOpts, optBytesRemaining))
		goto error;

	return DDOK;

error:
	parseFree(*pp);
	*pp = NULL;
	return DDUNKNOWN;
}
