/*
 * Broadcom DHCP Server
 * DHCP send routines. 
 * Create and emit DHCP packets based on parsed requests from clients.
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: dhcpsend.c,v 1.15 2010-09-10 08:22:25 $
 */

#include <stdio.h>
#include <string.h>
#include <malloc.h>
#ifdef WIN32
#include <winsock.h>
#endif

#include "dhcp.h"
#include "packet.h"
#include "pktparse.h"
#include "ippool.h"
#include "dhcpdsocket.h"
#include "dhcpdsend.h"
#include "config.h"
#include "dhcpdebug.h"
#include "osl.h"

// Fill out options fields in templates
// TODO: Add DNS & Router to config struct
// TODO: determine IP address. (from sockaddr or ???)
// Note: ServerID, DNS & Router are temporary set to default 192.168.16.1
//       These fields will be adjusted at DHCP_init() time when a 'subnet' is specified
// 
unsigned char AckOptionsTemplate[] = {
/* code, size, data */
0x35, 0x01, 0x05,						// DHCP ACK !! (in response to DHCPREQUEST)
0x36, 0x04, 0xc0, 0xa8, 0x10, 0x01,		// Server ID 
0x33, 0x04, 0x00, 0x03, 0xf4, 0x80,		// Lease time (3 days)
0x01, 0x04, 0xff, 0xff, 0xff, 0x00,		// Subnet Mask, 255.255.255.0
0x06, 0x04, 0xc0, 0xa8, 0x10, 0x01,		// Domain name server, 192.168.16.1
0x03, 0x04, 0xc0, 0xa8, 0x10, 0x01,		// Router, 192.168.16.1
0xff };									// End

unsigned char AckInformOptionsTemplate[] = {
/* code, size, data */
0x35, 0x01, 0x05,						// DHCP ACK !! (in response to DHCPINFORM)
0x36, 0x04, 0xc0, 0xa8, 0x10, 0x01,		// Server ID 
0x01, 0x04, 0xff, 0xff, 0xff, 0x00,		// Subnet Mask, 255.255.255.0
0x06, 0x04, 0xc0, 0xa8, 0x10, 0x01,		// Domain name server, 192.168.16.1
0x03, 0x04, 0xc0, 0xa8, 0x10, 0x01,		// Router, 192.168.16.1
0xff };									// End

unsigned char NakOptionsTemplate[] = {
0x35, 0x01, 0x06,						// DHCP NAK !!
0x36, 0x04, 0xc0, 0xa8, 0x10, 0x01,		// Server ID 
0xff };									// End

unsigned char OfferOptionsTemplate[] = {
0x35, 0x01, 0x02,						// DHCP OFFER !!
0x36, 0x04, 0xc0, 0xa8, 0x10, 0x01,		// Server ID
0x33, 0x04, 0x00, 0x03, 0xf4, 0x80,		// IP Address Lease time 3 days (in seconds)
0x01, 0x04, 0xff, 0xff, 0xff, 0x00,		// Subnet Mask, 255.255.255.0
0x06, 0x04, 0xc0, 0xa8, 0x10, 0x01,		// Domain name server , 192.168.16.1
0x03, 0x04, 0xc0, 0xa8, 0x10, 0x01,		// Router, 192.168.16.1
0xff };									// End

//
// Fix one option template for sending to clients
//
void FixSendOptionTemplate(unsigned char *pOptionTemplate, int optBytes)
{
	unsigned long serverIP = htonl(gConfig.GateWay);	// e.g. =0xc0a81001 = 192.168.16.1
	unsigned long dnsIP =  htonl(gConfig.DNS1);
	unsigned long networkMask = 0;
	unsigned char optType = *pOptionTemplate++;
	int i;

	// Temp fix.
	// DHCP API must be changed to pass network mask and handle all network masks
	for (i=3 ; i>0 ; i--) {
		if (gConfig.Subnet & (0xFF << (8*i)))
			networkMask += 0xFF << 8*i ;
	}
	networkMask =  htonl(networkMask);

	while (optType != 0xff)
	{
		int optLen = *pOptionTemplate++;

		if ((optType == 0x36) ||		// ServerID
		    (optType == 0x03)) {		// Router
			memcpy(pOptionTemplate, &serverIP, sizeof(unsigned long));
		}
		if (optType == 0x06) {			// DNS
			memcpy(pOptionTemplate, &dnsIP, sizeof(unsigned long));
		}
		if (optType == 0x01) {			// networkMask
			memcpy(pOptionTemplate, &networkMask, sizeof(unsigned long));
		}

		pOptionTemplate += optLen;

		optType = *pOptionTemplate++;
	}
}

//
// Fix all Options Template for sending to clients
//
void FixAllSendOptionsTemplate()
{
	
	FixSendOptionTemplate(AckOptionsTemplate, sizeof(AckOptionsTemplate));

	FixSendOptionTemplate(AckInformOptionsTemplate, sizeof(AckInformOptionsTemplate));

	FixSendOptionTemplate(NakOptionsTemplate, sizeof(NakOptionsTemplate));

	FixSendOptionTemplate(OfferOptionsTemplate, sizeof(OfferOptionsTemplate));
}

/*
 * setup a common reply-packet header 
 * input:
 *        pp -- point to a 'parsed' Packet received from the client
 *        p  -- point to a Packet that will be sent to the client
 */
void InitReplyPacket(struct parsedPacket *pp, struct Packet *p) {
	struct dhcp_bootp_frame *pb;

	pb = (struct dhcp_bootp_frame *) p->Data;
	if (pb == (struct dhcp_bootp_frame *) NULL)	// caller should have allocated the buffer
		return;				

	memset(p->Data, 0, p->maxSize);				// first, reset all fields to zero

	pb->msg_type = 2;		// BOOTREPLY 
	pb->hardware_type = 1;	// ethernet
	pb->addr_len = 6;		// ethernet address length
	pb->hops = 0;

	pb->magic = DHCPMAGICCOOKIE;

	pb->your_ip = 0;

	// set fields from the original client's message
	if (pp->Packet != NULL)
	{
		struct bootp_frame *pClientMsg = (struct bootp_frame *)pp->Packet->Data;	/* original msg from clients */
		if (pClientMsg)
		{
			pb->xid = pClientMsg->xid;				// transaction id
			pb->relay_ip = pClientMsg->relay_ip;	// relay agent IP address
			pb->flags = pClientMsg->flags;
			memcpy(pb->client_mac, pClientMsg->client_mac, sizeof(pb->client_mac));
		}
	}

	// temp set the size, caller should adjust this later
	p->Size = sizeof(struct dhcp_bootp_frame);

	return;
}

/* 
  Send 'DHCP OFFER' message to client
*/
int SendOfferPkt(struct parsedPacket *pp, struct IP *pIP) {
	int rVal;
	struct Packet *p = NULL;
	struct dhcp_bootp_frame *pb;

	rVal = packetAlloc(sizeof(struct dhcp_bootp_frame) + sizeof(OfferOptionsTemplate), &p);

	if (DDOK != rVal) {
		DHCPLOG(("DHCP: SendOfferPkt - alloc failed!\n"));
		return rVal;
	}

	VALIDATE(p, PACKET);

	pb = (struct dhcp_bootp_frame *) p->Data;

	ASSERT(pb);

	// format the message to be sent to the client
	InitReplyPacket(pp, p);

	pb->your_ip = htonl(pIP->IPaddress);	// IP address offered to client

	// set 'Options' fields
	memcpy((void *) (pb + 1), OfferOptionsTemplate, sizeof(OfferOptionsTemplate));
	p->Size = sizeof(struct dhcp_bootp_frame) + sizeof(OfferOptionsTemplate);

	rVal = socketSend(p);

	DHCPLOG(("DHCP: tx DHCPOFFER IP=0x%08x to %02x:%02x:%02x:%02x:%02x:%02x, rVal/status=%d\n", 
			pIP->IPaddress, 
			pb->client_mac[0], pb->client_mac[1], pb->client_mac[2],
			pb->client_mac[3], pb->client_mac[4], pb->client_mac[5],
			rVal));

	packetFree(p);

	return rVal;
}

/*
  Send DHCP ACK message to client in response to client's DHCP REQUEST message
*/
int SendACKPkt(struct parsedPacket *pp, struct IP *pIP) {
	int rVal;
	struct Packet *p = NULL;
	struct dhcp_bootp_frame *pb;
	struct bootp_frame *pClientMsg = NULL;

	rVal = packetAlloc(sizeof(struct dhcp_bootp_frame) + sizeof(AckOptionsTemplate), &p);
	if (DDOK != rVal) {
		DHCPLOG(("DHCP: SendAckPkt - alloc failed!\n"));
		return rVal;
	}
	VALIDATE(p, PACKET);

	pb = (struct dhcp_bootp_frame *) p->Data;
	ASSERT(pb);

	// format the message to be sent to the client
	InitReplyPacket(pp, p);

	pb->your_ip = htonl(pIP->IPaddress);	// IP address assigned to client

	// get the client-provided IP address from the client-message
	if (pp->Packet)
		pClientMsg = (struct bootp_frame *) pp->Packet->Data;
	if (pClientMsg)
	{
		pb->client_ip = pClientMsg->client_ip;
	}

	// set 'Options' fields
	p->Size = sizeof(struct dhcp_bootp_frame) + sizeof(AckOptionsTemplate);
	memcpy((void *) (pb + 1), AckOptionsTemplate, sizeof(AckOptionsTemplate));

	rVal = socketSend(p);

	DHCPLOG(("DHCP: tx DHCPACK (respond to DHCPREQUEST) IP=0x%08x to %02x:%02x:%02x:%02x:%02x:%02x, rVal/status=%d\n", 
			pIP->IPaddress, 
			pb->client_mac[0], pb->client_mac[1], pb->client_mac[2],
			pb->client_mac[3], pb->client_mac[4], pb->client_mac[5],
			rVal));

	packetFree(p);

	return rVal;
}

/*
  Send DHCP ACK message to client in response to client's DHCP INFORM message
*/
int SendACKInformPkt(struct parsedPacket *pp, struct IP *pIP) {
	int rVal;
	struct Packet *p = NULL;
	struct dhcp_bootp_frame *pb;

	rVal = packetAlloc(sizeof(struct dhcp_bootp_frame) + sizeof(AckInformOptionsTemplate), &p);
	if (DDOK != rVal) {
		DHCPLOG(("DHCP: SendAckiNFORMPkt - alloc failed!\n"));
		return rVal;
	}
	VALIDATE(p, PACKET);

	pb = (struct dhcp_bootp_frame *) p->Data;
	ASSERT(pb);

	// format the message to be sent to the client
	InitReplyPacket(pp, p);

	// according to the RFC2131 (Mar 1997, page 33), MUST NOT send a lease expiration time
	// and should not fill in 'yiaddr'.

	// set 'Options' fields
	p->Size = sizeof(struct dhcp_bootp_frame) + sizeof(AckInformOptionsTemplate);
	memcpy((void *) (pb + 1), AckInformOptionsTemplate, sizeof(AckInformOptionsTemplate));
	
	rVal = socketSend(p);

	DHCPLOG(("DHCP: tx DHCPACK (respond to DHCPINFORM) IP=0x%08x to %02x:%02x:%02x:%02x:%02x:%02x, rVal/status=%d\n", 
			pIP->IPaddress, 
			pb->client_mac[0], pb->client_mac[1], pb->client_mac[2],
			pb->client_mac[3], pb->client_mac[4], pb->client_mac[5],
			rVal));

	packetFree(p);

	return rVal;
}

/*
  Send DHCP NAK message to client
*/
int SendNAKPkt(struct parsedPacket *pp) {
	int rVal;
	struct Packet *p;
	struct dhcp_bootp_frame *pb;

	rVal = packetAlloc(sizeof(struct dhcp_bootp_frame) + sizeof(NakOptionsTemplate), &p);
	if (DDOK != rVal) {
		DHCPLOG(("DHCP: SendNAKPkt - alloc failed!\n"));
		return rVal;
	}
	VALIDATE(p, PACKET);

	pb = (struct dhcp_bootp_frame *) p->Data;
	ASSERT(pb);

	// format the message to be sent to the client
	InitReplyPacket(pp, p);

	// set 'options' fields
	memcpy((void *) (pb + 1), NakOptionsTemplate, sizeof(NakOptionsTemplate));
	p->Size = sizeof(struct dhcp_bootp_frame) + sizeof(NakOptionsTemplate);

	rVal = socketSend(p);

	DHCPLOG(("DHCP: tx DHCPNAK to %02x:%02x:%02x:%02x:%02x:%02x, rVal=%d\n", 
			pb->client_mac[0], pb->client_mac[1], pb->client_mac[2],
			pb->client_mac[3], pb->client_mac[4], pb->client_mac[5],
			rVal));

	packetFree(p);

	return rVal;
}
