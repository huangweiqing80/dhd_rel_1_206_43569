/*
 * Broadcom DHCP Server
 * DHCP packet parsing definitions
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: pktparse.h,v 1.6 2009-12-23 15:58:59 $
 */

#define PKT_UNKNOWN	0
#define PKT_DISCOVER	1
#define PKT_REQUEST		2
#define PKT_DECLINE		3
#define PKT_INFORM		8

#define OPT_DHCPMESSAGE		53
#define OPT_REQUESTDIP		50
#define OPT_END				255
#define OPT_PADDING			0
#define OPT_SERVER_ID		54

#define PARSEDPACKET_MAGIC	0xfd212acf

struct parsedPacket {
	int packetType;
	unsigned long RequestedIP;			// 'requested IP addr' optional parameter
	unsigned char *ClientID;
	unsigned char *ClientMAC;
	unsigned long *ClientIP;			// client fill in client-IP address
	unsigned long *TransactionID;
	unsigned long optServerID;			// 'ServerID' optional parameter
	struct Packet *Packet;
	unsigned long magic;
};

int parsePacket(struct Packet *p, struct parsedPacket **pp);
int parseFree(struct parsedPacket *pp);
