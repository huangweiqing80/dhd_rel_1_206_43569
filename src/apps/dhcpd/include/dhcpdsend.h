/*
 * Broadcom DHCP Server
 * DHCP send definitions. 
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: dhcpdsend.h,v 1.4 2009-10-06 18:03:51 $
 */
void FixAllSendOptionsTemplate();

int SendOfferPkt(struct parsedPacket *pp, struct IP *pIP);
int SendACKPkt(struct parsedPacket *pp, struct IP *pIP);
int SendACKInformPkt(struct parsedPacket *pp, struct IP *pIP);
int SendNAKPkt(struct parsedPacket *pp);
