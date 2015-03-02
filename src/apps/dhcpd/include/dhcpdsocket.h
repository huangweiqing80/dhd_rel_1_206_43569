/*
 * Broadcom DHCP Server
 * DHCP socket definitions. 
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: dhcpdsocket.h,v 1.5 2011-01-24 15:13:09 $
 */

int socketInit();
int socketDeinit();
int socketGet(struct Packet **p);
int socketSend(struct Packet *p);
int socketBind();
