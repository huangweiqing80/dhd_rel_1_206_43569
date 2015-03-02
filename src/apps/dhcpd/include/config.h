/*
 * Broadcom DHCP Server
 * DHCP Configuration
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: config.h,v 1.5 2010-05-19 15:12:06 $
 */


struct configuration {
	unsigned long Subnet;
	unsigned long GateWay;
	unsigned long DNS1;
	unsigned long DNS2;
	unsigned long DNS3;
	unsigned char StartingIP;
	unsigned char EndingIP;
	unsigned long LeaseTime;
};

extern struct configuration gConfig;

void InitDHCPGlobalConfig(unsigned long subnet, unsigned char starting_ip, unsigned char ending_ip,
                          unsigned long, unsigned long dns);
