/* 
 * Broadcom DHCP Server 
 * Test.c Standalone test for linux
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: test.c,v 1.2 2009-08-08 01:50:10 $
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
#include "mac.h"

unsigned char broadcastMacAddress[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

main() {                
        void *DHCPHandle;
                
        DHCPHandle = (void *) DHCP_init(NULL, NULL, NULL);

        printf("Setting accept any mac address\n");
	MACAllocate(broadcastMacAddress, NULL);
 
        DHCP_main(DHCPHandle);
}   
