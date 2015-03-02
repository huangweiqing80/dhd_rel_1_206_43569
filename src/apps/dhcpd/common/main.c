/*
 * Broadcom DHCP Server
 * Main, top level routines
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: main.c,v 1.31 2011-01-24 15:13:09 $
 */
#include <stdio.h>
#include <stdarg.h>
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

/* flag to control DHCP_main() exit */
int gDHCPStatus = 0;			

static unsigned char broadcastMacAddress[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

/* Dynamically registered log redirection function */
static DHCP_LOG_OUTPUT_FN logOutputFn = NULL;

/* Redirect debug logs to the given function */
void
DHCP_Redirect_Logs(DHCP_LOG_OUTPUT_FN fn)
{
	logOutputFn = fn;
}

/* Print a debug log */
void LOGprintf(const char *fmt, ...)
{
	va_list argp;
	char logstr[512];

	va_start(argp, fmt);
	strncpy(logstr, "DHCP: ", sizeof(logstr));
#if defined(TARGETOS_symbian)
	// Fix second parameter
	vsnprintf(logstr + 6, sizeof(logstr)-6, fmt, argp);
#else
	vsnprintf(logstr + 6, sizeof(logstr), fmt, argp);
#endif
	va_end(argp);

	if (logOutputFn != NULL) {
		logOutputFn(0, logstr);
	} else {
		printf("%s", logstr);
	}
}

void DHCP_Register_Mac_addr(void *Handle, unsigned char *mac) {
	struct MAC *pMac;

	ASSERT((void *)DHCPHANDLECOOKIE == Handle);

	// check if the addr has been registered
	if (DDOK == MACThreadSafeLookup(mac, NULL))
	{
		DHCPLOG(("DHCP_Register_Mac_addr: %02x:%02x:%02x:%02x:%02x:%02x - no action, already registered\n",
			mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]));

		return;
	}

	DHCPLOG(("DHCP_Register_Mac_addr: %02x:%02x:%02x:%02x:%02x:%02x\n",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]));
	MACAllocate(mac, &pMac);

	return;
}

void DHCP_Deregister_Mac_addr(void *Handle, unsigned char *mac) {

	ASSERT((void *)DHCPHANDLECOOKIE == Handle);

	DHCPLOG(("DHCP_Deregister_Mac_addr: %02x:%02x:%02x:%02x:%02x:%02x\n",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]));
	MACFree(mac);
	
	return;
}

void *DHCP_init(unsigned long subnet, unsigned char starting_ip, unsigned char ending_ip, 
                unsigned long gateway, unsigned long dns) 
{
	int rVal;
	gDHCPStatus = 0;
	
	DHCPLOG(("DHCP_init: subnet=0x%x, starting_ip=%d, ending_ip=%d gateway=0x%8x dns=0x%8x\n",
             subnet, starting_ip, ending_ip, gateway, dns));

	InitDHCPGlobalConfig(subnet, starting_ip, ending_ip, gateway, dns);

	if (DDOK != (rVal = IPInit()))
		return (void *) NULL;

	if (DDOK != (rVal = MACInit())) {
		IPDeinit();
		return (void *) NULL;
	}

	if (DDOK != (rVal = socketInit())) {
		MACDeinit();
		IPDeinit();
		return (void *) NULL;
	}

	return (void *) DHCPHANDLECOOKIE;
}


void *DHCP_Shutdown() {
	gDHCPStatus |= DS_EXITPENDING;
	
	DHCPLOG(("DHCP_Shutdown: begin\n"));
	while (gDHCPStatus & DS_EXITPENDING)
#if defined(WIN32)
		Sleep(1000);
#elif defined(TARGETOS_symbian)
		osl_delay(100000);
#else
		sleep(1);
#endif /* WIN32 */
	DHCPLOG(("DHCP_Shutdown: end\n"));

	return DDOK;
}

void *DHCP_Unload() {
	DHCPLOG(("DHCP_Unload: begin\n"));

	MACDeinit();
	IPDeinit();
	socketDeinit();

	DHCPLOG(("DHCP_Unload: end\n"));

	return DDOK;
}

void DHCP_main(void *Handle) {
	struct Packet *pPkt;
	struct parsedPacket *pp;
	struct IP *pIP;

	ASSERT((void *)DHCPHANDLECOOKIE == Handle);
	DHCPLOG(("DHCP_main: enter\n"));

	// make sure the socket is bound to the interface
	socketBind();

	// TODO: Add Lookup by ClientID, copy ClientID in IP struct, work out clean way to do this
	// TODO: Don't commit IP until ACK is sent. (short lease for offers or add commited flag to IP struct)

	while (1) {
		if (DDOK == socketGet(&pPkt)) {
			
			VALIDATE(pPkt, PACKET);

			if (DDOK != parsePacket(pPkt, &pp))
				goto next2;

			VALIDATE(pp, PARSEDPACKET);

			DHCPLOG(("DHCP_main: lookup MAC %02x:%02x:%02x:%02x:%02x:%02x" 
				" type=%d tid=0x%x\n",
				pp->ClientMAC[0], pp->ClientMAC[1], pp->ClientMAC[2],
				pp->ClientMAC[3], pp->ClientMAC[4], pp->ClientMAC[5],
				pp->packetType, *pp->TransactionID));
			if (DDOK != MACThreadSafeLookup(pp->ClientMAC, NULL)) {
				if (DDOK != MACThreadSafeLookup(broadcastMacAddress, NULL)) {
					if (PKT_DISCOVER == pp->packetType) {
						// When DHCP DISCOVER is received too rapidly, we don't respond to
						// this frame as the Mac Address is not yet registered by p2pconnect
						// because of the polling in p2papi_bss_wait_for_join.
						// The consequence is a retry of DHCP DISCOVER frame in DHCP client
						// introducing delay for getting IP address
					    DHCP_Register_Mac_addr((void *)DHCPHANDLECOOKIE, pp->ClientMAC);
					}
					else {
						DHCPLOG(("DHCP_main: MAC not allowed\n"));
						goto next;				
					}
				} else {
					DHCPLOG(("DHCP_main: bcast MAC allowed\n"));
				}
			} else {
				DHCPLOG(("DHCP_main: MAC allowed\n"));
			}

			if (PKT_DISCOVER == pp->packetType) {
				DHCPLOG(("DHCP_main: rx DHCPDISCOVER requestedIP=0x%08x\n",
					(pp->RequestedIP == 0) ? 0 : ntohl(pp->RequestedIP)));

				if (DDOK != IPLookupByMAC((char *)pp->ClientMAC, &pIP))				
					if (!(pp->RequestedIP)  || (DDOK != IPLookup(ntohl(pp->RequestedIP), &pIP)))
						if (DDOK != IPAllocate(&pIP)) {
							DHCPLOG(("DHCP_main: IPAllocate failed\n"));
							goto next;
						}

				VALIDATE(pIP, IP);
				
				memcpy(&pIP->ClientID, pp->ClientMAC, 6);

				// We have valid IP, Offer to client

				if (DDOK != SendOfferPkt(pp, pIP))
					goto next;

			} else if (PKT_REQUEST == pp->packetType) {
				DHCPLOG(("DHCP_main: rx DHCPREQUEST requestedIP=0x%08x clientIP=0x%08x\n",
					(pp->RequestedIP == 0) ? 0 : ntohl(pp->RequestedIP),
					ntohl(*(pp->ClientIP))));
				if (!pp->RequestedIP) {
					// Request packet without a specific IP address requested in options field
					// (e.g. from XP client when user clicks Repair button in network options dialog)
					// see if we can ACK based on existing lease from ClientIP field
					if (DDOK != IPLookup(ntohl(*(pp->ClientIP)), &pIP)) {
						DHCPLOG(("DHCP_main: clientIP not found, ignored.\n"));
						DHCPLOG(("DHCP_main: tx DHCPNAK (in response to DHCPREQUEST) to client\n"));
						SendNAKPkt(pp);
						goto next;
					}
				} else if (DDOK != IPLookup(ntohl(pp->RequestedIP), &pIP)) {
					DHCPLOG(("DHCP_main: requestedIP not found, ignored.\n"));
					DHCPLOG(("DHCP_main: tx DHCPNAK (in response to DHCPREQUEST) to client\n"));
					SendNAKPkt(pp);
					goto next;
				}
				VALIDATE(pIP, IP);

				// We have valid IP, ACK the client

				DHCPLOG(("DHCP_main: tx DHCPACK (in response to DHCPREQUEST) to client, IP=0x%08x\n",
						htonl(pIP->IPaddress)));
				SendACKPkt(pp, pIP);
			} else if (PKT_DECLINE == pp->packetType) {
				//
				// Client declines offered IP
				// Most likely we were restarted and some of the IP's in our pool are in use on the network
				// Mark the IP in use and allow the client to send another discover to get a different IP address
				// from our pool.
				//
				DHCPLOG(("DHCP_main: rx DHCPDECLINE reqIP=0x%08x",
					(pp->RequestedIP == 0) ? 0 : htonl(pp->RequestedIP)));

				if (DDOK == IPLookup(ntohl(pp->RequestedIP), &pIP)) {
					// Mark the IP in use by broadcast mac (something the client will not ever use for src MAC).
					memcpy(&pIP->ClientID, broadcastMacAddress, 6);
				}
			}
			else
			{
				DHCPLOG(("DHCP_main: rx %d packet, ingore it\n", pp->packetType));
			}
next:
			parseFree(pp);
next2:
			packetFree(pPkt);
		}

		if (gDHCPStatus & DS_EXITPENDING) {
#ifdef TARGETOS_symbian
			socketStop();
#endif			
			gDHCPStatus &= ~DS_EXITPENDING;
			break;
		}
	}
	DHCPLOG(("DHCP_main: exit\n"));
}
