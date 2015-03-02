/*
 * Broadcom DHCP Server
 * Socket routines for Linux
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: linuxsocket.c,v 1.9 2010-04-01 17:36:33 $
 */


#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "dhcp.h"
#include "osl.h"
#include "packet.h"
#include "dhcpdebug.h"

struct sockaddr SenderAddr;
struct sockaddr_in serverAddr;;
struct sockaddr_in serv_addr;

int hSocket;

int socketBind() {
    int bcast = 1;

    // Set up the socket.
    bind( hSocket, (const struct sockaddr *) &serverAddr , sizeof( serverAddr ) );

	// Set broadcast (or sends will fail)
    if(setsockopt(hSocket, SOL_SOCKET, SO_BROADCAST, (const char *)&bcast, sizeof(bcast)) < 0){
      perror("setsockopt");
    }

    return DDOK;


}

int socketInit() {
	int SenderAddrSize = sizeof(struct sockaddr_in);

    // Create a socket and store the handle to it.
    hSocket = socket( AF_INET, SOCK_DGRAM, 0 );
	if (hSocket < 0) {
		DHCPLOG(("DHCP: socket create failed with %d\n", hSocket));
		return DDFAIL;
	}
 
    // RECEIVE related variables
	//
	// Socket address for receive
    // serverAddr = { 0 };
	memset(&serverAddr, '\0', sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons( DHCP_RECV_SOCKET );
    serverAddr.sin_addr.s_addr = INADDR_ANY;

	// Receive buffer & pointers
    // unsigned char buffer[1024] = { 0 };
	// struct bootp_frame *pRequest;

	// SEND related variables
	//
	// Socket address for send.
	memset(&serv_addr, '\0', sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
	serv_addr.sin_port = htons(DHCP_SEND_SOCKET); 

	// Send buffer & pointers
	// struct bootp_frame *pOffer = (struct bootp_frame *) dhcp_offer_template;
	// struct bootp_frame *pAck = (struct bootp_frame *) dhcp_ack_template;


	return DDOK;
}

int socketDeinit() {
	close(hSocket);
	return DDOK;
}

int socketGet(struct Packet **p) {
	int rVal;
	int SenderAddrSize = sizeof(struct sockaddr_in);
	fd_set fd;
	struct timeval tm;


	ASSERT(p);

	if (DDOK != (rVal = packetAlloc(MAXBUFFERSIZE, p)))
		return rVal;

	/* sleep one second then check for data or shutdown request. */
	/* if no data or shutdown, sleep and check again */

	for (rVal = 0; !rVal; ) {
		FD_ZERO(&fd);
		FD_SET(hSocket, &fd);


		tm.tv_sec = 1;
		tm.tv_usec = 0;

		rVal = select(hSocket + 1, &fd, NULL, NULL, &tm);

		if (gDHCPStatus & DS_EXITPENDING)
			return DDSHUTDOWN;
	}


	rVal = recvfrom( hSocket, (char *) (*p)->Data, (*p)->maxSize, 0, ( struct sockaddr *) &SenderAddr, &SenderAddrSize );

	if (rVal < 0) {
		packetFree(*p);
		return DDFAIL;
	}

	(*p)->Size = rVal;

	return DDOK;
}

int socketSend(struct Packet *p) {
	int rVal;

	ASSERT(p);

	rVal = sendto( hSocket, (const char *) p->Data, p->Size, 0,(struct sockaddr *)&serv_addr, sizeof(serv_addr));

	if (rVal < 0) {
		DHCPLOG(("socketSend: sendto failed, rVal=%d\n", rVal));
#ifdef TARGETENV_android
		perror("sendto");
#endif /* TARGETENV_android */
		return DDFAIL;
	}

	return DDOK;
}
