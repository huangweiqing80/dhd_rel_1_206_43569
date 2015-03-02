/*
 * Broadcom WPS Enrollee platform dependent hook function
 *
 * This file is the linux specific implementation of the OS hooks
 * necessary for implementing the wps_enr.c reference application
 * for WPS enrollee code. It is mainly the implementation of eap transport
 * but also add basic OS layer interface (should it be renamed like linux_osl ??)
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wps_linux_hooks.c 470127 2014-04-14 04:14:51Z $
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <errno.h>

#include <tutrace.h>
#include <wpserror.h>
#include <wlioctl.h>
#include <portability.h>
#include <wps_staeapsm.h>
#include <wps_enrapi.h>
#include <wps_enr_osl.h>
#include <wpscommon.h>

#define ETH_8021X_PROT 0x888e

#ifdef _TUDEBUGTRACE
void print_buf(unsigned char *buff, int buflen);
#endif

#ifdef TARGETENV_android
char* ether_ntoa(const struct ether_addr *addr)
{
	return "";
}
#else
extern char* ether_ntoa(const struct ether_addr *addr);
#endif

static uint32 Eap_OSInit(uint8 *bssid);
static uint32 Eap_ReadData(char * dataBuffer, uint32 * dataLen, struct timeval timeout);
static uint32 Eap_SendDataDown(char * dataBuffer, uint32 dataLen);

/* For testing ... should be set to real peer value (bssid) */
static uint8 peer_mac[6] = {0, 0x90, 0xac, 0x6d, 0x9, 0x48};

static int eap_fd = -1; /* descriptor to raw socket  */
static int ifindex = -1; /* interface index */
static char if_name[IFNAMSIZ] = "";

int
wps_osl_get_ifname(char *ifname)
{
	if (!if_name[0]) {
		printf("Wireless Interface not specified.\n");
		return WPS_ERR_SYSTEM;
	}
	strcpy(ifname, if_name);
	return 0;
}


/* we need to set the ifname before anything else. */
int
wps_osl_set_ifname(char *ifname)
{
	wps_strncpy(if_name, ifname, sizeof(if_name));
	return 0;
}

int
wps_osl_get_mac(uint8 *mac)
{
	struct ifreq ifr;
	int ret = 0;
	int s;

	if (!if_name[0]) {
		printf("Wireless Interface not specified.\n");
		return WPS_ERR_SYSTEM;
	}

	/* Open a raw socket */
	if ((s = socket (AF_INET, SOCK_DGRAM, 0)) < 0) {
		printf("socket open failed\n");
		return WPS_ERR_SYSTEM;
	}

	memset(&ifr, 0, sizeof(ifr));
	wps_strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
	if ((ret = ioctl(s, SIOCGIFHWADDR, &ifr)) < 0) {
		printf("ioctl  to get hwaddr failed.\n");
		close(s);
		return WPS_ERR_SYSTEM;
	}

	/* Copy the result back */
	memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

	close(s);
	return ret;
}

int
wps_osl_init(char *bssid)
{
	return Eap_OSInit((uint8 *)bssid);
}

void
wps_osl_deinit()
{
	if (eap_fd != -1)
		close(eap_fd);
}

uint32
Eap_OSInit(uint8 *bssid)
{
	struct ifreq ifr;
	struct sockaddr_ll ll;
	int err;

	if (!if_name[0]) {
		printf("Wireless Interface not specified.\n");
		return WPS_ERR_SYSTEM;
	}

	eap_fd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_8021X_PROT));
	if (eap_fd == -1) {
		TUTRACE((TUTRACE_ERR, "UDP Open failed.\n"));
		return WPS_ERR_SYSTEM;
	}

	if (bssid)
		memcpy(peer_mac, bssid, 6);

	memset(&ifr, 0, sizeof(ifr));
	wps_strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));

	err = ioctl(eap_fd, SIOCGIFINDEX, &ifr);
	if (err < 0) {
		TUTRACE((TUTRACE_ERR, "Get interface index failed\n"));
		close(eap_fd);
		eap_fd = -1;
		return WPS_ERR_SYSTEM;
	}

	memset(&ll, 0, sizeof(ll));

	ll.sll_family = PF_PACKET;
	ll.sll_ifindex = ifr.ifr_ifindex;
	ifindex  = ifr.ifr_ifindex;
	ll.sll_protocol = htons(ETH_8021X_PROT);
	if (bind(eap_fd, (struct sockaddr *) &ll, sizeof(ll)) < 0) {
		TUTRACE((TUTRACE_ERR, "Bind interface failed\n"));
		close(eap_fd);
		eap_fd = -1;
		return WPS_ERR_SYSTEM;
	}

	return WPS_SUCCESS;
}
uint32 Eap_ReadData(char * dataBuffer, uint32 * dataLen, struct timeval timeout)
{
	int recvBytes = 0;
	int fromlen;
	struct sockaddr_ll ll;
	fd_set fdvar;

	if (dataBuffer && (! dataLen)) {
		return WPS_ERR_INVALID_PARAMETERS;
	}

	FD_ZERO(&fdvar);
	FD_SET(eap_fd, &fdvar);
	if (select(eap_fd + 1, &fdvar, NULL, NULL, &timeout) < 0) {
		TUTRACE((TUTRACE_ERR, "l2 select recv failed\n"));
		return TREAP_ERR_SENDRECV;
	}

	if (FD_ISSET(eap_fd, &fdvar)) {
		memset(&ll, 0, sizeof(ll));
		fromlen = sizeof(ll);
		recvBytes = recvfrom(eap_fd, dataBuffer, *dataLen, 0, (struct sockaddr *) &ll,
			(socklen_t *)&fromlen);
		if (recvBytes == -1) {
			printf("UDP recv failed; recvBytes = %d\n", recvBytes);
			return TREAP_ERR_SENDRECV;
		}
		/* make sure we received from our bssid */
		if (memcmp(peer_mac, &(ll.sll_addr), 6)) {
			printf("received frame from wrong AP %s\n",
				(char *)ether_ntoa((struct ether_addr *)(&ll.sll_addr)));
			return TREAP_ERR_SENDRECV;
		}
		*dataLen = recvBytes;

#ifdef _TUDEBUGTRACE
	print_buf((unsigned char*)dataBuffer, *dataLen);
#endif

		return WPS_SUCCESS;
	}

	return EAP_TIMEOUT;
}
uint32
Eap_SendDataDown(char * dataBuffer, uint32 dataLen)
{
	int sentBytes = 0;
	struct sockaddr_ll ll;

	TUTRACE((TUTRACE_ERR, "In CInbEap::SendDataDown buffer Length = %d\n",
		dataLen));
	if ((!dataBuffer) || (!dataLen)) {
		TUTRACE((TUTRACE_ERR, "Invalid Parameters\n"));
		return WPS_ERR_INVALID_PARAMETERS;
	}

#ifdef _TUDEBUGTRACE
	print_buf((unsigned char*)dataBuffer, dataLen);
#endif

	memset(&ll, 0, sizeof(ll));
	ll.sll_family = AF_PACKET;
	ll.sll_ifindex = ifindex;
	ll.sll_protocol = htons(ETH_8021X_PROT);
	ll.sll_halen = 6;
	memcpy(ll.sll_addr, peer_mac, 6);
	sentBytes = sendto(eap_fd, dataBuffer, dataLen, 0, (struct sockaddr *) &ll,
		sizeof(ll));

	if (sentBytes != (int32) dataLen) {
		TUTRACE((TUTRACE_ERR, "L2 send failed; sentBytes = %d\n", sentBytes));
		return TREAP_ERR_SENDRECV;
	}

	return WPS_SUCCESS;
}

/* implement Portability.h */
uint32
WpsHtonl(uint32 intlong)
{
	return htonl(intlong);
}

uint16
WpsHtons(uint16 intshort)
{
	return htons(intshort);
}

uint16 WpsHtonsPtr(uint8 * in, uint8 * out)
{
	uint16 v;
	uint8 *c;

	c = (uint8 *)&v;
	c[0] = in[0]; c[1] = in[1];
	v = htons(v);
	out[0] = c[0]; out[1] = c[1];

	return v;
}

uint32
WpsHtonlPtr(uint8 * in, uint8 * out)
{
	uint32 v;
	uint8 *c;

	c = (uint8 *)&v;
	c[0] = in[0]; c[1] = in[1]; c[2] = in[2]; c[3] = in[3];
	v = htonl(v);
	out[0] = c[0]; out[1] = c[1]; out[2] = c[2]; out[3] = c[3];

	return v;
}


uint32
WpsNtohl(uint8 *a)
{
	uint32 v;

	v = (a[0] << 24) + (a[1] << 16) + (a[2] << 8) + a[3];
	return v;
}

uint16
WpsNtohs(uint8 *a)
{
	uint16 v;

	v = (a[0]*256) + a[1];
	return v;
}

void
WpsSleepMs(uint32 ms)
{
	usleep(1000*ms);
}

void
WpsSleep(uint32 seconds)
{
	WpsSleepMs(1000*seconds);
}

uint32
wait_for_eapol_packet(char* buf, uint32* len, uint32 timeout)
{
	struct timeval time;

	time.tv_sec = timeout;
	time.tv_usec = 0;

	return Eap_ReadData(buf, len, time);
}

uint32
send_eapol_packet(char *packet, uint32 len)
{
	return Eap_SendDataDown(packet, len);
}

unsigned long
get_current_time()
{
	struct timeval now;

	gettimeofday(&now, NULL);

	return now.tv_sec;
}

void
wps_setProcessStates(int state)
{
	char tmpbuf[16];

	sprintf(tmpbuf, "%d", state);

	/* nvram_set("wps_proc_status", tmpbuf); */
	/* printf("\n  %s()>> %s\n", __FUNCTION__, tmpbuf); */
	return;
}

void
wps_setStaDevName(char *str)
{
	if (str) {
		/* nvram_set("wps_sta_devname", str); */
		/* printf("\n  %s()>> %s\n", __FUNCTION__, str); */
	}
	return;
}

void
wps_setPinFailInfo(uint8 *mac, char *name, char *state)
{
	return;
}

/* Link to wl driver. */
int
wps_wl_ioctl(int cmd, void *buf, int len, bool set)
{
	struct ifreq ifr;
	wl_ioctl_t ioc;
	int ret = 0;
	int s;

	memset(&ifr, 0, sizeof(ifr));
	wps_strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));

	/* open socket to kernel */
	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		ret = -1;
		return ret;
	}

	/* do it */
	ioc.cmd = cmd;
	ioc.buf = buf;
	ioc.len = len;
	ioc.set = set;
	ifr.ifr_data = (caddr_t) &ioc;
	if ((ret = ioctl(s, SIOCDEVPRIVATE, &ifr)) < 0) {
		if (cmd != WLC_GET_MAGIC) {
			ret = -2;
		}
	}

	/* cleanup */
	close(s);
	return ret;
}
