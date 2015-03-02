/*
 * Broadcom DHCP Server
 * DHCP definitions.
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: dhcp.h,v 1.13 2010-05-19 15:12:06 $
 */

#define MAXBUFFERSIZE 1600


struct bootp_frame {
	unsigned char	msg_type;
	unsigned char	hardware_type;
	unsigned char	addr_len;
	unsigned char	hops;
	unsigned long	xid;
	unsigned short	elapsed;
	unsigned short	flags;
	unsigned long	client_ip;
	unsigned long	your_ip;
	unsigned long	next_server_ip;
	unsigned long	relay_ip;
	unsigned char	client_mac[6];
	unsigned char	client_mac_unused[10];
	unsigned char	server_name[0x40];
	unsigned char	boot_file_name[0x80];
};

struct dhcp_bootp_frame {
	unsigned char	msg_type;
	unsigned char	hardware_type;
	unsigned char	addr_len;
	unsigned char	hops;
	unsigned long	xid;
	unsigned short	elapsed;
	unsigned short	flags;
	unsigned long	client_ip;				/* client-provided for 'renew/rebinding' */
	unsigned long	your_ip;				/* server assigned IP address */
	unsigned long	next_server_ip;			/* siaddr */
	unsigned long	relay_ip;				/* giaddr */
	unsigned char	client_mac[6];			/* client's MAC address */
	unsigned char	client_mac_unused[10];	/* padding */
	unsigned char	server_name[0x40];
	unsigned char	boot_file_name[0x80];
	unsigned long	magic;
};

#define DHCPHANDLECOOKIE		0xef12bcca
#define DHCPMAGICCOOKIE			0x63538263

#define DHCP_OPTION				0x35
#define DHCP_MSG_TYPE_DISCOVER	0x01
#define DHCP_MSG_TYPE_REQUEST	0x03
#define DHCP_MSG_TYPE_DECLINE	0x04
#define DHCP_MSG_TYPE_INFORM	0x08

#define DHCP_RECV_SOCKET		67
#define DHCP_SEND_SOCKET		68


/* Error Values */

#define DDOK		0
#define DDRESOURCES	1
#define DDFAIL		2
#define DDINVALID	3
#define DDBADPACKET 	4
#define DDUNKNOWN	5
#define DDNOTFOUND	6
#define DDSHUTDOWN	7

/* Global Status */

extern int gDHCPStatus;

#define DS_EXITPENDING	1

/* Main API */
#ifdef __cplusplus
extern "C" {
#endif
void DHCP_main(void *Handle);
void *DHCP_init(unsigned long subnet, unsigned char starting_ip, unsigned char ending_ip,
                unsigned long gateway, unsigned long dns);
void DHCP_Register_Mac_addr(void *Handle, unsigned char *mac);
void DHCP_Deregister_Mac_addr(void *Handle, unsigned char *mac);
void *DHCP_Shutdown();
void *DHCP_Unload();

#ifdef TARGETENV_android
void *DHCP_Set_Gateway(unsigned char *ifname);
#endif /* TARGETENV_android */

typedef void (*DHCP_LOG_OUTPUT_FN)(int is_err, char *traceMsg);
void DHCP_Redirect_Logs(DHCP_LOG_OUTPUT_FN fn);
#ifdef __cplusplus
}
#endif
