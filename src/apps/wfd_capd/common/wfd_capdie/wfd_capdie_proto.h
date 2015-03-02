/* Fundamental types and data structure related to Wi-Fi Display P2P implementation
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id:$
 */
#ifndef _WFD_IE_H_
#define _WFD_IE_H_

#ifndef _TYPEDEFS_H_
#include <typedefs.h>
#endif

#include <packed_section_start.h>

#define WFD_IE_ID		0xdd			/* WFD IE element ID */
#define WFD_OUI			"\x50\x6F\x9A"	/* WFD OUI */
#define WFD_OUI_LEN		3				/* WFD OUI length */
#define WFD_OUI_TYPE	0x0A
#define WFD_VNDR_IE_HDR_LEN		2	/* Size of "Element ID" + size of "Length" */

#define WFD_SEID_SIZE			1
#define WFD_SEID_LEN_SIZE 		2

#define WIDI_OUI		0x00173520


/* WFD subelement header size */
#define WFD_SE_HDR_LEN			(WFD_SEID_SIZE + WFD_SEID_LEN_SIZE)

/* WFD IE Subelement IDs */
#define WFD_SEID_DEV_INFO		0	/* Device Infomation Subelement ID*/
#define WFD_SEID_ASSOC_BSSID	1   /* Associated BSSID Subelement ID*/
#define WFD_SEID_AUDIO_FORMATS	2	
#define WFD_SEID_VIDEO_FORMATS	3
#define WFD_SEID_3D_VIDEO_FORMATS	4
#define WFD_SEID_CONTENT_PROTECTION	5
#define WFD_SEID_CPL_SINK_INFO	6
#define WFD_SEID_EXTENDED_CAP	7
#define WFD_SEID_LOCAL_IP_INFO	8
#define WFD_SEID_SESSION_INFO	9
#define WFD_SEID_ALTERNATIVE_MAC	10

/* WFD device types */
#define WFD_DEV_INFO_SRC		0x00		/* WFD source. */
#define WFD_DEV_INFO_PRIM_SINK	0x01		/* WFD primary sink. */
#define WFD_DEV_INFO_SEC_SINK	0x02		/* WFD second sink. */
#define WFD_DEV_INFO_SRC_PRIM_SINK	0x03	/* WFD source and primary sinks. */

#define WFD_MAX_CONNECTED_PEERS	8

/* WiFi P2P IE */
BWL_PRE_PACKED_STRUCT struct wifi_wfd_ie_s {
	uint8	id;		/* IE ID: 0xDD */
	uint8	len;		/* IE length */
	uint8	OUI[3];		/* WiFi P2P specific OUI: P2P_OUI */
	uint8	oui_type;	/* Identifies P2P version: P2P_VER */
	uint8	subelts[1];	/* variable length subelements */
} BWL_POST_PACKED_STRUCT;
typedef struct wifi_wfd_ie_s wifi_wfd_ie_t;

/* Device Information subelement */
BWL_PRE_PACKED_STRUCT struct wifi_wfd_devinfo_se {
	uint8	eltId;			/* SE ID: WFD_SEID_DEV_INFO  */
	uint16	len;			/* SE length not including eltId, len fields */
	uint16	info_bmp;		/* WFD Device Info bitmap */
	uint16  port;
	uint16  max_tput;
} BWL_POST_PACKED_STRUCT;
typedef struct wifi_wfd_devinfo_se wifi_wfd_devinfo_se_t;

/* STA local IP subelement */
BWL_PRE_PACKED_STRUCT struct wifi_wfd_local_ip_se {
	uint8	eltId;			/* SE ID: WFD_SEID_DEV_INFO  */
	uint16	len;			/* SE length not including eltId, len fields */
	uint8	ip_ver;			/* Version 1: IPv4 address field follows */
	uint32	ip4_addr;		/* IPv4 host address of the STA */
} BWL_POST_PACKED_STRUCT;
typedef struct wifi_wfd_local_ip_se wifi_wfd_local_ip_se_t;

/* Associated BSSID subelement */
BWL_PRE_PACKED_STRUCT struct wifi_wfd_associated_bssid_se {
	uint8	eltId;			/* SE ID: WFD_SEID_DEV_INFO  */
	uint16	len;			/* SE length not including eltId, len fields */
	uint8	bssid[6];		/* Address of the associated AP */
} BWL_POST_PACKED_STRUCT;
typedef struct wifi_wfd_associated_bssid_se wifi_wfd_associated_bssid_se_t;

/* Coupled sink information */
BWL_PRE_PACKED_STRUCT struct wifi_wfd_cpl_sink_info_se {
	uint8	status_bmp;
	uint8	cpl_sink_addr[6];
} BWL_POST_PACKED_STRUCT;
typedef struct wifi_wfd_cpl_sink_info_se wifi_wfd_cpl_sink_info_se_t;

/* Device information descriptor with size of 24 bytes */
BWL_PRE_PACKED_STRUCT struct wifi_wfd_devinfo_desc {
	uint8	len;
	uint8	peer_mac[6];
	uint8	assoc_bssid[6];
	uint16	info_bmp;
	uint16  max_tput;
	uint8	cpl_sink_status;
	uint8	cpl_sink_addr[6];
} BWL_POST_PACKED_STRUCT;
typedef struct wifi_wfd_devinfo_desc wifi_wfd_devinfo_desc_t;

/* Session information subelement*/
BWL_PRE_PACKED_STRUCT struct wifi_wfd_sessinfo_se{
	uint8	eltId;			/* SE ID: WFD_SEID_DEV_INFO  */
	uint16	len;			/* SE length not including eltId, len fields */
	uint8	data[WFD_MAX_CONNECTED_PEERS * sizeof(wifi_wfd_devinfo_desc_t)];
							/* List of WFD device Info Descriptor in WFD group */
} BWL_POST_PACKED_STRUCT;
typedef struct wifi_wfd_sessinfo_se wifi_wfd_sesinfo_se_t;

/* Alternative ac subelement*/
BWL_PRE_PACKED_STRUCT struct wifi_wfd_altmac_se {
	uint8	eltId;			/* SE ID: WFD_SEID_ALTERNATIVE_MAC  */
	uint16	len;			/* SE length not including eltId, len fields */
	uint8	alt_mac[6];		/* Mac address */
} BWL_POST_PACKED_STRUCT;
typedef struct wifi_wfd_altmac_se wifi_wfd_altmac_se_t;

/* This marks the end of a packed structure section. */
#include <packed_section_end.h>

#endif  /* _WFD_IE_H_ */
