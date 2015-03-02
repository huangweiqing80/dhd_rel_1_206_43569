/*
 * WFD Library API - IE realted functions
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
#include <stdlib.h>
#include <string.h>
#include <typedefs.h>
#include <bcmendian.h>
#include <802.11.h>
#include <tutrace.h>
#include "wfd_capd.h"
#include "wfd_capdie.h"
#include "wfd_capdie_proto.h"
#include "wfd_capdie_lib.h"

const char CAPDIE_ZERO_MAC[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/* Encode a P2P IE header */
static uint8*
capdie_encode_wfd_ie_hdr(wifi_wfd_ie_t *wfd_ie, uint16 *ie_len)
{
	wfd_ie->id = WFD_IE_ID;
	wfd_ie->len = (uint8) *ie_len;
	wfd_ie->OUI[0] = WFD_OUI[0];
	wfd_ie->OUI[1] = WFD_OUI[1];
	wfd_ie->OUI[2] = WFD_OUI[2];
	wfd_ie->oui_type = WFD_OUI_TYPE;

	*ie_len += sizeof(wifi_wfd_ie_t) - 1;  /* Total len of the IE */
	return wfd_ie->subelts;
}

static bool
capdie_is_zero_mac(const WFDCAPD_ETHER_ADDR *mac)
{
	return (memcmp(mac->octet, CAPDIE_ZERO_MAC, 6) == 0)? true : false;
}

bool
capdie_is_wfd_ie(const uint8 *ie)
{
	bool ret = false;

	/* If the contents match the WFD IE length, OUI, and OUI type,
	 * this is a WFD IE - return true.
	 */
	WFDCAPDLOG((TUTRACE_INFO, "Entered.\n"));
	
	WFDCAPDLOG((TUTRACE_INFO, "IE data %02x%02x%02x%02x %02x%02x%02x%02x\n",
		ie[1], ie[2], ie[3], ie[4],  ie[5], ie[6], ie[7], ie[8]));

	if (ie[1] >= 4 && !memcmp(&ie[2], WFD_OUI, 3)) {
		if (ie[5] == WFD_OUI_TYPE) {
			ret = true;
			goto exit;
		}
	}

exit:	
	WFDCAPDLOG((TUTRACE_INFO, "Exiting. ret=%d\n", ret));
	return ret;
}

static uint16
capdie_encode_dev_cap_bitmap(const WFDCAPD_CAP_CONFIG *cap_cfg)
{
	uint16 dev_cap = 0;

	if (cap_cfg == NULL)
		goto exit;

	/* Device type */
	switch (cap_cfg->dev_type) {
		case WFDCAPD_DEVICE_TYPE_SRC:		/* WFD source */
			break;
		case WFDCAPD_DEVICE_TYPE_PRIM_SINK:	/* WFD primary sink */
			dev_cap |= WFD_DEV_INFO_PRIM_SINK;
			break;
		case WFDCAPD_DEVICE_TYPE_SEC_SINK:	/* WFD second sink */
			dev_cap |= WFD_DEV_INFO_SEC_SINK;
			break;
		case WFDCAPD_DEVICE_TYPE_SRC_PRIM_SINK:	/* WFD source and primary sink */
			dev_cap |= WFD_DEV_INFO_SRC_PRIM_SINK;
			break;
		default:
			WFDCAPDLOG((TUTRACE_INFO, "Unexpected WFD device type\n"));
	};

	/* Coupled sink support */
	if (cap_cfg->support_cpl_sink) {
		if (cap_cfg->dev_type == WFDCAPD_DEVICE_TYPE_SRC ||
			cap_cfg->dev_type == WFDCAPD_DEVICE_TYPE_SRC_PRIM_SINK)
			dev_cap |= (1<<2);	/* b2 valid for source device */
		else
			dev_cap |= (1<<3);	/* b3 valid for sink device */
	}

	/* Available for WFD session */
	if (cap_cfg->sess_avl)
		dev_cap |= (1<<4);	/* b4. b5 reserved */

	/* WSD (WFD Service Discovery) support */
	if (cap_cfg->support_wsd)
		dev_cap |= (1<<6);	/* b6 */

	/* Preferred connection: P2P or TDLS */
	if (cap_cfg->preferred_connection == WFDCAPD_CONNECTION_TDLS)
		dev_cap |= (1<<7);	/* b7. Default b7->0 prefer p2p */

	/* Content protection */
	if (cap_cfg->content_protected)
		dev_cap |= (1<<8);	/* b8 */

	/* Time synchrnoization using 802.1AS support */
	if (cap_cfg->support_time_sync)
		dev_cap |= (1<<9);	/* b9 */

exit:
	return dev_cap;
}

bool
capdie_decode_dev_cap_bitmap(uint16 dev_info_bmp, wfd_capdie_dev_info_t *dev_info)
{
	if (dev_info == NULL)
		return false;

	/* Device type */
	dev_info->dev_type = (WFDCAPD_DEVICE_TYPE)(dev_info_bmp & 0x03);

	/* Is coupled sink supported */
	switch (dev_info->dev_type) {
	case WFDCAPD_DEVICE_TYPE_SRC:
		/* b2 valid for source device */
		dev_info->support_cpl_sink =
			(dev_info_bmp & (1 << 2))? WFDCAPD_TRUE : WFDCAPD_FALSE;
		break;
	case WFDCAPD_DEVICE_TYPE_PRIM_SINK:
	case WFDCAPD_DEVICE_TYPE_SEC_SINK:
		/* b3 valid for source device */
		dev_info->support_cpl_sink =
			(dev_info_bmp & (1 << 3))? WFDCAPD_TRUE : WFDCAPD_FALSE;
		break;
	case WFDCAPD_DEVICE_TYPE_SRC_PRIM_SINK:
		dev_info->support_cpl_sink = 
			(dev_info_bmp & (1 << 2)) || (dev_info_bmp & (1 << 3))? WFDCAPD_TRUE : WFDCAPD_FALSE;
		break;
	default:
		dev_info->support_cpl_sink = WFDCAPD_FALSE;
	}

	/* Is available for session */
	dev_info->sess_avl = 
		(dev_info_bmp & (1 << 4))? WFDCAPD_TRUE : WFDCAPD_FALSE;

	/* Is WSD supported */
	dev_info->support_wsd =
		(dev_info_bmp & (1 << 6))? WFDCAPD_TRUE : WFDCAPD_FALSE;

	/* Preferred connection type */
	dev_info->preferred_connection = 
		(dev_info_bmp & (1 << 7))? WFDCAPD_CONNECTION_TDLS : WFDCAPD_CONNECTION_P2P;

	/* Content protection support */
	dev_info->content_protected =
		(dev_info_bmp & (1 << 8))? WFDCAPD_TRUE : WFDCAPD_FALSE;

	/* Time sync support */
	dev_info->support_time_sync =
		(dev_info_bmp & (1 << 9))? WFDCAPD_TRUE : WFDCAPD_FALSE;

	return true;
}

/* Encode WFD device information subelement */
static uint8*
capdie_encode_wfd_se_devinfo(uint16 dev_cap_bitmap, uint16 dev_cap_tcp_port, uint16 dev_cap_max_tput,
	uint8 *subel, uint16 *ie_len)
{
	uint16 data16;
	wifi_wfd_devinfo_se_t devinfo_se;
	bool is_available = true;

	WFDCAPDLOG((TUTRACE_INFO, "Entered. dev_cap_bitmap=%d "
		"dev_cap_tcp_port=%d, dev_cap_max_tput=%d\n",
		dev_cap_bitmap, dev_cap_tcp_port, dev_cap_max_tput));

	/* Sub-element ID */
	devinfo_se.eltId = WFD_SEID_DEV_INFO;

	/* Sub-element length */
	data16 = hton16(sizeof(wifi_wfd_devinfo_se_t) - WFD_SE_HDR_LEN);
	devinfo_se.len = data16;

	/* Device information bitmap */
	data16 = hton16(dev_cap_bitmap);
	devinfo_se.info_bmp = data16;

	/*  RTSP tcp port */
	data16 = hton16(dev_cap_tcp_port);
	devinfo_se.port = data16;

	/* Set Maximum Device Throughput*/
	data16 = hton16(dev_cap_max_tput);
	devinfo_se.max_tput = data16;

	memcpy(subel, &devinfo_se, sizeof(wifi_wfd_devinfo_se_t));

	subel += sizeof(wifi_wfd_devinfo_se_t);
	*ie_len += sizeof(wifi_wfd_devinfo_se_t);

	WFDCAPDLOG((TUTRACE_INFO, "Exiting. *ie_len %d\n", *ie_len));
	return subel;
}

/* Encode STA local IP address */
static uint8*
capdie_encode_wfd_se_local_ip(uint32 ip4_addr, uint8 *subel, uint16 *ie_len)
{
	uint8 buf[4];
	wifi_wfd_local_ip_se_t wfd_ip;

	WFDCAPDLOG((TUTRACE_INFO, "Entered.\n"));

	memcpy(buf, &ip4_addr, 4);
	WFDCAPDLOG((TUTRACE_INFO, "Local IP %d.%d.%d.%d\n",
		buf[3], buf[2], buf[1], buf[0]));

	/* Subelement ID */
	wfd_ip.eltId = WFD_SEID_LOCAL_IP_INFO;

	/* Length of following subelement fields */
	wfd_ip.len = hton16(5);

	/* Version 1: IP4 address field follows */
	wfd_ip.ip_ver = 1;

	/* 4-byte local ip address. No need to do endianness converstion as we assume the
	 * network address in 4-byte integer format should be always in big endianness
	 */
	wfd_ip.ip4_addr = ip4_addr;

	/* Copy over the whole IE data */
	memcpy(subel, &wfd_ip, sizeof(wifi_wfd_local_ip_se_t));

	subel += sizeof(wifi_wfd_local_ip_se_t);
	*ie_len += sizeof(wifi_wfd_local_ip_se_t);

	WFDCAPDLOG((TUTRACE_INFO, "Exiting. (*ie_len)=%d.\n", *ie_len));
	return subel;
}

/* Encode Associated BSSID subelement */
static uint8*
capdie_encode_wfd_se_associated_bssid(const WFDCAPD_ETHER_ADDR *ap_addr,
	uint8 *subel, uint16 *ie_len)
{
	uint16 subie_len;
	wifi_wfd_associated_bssid_se_t assoc_bssid_se;

	WFDCAPDLOG((TUTRACE_INFO, "Entered.\n"));

	WFDCAPDLOG_MAC(("capdie_encode_wfd_se_associated_bssid: assoc_bssid ", ap_addr->octet));

	subie_len = sizeof(wifi_wfd_associated_bssid_se_t);

	/* Subelement ID */
	assoc_bssid_se.eltId = WFD_SEID_ASSOC_BSSID;

	/* Length */
	assoc_bssid_se.len = hton16(6);

	/* Associated bssid value */
	memcpy(assoc_bssid_se.bssid, ap_addr->octet, 6);

	/* Copy over the whole IE data */
	memcpy(subel, &assoc_bssid_se, subie_len);

	*ie_len += subie_len;
	subel += subie_len;

	WFDCAPDLOG((TUTRACE_INFO, "Exiting. (*subie_len)=%d\n", subie_len));
	return subel;
}

/* Encode Alternative Mac subelement */
static uint8*
capdie_encode_wfd_se_alternative_mac(const WFDCAPD_ETHER_ADDR *alt_mac,
	uint8 *subel, uint16 *ie_len)
{
	uint16 subie_len;
	wifi_wfd_altmac_se_t alt_mac_se;

	WFDCAPDLOG((TUTRACE_INFO, "Entered.\n"));

	WFDCAPDLOG_MAC(("capdie_encode_wfd_se_alternative_mac: alt_mac ", alt_mac->octet));

	subie_len = sizeof(wifi_wfd_altmac_se_t);

	/* Subelement ID */
	alt_mac_se.eltId = WFD_SEID_ALTERNATIVE_MAC;

	/* Length */
	alt_mac_se.len = hton16(6);

	/* Associated bssid value */
	memcpy(alt_mac_se.alt_mac, alt_mac->octet, 6);

	/* Copy over the whole IE data */
	memcpy(subel, &alt_mac_se, subie_len);

	*ie_len += subie_len;
	subel += subie_len;

	WFDCAPDLOG((TUTRACE_INFO, "Exiting. (*subie_len)=%d\n", subie_len));
	return subel;
}

static uint8*
capdie_encode_se_sessinfo(const wfd_capdie_dev_ie_t *group_dev_ie_list,
	WFDCAPD_UINT8 group_dev_total, uint8 *subel, uint16 *ie_len)
{
	uint16 data16;
	uint8 num;
	wifi_wfd_sesinfo_se_t *sessinfo_ie = NULL;
	uint16 sessinfo_ie_len = 0, sessinfo_ie_data_len;
	wifi_wfd_devinfo_desc_t *devinfo_desc;
	const wfd_capdie_dev_ie_t *dev_ie;

	WFDCAPDLOG((TUTRACE_INFO, "Entered. *ie_len %d, group_dev_total %d\n",
		*ie_len, group_dev_total));

	if (group_dev_total == 0 || group_dev_ie_list == NULL) {
		WFDCAPDLOG((TUTRACE_INFO, "Invalid parameters passed in. group_dev_total=%d ",
			"group_dev_ie_list=%u\n", group_dev_total, group_dev_ie_list));
		goto exit;
	}

	/* Set session information IE header */
	sessinfo_ie = (wifi_wfd_sesinfo_se_t *)malloc(sizeof(wifi_wfd_sesinfo_se_t));
	if (!sessinfo_ie) {
		WFDCAPDLOG((TUTRACE_ERR, "malloc failed\n"));
		goto exit;
	}

	memset(sessinfo_ie, 0, sizeof(wifi_wfd_sesinfo_se_t));

	/* "ID" of Session Info subie */
	sessinfo_ie->eltId = WFD_SEID_SESSION_INFO;
	
	/* Encode device descriptors from wifi_wfd_cpl_sink_info_se_t data */
	devinfo_desc = (wifi_wfd_devinfo_desc_t *)sessinfo_ie->data;
	sessinfo_ie_data_len = 0;
	for (num = 0; num < group_dev_total; num++) {
		wfd_capdie_ie_t wfd_capdie;

		dev_ie = &group_dev_ie_list[num];

		/* Decode the IE first */
		if (dev_ie == NULL) {
			continue;
		}

		WFDCAPDLOG((TUTRACE_INFO, "dev_ie->ie_data %d, dev_ie->ie_data_len %d\n",
			dev_ie->ie_data, dev_ie->ie_data_len));

		if (dev_ie->ie_data == NULL || dev_ie->ie_data_len == 0) {
			continue;
		}

		WFDCAPDLOG_HEX(("capdie_encode_se_sessinfo, peer gc ie: ", dev_ie->ie_data, dev_ie->ie_data_len));

		/* Set fields in device info descriptor */
		memset(&wfd_capdie, 0, sizeof(wfd_capdie));
		if (capdie_search_wfd_ies(dev_ie->ie_data, dev_ie->ie_data_len, &wfd_capdie)) {
			/* Lenth of the descriptor attributes */
			devinfo_desc->len = sizeof(wifi_wfd_devinfo_desc_t) - 1;  /* 23 octets */
			
			/* Device address */
			memcpy(devinfo_desc->peer_mac, dev_ie->peer_addr, 6);

			/* Associated bssid */
			memcpy(devinfo_desc->assoc_bssid, wfd_capdie.assocbssid_subelt.bssid, 6);

			/* WFD device info bitmap */
			data16 = hton16(wfd_capdie.devinfo_subelt.info_bmp);
			devinfo_desc->info_bmp = data16;

			/* WFD device maximum throughput */
			data16 = hton16(wfd_capdie.devinfo_subelt.max_tput);
			devinfo_desc->max_tput = data16;

			/* Coupled sink information */
			devinfo_desc->cpl_sink_status = wfd_capdie.cplsinkinfo_subelt.status_bmp;
			memcpy(devinfo_desc->cpl_sink_addr,
				wfd_capdie.cplsinkinfo_subelt.cpl_sink_addr, 6);

			/* Copy over the whole device descriptor information */
			memcpy(subel, devinfo_desc, sizeof(wifi_wfd_devinfo_desc_t)); /* 24 bytes */
			devinfo_desc = (wifi_wfd_devinfo_desc_t *)((uint8 *)devinfo_desc +
				sizeof(wifi_wfd_devinfo_desc_t));

			/* Increment the total size of device descriptors */
			sessinfo_ie_data_len += sizeof(wifi_wfd_devinfo_desc_t);
		}
	}

	/* Total size of Session Information subie */
	sessinfo_ie_len = WFD_SE_HDR_LEN + sessinfo_ie_data_len;

	/* "len" of Session Information subie */
	sessinfo_ie->len = hton16(sessinfo_ie_data_len);

	WFDCAPDLOG_HEX(("Session info IE buf", subel, sessinfo_ie_len));

	/* Set the whole session information subelement */
	if (sessinfo_ie->len > 0) {
		memcpy(subel, sessinfo_ie, sessinfo_ie_len);
		*ie_len += sessinfo_ie_len;
		subel += sessinfo_ie_len;
	}

exit:
	if (sessinfo_ie)
		free(sessinfo_ie);

	WFDCAPDLOG((TUTRACE_INFO, "Exiting. session info subie len %d\n", sessinfo_ie_len));
	return subel;
}

/* Encode a probe request WFD IE */
void
capdie_encode_prbreq_wfd_ie(const WFDCAPD_CAP_CONFIG *cap_cfg, uint8 *ie_buf, uint16 *ie_len)
{
	uint8 *subel;
	wifi_wfd_ie_t *wfd_ie;
	uint16 dev_cap_bitmap;

	WFDCAPDLOG((TUTRACE_INFO, "Entered.\n"));

	wfd_ie = (wifi_wfd_ie_t *)ie_buf;
	*ie_len = 0;

	/* Add the WFD IE header */
	subel = capdie_encode_wfd_ie_hdr(wfd_ie, ie_len);

	/* Generate the WFD device information bitmap */
	dev_cap_bitmap = capdie_encode_dev_cap_bitmap(cap_cfg);

	/* Add the Capability Info subelement */
	subel = capdie_encode_wfd_se_devinfo(dev_cap_bitmap, cap_cfg->rtsp_tcp_port, 
		cap_cfg->max_tput, subel, ie_len);

	/* Associated BSSID IE */
	if (cap_cfg->tdls_available)
		subel = capdie_encode_wfd_se_associated_bssid(&cap_cfg->tdls_cfg.assoc_bssid, subel, ie_len);

	/* TODO: Coupled Sink Information */

	/* Set WFD IE length */
	wfd_ie->len = (uint8) *ie_len - WFD_VNDR_IE_HDR_LEN;

	/* Dump WFD IE */
	WFDCAPDLOG_HEX(("Probreq WFD IE data", (uint8 *)wfd_ie, *ie_len));

	WFDCAPDLOG((TUTRACE_INFO, "Exiting. wfd_ie total data len %u\n",
		subel - ((uint8*)wfd_ie)));
}

/* Encode a probe response WFD IE */
void
capdie_encode_prbresp_wfd_ie(const WFDCAPD_CAP_CONFIG *cap_cfg,
	const wfd_capdie_dev_ie_t *group_dev_ie_list, uint8 group_dev_total,
	uint8 *ie_buf, uint16 *ie_len)
{
	uint8 *subel;
	wifi_wfd_ie_t *wfd_ie;
	uint16 dev_cap_bitmap;

	WFDCAPDLOG((TUTRACE_INFO, "Entered. group_dev_total %d\n", group_dev_total));
	
	wfd_ie = (wifi_wfd_ie_t *)ie_buf;
	*ie_len = 0;

	/* Add the WFD IE header */
	subel = capdie_encode_wfd_ie_hdr(wfd_ie, ie_len);

	/* Generate the WFD device information bitmap */
	dev_cap_bitmap = capdie_encode_dev_cap_bitmap(cap_cfg);

	/* Add the Capability Info subelement */
	subel = capdie_encode_wfd_se_devinfo(dev_cap_bitmap, cap_cfg->rtsp_tcp_port, 
		cap_cfg->max_tput, subel, ie_len);

	/* Alternative mac address */
	subel = capdie_encode_wfd_se_alternative_mac(&cap_cfg->alt_mac, subel, ie_len);

	if (cap_cfg->tdls_available) {
		/* Associated bassid */		
		subel = capdie_encode_wfd_se_associated_bssid(&cap_cfg->tdls_cfg.assoc_bssid, subel, ie_len);
		

	}

	/* TODO: Coupled Sink Information */

	/* Session Information */
	if (group_dev_total > 0 && group_dev_ie_list)
		subel = capdie_encode_se_sessinfo(group_dev_ie_list, group_dev_total,
					subel, ie_len);

	/* Set WFD IE length */
	wfd_ie->len = (uint8) *ie_len - WFD_VNDR_IE_HDR_LEN;

	/* Dump WFD IE */
	WFDCAPDLOG_HEX(("Probrsp WFD IE data", (uint8 *)wfd_ie, *ie_len));

	WFDCAPDLOG((TUTRACE_INFO, "Exiting. wfd_ie total data len %u\n",
		subel - ((uint8*)wfd_ie)));
}


/* Encode a Association Request WFD IE */
void
capdie_encode_assocreq_wfd_ie(const WFDCAPD_CAP_CONFIG *cap_cfg,
	uint8 *ie_buf, uint16 *ie_len)
{
	uint8 *subel;
	wifi_wfd_ie_t *wfd_ie;
	uint16 dev_cap_bitmap;

	WFDCAPDLOG((TUTRACE_INFO, "Entered.\n"));

	wfd_ie = (wifi_wfd_ie_t *)ie_buf;
	*ie_len = 0;

	/* Add the WFD IE header */
	subel = capdie_encode_wfd_ie_hdr(wfd_ie, ie_len);

	/* Generate the WFD device information bitmap */
	dev_cap_bitmap = capdie_encode_dev_cap_bitmap(cap_cfg);

	/* Add the Capability Info subelement */
	subel = capdie_encode_wfd_se_devinfo(dev_cap_bitmap, cap_cfg->rtsp_tcp_port, 
		cap_cfg->max_tput, subel, ie_len);

	/* Associated BSSID IE */
	if (cap_cfg->tdls_available)
		subel = capdie_encode_wfd_se_associated_bssid(&cap_cfg->tdls_cfg.assoc_bssid, subel, ie_len);

	/* TODO: Coupled Sink Information */

	/* Set WFD IE length */
	wfd_ie->len = (uint8) *ie_len - WFD_VNDR_IE_HDR_LEN;

	WFDCAPDLOG((TUTRACE_INFO, "Exiting. wfd_ie total data len %u, wfd_ie->len %d\n",
		subel - ((uint8*)wfd_ie), wfd_ie->len));
}

/* Encode a Association Response WFD IE */
void
capdie_encode_assocresp_wfd_ie(const WFDCAPD_CAP_CONFIG *cap_cfg,
	const wfd_capdie_dev_ie_t *group_dev_ie_list, uint8 group_dev_total,
	uint8 *ie_buf, uint16 *ie_len)
{
	uint8 *subel;
	wifi_wfd_ie_t *wfd_ie;
	uint16 dev_cap_bitmap;

	WFDCAPDLOG((TUTRACE_INFO, "Entered.\n"));

	wfd_ie = (wifi_wfd_ie_t *)ie_buf;
	*ie_len = 0;

	/* Add the WFD IE header */
	subel = capdie_encode_wfd_ie_hdr(wfd_ie, ie_len);

	/* Generate the WFD device information bitmap */
	dev_cap_bitmap = capdie_encode_dev_cap_bitmap(cap_cfg);

	/* Add the Capability Info subelement */
	subel = capdie_encode_wfd_se_devinfo(dev_cap_bitmap, cap_cfg->rtsp_tcp_port, 
		cap_cfg->max_tput, subel, ie_len);

	/* Associated BSSID IE */
	if (cap_cfg->tdls_available)
		subel = capdie_encode_wfd_se_associated_bssid(&cap_cfg->tdls_cfg.assoc_bssid, subel, ie_len);

	/* TODO: Coupled Sink Information */

	/* Session Information */
	if (group_dev_total > 0 && group_dev_ie_list)
		subel = capdie_encode_se_sessinfo(group_dev_ie_list, group_dev_total,
					subel, ie_len);

	/* Set WFD IE length */
	wfd_ie->len = (uint8) *ie_len - WFD_VNDR_IE_HDR_LEN;

	WFDCAPDLOG((TUTRACE_INFO, "Exiting. wfd_ie total data len %u\n",
		subel - ((uint8*)wfd_ie, wfd_ie->len)));
}


/* Encode a beacon WFD IE */
void
capdie_encode_beacon_wfd_ie(const WFDCAPD_CAP_CONFIG *cap_cfg,
	uint8 *ie_buf, uint16 *ie_len)
{
	uint8 *subel;
	wifi_wfd_ie_t *wfd_ie;
	uint16 dev_cap_bitmap;

	WFDCAPDLOG((TUTRACE_INFO, "Entered.\n"));

	wfd_ie = (wifi_wfd_ie_t *)ie_buf;
	*ie_len = 0;

	/* Add the WFD IE header */
	subel = capdie_encode_wfd_ie_hdr(wfd_ie, ie_len);

	/* Generate the WFD device information bitmap */
	dev_cap_bitmap = capdie_encode_dev_cap_bitmap(cap_cfg);

	/* Add the Capability Info subelement */
	subel = capdie_encode_wfd_se_devinfo(dev_cap_bitmap, cap_cfg->rtsp_tcp_port, 
		cap_cfg->max_tput, subel, ie_len);

	/* Associated BSSID IE */
	if (cap_cfg->tdls_available)
		subel = capdie_encode_wfd_se_associated_bssid(&cap_cfg->tdls_cfg.assoc_bssid, subel, ie_len);

	/* TODO: Coupled Sink Information */

	/* Set WFD IE length */
	wfd_ie->len = (uint8) *ie_len - WFD_VNDR_IE_HDR_LEN;

	WFDCAPDLOG((TUTRACE_INFO, "wfd_ie total data len %u\n",
		subel - ((uint8*)wfd_ie)));
}

/* Encode provision discovery WFD IE */
void
capdie_encode_provdis_wfd_ie(const WFDCAPD_CAP_CONFIG *cap_cfg,
	const wfd_capdie_dev_ie_t *group_dev_ie_list, uint8 group_dev_total,
	uint8 *ie_buf, uint16 *ie_len)
{
	uint8 *subel;
	wifi_wfd_ie_t *wfd_ie;
	uint16 dev_cap_bitmap;

	WFDCAPDLOG((TUTRACE_INFO, "Entered.\n"));

	wfd_ie = (wifi_wfd_ie_t *)ie_buf;
	*ie_len = 0;

	/* Add the WFD IE header */
	subel = capdie_encode_wfd_ie_hdr(wfd_ie, ie_len);

	/* Generate the WFD device information bitmap */
	dev_cap_bitmap = capdie_encode_dev_cap_bitmap(cap_cfg);

	/* Add the Capability Info subelement */
	subel = capdie_encode_wfd_se_devinfo(dev_cap_bitmap, cap_cfg->rtsp_tcp_port, 
		cap_cfg->max_tput, subel, ie_len);

	/* Associated BSSID IE */
	if (cap_cfg->tdls_available)
		subel = capdie_encode_wfd_se_associated_bssid(&cap_cfg->tdls_cfg.assoc_bssid, subel, ie_len);

	/* TODO: Coupled Sink Information */

	/* Session Information */
	if (group_dev_total > 0 && group_dev_ie_list)
		subel = capdie_encode_se_sessinfo(group_dev_ie_list, group_dev_total,
					subel, ie_len);

	/* Set WFD IE length */
	wfd_ie->len = (uint8) *ie_len - WFD_VNDR_IE_HDR_LEN;

	WFDCAPDLOG((TUTRACE_INFO, "wfd_ie total data len %u\n",
		subel - ((uint8*)wfd_ie)));
}


/* Encode a Group Owner Negotiation WFD IE 
 * The same WFD IE can be included in GON Req, GON Rsp or GON Confirmation
 * action frame
*/
void
capdie_encode_gon_wfd_ie(const WFDCAPD_CAP_CONFIG *cap_cfg,
	uint8 *ie_buf, uint16 *ie_len)
{
	uint8 *subel;
	wifi_wfd_ie_t *wfd_ie;
	uint16 dev_cap_bitmap;

	WFDCAPDLOG((TUTRACE_INFO, "Entered.\n"));

	wfd_ie = (wifi_wfd_ie_t *)ie_buf;
	*ie_len = 0;

	/* Add the WFD IE header */
	subel = capdie_encode_wfd_ie_hdr(wfd_ie, ie_len);

	/* Generate the WFD device information bitmap */
	dev_cap_bitmap = capdie_encode_dev_cap_bitmap(cap_cfg);

	/* Add the Capability Info subelement */
	subel = capdie_encode_wfd_se_devinfo(dev_cap_bitmap, cap_cfg->rtsp_tcp_port, 
		cap_cfg->max_tput, subel, ie_len);

	/* Associated BSSID IE */
	if (cap_cfg->tdls_available)
		subel = capdie_encode_wfd_se_associated_bssid(&cap_cfg->tdls_cfg.assoc_bssid, subel, ie_len);

	/* TODO: Coupled Sink Information */

	/* Set WFD IE length */
	wfd_ie->len = (uint8) *ie_len - WFD_VNDR_IE_HDR_LEN;

	WFDCAPDLOG((TUTRACE_INFO, "Exiting. wfd_ie total data len %u\n",
		subel - ((uint8*)wfd_ie)));
}

/* Decode WFD informaiton of custom IE data.  Returns the total IE len including the ID & len fields */
uint16
capdie_decode_wfd_ie(const uint8* ie_buf, wfd_capdie_ie_t *out_wfd_ie)
{
	wifi_wfd_ie_t *ie = (wifi_wfd_ie_t *)ie_buf;
	uint8 *subel, *next_subel, subelt_id;
	uint16 len, subelt_len, data16;

	WFDCAPDLOG((TUTRACE_INFO, "Entered.\n"));

	WFDCAPDLOG_HEX(("capdie_decode_wfd_ie: ie_buf", ie_buf, ie->len + 1));

	/* Point subel to the WFD IE's subelt field.
	 * Subtract the preceding fields (id, len, OUI, oui_type) from the length.
	 */
	subel = ie->subelts;
	next_subel = NULL;
	len = (int16)ie->len - 4;	/* exclude OUI */

	WFDCAPDLOG((TUTRACE_INFO, "subie total len %d\n", len));

	/* WFD IE header */
	memcpy(&out_wfd_ie->wifi_wfd_ie, ie, sizeof(wifi_wfd_ie_t) - 1);

	while ((subel != NULL) && (len >= WFD_SE_HDR_LEN)) {
		/* WFD attribute id with the size of 1 byte */
		subelt_id = *subel;
		subel += WFD_SEID_SIZE;
		len -= WFD_SEID_SIZE;

		/* attribute length */
		memcpy(&data16, subel, WFD_SEID_LEN_SIZE);
		subelt_len = ntoh16(data16);

 		/* point to the next sub element */
		next_subel = subel + subelt_len;

		if (subelt_len == 0) {
			WFDCAPDLOG((TUTRACE_ERR, "Unexpected 0 subie length. subelt_id %d\n", subelt_id));
			continue;
		}

		subel += WFD_SEID_LEN_SIZE;  /* Length field is 2 byte */
		len -= WFD_SEID_LEN_SIZE;

		/* check attribute length doesn't exceed buffer */
		if (subelt_len > len) {
			WFDCAPDLOG((TUTRACE_ERR, "subelement length.exceeds input!!\n"));
			break;
		}
		len -= subelt_len;	/* for the remaining subelt fields */

		WFDCAPDLOG((TUTRACE_INFO, " subelt_id=%u subelt_len=%u\n", subelt_id, subelt_len));

		/* Important as some vendor may calculate the vendor IE length wrong */
		if (subelt_len == 0)
			continue;  

		switch (subelt_id) {
		case WFD_SEID_DEV_INFO:
			/* WFD subelement id and length */
			out_wfd_ie->devinfo_subelt.eltId = subelt_id;
			out_wfd_ie->devinfo_subelt.len = subelt_len;

			/* Device info bitmap */
			memcpy(&data16, subel, 2);
			out_wfd_ie->devinfo_subelt.info_bmp = ntoh16(data16);
			subel += 2;

			/* RTSP port */
			memcpy(&data16, subel, 2);
			out_wfd_ie->devinfo_subelt.port = ntoh16(data16);
			subel += 2;

			/* Maximum throughput in Mbps */
			memcpy(&data16, subel, 2);
			out_wfd_ie->devinfo_subelt.max_tput = ntoh16(data16);
			subel += 2;

			WFDCAPDLOG((TUTRACE_INFO, "  len=%u device info bitmap 0x%x\n",
				out_wfd_ie->devinfo_subelt.len, out_wfd_ie->devinfo_subelt.info_bmp));
			break;
		case WFD_SEID_ASSOC_BSSID:
			out_wfd_ie->assocbssid_subelt.eltId = subelt_id;
			out_wfd_ie->assocbssid_subelt.len = subelt_len;

			/* Associated bssid */
			memcpy(out_wfd_ie->assocbssid_subelt.bssid, subel, 6);
			subel += 6;

			break;
		case WFD_SEID_ALTERNATIVE_MAC:
			out_wfd_ie->altmac_subelt.eltId = subelt_id;
			out_wfd_ie->altmac_subelt.len = subelt_len;

			/* Alternaive mac address */
			memcpy(out_wfd_ie->altmac_subelt.alt_mac, subel, 6);
			subel += 6;

			break;
		case WFD_SEID_LOCAL_IP_INFO:
			out_wfd_ie->localip_subelt.eltId = subelt_id;
			out_wfd_ie->localip_subelt.len = subelt_len;

			out_wfd_ie->localip_subelt.ip_ver = 1;
			subel += 1;
			
			/* Keep the network order */
			memcpy(&out_wfd_ie->localip_subelt.ip4_addr, subel, 4);
			subel += 4;

			break;
		case WFD_SEID_SESSION_INFO:
			{
			uint16 total_len = 0;
			wifi_wfd_devinfo_desc_t *devinfo_desc;

			out_wfd_ie->sessinfo_subelt.eltId = subelt_id;
			out_wfd_ie->sessinfo_subelt.len = subelt_len;

			/* Get the list of device descriptors */
			devinfo_desc = (wifi_wfd_devinfo_desc_t *)out_wfd_ie->sessinfo_subelt.data;
			out_wfd_ie->sess_dev_total = 0;
			while (total_len < out_wfd_ie->sessinfo_subelt.len) {
				/* Get each attributes of the device descriptor */

				/* Total length of attributes in the device descriptor 23 bytes */

				if (devinfo_desc == NULL)
					break;

				devinfo_desc->len = *subel;
				subel++;

				/* Device addr */
				memcpy(devinfo_desc->peer_mac, subel, 6);
				subel += 6;

				/* Associated bssid */
				memcpy(devinfo_desc->assoc_bssid, subel, 6);
				subel += 6;

				/* WFD device information */
				memcpy(&data16, subel, 2);
				devinfo_desc->info_bmp = ntoh16(data16);

				subel += 2;

				/* WFD device maximum throughput */
				memcpy(&data16, subel, 2);
				devinfo_desc->max_tput = ntoh16(data16);
				subel += 2;

				/* Coupled sink information */
				devinfo_desc->cpl_sink_status = *subel++;
				memcpy(devinfo_desc->cpl_sink_addr, subel, 6);
				subel += 6;
				
				out_wfd_ie->sess_dev_total++;
				WFDCAPDLOG((TUTRACE_INFO, "devinfo_desc->info_bmp 0x%02x, "
					"out_wfd_ie->sess_dev_total %d, devinfo_desc->max_tput %d\n",
					devinfo_desc->info_bmp, out_wfd_ie->sess_dev_total,
					devinfo_desc->max_tput));

				total_len += sizeof(wifi_wfd_devinfo_desc_t);

				/* Move to next device descriptor */
				devinfo_desc = (wifi_wfd_devinfo_desc_t *)((uint8 *)devinfo_desc
					+ sizeof(wifi_wfd_devinfo_desc_t));
			}
			break;
			}
		default:
			WFDCAPDLOG((TUTRACE_INFO, "unknown subel %u len=%u\n",
				subelt_id, subelt_len));
			break;
		}
		 /* increment to next sub element */		
		subel = next_subel;		
	}

	WFDCAPDLOG((TUTRACE_INFO, "Exiting. ie->len %d out_wfd_ie->sess_dev_total %d\n", ie->len, out_wfd_ie->sess_dev_total));
	return ie->len + 2;  /* 2 bytes of vendor IE header size */
}

/* Encode the WFD IE included in TDLS setup request or response action frames */
void
capdie_encode_tdls_setup_wfd_ie(const WFDCAPD_CAP_CONFIG *cap_cfg,
	uint8 *ie_buf, uint16 *ie_len)
{
	uint8 *subel;
	wifi_wfd_ie_t *wfd_ie;
	uint16 dev_cap_bitmap;

	WFDCAPDLOG((TUTRACE_INFO, "Entered.\n"));

	wfd_ie = (wifi_wfd_ie_t *)ie_buf;
	*ie_len = 0;

	/* Add the WFD IE header */
	subel = capdie_encode_wfd_ie_hdr(wfd_ie, ie_len);

	/* Generate the WFD device information bitmap */
	dev_cap_bitmap = capdie_encode_dev_cap_bitmap(cap_cfg);

	/* Add the Capability Info subelement */
	subel = capdie_encode_wfd_se_devinfo(dev_cap_bitmap, cap_cfg->rtsp_tcp_port, 
		cap_cfg->max_tput, subel, ie_len);

	/* Associated BSSID IE */
	subel = capdie_encode_wfd_se_associated_bssid(&cap_cfg->tdls_cfg.assoc_bssid, subel, ie_len);

	/* Local IP address in the network */
	subel = capdie_encode_wfd_se_local_ip(cap_cfg->tdls_cfg.local_ip, subel, ie_len);

	/* Set WFD IE length */
	wfd_ie->len = (uint8) *ie_len - WFD_VNDR_IE_HDR_LEN;

	WFDCAPDLOG((TUTRACE_INFO, "Exiting. wfd_ie total data len %u\n",
		subel - ((uint8*)wfd_ie)));
}

/*
 * Traverse to next TLV.
 */
const uint8 *
capdie_next_tlv(const uint8 *tlv_buf, uint *buflen)
{
	const uint8 *tlv = 0;
	int length = *buflen;

	if (length >= 2) {
		int tlvlen = *(tlv_buf + 1);
		length -= 2;
		if (length >= tlvlen) {
			tlv = tlv_buf + 2 + tlvlen;
			length -= tlvlen;
		}
	}

	*buflen = length;
	return tlv;
}

/*
 * Traverse a buffer of 1-byte tag/1-byte length/variable-length value
 * triples, returning a pointer to the substring whose first element
 * matches 'key'.
 */
const uint8 *
capdie_parse_tlvs(const uint8 *tlv_buf, uint *buflen, uint *ielen, uint key)
{
	const uint8 *cp;
	uint totlen;

	cp = tlv_buf;
	totlen = *buflen;

	/* find tagged parameter */
	while (totlen >= 2) {
		uint tag;
		uint len;

		tag = *cp;
		len = *(cp +1);

		WFDCAPDLOG((TUTRACE_INFO, "  TLV Info: tag=%x len=%d, totlen=%d\n",
			tag, len, totlen));

		/* check length is within buffer */
		if (totlen < (len + 2)) {
//			capdie_log_hexdata(log, "tlv length exceeds buffer",
//				cp, totlen);
			return NULL;
		}

		/* check for matching key */
		if (tag == key) {
			*ielen = len;
			*buflen = totlen;
			return (cp);
		}

		cp += (len + 2);
		totlen -= (len + 2);
	}

	WFDCAPDLOG((TUTRACE_INFO, "no more tlvs, totlen=%d\n", totlen));
	return NULL;
}

bool
capdie_search_wfd_ies(const uint8* cp, uint len, wfd_capdie_ie_t *out_wfd_ie)
{
	uint buflen, ielen = 0;
	const uint8 *ie;
	bool found = false;

	WFDCAPDLOG((TUTRACE_INFO, "Entered\n"));

	WFDCAPDLOG_HEX(("capdie_search_wfd_ies: dev_ie->ie_data", cp, len));

	ie = cp;
	buflen = len;
	while ((ie = capdie_parse_tlvs(ie, &buflen, &ielen, DOT11_MNG_PROPR_ID)) != NULL) {
		if (capdie_is_wfd_ie(ie)) {
			capdie_decode_wfd_ie(ie, out_wfd_ie);
			WFDCAPDLOG((TUTRACE_INFO, "found WFD IE, len=%u offset=%d\n",
				ielen, ie - cp));
			found = true;
			break;
		}
		ie = capdie_next_tlv(ie, &buflen);
	}

	WFDCAPDLOG((TUTRACE_INFO, "Exiting. found=%d\n", found));
	return found;
}
