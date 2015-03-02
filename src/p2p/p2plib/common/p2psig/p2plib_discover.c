/*
 * P2P Library API - Discovery-related functions (OS-independent)
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: p2plib_discover.c,v 1.280 2011-01-19 20:14:59 $
 */
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>

/* P2P Library include files */
#include <BcmP2PAPI.h>
#include <p2plib_api.h>
#include <p2plib_int.h>
#include <p2pwl.h>
#include <p2plib_sd.h>

/* WL driver include files */
#include <bcmendian.h>
#include <wlioctl.h>
#include <bcmutils.h>

/* WPS include files */
#include <reg_prototlv.h>

/* Vendor-specific Information Element ID */
#define P2PAPI_VNDR_SPEC_ELEMENT_ID 0xdd

/* WPS OUI */
uint8 P2PAPI_WPS_OUI[4] = { 0x00, 0x50, 0xf2, 0x04 };

/* P2P attributes */
#define P2PAPI_ATTRIBUTE_ID_SIZE	1
#define P2PAPI_LENGTH_SIZE 			2

/* channel regulatory class */
#define CHANNEL_REG_CLASS	81	/* band WLC_REGCLASS_USA_2G_20MHZ */

#ifndef SOFTAP_ONLY



static uint8
p2papi_generate_grp_cap_bitmap(p2papi_instance_t* hdl)
{
	uint8 grp_cap_bm = 0;

	if (hdl->is_ap)
		grp_cap_bm |= P2P_CAPSE_GRP_OWNER;
	if (hdl->persistent_grp)
		grp_cap_bm |= P2P_CAPSE_PERSIST_GRP | P2P_CAPSE_GRP_PERSISTENT;
	if (hdl->is_intra_bss)
		grp_cap_bm |= P2P_CAPSE_GRP_INTRA_BSS;
	if (hdl->is_provisioning)
		grp_cap_bm |= P2P_CAPSE_GRP_FORMATION;
	if (hdl->client_list_count >= (int32) hdl->ap_config.maxClients)
		grp_cap_bm |= P2P_CAPSE_GRP_LIMIT;

	return grp_cap_bm;
}

static uint8
p2papi_generate_dev_cap_bitmap(p2papi_instance_t* hdl)
{
	uint8 dev_cap_bm = 0;

	if (hdl->sd.is_service_discovery)
		dev_cap_bm |= P2P_CAPSE_DEV_SERVICE_DIS;
	if (hdl->is_client_discovery)
		dev_cap_bm |= P2P_CAPSE_DEV_CLIENT_DIS;
	if (hdl->is_concurrent)
		dev_cap_bm |= P2P_CAPSE_DEV_CONCURRENT;
	if (hdl->is_managed_device)
		dev_cap_bm |= P2P_CAPSE_DEV_INFRA_MAN;
	if (hdl->is_connected || hdl->is_wps_enrolling ||
		hdl->conn_state == P2PAPI_ST_NEG_CONFIRMED)
		dev_cap_bm |= P2P_CAPSE_DEV_LIMIT;
	if (hdl->is_invitation)
		dev_cap_bm |= P2P_CAPSE_INVITE_PROC;

	return dev_cap_bm;
}

#endif /* not SOFTAP_ONLY */

/* Fill in a probe request WPS IE header */
static void
p2papi_encode_wps_ie_begin(p2papi_instance_t* hdl, p2papi_p2p_ie_enc_t *wps_ie)
{
	memset(wps_ie, 0, sizeof(*wps_ie));

	wps_ie->id = P2PAPI_VNDR_SPEC_ELEMENT_ID;
	wps_ie->len = 3 + 1;	/* includes oui and data */
	wps_ie->OUI[0] = WPS_OUI[0];
	wps_ie->OUI[1] = WPS_OUI[1];
	wps_ie->OUI[2] = WPS_OUI[2];
	wps_ie->data[0] = WPS_OUI_TYPE;

	wps_ie->subelts = &wps_ie->data[1];
}



static void
p2papi_enc_wps_attr_u8(p2papi_p2p_ie_enc_t *wps_ie, uint16 attr_id, uint8 data)
{
	uint16 val;
	uint8 *valptr = (uint8*) &val;
	uint8 *subel = wps_ie->subelts;

	/* Add the attribute ID */
	val = HTON16(attr_id);
	*subel++ = valptr[0];
	*subel++ = valptr[1];

	/* Add the attribute length */
	val = HTON16(1);
	*subel++ = valptr[0];
	*subel++ = valptr[1];

	/* Add the attribute data */
	*subel++ = data;

	/* Update the IE's length and attribute ptr */
	wps_ie->subelts = subel;
	wps_ie->len += 1 + 2 + 2;
}

static void
p2papi_enc_wps_attr_u16(p2papi_p2p_ie_enc_t *wps_ie, uint16 attr_id,
	uint16 data)
{
	uint16 val;
	uint8 *valptr = (uint8*) &val;
	uint8 *subel = wps_ie->subelts;

	/* Add the attribute ID */
	val = HTON16(attr_id);
	*subel++ = valptr[0];
	*subel++ = valptr[1];

	/* Add the attribute length */
	val = HTON16(2);
	*subel++ = valptr[0];
	*subel++ = valptr[1];

	/* Add the attribute data */
	val = HTON16(data);
	*subel++ = valptr[0];
	*subel++ = valptr[1];

	/* Update the IE's length and attribute ptr */
	wps_ie->subelts = subel;
	wps_ie->len += 2 + 2 + 2;
}

/* Encode WPS IE for provision discovery frame */
void
p2papi_encode_provdis_wps_ie(p2papi_instance_t* hdl,
	p2papi_p2p_ie_enc_t *wps_ie, uint8 *name, uint8 name_len,
	BCMP2P_BOOL enc_cfg_meth, uint16 cfg_methods,
	uint16 *total_ie_len)
{
	(void) name;
	(void) name_len;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"enc_provdis_wps_ie: cfgmeth=0x%04x (pinmode=%d pin=%s)\n",
		cfg_methods, hdl->ap_config.WPSConfig.wpsPinMode,
		hdl->ap_config.WPSConfig.wpsPin));

	/* Fill in the WPS IE header */
	p2papi_encode_wps_ie_begin(hdl, wps_ie);

	/* Add the Config Methods attribute */
	if (enc_cfg_meth) {
		p2papi_enc_wps_attr_u16(wps_ie, WPS_ID_CONFIG_METHODS, cfg_methods);
	}

	*total_ie_len = wps_ie->len + 2;
}

/* Encode WPS IE for group owner negotiation frame */
void
p2papi_encode_gon_wps_ie(p2papi_instance_t* hdl, p2papi_p2p_ie_enc_t *wps_ie,
	uint8 *name, uint8 name_len, BCMP2P_BOOL enc_cfg_meth, uint16 cfg_methods,
	uint16 dev_pwdid, uint16 *total_ie_len)
{
	/* prevent unused parameter compiler warnings */
	(void) enc_cfg_meth;
	(void) cfg_methods;
	(void) name;
	(void) name_len;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"encode_gon_wps_ie: pwdid=%d (pinmode=%d pin=%s cfgmeth=0x%04x)\n",
		dev_pwdid, hdl->ap_config.WPSConfig.wpsPinMode,
		hdl->ap_config.WPSConfig.wpsPin, cfg_methods));

	/* Fill in the WPS IE header */
	p2papi_encode_wps_ie_begin(hdl, wps_ie);

	/* Add the Version attribute */
	p2papi_enc_wps_attr_u8(wps_ie, WPS_ID_VERSION, 0x10);

	/* Add the Device Password ID attribute */
	p2papi_enc_wps_attr_u16(wps_ie, WPS_ID_DEVICE_PWD_ID, dev_pwdid);

	*total_ie_len = wps_ie->len + 2;
}

/* Encode a probe request WPS IE */
static void
p2papi_encode_prbreq_wps_ie(p2papi_instance_t* hdl,
	p2papi_p2p_ie_enc_t *wps_ie, uint16 primdev_cat, uint16 primdev_subcat,
	uint8 *name, uint8 name_len, uint16 cfg_methods, uint16 *total_ie_len)
{
	int max_length;
	char *buf;
	int devpwdid;
	char device_name[64+1];
	int length = 0;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"enc_prbreq_wps_ie: name=%s len=%u\n",
		name, name_len));

	/* Fill in the WPS IE header */
	p2papi_encode_wps_ie_begin(hdl, wps_ie);

	/* calculate remaining data size and end of data */
	max_length = sizeof(wps_ie->data) - (wps_ie->len - sizeof(wps_ie->OUI));
	buf = (char *)wps_ie->subelts;

	/* activate pushbutton if pbc mode and pushed */
	devpwdid = hdl->ap_config.WPSConfig.wpsIsButtonPushed ?
		WPS_DEVICEPWDID_PUSH_BTN : WPS_DEVICEPWDID_DEFAULT;
	BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
		"    wps_ie=%p cfgmeth=0x%04x devcat=%u subcat=%u devpwdid=%d\n",
		wps_ie, cfg_methods, primdev_cat, primdev_subcat, devpwdid));

	/* null-terminate device name */
	memcpy(device_name, name, name_len);
	device_name[name_len] = '\0';

#if P2PAPI_ENABLE_WPS
	/* encode WPS IE */
#ifndef SECONDARY_DEVICE_TYPE
		length = wpscli_softap_encode_probe_request_wps_ie(buf, max_length,
			cfg_methods, primdev_cat, primdev_subcat, devpwdid, device_name,
			hdl->req_dev_type, hdl->req_dev_subcat);
#else
		length = wpscli_softap_encode_probe_request_wps_ie(buf, max_length,
			cfg_methods, primdev_cat, primdev_subcat, devpwdid, device_name,
			hdl->req_dev_type, hdl->req_dev_subcat, hdl->sec_dev_oui,
				hdl->sec_dev_type, hdl->sec_dev_subcat);
#endif /* SECONDARY_DEVICE_TYPE */
#else
	/* prevent unused parameter compiler warnings */
	(void) cfg_methods;
	(void) primdev_cat;
	(void) primdev_subcat;
	(void) devpwdid;
#endif

	/* update length */
	wps_ie->len += length;

	/* total length of wps_ie */
	*total_ie_len = wps_ie->len + 2;
}

/* Encode a probe response WPS IE */
static void
p2papi_encode_prbresp_wps_ie(p2papi_instance_t* hdl,
	p2papi_p2p_ie_enc_t *wps_ie, uint16 primdev_cat, uint16 primdev_subcat,
#if SECONDARY_DEVICE_TYPE
		uint16 secdev_cat, uint16 secdev_subcat,
#endif
	uint8 *name, uint8 name_len, BCMP2P_BOOL enc_cfg_meth, uint16 cfg_methods,
	uint16 *total_ie_len)
{
	int max_length;
	char *buf;
	char device_name[64+1];
	int length = 0;
	uint16 devpwdid;
	int window_is_open = false;

	/* Suppress compiler warnings on unused parameters */
	(void) enc_cfg_meth;

	/* Fill in the WPS IE header */
	p2papi_encode_wps_ie_begin(hdl, wps_ie);

	/* calculate remaining data size and end of data */
	max_length = sizeof(wps_ie->data) - (wps_ie->len - sizeof(wps_ie->OUI));
	buf = (char *)wps_ie->subelts;

	/* null-terminate device name */
	memcpy(device_name, name, name_len);
	device_name[name_len] = '\0';

#if P2PAPI_ENABLE_WPS
	/* activate pushbutton if pbc mode and pushed */
	devpwdid = hdl->ap_config.WPSConfig.wpsIsButtonPushed ?
		WPS_DEVICEPWDID_PUSH_BTN : WPS_DEVICEPWDID_DEFAULT;
	window_is_open = brcm_wpscli_softap_is_wps_window_open();

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"enc_prbresp_wps_ie: name=%s len=%u push=%d, SelRegistrar=%d\n",
		name, name_len, hdl->ap_config.WPSConfig.wpsIsButtonPushed, window_is_open));
	BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
		"    cfgmeth=0x%04x devcat=%u subcat=%u devpwdid=%d\n",
		cfg_methods, primdev_cat, primdev_subcat, devpwdid));

	length = wpscli_softap_encode_probe_response_wps_ie(buf, max_length,
		cfg_methods, primdev_cat, primdev_subcat,
#if SECONDARY_DEVICE_TYPE
		secdev_cat, secdev_subcat,
#endif
		devpwdid, device_name, window_is_open);
#endif /* P2PAPI_ENABLE_WPS */


	/* update length */
	wps_ie->len += length;

	/* total length of wps_ie */
	*total_ie_len = wps_ie->len + 2;
}

/* Encode a beacon WPS IE */
void
p2papi_encode_beacon_wps_ie(p2papi_instance_t* hdl,
	p2papi_p2p_ie_enc_t *wps_ie, uint16 *total_ie_len)
{
	int max_length;
	char *buf;
	int length = 0;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"enc_beacon_wps_ie: wps_ie=%p push=%d\n",
		wps_ie,	hdl->ap_config.WPSConfig.wpsIsButtonPushed));

	/* Fill in the WPS IE header */
	p2papi_encode_wps_ie_begin(hdl, wps_ie);

	/* calculate remaining data size and end of data */
	max_length = sizeof(wps_ie->data) - (wps_ie->len - sizeof(wps_ie->OUI));
	buf = (char *)wps_ie->subelts;

#if P2PAPI_ENABLE_WPS
	/* encode WPS IE */
	length = wpscli_softap_encode_beacon_wps_ie(buf, max_length, (char*)hdl->fname_ssid,
	                                            hdl->pri_dev_type, hdl->pri_dev_subcat);
#endif

	/* update length */
	wps_ie->len += length;

	/* total length of wps_ie */
	*total_ie_len = wps_ie->len + 2;
}


#ifndef SOFTAP_ONLY

static  uint8*
encode_integer(uint8 *buf, int length, uint32 value)
{
	int i;
	for (i = 0; i < length; i++) {
		*buf++ = value >> (i * 8);
	}
	return buf;
}

static uint8*
decode_integer(uint8 *buf, int length, uint32 *value)
{
	int i;
	*value = 0;
	for (i = 0; i < length; i++) {
		*value |= *buf++ << (i * 8);
	}
	return buf;
}


/* Encode a P2P IE header */
static uint8*
p2papi_encode_p2p_ie_hdr(p2papi_instance_t* hdl, wifi_p2p_ie_t *p2p_ie,
	uint16 *ie_len)
{
	p2p_ie->id = P2P_IE_ID;
	p2p_ie->len = (uint8) *ie_len;
	p2p_ie->OUI[0] = P2P_OUI[0];
	p2p_ie->OUI[1] = P2P_OUI[1];
	p2p_ie->OUI[2] = P2P_OUI[2];
	p2p_ie->oui_type = P2P_VER;

	*ie_len += 6;
	return p2p_ie->subelts;
}

static void
p2papi_encode_p2p_ie_length(uint8 *buf, uint16 length)
{
	/* 2-byte little endian */
	*buf++ = (uint8) length;
	*buf++ = length >> 8;
}

uint16
p2papi_decode_p2p_ie_length(uint8 *buf)
{
	uint16 length;
	/* 2-byte little endian */
	length = *buf++;
	length |= *buf++ << 8;
	return length;
}

/* Encode P2P IE subelement: Status */
static uint8*
p2papi_enc_se_status(uint8 status, uint8 *subel, uint16 *ie_len)
{
	*subel++ = P2P_SEID_STATUS;		/* Sub-element ID */
	p2papi_encode_p2p_ie_length(subel, 1);	/* Sub-element length */
	subel += P2PAPI_LENGTH_SIZE;

	*subel++ = status;				/* Status Code: P2P_STATSE_* */

	*ie_len += P2PAPI_ATTRIBUTE_ID_SIZE + P2PAPI_LENGTH_SIZE + 1;
	return subel;
}

/* Encode P2P IE subelement: Capability info */
static uint8*
p2papi_enc_se_capability(uint8 dev_cap_bitmap, uint8 grp_cap_bitmap,
	uint8 *subel, uint16 *ie_len)
{
	*subel++ = P2P_SEID_P2P_CAPABILITY;	/* Sub-element ID */
	p2papi_encode_p2p_ie_length(subel, 2);	/* Sub-element length */
	subel += P2PAPI_LENGTH_SIZE;

	*subel++ = dev_cap_bitmap;	/* Device Capability Bitmap: P2P_CAPSE_DEV_* */
	*subel++ = grp_cap_bitmap;	/* Group Capability Bitmap: P2P_CAPSE_GRP_* */

	*ie_len += P2PAPI_ATTRIBUTE_ID_SIZE + P2PAPI_LENGTH_SIZE + 2;
	return subel;
}

/* Encode P2P IE subelement: Device ID */
static uint8*
p2papi_enc_se_dev_id(uint8 *mac, uint8 *subel, uint16 *ie_len)
{
	/* Add the Device ID subelement */
	*subel++ = P2P_SEID_DEV_ID;		/* Sub-element ID */
	p2papi_encode_p2p_ie_length(subel, 6);	/* Sub-element length */
	subel += P2PAPI_LENGTH_SIZE;
	memcpy(subel, mac, 6);			/* P2P Device address */
	subel += 6;

	*ie_len += P2PAPI_ATTRIBUTE_ID_SIZE + P2PAPI_LENGTH_SIZE + 6;
	return subel;
}

/* Encode P2P IE subelement: Intent */
static uint8*
p2papi_enc_se_intent(uint8 intent, uint8 *subel, uint16 *ie_len)
{
	*subel++ = P2P_SEID_INTENT;			/* Sub-element ID */
	p2papi_encode_p2p_ie_length(subel, 1);		/* Sub-element length */
	subel += P2PAPI_LENGTH_SIZE;

	*subel++ = intent;					/* Group Owner Intent */

	*ie_len += P2PAPI_ATTRIBUTE_ID_SIZE + P2PAPI_LENGTH_SIZE + 1;
	return subel;
}

/* Encode P2P IE subelement: Configuration Timeout */
static uint8*
p2papi_enc_se_cfg_timeout(uint8 go_cfg_tmo_10ms, uint8 client_cfg_tmo_10ms,
	uint8 *subel, uint16 *ie_len)
{
	*subel++ = P2P_SEID_CFG_TIMEOUT;	/* Sub-element ID */
	p2papi_encode_p2p_ie_length(subel, 2);		/* Sub-element length */
	subel += P2PAPI_LENGTH_SIZE;

	/* Time needed by the device to get configured and function as a Group
	 * Owner, in units of 10ms.
	 */
	*subel++ = go_cfg_tmo_10ms;

	/* Time needed by the device to get configured and function as a P2P
	 * Client, in units of 10ms.
	 */
	*subel++ = client_cfg_tmo_10ms;

	*ie_len += P2PAPI_ATTRIBUTE_ID_SIZE + P2PAPI_LENGTH_SIZE + 2;
	return subel;
}

/* Encode P2P IE subelement: Channel */
static uint8*
p2papi_enc_se_listen_channel(char *country, BCMP2P_CHANNEL *channel,
	uint8 *subel, uint16 *ie_len)
{
	*subel++ = P2P_SEID_LISTEN_CHANNEL;		/* Sub-element ID */
	p2papi_encode_p2p_ie_length(subel, 3 + 1 + 1);		/* Sub-element length */
	subel += P2PAPI_LENGTH_SIZE;

	memcpy(subel, country, 3);			/* Country */
	subel += 3;
	*subel++ = channel->channel_class;				/* Regulatory Class */
	*subel++ = channel->channel;					/* Channel Number */

	*ie_len += P2PAPI_ATTRIBUTE_ID_SIZE + P2PAPI_LENGTH_SIZE + 3 + 1 + 1;
	return subel;
}

/* Encode P2P IE subelement: Operating Channel */
static uint8*
p2papi_enc_se_op_channel(char *country, BCMP2P_CHANNEL *channel,
	uint8 *subel, uint16 *ie_len)
{
	/* Only encode non-zero channel numbers. */
	if (channel->channel == 0) {
		return subel;
	}

	*subel++ = P2P_SEID_OPERATING_CHANNEL;		/* Sub-element ID */
	p2papi_encode_p2p_ie_length(subel, 3 + 1 + 1);		/* Sub-element length */
	subel += P2PAPI_LENGTH_SIZE;

	memcpy(subel, country, 3);			/* Country */
	subel += 3;
	*subel++ = channel->channel_class;	/* Regulatory Class */
	*subel++ = channel->channel;		/* Channel Number */

	*ie_len += P2PAPI_ATTRIBUTE_ID_SIZE + P2PAPI_LENGTH_SIZE + 3 + 1 + 1;
	return subel;
}

/* Encode P2P IE subelement: Channel List */
static uint8*
p2papi_enc_se_chan_list(char *country_code,
	p2p_chanlist_t *channel_list, uint8 *subel, uint16 *ie_len)
{
	uint8 *subel_len;
	int length;
	int i, j;

	/* Add the Channel List subelement */
	*subel++ = P2P_SEID_CHAN_LIST;		/* Sub-element ID */
	subel_len = subel; 	/* point to length for later update */
	subel += P2PAPI_LENGTH_SIZE;

	memcpy(subel, country_code, 3);		/* Country String */
	subel += 3;

	/* length up to and including country */
	length = P2PAPI_ATTRIBUTE_ID_SIZE + P2PAPI_LENGTH_SIZE + 3;

	for (i = 0; i < channel_list->num_entries; i++) {
		*subel++ = channel_list->entries[i].band;
		*subel++ = channel_list->entries[i].num_channels;
		for (j = 0; j < channel_list->entries[i].num_channels; j++)
			*subel++ = channel_list->entries[i].channels[j];
		length += 2 + channel_list->entries[i].num_channels;
	}

	p2papi_encode_p2p_ie_length(subel_len,
		length - P2PAPI_ATTRIBUTE_ID_SIZE - P2PAPI_LENGTH_SIZE);
	*ie_len += length;
	return subel;
}

/* Encode P2P IE subelement: P2P Group BSSID */
static uint8*
p2papi_enc_se_grp_bssid(uint8* bssid, uint8 *subel, uint16 *ie_len)
{
	*subel++ = P2P_SEID_GRP_BSSID;		/* Sub-element ID */
	p2papi_encode_p2p_ie_length(subel, 6);		/* Sub-element length */
	subel += P2PAPI_LENGTH_SIZE;

	memcpy(subel, bssid, 6);			/* P2P Group BSSID */
	subel += 6;

	*ie_len += P2PAPI_ATTRIBUTE_ID_SIZE + P2PAPI_LENGTH_SIZE + 6;
	return subel;
}

/* Encode P2P IE subelement: P2P Group ID */
static uint8*
p2papi_enc_se_group_id(uint8* dev_mac_addr, uint8 *ssid, int ssid_len,
	uint8 *subel, uint16 *ie_len)
{
	*subel++ = P2P_SEID_GROUP_ID;		/* Sub-element ID */
	p2papi_encode_p2p_ie_length(subel, 6 + ssid_len);	/* Sub-element length */
	subel += P2PAPI_LENGTH_SIZE;

	memcpy(subel, dev_mac_addr, 6);			/* P2P Device address */
	subel += 6;
	memcpy(subel, ssid, ssid_len);			/* SSID */
	subel += ssid_len;

	*ie_len += P2PAPI_ATTRIBUTE_ID_SIZE + P2PAPI_LENGTH_SIZE + 6 + ssid_len;
	return subel;
}

/* Encode P2P IE subelement: Extended Listen Timing */
static uint8*
p2papi_enc_se_xt_listen_timing(uint16 avail_period, uint16 avail_interval,
	uint8 *subel, uint16 *ie_len)
{
	*subel++ = P2P_SEID_XT_TIMING;		/* Sub-element ID */
	p2papi_encode_p2p_ie_length(subel, 4);		/* Sub-element length */
	subel += P2PAPI_LENGTH_SIZE;

	*subel++ = avail_period & 0xff;		/* Availability Period */
	*subel++ = avail_period >> 8;

	*subel++ = avail_interval & 0xff;	/* Availability Interval */
	*subel++ = avail_interval >> 8;

	*ie_len += P2PAPI_ATTRIBUTE_ID_SIZE + P2PAPI_LENGTH_SIZE + 4;
	return subel;
}

/* Encode P2P IE subelement: Intended P2P Interface Address */
static uint8*
p2papi_enc_se_intd_if_addr(uint8 *mac, uint8 *subel, uint16 *ie_len)
{
	*subel++ = P2P_SEID_INTINTADDR;		/* Sub-element ID */
	p2papi_encode_p2p_ie_length(subel, 6);		/* Sub-element length */
	subel += P2PAPI_LENGTH_SIZE;

	memcpy(subel, mac, 6);				/* P2P Interface Address */
	subel += 6;

	*ie_len += P2PAPI_ATTRIBUTE_ID_SIZE + P2PAPI_LENGTH_SIZE + 6;
	return subel;
}

/* Encode P2P IE subelement: P2P Device Info */
static uint8*
p2papi_enc_se_devinfo(uint8 *dev_addr, uint8 *name, uint8 name_len,
	uint16 wps_cfg_meths, uint16 primdev_cat, uint16 primdev_subcat,
#ifndef SECONDARY_DEVICE_TYPE
	uint8 *subel, uint16 *ie_len)
#else
	uint8 *subel, uint16 *ie_len, uint8 secdev_cat, uint8 secdev_subcat, uint32 secdev_oui)
#endif
{
	/* Add the Device Info subelement */
	*subel++ = P2P_SEID_DEV_INFO;		/* Sub-element ID */
	p2papi_encode_p2p_ie_length(subel,
#ifndef SECONDARY_DEVICE_TYPE
		6 + 2 + 8 + 1 + (2 + 2 + name_len));	/* Sub-element length */
#else
		6 + 2 + 8 + 1 + 8 + (2 + 2 + name_len));	/* Sub-element length */
#endif		
	subel += P2PAPI_LENGTH_SIZE;

	/* P2P Device Address */
	BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
		"  p2papi_enc_se_devinfo: P2PDevAddr=%02x:%02x:%02x:%02x:%02x:%02x\n",
		dev_addr[0], dev_addr[1], dev_addr[2], dev_addr[3], dev_addr[4],
		dev_addr[5]));
	memcpy(subel, dev_addr, 6);
	subel += 6;

	/* Config Methods (big endian) */
	*subel = (wps_cfg_meths >> 8) & 0xff;
	*(subel + 1) = wps_cfg_meths & 0xff;
	subel += 2;

	/* Primary Device Type (big endian) */
	*subel = (primdev_cat >> 8) & 0xff;
	*(subel + 1) = primdev_cat & 0xff;
	*(subel + 2) = WPS_OUI[0];
	*(subel + 3) = WPS_OUI[1];
	*(subel + 4) = WPS_OUI[2];
	*(subel + 5) = WPS_OUI_TYPE;
	*(subel + 6) = (primdev_subcat >> 8) & 0xff;
	*(subel + 7) = (primdev_subcat >> 0) & 0xff;	
	subel += 8;

	/* Number of Secondary Devices */
#ifndef SECONDARY_DEVICE_TYPE
	*subel = 0;
	subel += 1;
#else
	*subel = 0x01;
	subel += 1;

	/* Secondary Device Type List (big endian) */
	*subel = (secdev_cat >> 8) & 0xff;
	*(subel + 1) = secdev_cat & 0xff;
	*(subel + 2) = (secdev_oui >> 24) & 0xff;
	*(subel + 3) = (secdev_oui >> 16) & 0xff;
	*(subel + 4) = (secdev_oui >>  8) & 0xff;
	*(subel + 5) = (secdev_oui >>  0) & 0xff;
	*(subel + 6) = (secdev_subcat >> 8) & 0xff;
	*(subel + 7) = (secdev_subcat >> 0) & 0xff;
	subel += 8;
#endif

	/* Device Name - friendly name in WPS TLV format */
	*subel = (WPS_ID_DEVICE_NAME >> 8) & 0xff;
	*(subel + 1) = (WPS_ID_DEVICE_NAME) & 0xff;
	subel += 2;
	*subel = 0;
	*(subel + 1) = (name_len) & 0xff;
	subel += 2;
	memcpy(subel, name, name_len);
	subel += name_len;

	*ie_len += P2PAPI_ATTRIBUTE_ID_SIZE + P2PAPI_LENGTH_SIZE +
#ifndef SECONDARY_DEVICE_TYPE
				6 + 2 + 8 + 1 + (2 + 2 + name_len);
#else
				6 + 2 + 8 + 1 + 8 + (2 + 2 + name_len);
#endif

	return subel;
}

/* Encode P2P IE subelement: P2P Group Info */
static uint8*
p2papi_enc_se_grpinfo(p2papi_instance_t *hdl,
	uint16 max_ie_len, uint8 *subel, uint16 *ie_len)
{
	int i;
	uint8 *subel_lenp;
	uint8 subel_len;
	uint8 *cid_lenp;
	uint8 cid_len;
	uint8 *addr;
	uint16 cfg_meth;
	p2papi_client_info_t *cinfo;
	uint16 namelen;

	BCMP2PLOG((BCMP2P_LOG_INFO, TRUE, "  p2papi_enc_se_grpinfo: %u clients\n",
		hdl->client_list_count));

	/* Add the Group Info subelement */
	*subel++ = P2P_SEID_GROUP_INFO;		/* Sub-element ID */
	subel_lenp = subel;				/* Sub-element length (fill in below) */
	subel += P2PAPI_LENGTH_SIZE;
	subel_len = 0;

	for (i = 0; i < hdl->client_list_count; i++) {
		cinfo = &hdl->client_list[i];
		if (!cinfo->is_p2p_client) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "  %d) legacy client, ignored\n"));
			continue;
		}
		namelen = (cinfo->devinfo.name_len_be[0] << 8)
			| cinfo->devinfo.name_len_be[1];
		if (namelen > 32)
			namelen = 32;

		/* Check if there is enough space remaining in the IE encode buffer */
		if (*ie_len + 1 + 6 + 6 + 1 + 2 + 8 + 1 + 2 + 2 + namelen
			> max_ie_len) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
				"p2papi_enc_se_grpinfo: out of space at client %d\n", i));
			break;
		}

		/* Client Info Descriptor: Length (fill in below) */
		cid_len = 0;
		cid_lenp = subel;
		subel += 1;

		/* Client Info Descriptor: P2P Device Address */
		addr = cinfo->p2p_dev_addr;
		memcpy(subel, addr, 6);
		subel += 6;
		cid_len += 6;

		/* Client Info Descriptor: P2P Interface Address */
		addr = cinfo->p2p_int_addr;
		memcpy(subel, addr, 6);
		subel += 6;
		cid_len += 6;

		/* Client Info Descriptor: Device Capability Bitmap */
		*subel = cinfo->dev_cap_bitmap;
		subel += 1;
		cid_len += 1;

		/* Client Info Descriptor: Config Methods (little endian) */
		cfg_meth = cinfo->devinfo.wps_cfg_meths;
		*subel = cfg_meth & 0xff;
		*(subel+1) = cfg_meth >> 8;
		subel += 2;
		cid_len += 2;

		/* Client Info Descriptor: Primary Device Type */
		addr = cinfo->devinfo.pri_devtype;
		memcpy(subel, addr, 8);
		subel += 8;
		cid_len += 8;

		/* Client Info Descriptor: Number of Secondary Devices */
		*subel = 0;
		subel += 1;
		cid_len += 1;

		/* Client Info Descriptor: Device Name in WPS TLV format */
		*subel = cinfo->devinfo.name_type_be[0];
		*(subel+1) = cinfo->devinfo.name_type_be[1];
		subel += 2;
		cid_len += 2;

		*subel = (namelen & 0xff00) >> 8;
		*(subel+1) = (namelen & 0xff);
		subel += 2;
		cid_len += 2;

		addr = cinfo->devinfo.name_val;
		memcpy(subel, addr, namelen);
		subel += namelen;
		cid_len += namelen;

		/* Client Info Descriptor: Length */
		*cid_lenp = cid_len;
		subel_len += cid_len + 1;

		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "  %d) cidlen=%d devcap=0x%x"
			" cfgMeth=0x%x devaddr=%02x:%02x:%02x:%02x:%02x:%02x\n",
			i, cid_len, cinfo->dev_cap_bitmap, cinfo->devinfo.wps_cfg_meths,
			cinfo->p2p_dev_addr[0], cinfo->p2p_dev_addr[1],
			cinfo->p2p_dev_addr[2], cinfo->p2p_dev_addr[3],
			cinfo->p2p_dev_addr[4], cinfo->p2p_dev_addr[5]));
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"     intaddr=%02x:%02x:%02x:%02x:%02x:%02x"
			" fnameTLV=0x%02x%02x,0x%02x%02x,%s\n",
			cinfo->p2p_int_addr[0], cinfo->p2p_int_addr[1],
			cinfo->p2p_int_addr[2], cinfo->p2p_int_addr[3],
			cinfo->p2p_int_addr[4], cinfo->p2p_int_addr[5],
			cinfo->devinfo.name_type_be[0], cinfo->devinfo.name_type_be[1],
			(namelen & 0xff00) >> 8, (namelen & 0xff),
			cinfo->devinfo.name_val));
	}
	p2papi_encode_p2p_ie_length(subel_lenp, subel_len);

	*ie_len += P2PAPI_ATTRIBUTE_ID_SIZE + P2PAPI_LENGTH_SIZE + subel_len;
	return subel;
}

/* Encode P2P IE subelement: Notice of Absence */
static uint8*
p2papi_enc_se_noa(uint8 index, BCMP2P_BOOL oppps, uint8 ctwindow,
	uint8 num_noa_desc, wifi_p2p_noa_desc_t *noa_desc,
	uint8 *subel, uint16 *ie_len)
{
	int length = num_noa_desc * 13 + 2;
	uint8 value;
	int i;

	*subel++ = P2P_SEID_ABSENCE;	/* Sub-element ID */
	p2papi_encode_p2p_ie_length(subel, length);	/* Sub-element length */
	subel += P2PAPI_LENGTH_SIZE;

	*subel++ = index;
	value = ctwindow & P2P_NOA_CTW_MASK;
	if (oppps)
		value |= P2P_NOA_OPS_MASK;
	*subel++ = value;
	for (i = 0; i < num_noa_desc; i++) {
		*subel++ = noa_desc[i].cnt_type;
		subel = encode_integer(subel,
			sizeof(noa_desc[i].duration), noa_desc[i].duration);
		subel = encode_integer(subel,
			sizeof(noa_desc[i].interval), noa_desc[i].interval);
		subel = encode_integer(subel,
			sizeof(noa_desc[i].start), noa_desc[i].start);
	}

	*ie_len += P2PAPI_ATTRIBUTE_ID_SIZE + P2PAPI_LENGTH_SIZE + length;
	return subel;
}

/* Encode P2P IE attribute: Invitation Flags */
static uint8*
p2papi_enc_se_invite_flags(uint8 invite_flags, uint8 *subel, uint16 *ie_len)
{
	*subel++ = P2P_SEID_INVITATION_FLAGS;
	p2papi_encode_p2p_ie_length(subel, 1);
	subel += P2PAPI_LENGTH_SIZE;

	*subel++ = invite_flags;

	*ie_len += P2PAPI_ATTRIBUTE_ID_SIZE + P2PAPI_LENGTH_SIZE + 1;
	return subel;
}

/* Encode P2P IE subelement: P2P Interface */
static uint8*
p2papi_enc_se_interface(uint8 *devaddr, uint8* intaddr,
	uint8 *subel, uint16 *ie_len)
{
	BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
		"  p2papi_enc_se_interface: dev=%02x:%02x:%02x:%02x:%02x:%02x"
		" int=%02x:%02x:%02x:%02x:%02x:%02x\n",
		devaddr[0], devaddr[1], devaddr[2], devaddr[3], devaddr[4], devaddr[5],
		intaddr[0], intaddr[1], intaddr[2], intaddr[3], intaddr[4], intaddr[5]));

	*subel++ = P2P_SEID_P2P_IF;
	p2papi_encode_p2p_ie_length(subel, 6 + 1 + 6);
	subel += P2PAPI_LENGTH_SIZE;

	/* P2P Device Address */
	memcpy(subel, devaddr, 6);
	subel += 6;

	/* P2P Interface Address Count */
	*subel++ = 1;

	/* P2P Interface Address List */
	memcpy(subel, intaddr, 6);
	subel += 6;

	*ie_len += P2PAPI_ATTRIBUTE_ID_SIZE + P2PAPI_LENGTH_SIZE + 6 + 1 + 6;
	return subel;
}


/* Encode a probe request P2P IE */
static void
p2papi_encode_prbreq_p2p_ie(p2papi_instance_t* hdl,
	uint8 dev_cap_bitmap, uint8 grp_cap_bitmap,
	char *country, BCMP2P_CHANNEL *listen_channel,
	BCMP2P_BOOL is_ext_listen, uint16 ext_listen_period, uint16 ext_listen_interval,
	BCMP2P_CHANNEL *op_channel, wifi_p2p_ie_t *p2p_ie, uint16 *ie_len)
{
	uint8 *subel;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"enc_prbreq_p2p_ie: devcap=0x%x grpcap=0x%x liCh=%d:%d opCh=%d:%d"
		" isel=%d per=%d int=%d\n",
		dev_cap_bitmap, grp_cap_bitmap,
		listen_channel->channel_class, listen_channel->channel,
		op_channel->channel_class, op_channel->channel,
		is_ext_listen, ext_listen_period, ext_listen_interval));

	/* Add the P2P IE header */
	*ie_len = 0;
	subel = p2papi_encode_p2p_ie_hdr(hdl, p2p_ie, ie_len);
	p2p_ie->len = (uint8) *ie_len - 2;
	/* p2papi_dbg_dump_p2p_ie("after enc_p2p_begin  : ", p2p_ie); */

	/* Add the Capability Info subelement */
	subel = p2papi_enc_se_capability(dev_cap_bitmap, grp_cap_bitmap, subel,
		ie_len);
	p2p_ie->len = (uint8) *ie_len - 2;
	/* p2papi_dbg_dump_p2p_ie("after enc_p2p_se_caps: ", p2p_ie); */

	/* Add the Listen Channel subelement */
	subel = p2papi_enc_se_listen_channel(country, listen_channel,
		subel, ie_len);

	/* extended listen timing */
	if (is_ext_listen)
		subel = p2papi_enc_se_xt_listen_timing(
			ext_listen_period, ext_listen_interval,	subel, ie_len);

	/* Add the Operating Channel subelement */
	subel = p2papi_enc_se_op_channel(country, op_channel, subel,
		ie_len);

	p2p_ie->len = (uint8) *ie_len - 2;

	/* p2papi_dbg_dump_p2p_ie("enc_prbreq_p2p_ie end: ", p2p_ie); */
}

/* Encode a probe response P2P IE */
static void
p2papi_encode_prbresp_p2p_ie(p2papi_instance_t* hdl,
	uint8 dev_cap_bitmap, uint8 grp_cap_bitmap,
	BCMP2P_BOOL is_ext_listen, uint16 ext_listen_period,
	uint16 ext_listen_interval,
	uint8* dev_mac_addr, uint8 *friendly_name, uint8 name_len,
	uint16 max_ie_len, wifi_p2p_ie_t *p2p_ie, uint16 *ie_len)
{
	uint8 *subel;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"enc_prbresp_p2p_ie: dcap=0x%x gcap=0x%x ap=%d name=%s\n",
		dev_cap_bitmap, grp_cap_bitmap,	hdl->is_ap, friendly_name));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"        ext listen: isel=%d per=%d int=%d\n",
		is_ext_listen, ext_listen_period, ext_listen_interval));

	/* Add the P2P IE header */
	*ie_len = 0;
	subel = p2papi_encode_p2p_ie_hdr(hdl, p2p_ie, ie_len);
	p2p_ie->len = (uint8) *ie_len - 2;
	/* p2papi_dbg_dump_p2p_ie("after enc_p2p_begin  : ", p2p_ie); */

	/* Add the Capability Info subelement */
	subel = p2papi_enc_se_capability(dev_cap_bitmap, grp_cap_bitmap, subel,
		ie_len);
	p2p_ie->len = (uint8) *ie_len - 2;
	/* p2papi_dbg_dump_p2p_ie("after enc_p2p_se_cap: ", p2p_ie); */

	/* extended listen timing */
	if (is_ext_listen) {
		subel = p2papi_enc_se_xt_listen_timing(
			ext_listen_period, ext_listen_interval,	subel, ie_len);
		p2p_ie->len = (uint8) *ie_len - 2;
	}

	/* Add the P2P Device Info subelement */
	subel = p2papi_enc_se_devinfo(dev_mac_addr, friendly_name, name_len,
		hdl->ap_config.WPSConfig.wpsConfigMethods,
		hdl->pri_dev_type, hdl->pri_dev_subcat,
#ifndef SECONDARY_DEVICE_TYPE
		subel, ie_len);
#else
		subel, ie_len, hdl->sec_dev_type, hdl->sec_dev_subcat, hdl->sec_dev_oui);
#endif	
	p2p_ie->len = (uint8) *ie_len - 2;

	/* If we are a Group Owner, add the Group Info subelement */
	if (hdl->is_ap) {
		subel = p2papi_enc_se_grpinfo(hdl, max_ie_len, subel, ie_len);
		p2p_ie->len = (uint8) *ie_len - 2;
	}

	/* p2papi_dbg_dump_p2p_ie("enc_prbresp_p2p_ie end: ", p2p_ie); */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "    p2p_ie len=%u\n",
		subel - ((uint8*)p2p_ie)));
}

/* Encode a Association Request P2P IE */
static void
p2papi_encode_assocreq_p2p_ie(p2papi_instance_t* hdl,
	uint8 dev_cap_bitmap, uint8 grp_cap_bitmap,
	BCMP2P_BOOL is_ext_listen, uint16 ext_listen_period, uint16 ext_listen_interval,
	uint8 *mac, uint8 *name, uint8 name_len,
	wifi_p2p_ie_t *p2p_ie, uint16 *ie_len)
{
	uint8 *subel;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"enc_assocreq_p2p_ie: devcap=0x%x grpcap=0x%x, isel=%d per=%d int=%d\n",
		dev_cap_bitmap, grp_cap_bitmap,
		is_ext_listen, ext_listen_period, ext_listen_interval));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "    :"
		" mac=%02x:%02x:%02x:%02x:%02x:%02x name=%s len=%u\n",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], name, name_len));

	/* Add the P2P IE header */
	*ie_len = 0;
	subel = p2papi_encode_p2p_ie_hdr(hdl, p2p_ie, ie_len);

	/* Add the Capability Info subelement */
	subel = p2papi_enc_se_capability(dev_cap_bitmap, grp_cap_bitmap, subel,
		ie_len);

	/* extended listen timing */
	if (is_ext_listen)
		subel = p2papi_enc_se_xt_listen_timing(
			ext_listen_period, ext_listen_interval,	subel, ie_len);

	/* Add the Device Info subelement */
	subel = p2papi_enc_se_devinfo(mac, name, name_len,
		hdl->ap_config.WPSConfig.wpsConfigMethods,
		hdl->pri_dev_type, hdl->pri_dev_subcat,
#ifndef SECONDARY_DEVICE_TYPE
				subel, ie_len);
#else
				subel, ie_len, hdl->sec_dev_type, hdl->sec_dev_subcat, hdl->sec_dev_oui);
#endif

	/* Add the P2P Interface subelement */
	subel = p2papi_enc_se_interface(mac, hdl->conn_ifaddr.octet, subel, ie_len);

	p2p_ie->len = *ie_len - 2;
}

/* Encode a Association Response P2P IE */
static void
p2papi_encode_assocresp_p2p_ie(p2papi_instance_t* hdl, uint8 status,
	BCMP2P_BOOL is_ext_listen, uint16 ext_listen_period,
	uint16 ext_listen_interval, uint8 mgbt_bitmap,
	wifi_p2p_ie_t *p2p_ie, uint16 *ie_len)
{
	uint8 *subel;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"enc_assocresp_p2p_ie: status=%u mgbt=%u, isel=%d per=%d int=%d\n",
		status, mgbt_bitmap,
		is_ext_listen, ext_listen_period, ext_listen_interval));

	/* Add the P2P IE header */
	*ie_len = 0;
	subel = p2papi_encode_p2p_ie_hdr(hdl, p2p_ie, ie_len);

	/* Do not add a Status attribute.  The spec says this attribute is present
	 * only if the association is denied.  Onlyl the driver knows if an
	 * assocrsp is a denial so the driver will add this attribute as needed.
	 */
	/* subel = p2papi_enc_se_status(status, subel, ie_len); */

	/* extended listen timing */
	if (is_ext_listen)
		subel = p2papi_enc_se_xt_listen_timing(
			ext_listen_period, ext_listen_interval,	subel, ie_len);

	p2p_ie->len = *ie_len - 2;
}

/* Encode a Beacon P2P IE */
static void
p2papi_encode_beacon_p2p_ie(p2papi_instance_t* hdl,
	uint8 dev_cap_bitmap, uint8 grp_cap_bitmap, uint8 mgbt_bitmap,
	wifi_p2p_ie_t *p2p_ie, uint16 *ie_len)
{
	uint8 *subel;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"enc_beacon_p2p_ie: devcap=0x%x grpcap=0x%x mgbt=0x%x\n",
		dev_cap_bitmap, grp_cap_bitmap, mgbt_bitmap));

	/* Add the P2P IE header */
	*ie_len = 0;
	subel = p2papi_encode_p2p_ie_hdr(hdl, p2p_ie, ie_len);

	/* Add the Capability Info subelement */
	subel = p2papi_enc_se_capability(dev_cap_bitmap, grp_cap_bitmap, subel,
		ie_len);

	/* Add the P2P Device ID subelement */
	subel = p2papi_enc_se_dev_id(hdl->p2p_dev_addr.octet, subel, ie_len);

	p2p_ie->len = *ie_len - 2;
}

/* Encode a P2P Device Discoverability Request P2P IE */
void
p2papi_encode_dev_discb_req_p2p_ie(p2papi_instance_t* hdl,
	struct ether_addr *gc_dev_addr, wifi_p2p_ie_t *p2p_ie, uint16 *ie_len)
{
	uint8 *subel;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"enc_dev_discb_req: gc_dev_addr=%02x:%02x:%02x:%02x:%02x:%02x\n",
		gc_dev_addr[0], gc_dev_addr[1], gc_dev_addr[2],
		gc_dev_addr[3], gc_dev_addr[4], gc_dev_addr[5]));

	/* Add the P2P IE header */
	*ie_len = 0;
	subel = p2papi_encode_p2p_ie_hdr(hdl, p2p_ie, ie_len);

	/* Add the P2P Device ID subelement */
	subel = p2papi_enc_se_dev_id(gc_dev_addr->octet, subel, ie_len);

	p2p_ie->len = *ie_len - 2;
}

/* Encode a P2P Invitation Request P2P IE */
void
p2papi_encode_inv_req_p2p_ie(p2papi_instance_t* hdl,
    uint16 go_cfg_tmo_ms, uint16 gc_cfg_tmo_ms, BCMP2P_CHANNEL *op_channel,
	uint8 *p2p_grp_bssid, uint8 invite_flags,
	char *country, p2p_chanlist_t *chanlist,
	uint8 *p2pgrpid_dev_addr, uint8 *p2pgrpid_ssid, int p2pgrpid_ssid_len,
	uint8 *dev_addr, uint8 *name, uint8 name_len,
	wifi_p2p_ie_t *p2p_ie, uint16 *ie_len)
{
	uint8 *subel;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"enc_invreq_p2p_ie: cfg_tmo=%u,%u ch=%d:%d ssid=%s len=%d\n",
		go_cfg_tmo_ms, gc_cfg_tmo_ms, op_channel->channel_class,
		op_channel->channel, p2pgrpid_ssid,	p2pgrpid_ssid_len));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"        grpid_dev_addr=%02x:%02x:%02x:%02x:%02x:%02x\n",
		p2pgrpid_dev_addr[0], p2pgrpid_dev_addr[1], p2pgrpid_dev_addr[2],
		p2pgrpid_dev_addr[3], p2pgrpid_dev_addr[4], p2pgrpid_dev_addr[5]));
	if (p2p_grp_bssid) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"        grp_bssid=%02x:%02x:%02x:%02x:%02x:%02x\n",
			p2p_grp_bssid[0], p2p_grp_bssid[1], p2p_grp_bssid[2],
			p2p_grp_bssid[3], p2p_grp_bssid[4], p2p_grp_bssid[5]));
	}

	/* Add the P2P IE header */
	*ie_len = 0;
	subel = p2papi_encode_p2p_ie_hdr(hdl, p2p_ie, ie_len);
	/* p2papi_dbg_dump_p2p_ie("after enc_p2p_begin  : ", p2p_ie); */

	/* Add the Configuration Timeout attribute */
	subel = p2papi_enc_se_cfg_timeout((uint8)(go_cfg_tmo_ms / 10),
		(uint8)(gc_cfg_tmo_ms / 10), subel, ie_len);

	/* Add the Channel attribute */
	subel = p2papi_enc_se_op_channel(country, op_channel, subel,
		ie_len);
	/* p2papi_dbg_dump_p2p_ie("after enc_p2p_se_channel: ", p2p_ie); */

	/* Add the P2P Group BSSID attribute if we are a GO, or if we are a GC
	 * and the invitation type is "join an active group" (0).
	 */
	if (p2p_grp_bssid)
		subel = p2papi_enc_se_grp_bssid(p2p_grp_bssid, subel, ie_len);

	/* Add the Channel List attribute */
	subel = p2papi_enc_se_chan_list(country, chanlist, subel, ie_len);

	/* Add the Device Info attribute */
	subel = p2papi_enc_se_devinfo(dev_addr, name, name_len,
		hdl->ap_config.WPSConfig.wpsConfigMethods,
		hdl->pri_dev_type, hdl->pri_dev_subcat,
#ifndef SECONDARY_DEVICE_TYPE
		subel, ie_len);
#else
		subel, ie_len, hdl->sec_dev_type, hdl->sec_dev_subcat, hdl->sec_dev_oui);
#endif

	/* Add the P2P Group ID attribute */
	subel = p2papi_enc_se_group_id(p2pgrpid_dev_addr, p2pgrpid_ssid,
		p2pgrpid_ssid_len, subel, ie_len);

	/* Add the Invitation Flags attribute */
	subel = p2papi_enc_se_invite_flags(invite_flags, subel, ie_len);

	/* Fill in the IE's length field */
	p2p_ie->len = (uint8) *ie_len - 2;

	/* Return the total size of the IE */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"enc_invreq_p2p_ie end: ielen=%d\n", *ie_len));
}

/* Encode a P2P Invitation Response P2P IE */
void
p2papi_encode_inv_rsp_p2p_ie(p2papi_instance_t* hdl, uint8 status,
    uint16 go_cfg_tmo_ms, uint16 gc_cfg_tmo_ms, BCMP2P_CHANNEL *op_channel,
	uint8 *p2p_grp_bssid,
	char *country, p2p_chanlist_t *chanlist,
	wifi_p2p_ie_t *p2p_ie, uint16 *ie_len)
{
	uint8 *subel;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"enc_invrsp_p2p_ie: status=%u cfg_tmo=%u,%u ch=%d:%d\n",
		status, go_cfg_tmo_ms, gc_cfg_tmo_ms,
		op_channel->channel_class, op_channel->channel));

	/* Add the P2P IE header */
	*ie_len = 0;
	subel = p2papi_encode_p2p_ie_hdr(hdl, p2p_ie, ie_len);
	/* p2papi_dbg_dump_p2p_ie("after enc_p2p_begin  : ", p2p_ie); */

	/* Add the Status subelement */
	subel = p2papi_enc_se_status(status, subel, ie_len);
	/* p2papi_dbg_dump_p2p_ie("after enc_p2p_se_status: ", p2p_ie); */

	/* Add the Configuration Timeout subelement */
	subel = p2papi_enc_se_cfg_timeout((uint8)(go_cfg_tmo_ms / 10),
		(uint8)(gc_cfg_tmo_ms / 10), subel, ie_len);
	/* p2papi_dbg_dump_p2p_ie("after enc_p2p_se_cfg_timeout: ", p2p_ie); */

	/* Add the Channel subelement */
	subel = p2papi_enc_se_op_channel(country, op_channel, subel,
		ie_len);
	/* p2papi_dbg_dump_p2p_ie("after enc_p2p_se_channel: ", p2p_ie); */

	/* Add the P2P Group BSSID subelement (optional if we are a GC) */
	if (p2p_grp_bssid)
		subel = p2papi_enc_se_grp_bssid(p2p_grp_bssid, subel, ie_len);

	/* Add the Channel List subelement */
	subel = p2papi_enc_se_chan_list(country, chanlist, subel, ie_len);

	/* Fill in the IE's length field */
	p2p_ie->len = (uint8) *ie_len - 2;

	/* Return the total size of the IE */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"enc_invreq_p2p_ie end: ielen=%d\n", *ie_len));
}

/* Encode a P2P Presence Request IEs */
void
p2papi_encode_presence_req_p2p_ie(p2papi_instance_t* hdl,
	uint8 index, BCMP2P_BOOL oppps, uint8 ctwindow,
	uint8 num_noa_desc, wifi_p2p_noa_desc_t *noa_desc,
	wifi_p2p_ie_t *p2p_ie, uint16 *ie_len)
{
	uint8 *subel;

	*ie_len = 0;
	subel = p2papi_encode_p2p_ie_hdr(hdl, p2p_ie, ie_len);
	subel = p2papi_enc_se_noa(index, oppps, ctwindow,
		num_noa_desc, noa_desc,	subel, ie_len);

	p2p_ie->len = (uint8) *ie_len - 2;
}

/* Encode a P2P Presence Response P2P IEs */
void
p2papi_encode_presence_rsp_p2p_ie(p2papi_instance_t* hdl, uint8 status,
	uint8 index, BCMP2P_BOOL oppps, uint8 ctwindow,
	uint8 num_noa_desc, wifi_p2p_noa_desc_t *noa_desc,
	wifi_p2p_ie_t *p2p_ie, uint16 *ie_len)
{
	uint8 *subel;

	*ie_len = 0;
	subel = p2papi_encode_p2p_ie_hdr(hdl, p2p_ie, ie_len);
	subel = p2papi_enc_se_status(status, subel, ie_len);
	subel = p2papi_enc_se_noa(index, oppps, ctwindow,
		num_noa_desc, noa_desc,	subel, ie_len);

	p2p_ie->len = (uint8) *ie_len - 2;
}

/* Encode provision discovery P2P IE */
void
p2papi_encode_provdis_p2p_ie(p2papi_instance_t* hdl,
	uint8 *dev_addr, uint8 *name, uint8 name_len,
	uint8 *ssid, int ssid_len, uint8 *grp_dev_addr,
	wifi_p2p_ie_t *p2p_ie, uint16 *ie_len)
{
	uint8 *subel;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_encode_provdis_p2p_ie: name=%s nlen=%u\n",
		name, name_len));

	/* Add the P2P IE header */
	*ie_len = 0;
	subel = p2papi_encode_p2p_ie_hdr(hdl, p2p_ie, ie_len);

	/* Add the P2P Capability subelement */
	subel = p2papi_enc_se_capability(
		p2papi_generate_dev_cap_bitmap(hdl),
		p2papi_generate_grp_cap_bitmap(hdl),
		subel, ie_len);

	/* Add the P2P Device Info subelement */
	subel = p2papi_enc_se_devinfo(dev_addr, name, name_len,
		hdl->ap_config.WPSConfig.wpsConfigMethods,
		hdl->pri_dev_type, hdl->pri_dev_subcat,
#ifndef SECONDARY_DEVICE_TYPE
		subel, ie_len);
#else
		subel, ie_len, hdl->sec_dev_type, hdl->sec_dev_subcat, hdl->sec_dev_oui);
#endif

	if (ssid_len > 0 && grp_dev_addr) {
		/* Add the P2P Group ID attribute */
		subel = p2papi_enc_se_group_id(grp_dev_addr, ssid, ssid_len,
			subel, ie_len);
	}		

	/* Fill in the IE's length field */
	p2p_ie->len = (uint8) *ie_len - 2;

	/* Return the total size of the IE */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_encode_provdis_p2p_ie end: ielen=%d\n", *ie_len));
}

/* Encode a Device Discoverability Request P2P IE */
void
p2papi_encode_discb_req_p2p_ie(p2papi_instance_t* hdl, uint8 *client_dev_addr,
	uint8 *go_dev_addr, uint8 *go_ssid, int go_ssid_len,
	wifi_p2p_ie_t *p2p_ie, uint16 *ie_len)
{
	uint8 *subel;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_encode_discb_req_p2p_ie\n"));

	/* Add the P2P IE header */
	*ie_len = 0;
	subel = p2papi_encode_p2p_ie_hdr(hdl, p2p_ie, ie_len);

	/* Add the P2P Device Info subelement */
	subel = p2papi_enc_se_dev_id(client_dev_addr, subel, ie_len);

	/* Add the P2P Group ID attribute */
	subel = p2papi_enc_se_group_id(go_dev_addr, go_ssid, go_ssid_len,
		subel, ie_len);

	/* Fill in the IE's length field */
	p2p_ie->len = (uint8) *ie_len - 2;

	/* Return the total size of the IE */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_encode_discb_req_p2p_ie end: ielen=%d\n", *ie_len));
}

/* Encode a Device Discoverability Response P2P IE */
void
p2papi_encode_discb_rsp_p2p_ie(p2papi_instance_t* hdl, uint8 status,
	wifi_p2p_ie_t *p2p_ie, uint16 *ie_len)
{
	uint8 *subel;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_encode_discb_rsp_p2p_ie\n"));

	/* Add the P2P IE header */
	*ie_len = 0;
	subel = p2papi_encode_p2p_ie_hdr(hdl, p2p_ie, ie_len);

	/* Add the Status subelement */
	subel = p2papi_enc_se_status(status, subel, ie_len);

	/* Fill in the IE's length field */
	p2p_ie->len = (uint8) *ie_len - 2;

	/* Return the total size of the IE */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_encode_discb_rsp_p2p_ie end: ielen=%d\n", *ie_len));
}

/* Encode a Group Owner Negotiation P2P IE */
void
p2papi_encode_gon_req_p2p_ie(p2papi_instance_t* hdl, uint8 intent,
	BCMP2P_CHANNEL *listen_channel, BCMP2P_CHANNEL *op_channel,
	uint8 status, uint8 *dev_addr,
	BCMP2P_BOOL is_ext_listen, uint16 ext_listen_period, uint16 ext_listen_interval,
	char *country, p2p_chanlist_t *chanlist,
	uint8 *name, uint8 name_len, wifi_p2p_ie_t *p2p_ie, uint16 *ie_len)
{
	uint8 *subel;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"enc_gonreq_p2p_ie: int=0x%02x lch=%d:%d opch=%d:%d stat=%u name=%s nlen=%u\n",
		intent, listen_channel->channel_class, listen_channel->channel,
		op_channel->channel_class, op_channel->channel, status, name, name_len));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"       ext listen: is=%d per=%d int=%d\n",
		is_ext_listen, ext_listen_period, ext_listen_interval));

	/* Add the P2P IE header */
	*ie_len = 0;
	subel = p2papi_encode_p2p_ie_hdr(hdl, p2p_ie, ie_len);
	/* p2papi_dbg_dump_p2p_ie("after enc_p2p_begin  : ", p2p_ie); */

	/* Add the P2P Capability subelement */
	subel = p2papi_enc_se_capability(/* P2P_CAPSE_DEV_SERVICE_DIS | */
		p2papi_generate_dev_cap_bitmap(hdl),
		p2papi_generate_grp_cap_bitmap(hdl),
		subel, ie_len);
	/* p2papi_dbg_dump_p2p_ie("after enc_p2p_se_caps: ", p2p_ie); */

	/* Add the Group Owner Intent subelement */
	subel = p2papi_enc_se_intent(intent, subel, ie_len);

	/* Add the Configuration Timeout subelement */
	subel = p2papi_enc_se_cfg_timeout(hdl->peer_wps_go_cfg_tmo_ms/10, 0, subel,
		ie_len);

	/* Add the Listen Channel subelement */
	subel = p2papi_enc_se_listen_channel(country,
		listen_channel, subel, ie_len);
	/* p2papi_dbg_dump_p2p_ie("after enc_p2p_se_channel: ", p2p_ie); */

	/* Add the Operating Channel subelement */
	subel = p2papi_enc_se_op_channel(country, op_channel,
		subel, ie_len);
	/* p2papi_dbg_dump_p2p_ie("after enc_p2p_se_channel: ", p2p_ie); */

	/* extended listen timing */
	if (is_ext_listen)
		subel = p2papi_enc_se_xt_listen_timing(
			ext_listen_period, ext_listen_interval,	subel, ie_len);

	/* Add the Intended P2P Interface Address subelement */
	subel = p2papi_enc_se_intd_if_addr(hdl->conn_ifaddr.octet, subel, ie_len);

	/* Add the Channel List subelement */
	subel = p2papi_enc_se_chan_list(country, chanlist, subel, ie_len);

	/* Add the Device Info subelement */
	subel = p2papi_enc_se_devinfo(dev_addr, name, name_len,
		hdl->ap_config.WPSConfig.wpsConfigMethods,
		hdl->pri_dev_type, hdl->pri_dev_subcat,
#ifndef SECONDARY_DEVICE_TYPE
				subel, ie_len);
#else
				subel, ie_len, hdl->sec_dev_type, hdl->sec_dev_subcat, hdl->sec_dev_oui);
#endif

	/* p2papi_dbg_dump_p2p_ie("after enc_p2p_se_devinfo: ", p2p_ie); */

	/* Fill in the IE's length field */
	p2p_ie->len = (uint8) *ie_len - 2;

	/* Return the total size of the IE */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"enc_gon_req_p2p_ie end: ielen=%d\n", *ie_len));
}

void
p2papi_encode_gon_rsp_p2p_ie(p2papi_instance_t* hdl,
	char *grp_ssid, int grp_ssid_len,
	uint8 intent, BCMP2P_CHANNEL *channel, uint8 status, uint8 *dev_addr,
	char *country, p2p_chanlist_t *chanlist,
	uint8 *name, uint8 name_len, wifi_p2p_ie_t *p2p_ie, uint16 *ie_len)
{
	uint8 *subel;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"enc_gonrsp_p2p_ie: int=0x%02x ch=%d:%d stat=%u name=%s nlen=%u\n",
		intent, channel->channel_class, channel->channel,
		status, name, name_len));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"                   ssid=%s slen=%u\n", grp_ssid, grp_ssid_len));

	/* Add the P2P IE header */
	*ie_len = 0;
	subel = p2papi_encode_p2p_ie_hdr(hdl, p2p_ie, ie_len);
	/* p2papi_dbg_dump_p2p_ie("after enc_p2p_begin  : ", p2p_ie); */

	/* Add the Status subelement */
	subel = p2papi_enc_se_status(status, subel, ie_len);
	/* p2papi_dbg_dump_p2p_ie("after enc_p2p_se_status: ", p2p_ie); */

	/* Add the P2P Capability subelement */
	subel = p2papi_enc_se_capability(/* P2P_CAPSE_DEV_SERVICE_DIS | */
		p2papi_generate_dev_cap_bitmap(hdl),
		p2papi_generate_grp_cap_bitmap(hdl),
		subel, ie_len);
	/* p2papi_dbg_dump_p2p_ie("after enc_p2p_se_caps: ", p2p_ie); */

	/* Add the Group Owner Intent subelement */
	subel = p2papi_enc_se_intent(intent, subel, ie_len);

	/* Add the Configuration Timeout subelement */
	subel = p2papi_enc_se_cfg_timeout(hdl->peer_wps_go_cfg_tmo_ms/10, 0, subel,
		ie_len);

	/* Add the Operating Channel subelement */
	subel = p2papi_enc_se_op_channel(country, channel, subel, ie_len);
	/* p2papi_dbg_dump_p2p_ie("after enc_p2p_se_channel: ", p2p_ie); */

	/* Add the Intended P2P Interface Address subelement */
	subel = p2papi_enc_se_intd_if_addr(hdl->conn_ifaddr.octet, subel, ie_len);

	/* Add the Channel List subelement */
	subel = p2papi_enc_se_chan_list(country, chanlist, subel, ie_len);

	/* Add the Device Info subelement */
	subel = p2papi_enc_se_devinfo(dev_addr, name, name_len,
		hdl->ap_config.WPSConfig.wpsConfigMethods,
		hdl->pri_dev_type, hdl->pri_dev_subcat,
#ifndef SECONDARY_DEVICE_TYPE
						subel, ie_len);
#else
						subel, ie_len, hdl->sec_dev_type, hdl->sec_dev_subcat, hdl->sec_dev_oui);
#endif

	/* p2papi_dbg_dump_p2p_ie("after enc_p2p_se_devinfo: ", p2p_ie); */

	/* Add the P2P Group ID attribute if acting as a GO */
	if (grp_ssid_len > 0)
		subel = p2papi_enc_se_group_id(dev_addr, (uint8*)grp_ssid, grp_ssid_len,
			subel, ie_len);

	/* Fill in the IE's length field */
	p2p_ie->len = (uint8) *ie_len - 2;

	/* Return the total size of the IE */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"enc_gonrsp_p2p_ie end: ielen=%d\n", *ie_len));
}

void
p2papi_encode_gon_conf_p2p_ie(p2papi_instance_t* hdl,
	uint8 intent, BCMP2P_CHANNEL *channel, uint8 status, uint8 *dev_addr,
	char *country, p2p_chanlist_t *chanlist,
	char *grp_ssid, uint8 grp_ssid_len,
	wifi_p2p_ie_t *p2p_ie, uint16 *ie_len)
{
	uint8 *subel;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"enc_gonconf_p2p_ie: int=0x%02x ch=%d:%d stat=%u ssid=%s len=%u\n",
		intent, channel->channel_class, channel->channel,
		status, grp_ssid, grp_ssid_len));

	/* Add the P2P IE header */
	*ie_len = 0;
	subel = p2papi_encode_p2p_ie_hdr(hdl, p2p_ie, ie_len);
	/* p2papi_dbg_dump_p2p_ie("after enc_p2p_begin  : ", p2p_ie); */

	/* Add the Status subelement */
	subel = p2papi_enc_se_status(status, subel, ie_len);
	/* p2papi_dbg_dump_p2p_ie("after enc_p2p_se_status: ", p2p_ie); */

	/* Add the P2P Capability subelement */
	subel = p2papi_enc_se_capability(/* P2P_CAPSE_DEV_SERVICE_DIS | */
		p2papi_generate_dev_cap_bitmap(hdl),
		p2papi_generate_grp_cap_bitmap(hdl),
		subel, ie_len);
	/* p2papi_dbg_dump_p2p_ie("after enc_p2p_se_caps: ", p2p_ie); */

	/* Add the Channel subelement */
	subel = p2papi_enc_se_op_channel(country, channel, subel, ie_len);
	/* p2papi_dbg_dump_p2p_ie("after enc_p2p_se_channel: ", p2p_ie); */

	/* Add the Channel List subelement */
	subel = p2papi_enc_se_chan_list(country, chanlist, subel, ie_len);

	/* Add the P2P Group ID attribute if acting as a GO */
	if (grp_ssid_len > 0)
		subel = p2papi_enc_se_group_id(dev_addr, (uint8*)grp_ssid, grp_ssid_len,
			subel, ie_len);

	/* Fill in the IE's length field */
	p2p_ie->len = (uint8) *ie_len - 2;

	/* Return the total size of the IE */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"enc_gon_p2p_ie end: ielen=%d\n", *ie_len));
}

/* Decode a P2P IE.  Returns the total IE len including the ID & len fields */
uint16
p2papi_decode_p2p_ie(uint8* buf, p2papi_p2p_ie_t *out_p2p_ie, BCMP2P_LOG_LEVEL log)
{
	wifi_p2p_ie_t *ie = (wifi_p2p_ie_t*)buf;
	int16 len = (int16) ie->len;
	uint8 *subel, *subel_lenp;
	uint8 *subel2;
	uint8 subelt_id;
	uint16 subelt_len;
	uint16 subelt_len2;
	int i, j;
	int num_chans;
	p2p_chanlist_t *chanlist;

	/* Point subel to the P2P IE's subelt field.
	 * Subtract the preceding fields (id, len, OUI, oui_type) from the length.
	 */
	subel = ie->subelts;
	len -= 4;	/* exclude OUI */

	/* For debug, dump the IE data */
	p2papi_log_hexdata(log, "p2papi_decode_p2p_ie", subel, len);

	memcpy(&out_p2p_ie->p2p_ie, ie, sizeof(wifi_p2p_ie_t) - 1);

	while (len >= P2PAPI_ATTRIBUTE_ID_SIZE + P2PAPI_LENGTH_SIZE) {
		/* attribute id */
		subelt_id = *subel;
		subel += P2PAPI_ATTRIBUTE_ID_SIZE;
		len -= P2PAPI_ATTRIBUTE_ID_SIZE;

		/* attribute length */
		subel_lenp = subel;	/* point to length field */
		subelt_len = p2papi_decode_p2p_ie_length(subel);
		subel += P2PAPI_LENGTH_SIZE;
		len -= P2PAPI_LENGTH_SIZE;

		/* check attribute length doesn't exceed buffer */
		if (subelt_len > len) {
			p2papi_log_hexdata(log, "P2P attribute length exceeds buffer",
				ie->subelts, ie->len);
				break;
		}
		len -= subelt_len;	/* for the remaining subelt fields */

		BCMP2PLOG((log, TRUE,
			" subelt_id=%u subelt_len=%u\n", subelt_id, subelt_len));

		switch (subelt_id) {
		case P2P_SEID_MINOR_RC:
			out_p2p_ie->minorrc_subelt.eltId = subelt_id;
			memcpy(out_p2p_ie->minorrc_subelt.len, subel_lenp,
				P2PAPI_LENGTH_SIZE);
			out_p2p_ie->minorrc_subelt.minor_rc = *subel;
			BCMP2PLOG((log, TRUE,
				"  len=%u P2P MINORRC SE: minor_rc=%u\n",
				subelt_len, out_p2p_ie->minorrc_subelt.minor_rc));
			break;
		case P2P_SEID_P2P_CAPABILITY:
			out_p2p_ie->capability_subelt.eltId = subelt_id;
			memcpy(out_p2p_ie->capability_subelt.len, subel_lenp,
				P2PAPI_LENGTH_SIZE);
			out_p2p_ie->capability_subelt.dev = *subel;
			out_p2p_ie->capability_subelt.group = *(subel+1);
			BCMP2PLOG((log, TRUE,
				"  len=%u P2P CAPS SE: devbm=0x%x grpbm=0x%x\n",
				subelt_len, out_p2p_ie->capability_subelt.dev,
				out_p2p_ie->capability_subelt.group));
			break;
		case P2P_SEID_DEV_ID:
			out_p2p_ie->devid_subelt.eltId = subelt_id;
			memcpy(out_p2p_ie->devid_subelt.len, subel_lenp,
				P2PAPI_LENGTH_SIZE);
			memcpy(out_p2p_ie->devid_subelt.addr.octet, subel, 6);
			BCMP2PLOG((log, TRUE, "  len=%u "
				"P2P DEV ID SE: devaddr=%02x:%02x:%02x:%02x:%02x:%02x\n",
				subelt_len,
				out_p2p_ie->devid_subelt.addr.octet[0],
				out_p2p_ie->devid_subelt.addr.octet[1],
				out_p2p_ie->devid_subelt.addr.octet[2],
				out_p2p_ie->devid_subelt.addr.octet[3],
				out_p2p_ie->devid_subelt.addr.octet[4],
				out_p2p_ie->devid_subelt.addr.octet[5]));
			break;
		case P2P_SEID_GROUP_ID:
			out_p2p_ie->grpid_subelt.eltId = subelt_id;
			memcpy(out_p2p_ie->grpid_subelt.len, subel_lenp,
				P2PAPI_LENGTH_SIZE);
			subel2 = subel;
			memcpy(out_p2p_ie->grpid_subelt.devaddr.octet, subel2, 6);
			subel2 += 6;
			BCMP2PLOG((log, TRUE, "  len=%u "
				"P2P GRP ID SE: devaddr=%02x:%02x:%02x:%02x:%02x:%02x\n",
				subelt_len,
				out_p2p_ie->grpid_subelt.devaddr.octet[0],
				out_p2p_ie->grpid_subelt.devaddr.octet[1],
				out_p2p_ie->grpid_subelt.devaddr.octet[2],
				out_p2p_ie->grpid_subelt.devaddr.octet[3],
				out_p2p_ie->grpid_subelt.devaddr.octet[4],
				out_p2p_ie->grpid_subelt.devaddr.octet[5]));
			memcpy(out_p2p_ie->grpid_subelt.ssid, subel2, subelt_len - 6);
			out_p2p_ie->grpid_subelt.ssid_len = subelt_len - 6;
			break;
		case P2P_SEID_GRP_BSSID:
			out_p2p_ie->grp_bssid_subelt.eltId = subelt_id;
			memcpy(out_p2p_ie->grp_bssid_subelt.len, subel_lenp,
				P2PAPI_LENGTH_SIZE);
			memcpy(out_p2p_ie->grp_bssid_subelt.bssid.octet, subel, 6);
			BCMP2PLOG((log, TRUE, "  len=%u "
				"P2P GRP BSSID SE: bssid=%02x:%02x:%02x:%02x:%02x:%02x\n",
				subelt_len,
				out_p2p_ie->grp_bssid_subelt.bssid.octet[0],
				out_p2p_ie->grp_bssid_subelt.bssid.octet[1],
				out_p2p_ie->grp_bssid_subelt.bssid.octet[2],
				out_p2p_ie->grp_bssid_subelt.bssid.octet[3],
				out_p2p_ie->grp_bssid_subelt.bssid.octet[4],
				out_p2p_ie->grp_bssid_subelt.bssid.octet[5]));
			break;
		case P2P_SEID_INTENT:
			out_p2p_ie->intent_subelt.eltId = subelt_id;
			memcpy(out_p2p_ie->intent_subelt.len, subel_lenp,
				P2PAPI_LENGTH_SIZE);
			out_p2p_ie->intent_subelt.intent = *subel;
			BCMP2PLOG((log, TRUE,
				"  len=%u INTENT SE: int=0x%02x\n",
				subelt_len, out_p2p_ie->intent_subelt.intent));
			break;
		case P2P_SEID_STATUS:
			out_p2p_ie->status_subelt.eltId = subelt_id;
			memcpy(out_p2p_ie->status_subelt.len, subel_lenp,
				P2PAPI_LENGTH_SIZE);
			out_p2p_ie->status_subelt.status = *subel;
			BCMP2PLOG((log, TRUE,
				"  len=%u STATUS SE: status=%u\n",
				subelt_len, out_p2p_ie->status_subelt.status));
			break;
		case P2P_SEID_CFG_TIMEOUT:
			out_p2p_ie->cfg_tmo_subelt.eltId = subelt_id;
			memcpy(out_p2p_ie->cfg_tmo_subelt.len, subel_lenp,
				P2PAPI_LENGTH_SIZE);
			out_p2p_ie->cfg_tmo_subelt.go_tmo = *subel;
			out_p2p_ie->cfg_tmo_subelt.client_tmo = *(subel+1);
			BCMP2PLOG((log, TRUE,
				"  len=%u CFG_TIMEOUT SE: go_tmo=%u,client_tmo=%d\n",
				subelt_len, out_p2p_ie->cfg_tmo_subelt.go_tmo,
				out_p2p_ie->cfg_tmo_subelt.client_tmo));
			break;
		case P2P_SEID_LISTEN_CHANNEL:
			out_p2p_ie->listen_chan_subelt.eltId = subelt_id;
			memcpy(out_p2p_ie->listen_chan_subelt.len, subel_lenp,
				P2PAPI_LENGTH_SIZE);
			memcpy(out_p2p_ie->listen_chan_subelt.country, subel, 3);
			out_p2p_ie->listen_chan_subelt.band = *(subel+3);
			out_p2p_ie->listen_chan_subelt.channel = *(subel+4);
			BCMP2PLOG((log, TRUE,
				"  len=%u LISTEN_CHANNEL SE: regclass=%u channel=%u\n",
				subelt_len, out_p2p_ie->listen_chan_subelt.band,
				out_p2p_ie->listen_chan_subelt.channel));
			break;
		case P2P_SEID_OPERATING_CHANNEL:
			out_p2p_ie->op_chan_subelt.eltId = subelt_id;
			memcpy(out_p2p_ie->op_chan_subelt.len, subel_lenp,
				P2PAPI_LENGTH_SIZE);
			memcpy(out_p2p_ie->op_chan_subelt.country, subel, 3);
			out_p2p_ie->op_chan_subelt.band = *(subel+3);
			out_p2p_ie->op_chan_subelt.channel = *(subel+4);
			BCMP2PLOG((log, TRUE,
				"  len=%u OP_CHANNEL SE: regclass=%u channel=%u\n",
				subelt_len, out_p2p_ie->op_chan_subelt.band,
				out_p2p_ie->op_chan_subelt.channel));
			break;
		case P2P_SEID_P2P_MGBTY:
			BCMP2PLOG((log, TRUE,
				"  len=%u MANAGEABILITY SE\n",
				subelt_len));
			break;
		case P2P_SEID_CHAN_LIST:
			out_p2p_ie->chanlist_subelt.eltId = subelt_id;
			memcpy(out_p2p_ie->chanlist_subelt.len, subel_lenp,
				P2PAPI_LENGTH_SIZE);
			memcpy(out_p2p_ie->chanlist_subelt.country, subel, 3);
			subel2 = subel + 3;
			BCMP2PLOG((log, TRUE,
				"  len=%u CHANLIST SE: country=%s\n",
				subelt_len, out_p2p_ie->chanlist_subelt.country));
			chanlist = &out_p2p_ie->chanlist_subelt.chanlist;
			chanlist->num_entries = 0;
			for (i = 0; i < P2P_CHANLIST_SE_MAX_ENTRIES &&
				subel2 < (subel + subelt_len); i++) {
				chanlist->num_entries++;
				chanlist->entries[i].band = *subel2++;
				num_chans = *subel2++;
				if (num_chans > P2P_CHANNELS_MAX_ENTRIES) {
					BCMP2PLOG((log, TRUE,
						"  truncating channels %d\n",	num_chans));
					num_chans = P2P_CHANNELS_MAX_ENTRIES;
				}
				chanlist->entries[i].num_channels = num_chans;
				for (j = 0; j < num_chans; j++) {
					chanlist->entries[i].channels[j] = *subel2++;
				}
				BCMP2PLOG((log, TRUE,
					"  %d) regclass=%u #ch=%u "
					"channels=%u %u %u %u %u %u...\n",
					i, chanlist->entries[i].band,
					chanlist->entries[i].num_channels,
					chanlist->entries[i].channels[0],
					chanlist->entries[i].channels[1],
					chanlist->entries[i].channels[2],
					chanlist->entries[i].channels[3],
					chanlist->entries[i].channels[4],
					chanlist->entries[i].channels[5]));
			}
			break;
		case P2P_SEID_INTINTADDR:
			out_p2p_ie->intintad_subelt.eltId = subelt_id;
			memcpy(out_p2p_ie->intintad_subelt.len, subel_lenp,
				P2PAPI_LENGTH_SIZE);
			memcpy(out_p2p_ie->intintad_subelt.mac, subel, 6);
			BCMP2PLOG((log, TRUE, "  len=%u "
				"INTENDED_IFADDR SE: mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
				subelt_len,
				out_p2p_ie->intintad_subelt.mac[0],
				out_p2p_ie->intintad_subelt.mac[1],
				out_p2p_ie->intintad_subelt.mac[2],
				out_p2p_ie->intintad_subelt.mac[3],
				out_p2p_ie->intintad_subelt.mac[4],
				out_p2p_ie->intintad_subelt.mac[5]));
			break;
		case P2P_SEID_DEV_INFO:
		{
			uint8 name_len = 0;
			uint8 sec_devtype_count;

			subel2 = subel;
			subelt_len2 = subelt_len;

			out_p2p_ie->devinfo_subelt.eltId = subelt_id;
			memcpy(out_p2p_ie->devinfo_subelt.len, subel_lenp,
				P2PAPI_LENGTH_SIZE);

			if (subelt_len2 < 6)
				break;
			memcpy(out_p2p_ie->devinfo_subelt.mac, subel2, 6);
			subel2 += 6;
			subelt_len2 -= 6;

			/* WPS Config Methods. It is big-endian even it is part of P2P IE */
			if (subelt_len2 < 2)
				break;
			out_p2p_ie->devinfo_subelt.wps_cfg_meths =
				(*subel2 << 8) | (*(subel2 +1));
			subel2 += 2;
			subelt_len2 -= 2;

			/* Primary Device Type */
			if (subelt_len2 < 8)
				break;
			memcpy(out_p2p_ie->devinfo_subelt.pri_devtype, subel2, 8);
			subel2 += 8;
			subelt_len2 -= 8;

			/* Number of Secondary Devices */
			if (subelt_len2 < 1)
				break;
			sec_devtype_count = *subel2;
			subel2 += 1;
			subelt_len2 -= 1;

			/* Secondary Device Type: skip this field for now */
			if (subelt_len2 < 8 * sec_devtype_count)
				break;
			subel2 += 8 * sec_devtype_count;
			subelt_len2 -= 8 * sec_devtype_count;

			/* The remainder of this subelement is the friendly Name of the P2P
			 * device.  Contains the WPS Device Name attrib in TLV format which
			 * is big-endian.
			 */
			if (subelt_len2 < 2)
				break;
			out_p2p_ie->devinfo_subelt.name_type_be[0] = *subel2;
			out_p2p_ie->devinfo_subelt.name_type_be[1] = *(subel2 + 1);
			subel2 += 2;
			subelt_len2 -= 2;

			if (subelt_len2 < 2)
				break;
			out_p2p_ie->devinfo_subelt.name_len_be[0] = *subel2;
			out_p2p_ie->devinfo_subelt.name_len_be[1] = *(subel2 + 1);
			subel2 += 2;
			subelt_len2 -= 2;

			if (subelt_len2 > 0) {
				name_len = (uint8) subelt_len2;
				if (name_len >= sizeof(out_p2p_ie->devinfo_name))
					name_len = sizeof(out_p2p_ie->devinfo_name) - 1;
				memcpy(out_p2p_ie->devinfo_name, subel2, name_len);
			}
			out_p2p_ie->devinfo_name[name_len] = '\0';
			out_p2p_ie->devinfo_name_len = name_len;
			if (name_len > 0) {
				if (name_len > sizeof(out_p2p_ie->devinfo_subelt.name_val))
					name_len = sizeof(out_p2p_ie->devinfo_subelt.name_val);
				memcpy(out_p2p_ie->devinfo_subelt.name_val, subel2, name_len);
			}

			BCMP2PLOG((log, TRUE, "  len=%u DEVINFO SE:"
				" mac=%02x:%02x:%02x:%02x:%02x:%02x cfgmeth=0x%04x\n",
				subelt_len,
				out_p2p_ie->devinfo_subelt.mac[0],
				out_p2p_ie->devinfo_subelt.mac[1],
				out_p2p_ie->devinfo_subelt.mac[2],
				out_p2p_ie->devinfo_subelt.mac[3],
				out_p2p_ie->devinfo_subelt.mac[4],
				out_p2p_ie->devinfo_subelt.mac[5],
				out_p2p_ie->devinfo_subelt.wps_cfg_meths));
			BCMP2PLOG((log, TRUE,
				"  pridev=%02x%02x%02x%02x%02x%02x%02x%02x"
				" seccnt=%u namelen=%d name=%s\n",
				out_p2p_ie->devinfo_subelt.pri_devtype[0],
				out_p2p_ie->devinfo_subelt.pri_devtype[1],
				out_p2p_ie->devinfo_subelt.pri_devtype[2],
				out_p2p_ie->devinfo_subelt.pri_devtype[3],
				out_p2p_ie->devinfo_subelt.pri_devtype[4],
				out_p2p_ie->devinfo_subelt.pri_devtype[5],
				out_p2p_ie->devinfo_subelt.pri_devtype[6],
				out_p2p_ie->devinfo_subelt.pri_devtype[7],
				sec_devtype_count,
				out_p2p_ie->devinfo_name_len, out_p2p_ie->devinfo_name));
			break;
		}
		case P2P_SEID_GROUP_INFO:
		{
			uint8 cid_count = 0;	/* Number of Client Info Descriptors */
			wifi_p2p_client_info_desc_t* cid;
			wifi_p2p_client_info_desc_t cid_tmp; /* TEMP - parse and discard */
			uint8 cid_len;			/* Client Info Descriptor length */
			uint16 namelen;

			out_p2p_ie->grpinfo_subelt.eltId = subelt_id;
			memcpy(out_p2p_ie->grpinfo_subelt.len, subel_lenp,
				P2PAPI_LENGTH_SIZE);
			BCMP2PLOG((log, TRUE,
				"P2P_SEID_GROUP_INFO: len=%u\n", subelt_len));

			subel2 = subel;
			subelt_len2 = subelt_len;
			while (subelt_len2 > 0) {
				cid_len = *subel2++;
				subelt_len2--;

				if (subelt_len2 < (int16)cid_len) {
					BCMP2PLOG((log, TRUE,
						"P2P_SEID_GROUP_INFO: "
						"cid_len %u > subelt_len %u\n",
						cid_len, subelt_len2));
					break;
				}
				if (cid_len < (6 + 6 + 1 + 2 + 8 + 1)) {
					BCMP2PLOG((log, TRUE,
						"P2P_SEID_GROUP_INFO: "
						"cid_len %u < minimum of %u\n",
						cid_len, (1 + 6 + 6 + 1 + 2 + 8 + 1)));
					break;
				}
				++cid_count;

				/* If the output client info list is not full,
				 *   Decode the client info descriptor into the output
				 *   client info list.
				 * else
				 *   Decode the client info descriptor and discard the
				 *   results.
				 */
				if (cid_count < P2PAPI_GRPINFO_MAX_CIDS)
					cid = &out_p2p_ie->
						grpinfo_subelt.client_info[cid_count - 1];
				else
					cid = &cid_tmp;

				cid->cid_len = cid_len;

				if (subelt_len2 < 6)
					break;
				memcpy(cid->p2p_dev_addr, subel2, 6);
				subel2 += 6;
				subelt_len2 -= 6;

				BCMP2PLOG((log, TRUE,
					" cid %u: cid_len=%u se_len=%u"
					" p2p_dev_addr=%02x:%02x:%02x:%02x:%02x:%02x\n",
					cid_count, cid_len, subelt_len,
					cid->p2p_dev_addr[0], cid->p2p_dev_addr[1],
					cid->p2p_dev_addr[2], cid->p2p_dev_addr[3],
					cid->p2p_dev_addr[4], cid->p2p_dev_addr[5]));

				if (subelt_len2 < 6)
					break;
				memcpy(cid->p2p_int_addr, subel2, 6);
				subel2 += 6;
				subelt_len2 -= 6;

				if (subelt_len2 < 1)
					break;
				cid->dev_cap_bitmap = *subel2++;
				subelt_len2 -= 1;

				if (subelt_len2 < 2)
					break;
				cid->wps_cfg_meths = (*subel2 & 0xff) + (*(subel2+1) << 8);
				subel2 += 2;
				subelt_len2 -= 2;

				BCMP2PLOG((log, TRUE,
					"        p2p_int_addr=%02x:%02x:%02x:%02x:%02x:%02x"
					" devcap=0x%x cfgmeth=0x%04x\n",
					cid->p2p_int_addr[0], cid->p2p_int_addr[1],
					cid->p2p_int_addr[2], cid->p2p_int_addr[3],
					cid->p2p_int_addr[4], cid->p2p_int_addr[5],
					cid->dev_cap_bitmap, cid->wps_cfg_meths));

				if (subelt_len2 < 8)
					break;
				memcpy(cid->pri_devtype, subel2, 8);
				subel2 += 8;
				subelt_len2 -= 8;

				if (subelt_len2 < 1)
					break;
				cid->num_sec_devs = *subel2++;
				subelt_len2 -= 1;

				BCMP2PLOG((log, TRUE,
					"  pridev=%02x%02x%02x%02x%02x%02x%02x%02x "
					"seccnt=%u\n",
					cid->pri_devtype[0], cid->pri_devtype[1],
					cid->pri_devtype[2], cid->pri_devtype[3],
					cid->pri_devtype[4], cid->pri_devtype[5],
					cid->pri_devtype[6], cid->pri_devtype[7],
					cid->num_sec_devs));

				/* The decoded P2P IE structure has no field to store the
				 * Secondary Device Type List yet.  Skip this field.
				 */
				if (subelt_len2 < cid->num_sec_devs * 8)
					break;
				subel2 += cid->num_sec_devs * 8;
				subelt_len2 -= cid->num_sec_devs * 8;

				if (subelt_len2 < 4)
					break;
				cid->name_type_be[0] = *subel2++;
				subelt_len2--;
				cid->name_type_be[1] = *subel2++;
				subelt_len2--;
				cid->name_len_be[0] = *subel2++;
				subelt_len2--;
				cid->name_len_be[1] = *subel2++;
				subelt_len2--;

				namelen = (cid->name_len_be[0] << 8) | cid->name_len_be[1];
				if (namelen > sizeof(cid->name_val))
					namelen = sizeof(cid->name_val);
				if (subelt_len2 < namelen)
					break;
				memset(cid->name_val, 0, sizeof(cid->name_val));
				memcpy(cid->name_val, subel2, namelen);
				subel2 += namelen;
				subelt_len2 -= namelen;
				BCMP2PLOG((log, TRUE,
					"  namlen=%u name=%s\n", namelen, cid->name_val));
			}
			out_p2p_ie->grpinfo_subelt.num_clients = cid_count;
			break;
		}
		case P2P_SEID_VNDR:
			BCMP2PLOG((log, TRUE,
				"p2papi_decode_p2p_ie: VNDR subelt, len=%u\n",
				subelt_len));
			break;
		case P2P_SEID_ABSENCE:
		{
			int length = subelt_len;
			out_p2p_ie->noa_subelt.eltId = subelt_id;
			memcpy(out_p2p_ie->noa_subelt.len, subel_lenp,
				P2PAPI_LENGTH_SIZE);
			subel2 = subel;
			out_p2p_ie->noa_subelt.index = *subel2++;
			out_p2p_ie->noa_subelt.ops_ctw_parms = *subel2++;
			length -= 2;
			for (i = 0; i < P2P_NOA_SE_MAX_DESC &&
				length >= sizeof(wifi_p2p_noa_desc_t);
				i++, length -= sizeof(wifi_p2p_noa_desc_t)) {
				wifi_p2p_noa_desc_t *desc =
					&out_p2p_ie->noa_subelt.desc[i];
				desc->cnt_type = *subel2++;
				subel2 = decode_integer(subel2,
					sizeof(desc->duration),	(uint32 *)&desc->duration);
				subel2 = decode_integer(subel2,
					sizeof(desc->interval), (uint32 *)&desc->interval);
				subel2 = decode_integer(subel2,
					sizeof(desc->start), (uint32 *)&desc->start);
			}
			break;
		}
		case P2P_SEID_XT_TIMING:
			out_p2p_ie->extlisten_subelt.eltId = subelt_id;
			memcpy(out_p2p_ie->extlisten_subelt.len, subel_lenp,
				P2PAPI_LENGTH_SIZE);
			subel2 = subel;
			memcpy(out_p2p_ie->extlisten_subelt.avail, subel2,
				sizeof(out_p2p_ie->extlisten_subelt.avail));
			subel2 += sizeof(out_p2p_ie->extlisten_subelt.avail);
			memcpy(out_p2p_ie->extlisten_subelt.interval, subel2,
				sizeof(out_p2p_ie->extlisten_subelt.interval));
			subel2 += sizeof(out_p2p_ie->extlisten_subelt.interval);
			BCMP2PLOG((log, TRUE,
				"  len=%u P2P_SEID_XT_TIMING SE: avail=%u,interval=%d\n",
				subelt_len, out_p2p_ie->extlisten_subelt.avail,
				out_p2p_ie->extlisten_subelt.interval));
			break;
		case P2P_SEID_INVITATION_FLAGS:
			out_p2p_ie->invflags_subelt.eltId = subelt_id;
			memcpy(out_p2p_ie->invflags_subelt.len, subel_lenp,
				P2PAPI_LENGTH_SIZE);
			out_p2p_ie->invflags_subelt.inv_flags = *subel;
			BCMP2PLOG((log, TRUE,
				"  len=%u P2P INVIT_FLAGS SE: inv_flags=%u\n",
				subelt_len, out_p2p_ie->invflags_subelt.inv_flags));
			break;
		case P2P_SEID_P2P_IF:
			out_p2p_ie->interface_subelt.eltId = subelt_id;
			memcpy(out_p2p_ie->interface_subelt.len, subel_lenp,
				P2PAPI_LENGTH_SIZE);
			subel2 = subel;
			memcpy(&out_p2p_ie->interface_subelt.devAddr, subel2, 6);
			subel2 += 6;
			out_p2p_ie->interface_subelt.pia_list_count = *subel2++;
			if (out_p2p_ie->interface_subelt.pia_list_count > 0) {
				/* For now we only extract the first interface address in
				 * the P2P Interface Address List.
				 */
				memcpy(&out_p2p_ie->interface_pia_list[0], subel2, 6);
				subel2 += 6;
			}
			BCMP2PLOG((log, TRUE, "  len=%u P2P_IF SE: "
				"devAddr=%02x:%02x:%02x:%02x:%02x:%02x #pia=%u\n",
				subelt_len,
				out_p2p_ie->interface_subelt.devAddr.octet[0],
				out_p2p_ie->interface_subelt.devAddr.octet[1],
				out_p2p_ie->interface_subelt.devAddr.octet[2],
				out_p2p_ie->interface_subelt.devAddr.octet[3],
				out_p2p_ie->interface_subelt.devAddr.octet[4],
				out_p2p_ie->interface_subelt.devAddr.octet[5],
				out_p2p_ie->interface_subelt.pia_list_count));
			if (out_p2p_ie->interface_subelt.pia_list_count > 0) {
				BCMP2PLOG((log, TRUE,
					"    intAddr[0]=%02x:%02x:%02x:%02x:%02x:%02x\n",
					out_p2p_ie->interface_pia_list[0].octet[0],
					out_p2p_ie->interface_pia_list[0].octet[1],
					out_p2p_ie->interface_pia_list[0].octet[2],
					out_p2p_ie->interface_pia_list[0].octet[3],
					out_p2p_ie->interface_pia_list[0].octet[4],
					out_p2p_ie->interface_pia_list[0].octet[5]));
			}
			break;

		default:
			BCMP2PLOG((log, TRUE,
				"p2papi_decode_p2p_ie: unknown subel %u len=%u\n",
				subelt_id, subelt_len));
			break;
		}

		subel += subelt_len;
	}

	return ie->len + 2;
}

#endif /* not SOFTAP_ONLY */


/* Decode a WPS IE.  Returns the total IE len including the ID & len fields */
uint16
p2papi_decode_wps_ie(uint8* buf, p2papi_wps_ie_t *out_wps_ie, BCMP2P_LOG_LEVEL log)
{
	wifi_p2p_ie_t *ie = (wifi_p2p_ie_t*)buf;
	int16 len = (int16) ie->len;
	uint8 *subel = ie->subelts;
	uint16 subelt_id;
	uint16 subelt_len;
	uint16 val;
	uint8 *valptr = (uint8*) &val;

	BCMP2PLOG((log, TRUE, "p2papi_decode_wps_ie: ielen=%d\n", len));

	len -= 4;	/* for the WPS IE's OUI, oui_type fields */

	while (len >= 4) {		/* must have attr id, attr len fields */
		valptr[0] = *subel++;
		valptr[1] = *subel++;
		subelt_id = HTON16(val);

		valptr[0] = *subel++;
		valptr[1] = *subel++;
		subelt_len = HTON16(val);

		len -= 4;			/* for the attr id, attr len fields */
		if (subelt_len > len) {
			p2papi_log_hexdata(log, "WPS IE length exceeds buffer",
				ie->subelts, ie->len);
			return 0;
		}
		len -= subelt_len;	/* for the remaining fields in this attribute */
		BCMP2PLOG((log, TRUE,
			" subel=%p, subelt_id=0x%x subelt_len=%u\n",
			subel, subelt_id, subelt_len));

		if (subelt_id == WPS_ID_VERSION) {
			out_wps_ie->wps_version = *subel;
			BCMP2PLOG((log, TRUE,
				"  attr WPS_ID_VERSION: %u\n", out_wps_ie->wps_version));
		} else if (subelt_id == WPS_ID_REQ_TYPE) {
			out_wps_ie->req_type = *subel;
			BCMP2PLOG((log, TRUE,
				"  attr WPS_ID_REQ_TYPE: %u\n", out_wps_ie->req_type));
		} else if (subelt_id == WPS_ID_CONFIG_METHODS) {
			valptr[0] = *subel;
			valptr[1] = *(subel + 1);
			out_wps_ie->cfg_methods = HTON16(val);
			BCMP2PLOG((log, TRUE,
				"  attr WPS_ID_CONFIG_METHODS: %x\n",
				out_wps_ie->cfg_methods));
		} else if (subelt_id == WPS_ID_DEVICE_NAME) {
			uint16 name_len;
			name_len = subelt_len;
			if (name_len >= sizeof(out_wps_ie->devname)) {
				name_len = sizeof(out_wps_ie->devname) - 1;
			}
			memcpy(out_wps_ie->devname, subel, name_len);
			out_wps_ie->devname[name_len] = '\0';
			out_wps_ie->devname_len = (uint8)name_len;
			BCMP2PLOG((log, TRUE,
				"  attr WPS_ID_DEVICE_NAME: %s (len %u)\n",
				out_wps_ie->devname, name_len));
		} else if (subelt_id == WPS_ID_DEVICE_PWD_ID) {
			valptr[0] = *subel;
			valptr[1] = *(subel + 1);
			out_wps_ie->devpwd_id = HTON16(val);
			BCMP2PLOG((log, TRUE,
				"  attr WPS_ID_DEVICE_PWD_ID: %u\n",
				out_wps_ie->devpwd_id));
		} else if (subelt_id == WPS_ID_PRIM_DEV_TYPE) {
			valptr[0] = *subel;
			valptr[1] = *(subel + 1);
			out_wps_ie->devtype_cat_id = HTON16(val);
			valptr[0] = *(subel + 6);
			valptr[1] = *(subel + 7);
			out_wps_ie->devtype_subcat_id = HTON16(val);
			BCMP2PLOG((log, TRUE,
				"  attr WPS_ID_PRIM_DEV_TYPE: cat=%u subcat=%u\n",
				out_wps_ie->devtype_cat_id, out_wps_ie->devtype_subcat_id));
		} else if (subelt_id == WPS_ID_REQ_DEV_TYPE) {
			valptr[0] = *subel;
			valptr[1] = *(subel + 1);
			out_wps_ie->req_devtype_cat = HTON16(val);
			valptr[0] = *(subel + 6);
			valptr[1] = *(subel + 7);
			out_wps_ie->req_subcat = HTON16(val);
			BCMP2PLOG((log, TRUE,
				"  attr WPS_ID_REQ_DEV_TYPE: cat=%u subcat=%u\n",
				out_wps_ie->req_devtype_cat, out_wps_ie->req_subcat));
		} else {
			BCMP2PLOG((log, TRUE, "  unknown attr 0x%x\n",	subelt_id));
		}

		subel += subelt_len;
	}
	return ((int16)ie->len) + 2;
}


/* Get the BSSCFG index for a BSSCFG of the specified type */
int
p2papi_get_bsscfg_idx(p2papi_instance_t* hdl, p2papi_bsscfg_type_t bsscfg_type)
{
	if (bsscfg_type >= P2PAPI_BSSCFG_MAX) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_get_bsscfg_idx: bsscfg_type %d > %d\n",
			bsscfg_type, P2PAPI_BSSCFG_MAX));
		return 0;
	}
	return hdl->bssidx[bsscfg_type];
}

/* Given an encoded IE,
 * - extract the IE data needed for the vndr_ie iovar into the new IE
 * - atomically delete the old IE and add the new IE
 * - save the new IE, replacing the previous copy
 * The caller must call p2papi_osl_lock() before calling this fn.
 */
int
p2papi_replace_and_save_ie(p2papi_instance_t* hdl, uint32 pktflag,
	uint8 oui0, uint8 oui1, uint8 oui2, uint8 ie_id, int bssidx,
	uint8 **old_ie_bufp, int *old_ie_lenp, uint8 *new_ie, int new_ie_len)
{
	uint8 *old_ie_buf;
	int old_ie_len;
	uint8 *new_ie_buf;
	P2PWL_HDL wl;
	int err;
	int retval = 0;

	if (!P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl))
		return BCMP2P_INVALID_HANDLE;
	wl = P2PAPI_GET_WL_HDL(hdl);

	old_ie_buf = *old_ie_bufp;
	old_ie_len = *old_ie_lenp;
	BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
		"replace_and_save_ie: old_ie_len=%d new_ie_len=%d\n",
		old_ie_len, new_ie_len));

	/* Extract the IE data needed for the vndr_ie iovar into the new IE */
	if (new_ie == NULL || new_ie_len == 0) {
		new_ie_buf = NULL;
		new_ie_len = 0;
	} else {
		new_ie_buf = (uint8 *)P2PAPI_MALLOC(new_ie_len);
		if (new_ie_buf == NULL) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
				"p2papi_replace_and_save_ie: malloc fail, len=%d\n",
				new_ie_len));
			retval = -1;
			goto rsie_exit;
		}
		memcpy(new_ie_buf, new_ie, new_ie_len);
	}

		/* atomically delete the old IE and add the new IE */
		err = p2pwl_vndr_ie(wl, bssidx, pktflag, oui0, oui1, oui2,
			ie_id, old_ie_buf, old_ie_len, new_ie_buf, new_ie_len);
	if (err < 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"replace_and_save_ie: err %d, pktf=0x%02x, not saving IE.\n",
			err, pktflag));
		if (new_ie_buf)
			P2PAPI_FREE(new_ie_buf);
	} else {
		/* save the new IE, replacing the previous copy */
		BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
			"replace_and_save_ie: pktf=0x%02x old=%p,len=%d new=%p,len=%d\n",
			pktflag, *old_ie_bufp, *old_ie_lenp, new_ie_buf, new_ie_len));
		*old_ie_bufp = new_ie_buf;
		*old_ie_lenp = new_ie_len;
		if (old_ie_buf) {
			P2PAPI_FREE(old_ie_buf);
		}
	}

rsie_exit:
	return retval;
}

/* Reset all saved P2P and WPS IEs.  Call this when deleting a BSSCFG which
 * results in the driver wiping out all the previously set IEs.
 */
int
p2papi_reset_saved_p2p_wps_ies_nolock(p2papi_instance_t* hdl,
	p2papi_bsscfg_type_t bsscfg_type)
{
	p2papi_saved_ie_t *saved_ie;
	uint8 *ie_buf;

	if (bsscfg_type >= P2PAPI_BSSCFG_MAX) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_reset_saved_p2p_wps_ies: bsscfg_type %d > %d\n",
			bsscfg_type, P2PAPI_BSSCFG_MAX));
		return -1;
	}

	saved_ie = &hdl->saved_ie[bsscfg_type];
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_reset_saved_p2p_wps_ies: iscon=%d isdis=%d usage=%d idx=%d\n",
		hdl->is_connecting, hdl->is_p2p_discovery_on, bsscfg_type,
		saved_ie->ie_bsscfg_idx));

	saved_ie->ie_bsscfg_idx = 0;

	if (saved_ie->probreq_wps_ie_buf) {
		ie_buf = saved_ie->probreq_wps_ie_buf;
		saved_ie->probreq_wps_ie_buf = NULL;
		saved_ie->probreq_wps_ie_len = 0;
		P2PAPI_FREE(ie_buf);
	}

	if (saved_ie->probreq_p2p_ie_buf) {
		ie_buf = saved_ie->probreq_p2p_ie_buf;
		saved_ie->probreq_p2p_ie_buf = NULL;
		saved_ie->probreq_p2p_ie_len = 0;
		P2PAPI_FREE(ie_buf);
	}

	if (saved_ie->probrsp_wps_ie_buf) {
		ie_buf = saved_ie->probrsp_wps_ie_buf;
		saved_ie->probrsp_wps_ie_buf = NULL;
		saved_ie->probrsp_wps_ie_len = 0;
		P2PAPI_FREE(ie_buf);
	}

	if (saved_ie->probrsp_p2p_ie_buf) {
		ie_buf = saved_ie->probrsp_p2p_ie_buf;
		saved_ie->probrsp_p2p_ie_buf = NULL;
		saved_ie->probrsp_p2p_ie_len = 0;
		P2PAPI_FREE(ie_buf);
	}

	if (saved_ie->assocreq_p2p_ie_buf) {
		ie_buf = saved_ie->assocreq_p2p_ie_buf;
		saved_ie->assocreq_p2p_ie_buf = NULL;
		saved_ie->assocreq_p2p_ie_len = 0;
		P2PAPI_FREE(ie_buf);
	}

	if (saved_ie->assocrsp_p2p_ie_buf) {
		ie_buf = saved_ie->assocrsp_p2p_ie_buf;
		saved_ie->assocrsp_p2p_ie_buf = NULL;
		saved_ie->assocrsp_p2p_ie_len = 0;
		P2PAPI_FREE(ie_buf);
	}

	if (saved_ie->beacon_wps_ie_buf) {
		ie_buf = saved_ie->beacon_wps_ie_buf;
		saved_ie->beacon_wps_ie_buf = NULL;
		saved_ie->beacon_wps_ie_len = 0;
		P2PAPI_FREE(ie_buf);
	}

	if (saved_ie->beacon_p2p_ie_buf) {
		ie_buf = saved_ie->beacon_p2p_ie_buf;
		saved_ie->beacon_p2p_ie_buf = NULL;
		saved_ie->beacon_p2p_ie_len = 0;
		P2PAPI_FREE(ie_buf);
	}

	/* CUSTOM_IE: Free saved custom IEs */
	/* CUSTOM_IE */
	if (saved_ie->probreq_custom_ie_buf) {
		ie_buf = saved_ie->probreq_custom_ie_buf;
		saved_ie->probreq_custom_ie_buf = NULL;
		saved_ie->probreq_custom_ie_len = 0;
		P2PAPI_FREE(ie_buf);
	}

	if (saved_ie->probrsp_custom_ie_buf) {
		ie_buf = saved_ie->probrsp_custom_ie_buf;
		saved_ie->probrsp_custom_ie_buf = NULL;
		saved_ie->probrsp_custom_ie_len = 0;
		P2PAPI_FREE(ie_buf);
	}

	if (saved_ie->beacon_custom_ie_buf) {
		ie_buf = saved_ie->beacon_custom_ie_buf;
		saved_ie->beacon_custom_ie_buf = NULL;
		saved_ie->beacon_custom_ie_len = 0;
		P2PAPI_FREE(ie_buf);
	}

	if (saved_ie->assocreq_custom_ie_buf) {
		ie_buf = saved_ie->assocreq_custom_ie_buf;
		saved_ie->assocreq_custom_ie_buf = NULL;
		saved_ie->assocreq_custom_ie_len = 0;
		P2PAPI_FREE(ie_buf);
	}

	if (saved_ie->assocrsp_custom_ie_buf) {
		ie_buf = saved_ie->assocrsp_custom_ie_buf;
		saved_ie->assocrsp_custom_ie_buf = NULL;
		saved_ie->assocrsp_custom_ie_len = 0;
		P2PAPI_FREE(ie_buf);
	}

	return 0;
}
int
p2papi_reset_saved_p2p_wps_ies(p2papi_instance_t* hdl,
	p2papi_bsscfg_type_t bsscfg_type)
{
	int ret;

	P2PAPI_DATA_LOCK(hdl);
	ret = p2papi_reset_saved_p2p_wps_ies_nolock(hdl, bsscfg_type);
	P2PAPI_DATA_UNLOCK(hdl);
	return ret;
}


#define P2PAPI_MAX_P2P_IE_LEN (sizeof(*p2p_ie) + P2PAPI_MAX_VNDR_IE_SIZE)
#define P2PAPI_MAX_WPS_IE_LEN sizeof(*wps_ie)

/* Update P2P and WPS IEs in Probe Response frames.
 * The caller must call p2papi_osl_lock() before calling this fn.
 */
int
p2papi_update_prbresp_ies(p2papi_instance_t* hdl,
	p2papi_bsscfg_type_t bsscfg_type)
{
	p2papi_p2p_ie_enc_t *wps_ie = NULL;
	uint8 *wps_ie_data = NULL;
	int wps_ie_len = 0;
#ifndef SOFTAP_ONLY
	wifi_p2p_ie_t *p2p_ie = NULL;
	uint8 *p2p_ie_data = NULL;
	int p2p_ie_len = 0;
#endif /* not SOFTAP_ONLY */
	uint16 ie_len = 0;
	p2papi_saved_ie_t *saved_ie;
	int bssidx;
	int ret = 0;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_update_prbresp_ies: begin\n"));

	/* Check if the specified bsscfg type is valid */
	bssidx = p2papi_get_bsscfg_idx(hdl, bsscfg_type);
	if (bssidx == 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_update_prbresp_ies: bad bssidx 0 for bsscfg_type %u\n",
			bsscfg_type));
		ret = -1;
		goto update_prbrsp_ie_exit;
	}
	saved_ie = &hdl->saved_ie[bsscfg_type];

	if (saved_ie->ie_bsscfg_idx != 0 && saved_ie->ie_bsscfg_idx != bssidx) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_update_prbresp_ies: %d != %d, invalidate prev saved IEs\n",
			saved_ie->ie_bsscfg_idx, bssidx));
		p2papi_reset_saved_p2p_wps_ies_nolock(hdl, bsscfg_type);
	}

	/* Allocate the IE encode structs */
#ifndef SOFTAP_ONLY
	p2p_ie = (wifi_p2p_ie_t*) P2PAPI_MALLOC(P2PAPI_MAX_P2P_IE_LEN);
	if (p2p_ie == NULL) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_update_prbresp_ies: p2p_ie malloc fail, len=%d\n",
			sizeof(*p2p_ie)));
		ret = -1;
		goto update_prbrsp_ie_exit;
	}
#endif /* not SOFTAP_ONLY */
	wps_ie = (p2papi_p2p_ie_enc_t*)P2PAPI_MALLOC(P2PAPI_MAX_WPS_IE_LEN);
	if (wps_ie == NULL) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_update_prbresp_ies: wps_ie malloc fail, len=%d\n",
			sizeof(*wps_ie)));
		ret = -1;
		goto update_prbrsp_ie_exit;
	}

	/* Add/Delete the probe response WPS IE.
	 * Do not add WPS IEs for a connection bsscfg if we are acting as an AP.
	 * WPS add its own WPS IEs for that case.  WPSCLI also first deletes any
	 * WPS IE added by anyone else.
	 */
	if ((hdl->is_connecting || hdl->is_p2p_discovery_on) &&
		!(bsscfg_type == P2PAPI_BSSCFG_CONNECTION && hdl->is_ap)) {
		p2papi_encode_prbresp_wps_ie(hdl, wps_ie,
			hdl->pri_dev_type, hdl->pri_dev_subcat,
#ifdef SECONDARY_DEVICE_TYPE
						hdl->sec_dev_type, hdl->sec_dev_subcat,
#endif
			hdl->fname_ssid, hdl->fname_ssid_len,
			TRUE, hdl->ap_config.WPSConfig.wpsConfigMethods,
			&ie_len);
		P2PLIB_ASSERT(ie_len <= P2PAPI_MAX_WPS_IE_LEN);
		wps_ie_data = wps_ie->data;
		wps_ie_len = ie_len - 5;
	} else {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_update_prbresp_ies: no new wps ie\n"));
		wps_ie_data = NULL;
		wps_ie_len = 0;
	}
	if (0 != p2papi_replace_and_save_ie(hdl, VNDR_IE_PRBRSP_FLAG,
		WPS_OUI[0], WPS_OUI[1], WPS_OUI[2], WPS_OUI_TYPE, bssidx,
		&saved_ie->probrsp_wps_ie_buf, &saved_ie->probrsp_wps_ie_len,
		wps_ie_data, wps_ie_len)) {
		ret = -1;
		goto update_prbrsp_ie_exit;
	}

#ifndef SOFTAP_ONLY
	/* Add/Delete the probe response P2P IE */
	if (hdl->is_connecting || hdl->is_p2p_discovery_on) {
		memset(p2p_ie, 0, sizeof(*p2p_ie));
		p2papi_encode_prbresp_p2p_ie(hdl, /* P2P_CAPSE_DEV_SERVICE_DIS | */
			p2papi_generate_dev_cap_bitmap(hdl),
			p2papi_generate_grp_cap_bitmap(hdl),
			hdl->extended_listen.enabled,
			hdl->extended_listen.period, hdl->extended_listen.interval,
			hdl->p2p_dev_addr.octet,
			hdl->fname_ssid, hdl->fname_ssid_len,
			P2PAPI_MAX_P2P_IE_LEN, p2p_ie, &ie_len);
		P2PLIB_ASSERT(ie_len <= P2PAPI_MAX_P2P_IE_LEN);
		p2p_ie_data = &(p2p_ie->oui_type);
		p2p_ie_len = ie_len - 5;
	} else {
		p2p_ie_data = NULL;
		p2p_ie_len = 0;
	}
	if (0 != p2papi_replace_and_save_ie(hdl, VNDR_IE_PRBRSP_FLAG,
		P2P_OUI[0], P2P_OUI[1], P2P_OUI[2], P2P_IE_ID, bssidx,
		&saved_ie->probrsp_p2p_ie_buf, &saved_ie->probrsp_p2p_ie_len,
		p2p_ie_data, p2p_ie_len)) {
		ret = -1;
		goto update_prbrsp_ie_exit;
	}

	/* CUSTOM_IE: Add/Delete custom IE if provided */
	if (hdl->custom_mgmt_ie[BCMP2P_MGMT_IE_FLAG_PRBRSP].ie_buf != NULL) {
		vndr_ie_t *custom_ie =
			(vndr_ie_t *)hdl->custom_mgmt_ie[BCMP2P_MGMT_IE_FLAG_PRBRSP].ie_buf;
		ie_len = hdl->custom_mgmt_ie[BCMP2P_MGMT_IE_FLAG_PRBRSP].ie_buf_len;
		if (0 != p2papi_replace_and_save_ie(hdl, VNDR_IE_PRBRSP_FLAG,
			custom_ie->oui[0], custom_ie->oui[1], custom_ie->oui[2],
			custom_ie->id, bssidx,
			&saved_ie->probrsp_custom_ie_buf, &saved_ie->probrsp_custom_ie_len,
			custom_ie->data, ie_len - 5)) {
			ret = -1;
			goto update_prbrsp_ie_exit;
		}
	}

#endif /* not SOFTAP_ONLY */

update_prbrsp_ie_exit:
	if (wps_ie)
		P2PAPI_FREE(wps_ie);
#ifndef SOFTAP_ONLY
	if (p2p_ie)
		P2PAPI_FREE(p2p_ie);
#endif /* not SOFTAP_ONLY */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_update_prbresp_ies: end\n"));
	return ret;
}

/* Update all P2P and WPS IEs in all frame types based on the current P2P
 * connection state.
 */
int
p2papi_update_p2p_wps_ies_nolock(p2papi_instance_t* hdl,
	p2papi_bsscfg_type_t bsscfg_type)
{
	p2papi_p2p_ie_enc_t *wps_ie = NULL;
	uint8 *wps_ie_data = NULL;
	int wps_ie_len = 0;
#ifndef SOFTAP_ONLY
	wifi_p2p_ie_t *p2p_ie = NULL;
	uint8 *p2p_ie_data = NULL;
	int p2p_ie_len = 0;
#endif /* not SOFTAP_ONLY */
	uint16 ie_len = 0;
	p2papi_saved_ie_t *saved_ie;
	int bssidx;
	int ret = 0;

	/* Do not add any IEs if running as a non-P2P softAP */
	if (!hdl->enable_p2p) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_update_p2p_wps_ies: not deleting or adding any IEs.\n"));
		goto update_ie_exit;
	}

	/* Check if the specified bsscfg type is valid */
	bssidx = p2papi_get_bsscfg_idx(hdl, bsscfg_type);
	if (bssidx == 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_update_p2p_wps_ies: bad bssidx 0 for bsscfg_type %u\n",
			bsscfg_type));
		ret = -1;
		goto update_ie_exit;
	}

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_update_p2p_wps_ies: con=%d dis=%d ap=%d wps=%d idx=%d typ=%d\n",
		hdl->is_connecting, hdl->is_p2p_discovery_on, hdl->is_ap,
		hdl->is_wps_enrolling, bssidx, bsscfg_type));

	/* If the BSSCFG of our saved IEs no longer exists, invalidate the
	 * saved IEs.
	 * eg. this is the case when we:
	 * - call this fn to add & save IEs for the P2P discovery bsscfg with idx=1
	 * - delete the discovery BSSCFG (WL driver deletes all IEs on this bsscfg)
	 * - call this fn to update the IEs for no P2P discovery (curr bsscfg idx=0)
	 *   At this point our saved IEs are irrelevant because the bsscfg they were
	 *   saved for no longer exists.
	 */
	saved_ie = &hdl->saved_ie[bsscfg_type];
	if (saved_ie->ie_bsscfg_idx != 0 && saved_ie->ie_bsscfg_idx != bssidx) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_update_p2p_wps_ies: %d != %d, invalidate prev saved IEs\n",
			saved_ie->ie_bsscfg_idx, bssidx));
		p2papi_reset_saved_p2p_wps_ies_nolock(hdl, bsscfg_type);
	}

	/* Save the current bsscfg index of the BSSCFG we are updating IEs for */
	saved_ie->ie_bsscfg_idx = bssidx;

	(void) p2papi_update_prbresp_ies(hdl, bsscfg_type);

#ifndef SOFTAP_ONLY
	/* Allocate the IE encode structs */
	p2p_ie = (wifi_p2p_ie_t*) P2PAPI_MALLOC(P2PAPI_MAX_P2P_IE_LEN);
	if (p2p_ie == NULL) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_update_p2p_wps_ies: p2p_ie malloc fail, len=%d\n",
			sizeof(*p2p_ie)));
		ret = -1;
		goto update_ie_exit;
	}
#endif /* not SOFTAP_ONLY */
	wps_ie = (p2papi_p2p_ie_enc_t*) P2PAPI_MALLOC(P2PAPI_MAX_WPS_IE_LEN);
	if (wps_ie == NULL) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_update_p2p_wps_ies: wps_ie malloc fail, len=%d\n",
			sizeof(*wps_ie)));
		ret = -1;
		goto update_ie_exit;
	}


	/* Encode, update, and save the probe request WPS IE */
	if ((hdl->is_connecting || hdl->is_p2p_discovery_on) &&
		!(bsscfg_type == P2PAPI_BSSCFG_CONNECTION && hdl->is_ap)) {
		p2papi_encode_prbreq_wps_ie(hdl, wps_ie,
			hdl->pri_dev_type, hdl->pri_dev_subcat,
			hdl->fname_ssid, hdl->fname_ssid_len,
			hdl->ap_config.WPSConfig.wpsConfigMethods, &ie_len);
		P2PLIB_ASSERT(ie_len <= P2PAPI_MAX_WPS_IE_LEN);
		wps_ie_data = wps_ie->data;
		wps_ie_len = ie_len - 5;
	} else {
		wps_ie_data = NULL;
		wps_ie_len = 0;
	}
	if (0 != p2papi_replace_and_save_ie(hdl, VNDR_IE_PRBREQ_FLAG,
		WPS_OUI[0], WPS_OUI[1], WPS_OUI[2], WPS_OUI_TYPE, bssidx,
		&saved_ie->probreq_wps_ie_buf, &saved_ie->probreq_wps_ie_len,
		wps_ie_data, wps_ie_len)) {
		ret = -1;
		goto update_ie_exit;
	}

#ifndef SOFTAP_ONLY
	/* Encode, update, and save the probe request P2P IE */
	if (hdl->is_connecting || hdl->is_p2p_discovery_on) {
		memset(p2p_ie, 0, sizeof(*p2p_ie));
		p2papi_encode_prbreq_p2p_ie(hdl, /* P2P_CAPSE_DEV_SERVICE_DIS | */
			p2papi_generate_dev_cap_bitmap(hdl),
			p2papi_generate_grp_cap_bitmap(hdl),
			hdl->country,
			&hdl->listen_channel, hdl->extended_listen.enabled,
			hdl->extended_listen.period, hdl->extended_listen.interval,
			&hdl->op_channel, p2p_ie, &ie_len);
		P2PLIB_ASSERT(ie_len <= P2PAPI_MAX_P2P_IE_LEN);
		p2p_ie_data = &(p2p_ie->oui_type);
		p2p_ie_len = ie_len - 5;
	} else {
		p2p_ie_data = NULL;
		p2p_ie_len = 0;
	}
	if (0 != p2papi_replace_and_save_ie(hdl, VNDR_IE_PRBREQ_FLAG,
		P2P_OUI[0], P2P_OUI[1], P2P_OUI[2], P2P_IE_ID, bssidx,
		&saved_ie->probreq_p2p_ie_buf, &saved_ie->probreq_p2p_ie_len,
		p2p_ie_data, p2p_ie_len)) {
		ret = -1;
		goto update_ie_exit;
	}

	/* CUSTOM_IE: Update and save custom IE to probe request if provided */
	if (hdl->is_connecting || hdl->is_p2p_discovery_on) {
		vndr_ie_t *custom_ie =
			(vndr_ie_t *)hdl->custom_mgmt_ie[BCMP2P_MGMT_IE_FLAG_PRBREQ].ie_buf;
		ie_len = hdl->custom_mgmt_ie[BCMP2P_MGMT_IE_FLAG_PRBREQ].ie_buf_len;
		if (custom_ie != NULL) {
			if (0 != p2papi_replace_and_save_ie(hdl, VNDR_IE_PRBREQ_FLAG,
				custom_ie->oui[0], custom_ie->oui[1], custom_ie->oui[2], custom_ie->id, bssidx,
				&saved_ie->probreq_custom_ie_buf, &saved_ie->probreq_custom_ie_len,
				custom_ie->data, ie_len - 5)) {
				ret = -1;
				goto update_ie_exit;
			}
		}
	}

	/* Add/Delete the association request P2P IE unless this is a discovery
	 * bsscfg which never sends assoc req/rsp.
	 */
	if ((hdl->is_connecting || hdl->is_p2p_discovery_on) &&
		!(bsscfg_type == P2PAPI_BSSCFG_DEVICE)) {
		memset(p2p_ie, 0, sizeof(*p2p_ie));
		p2papi_encode_assocreq_p2p_ie(hdl, /* P2P_CAPSE_DEV_SERVICE_DIS | */
			p2papi_generate_dev_cap_bitmap(hdl),
			p2papi_generate_grp_cap_bitmap(hdl),
			hdl->extended_listen.enabled,
			hdl->extended_listen.period, hdl->extended_listen.interval,
			hdl->p2p_dev_addr.octet, hdl->fname_ssid, hdl->fname_ssid_len,
			p2p_ie, &ie_len);
		P2PLIB_ASSERT(ie_len <= P2PAPI_MAX_P2P_IE_LEN);
		p2p_ie_data = &(p2p_ie->oui_type);
		p2p_ie_len = ie_len - 5;
	} else {
		p2p_ie_data = NULL;
		p2p_ie_len = 0;
	}
	if (0 != p2papi_replace_and_save_ie(hdl, VNDR_IE_ASSOCREQ_FLAG,
		P2P_OUI[0], P2P_OUI[1], P2P_OUI[2], P2P_IE_ID, bssidx,
		&saved_ie->assocreq_p2p_ie_buf, &saved_ie->assocreq_p2p_ie_len,
		p2p_ie_data, p2p_ie_len)) {
		ret = -1;
		goto update_ie_exit;
	}

	/* CUSTOM_IE: Update and save custom IE to association request if provided */
	if ((hdl->is_connecting || hdl->is_p2p_discovery_on) &&
		!(bsscfg_type == P2PAPI_BSSCFG_DEVICE)) {
		vndr_ie_t *custom_ie =
			(vndr_ie_t *)hdl->custom_mgmt_ie[BCMP2P_MGMT_IE_FLAG_ASSOCREQ].ie_buf;
		ie_len = hdl->custom_mgmt_ie[BCMP2P_MGMT_IE_FLAG_ASSOCREQ].ie_buf_len;
		if (custom_ie != NULL) {
			if (0 != p2papi_replace_and_save_ie(hdl, VNDR_IE_ASSOCREQ_FLAG,
				custom_ie->oui[0], custom_ie->oui[1], custom_ie->oui[2], custom_ie->id, bssidx,
				&saved_ie->assocreq_custom_ie_buf, &saved_ie->assocreq_custom_ie_len,
				custom_ie->data, ie_len - 5)) {
				ret = -1;
				goto update_ie_exit;
			}
		}
	}

	/* Add/Delete the association response P2P IE unless this is a discovery
	 * bsscfg which never sends assoc req/rsp.
	 */
	if ((hdl->is_connecting || hdl->is_p2p_discovery_on) &&
		!(bsscfg_type == P2PAPI_BSSCFG_DEVICE)) {
		memset(p2p_ie, 0, sizeof(*p2p_ie));
		p2papi_encode_assocresp_p2p_ie(hdl, 0,
		    hdl->extended_listen.enabled,
		    hdl->extended_listen.period, hdl->extended_listen.interval,
		    0, p2p_ie, &ie_len);
		P2PLIB_ASSERT(ie_len <= P2PAPI_MAX_P2P_IE_LEN);
		p2p_ie_data = &(p2p_ie->oui_type);
		p2p_ie_len = ie_len - 5;
	} else {
		p2p_ie_data = NULL;
		p2p_ie_len = 0;
	}
	if (0 != p2papi_replace_and_save_ie(hdl, VNDR_IE_ASSOCRSP_FLAG,
		P2P_OUI[0], P2P_OUI[1], P2P_OUI[2], P2P_IE_ID, bssidx,
		&saved_ie->assocrsp_p2p_ie_buf, &saved_ie->assocrsp_p2p_ie_len,
		p2p_ie_data, p2p_ie_len)) {
		ret = -1;
		goto update_ie_exit;
	}

	/* CUSTOM_IE: Update and save custom IE to association response if provided */
	if ((hdl->is_connecting || hdl->is_p2p_discovery_on) &&
		!(bsscfg_type == P2PAPI_BSSCFG_DEVICE)) {
		vndr_ie_t *custom_ie =
			(vndr_ie_t *)hdl->custom_mgmt_ie[BCMP2P_MGMT_IE_FLAG_ASSOCRSP].ie_buf;
		ie_len = hdl->custom_mgmt_ie[BCMP2P_MGMT_IE_FLAG_ASSOCRSP].ie_buf_len;
		if (custom_ie != NULL) {
			if (0 != p2papi_replace_and_save_ie(hdl, VNDR_IE_ASSOCRSP_FLAG,
				custom_ie->oui[0], custom_ie->oui[1], custom_ie->oui[2], custom_ie->id, bssidx,
				&saved_ie->assocrsp_custom_ie_buf, &saved_ie->assocrsp_custom_ie_len,
				custom_ie->data, ie_len - 5)) {
				ret = -1;
				goto update_ie_exit;
			}
		}
	}

#endif /* not SOFTAP_ONLY */


	/* Do not add WPS IEs for a connection bsscfg if we are acting as an AP.
	 * WPS add its own WPS IEs for that case.  WPSCLI also first deletes any
	 * WPS IE added by anyone else.
	 */

#ifndef SOFTAP_ONLY
	/* Add/Delete the beacon P2P IE */
	if (hdl->is_connecting && hdl->is_ap) {
		memset(p2p_ie, 0, sizeof(*p2p_ie));
		p2papi_encode_beacon_p2p_ie(hdl, /* P2P_CAPSE_DEV_SERVICE_DIS | */
			p2papi_generate_dev_cap_bitmap(hdl),
			p2papi_generate_grp_cap_bitmap(hdl),
			0, p2p_ie, &ie_len);
		P2PLIB_ASSERT(ie_len <= P2PAPI_MAX_P2P_IE_LEN);
		p2p_ie_data = &(p2p_ie->oui_type);
		p2p_ie_len = ie_len - 5;
	} else {
		p2p_ie_data = NULL;
		p2p_ie_len = 0;
	}
	if (0 != p2papi_replace_and_save_ie(hdl, VNDR_IE_BEACON_FLAG,
		P2P_OUI[0], P2P_OUI[1], P2P_OUI[2], P2P_IE_ID, bssidx,
		&saved_ie->beacon_p2p_ie_buf, &saved_ie->beacon_p2p_ie_len,
		p2p_ie_data, p2p_ie_len)) {
		ret = -1;
		goto update_ie_exit;
	}

	/* CUSTOM_IE: Update and save custom IE to association request if provided */
	if (hdl->is_connecting && hdl->is_ap) {
		vndr_ie_t *custom_ie =
			(vndr_ie_t *)hdl->custom_mgmt_ie[BCMP2P_MGMT_IE_FLAG_BEACON].ie_buf;
		ie_len = hdl->custom_mgmt_ie[BCMP2P_MGMT_IE_FLAG_BEACON].ie_buf_len;
		if (custom_ie != NULL) {
			if (0 != p2papi_replace_and_save_ie(hdl, VNDR_IE_BEACON_FLAG,
				custom_ie->oui[0], custom_ie->oui[1], custom_ie->oui[2], custom_ie->id, bssidx,
				&saved_ie->beacon_custom_ie_buf, &saved_ie->beacon_custom_ie_len,
				custom_ie->data, ie_len - 5)) {
				ret = -1;
				goto update_ie_exit;
			}
		}
	}

#endif /* not SOFTAP_ONLY */

update_ie_exit:
	if (wps_ie)
		P2PAPI_FREE(wps_ie);
#ifndef SOFTAP_ONLY
	if (p2p_ie)
		P2PAPI_FREE(p2p_ie);
#endif /* not SOFTAP_ONLY */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_update_p2p_wps_ies: end\n"));
	return ret;
}
int
p2papi_update_p2p_wps_ies(p2papi_instance_t* hdl,
	p2papi_bsscfg_type_t bsscfg_type)
{
	int ret;

	P2PAPI_DATA_LOCK(hdl);
	ret = p2papi_update_p2p_wps_ies_nolock(hdl, bsscfg_type);
	P2PAPI_DATA_UNLOCK(hdl);
	return ret;
}


/* Initialize P2P Discovery (create P2P discovery BSS) */
int
p2papi_init_discovery(p2papi_instance_t* hdl)
{
	P2PWL_HDL wl;
	int retval = BCME_OK;
	int ret;
	int index = 0;

	P2PAPI_CHECK_P2PHDL(hdl);
	if (!P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl))
		return BCMP2P_INVALID_HANDLE;
	wl = P2PAPI_GET_WL_HDL(hdl);

	if (hdl->bssidx[P2PAPI_BSSCFG_DEVICE] != 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_init_discovery: do nothing, already initialized\n"));
		return retval;
	}


	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_init_discovery\n"));
	if (!hdl->enable_p2p) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_init_discovery: p2p not enabled\n"));
		return -1;
	}

	/* Set the bsscfg interface name for the discovery bsscfg. */
	p2posl_save_bssname(wl, P2PAPI_BSSCFG_DEVICE, hdl->primary_if_name);

	/* Enable P2P discovery in the WL driver */
	ret = p2pwl_set_p2p_discovery(wl, 1);
	if (ret < 0) {
		return ret;
	}

	/* Get the index of the bsscfg created by the driver for P2P discovery */
	ret = p2pwl_get_p2p_disc_idx(wl, &index);
	if (ret < 0) {
		return ret;
	}
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_init_discovery: discov_bssidx=%d\n", index));
	p2papi_save_bssidx(hdl, P2PAPI_BSSCFG_DEVICE, index);

	/* Set the initial discovery state to SCAN */
	ret = p2pwl_set_p2p_mode(wl, WL_P2P_DISC_ST_SCAN, 0, 0,
		hdl->bssidx[P2PAPI_BSSCFG_DEVICE]);
	if (ret != 0) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_init_discovery: unable to set WL_P2P_DISC_ST_SCAN\n"));
		(void) p2pwl_set_p2p_discovery(wl, 0);
		p2papi_save_bssidx(hdl, P2PAPI_BSSCFG_DEVICE, 0);
		return 0;
	}

	return retval;
}

/* Deinitialize P2P Discovery */
int
p2papi_deinit_discovery(p2papi_instance_t* hdl)
{
	int ret = BCME_OK;
	P2PWL_HDL wl;

	P2PAPI_CHECK_P2PHDL(hdl);
	if (!P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl))
		return BCMP2P_INVALID_HANDLE;
	wl = P2PAPI_GET_WL_HDL(hdl);

	if (hdl->bssidx[P2PAPI_BSSCFG_DEVICE] == 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_deinit_discovery: do nothing, not initialized\n"));
		return -1;
	}
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_deinit_discovery\n"));

	/* Set the discovery state to SCAN */
	ret = p2pwl_set_p2p_mode(wl, WL_P2P_DISC_ST_SCAN, 0, 0,
		hdl->bssidx[P2PAPI_BSSCFG_DEVICE]);

	/* Disable P2P discovery in the WL driver (deletes the discovery BSSCFG) */
	hdl->is_p2p_discovery_on = FALSE;
	ret = p2pwl_set_p2p_discovery(wl, 0);

/* TEMP - wait for driver to delete the discovery BSSCFG */
/*
BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_deinit_discovery: 300ms delay\n"));
p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_GENERIC, 300);
*/

	/* Clear our saved WPS and P2P IEs for the discovery BSS.  The driver
	 * deleted these IEs when p2pwl_set_p2p_discovery() deleted the discovery
	 * BSS.
	 */
	p2papi_reset_saved_p2p_wps_ies(hdl, P2PAPI_BSSCFG_DEVICE);

	/* Clear the saved bsscfg index of the discovery BSSCFG to indicate we
	 * have no discovery BSS.
	 */
	p2papi_save_bssidx(hdl, P2PAPI_BSSCFG_DEVICE, 0);

	return ret;
}

/* Enable P2P Discovery */
int
p2papi_enable_discovery(p2papi_instance_t* hdl)
{
	int ret;

	hdl->is_p2p_discovery_on = TRUE;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_enable_discovery\n"));

	hdl->is_in_discovery_disable = 0;

	ret = p2papi_init_discovery(hdl);
	if (ret < 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_enable_discovery: init error %d\n", ret));
		return ret;
	}

	/* Set wsec to any non-zero value in the discovery bsscfg to ensure our
	 * P2P probe responses have the privacy bit set in the 802.11 WPA IE.
	 * Some peer devices may not initiate WPS with us if this bit is not set.
	 */
	ret = p2pwlu_bssiovar_setint(hdl, "wsec",
		hdl->bssidx[P2PAPI_BSSCFG_DEVICE], AES_ENABLED);
	if (ret < 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_enable_discovery: wsec error %d\n", ret));
	}

	/* Add/Update the P2P IE in the discovery BSS's probe reqs and responses */
	p2papi_update_p2p_wps_ies(hdl, P2PAPI_BSSCFG_DEVICE);

	return 0;
}

/* Disable driver P2P Discovery */
int
p2papi_disable_discovery(p2papi_instance_t* hdl)
{
	int ret;
	P2PWL_HDL wl;
	bool old_is_p2p_discovery_on;
	BCMP2P_BOOL is_in_disable;

	P2PAPI_CHECK_P2PHDL(hdl);
	if (!P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl))
		return 0;
	wl = P2PAPI_GET_WL_HDL(hdl);

	is_in_disable = P2PAPI_TEST_AND_SET(hdl, &hdl->is_in_discovery_disable);
	if (is_in_disable) {	
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "%s: ignored, already started or done\n", __FUNCTION__)); 
		printf("@@@%s: ignored\n", __FUNCTION__); 
		return 0; 
	} 

	if (hdl->bssidx[P2PAPI_BSSCFG_DEVICE] == 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_disable_discovery: do nothing, not initialized\n"));
		return -1;
	}
	old_is_p2p_discovery_on = hdl->is_p2p_discovery_on;
	hdl->is_p2p_discovery_on = FALSE;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_disable_discovery\n"));

	ret = p2pwl_set_p2p_mode(wl, WL_P2P_DISC_ST_SCAN, 0, 0,
		hdl->bssidx[P2PAPI_BSSCFG_DEVICE]);
	if (ret < 0) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_disable_discovery: unable to set WL_P2P_DISC_ST_SCAN\n"));
	}

	/* Do a scan abort to stop the driver's scan engine in case it is still
	 * waiting out an action frame tx dwell time.
	 */
	p2pwlu_scan_abort(hdl, FALSE);

	/* Delete the device bsscfg unless we are still running as a GO.
	 * (A running GO needs to always have a device bsscfg to receive action
	 * frames sent to the GO's device address.)
	 */
	if (hdl->ap_ready) {
		hdl->is_p2p_discovery_on = old_is_p2p_discovery_on;
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_disable_discovery: is GO, don't delete device bsscfg.\n"));
		return 0;
	} else {
		return p2papi_deinit_discovery(hdl);
	}
}

/* Check if P2P Discovery is currently enabled */
bool
p2papi_is_discovery_enabled(void *p2pHdl)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*)p2pHdl;

	P2PAPI_CHECK_P2PHDL(hdl);
	return hdl->is_p2p_discovery_on;
}

/*
 * Traverse to next TLV.
 */
uint8 *
p2papi_next_tlv(uint8 *tlv_buf, uint *buflen)
{
	uint8 *tlv = 0;
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
uint8 *
p2papi_parse_tlvs(uint8 *tlv_buf, uint *buflen, uint *ielen, uint key,
	BCMP2P_LOG_LEVEL log)
{
	uint8 *cp;
	uint totlen;

	(void) log;
	cp = tlv_buf;
	totlen = *buflen;

	/* find tagged parameter */
	while (totlen >= 2) {
		uint tag;
		uint len;

		tag = *cp;
		len = *(cp +1);
		BCMP2PLOG((log, TRUE,
			"  p2papi_parse_tlvs: tag=%x len=%d, totlen=%d\n",
			tag, len, totlen));

		/* check length is within buffer */
		if (totlen < (len + 2)) {
			p2papi_log_hexdata(log, "tlv length exceeds buffer",
				cp, totlen);
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

/*
	BCMP2PLOG((log, TRUE,
		"  p2papi_parse_tlvs: no more tlvs, totlen=%d\n", totlen));
*/
	return NULL;
}

BCMP2P_BOOL
p2papi_is_p2p_ie(uint8 *p2pie)
{
	uint8 *ie = p2pie;

	/* If the contents match the P2P IE length, OUI, and OUI type
	 *     This is a P2P IE - return true.
	 */
	if (ie[1] >= 4 && !memcmp(&ie[2], P2P_OUI, 3)) {
		if (ie[5] == P2P_VER) {
			return TRUE;
		}
	}

	return FALSE;
}

BCMP2P_BOOL
p2papi_is_wps_ie(uint8 *wpsie)
{
	uint8 *ie = wpsie;

	/* Return true if the IE contents match the full WPS IE */
	if (ie[1] >= 4 && !memcmp(&ie[2], P2PAPI_WPS_OUI, 4)) {
		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
			"p2papi_is_wps_ie: TRUE  data=%02x%02x%02x%02x %02x%02x%02x%02x\n",
			ie[6], ie[7], ie[8], ie[9],  ie[10], ie[11], ie[12], ie[13]));
		return TRUE;
	}

	return FALSE;
}

BCMP2P_BOOL
p2papi_is_wpa_ie(uint8 *ie)
{
	if (ie[1] >= 4 && 0 == memcmp(&ie[2], WPA_OUI, 3) && ie[5] == WPA_VERSION) {
		return TRUE;
	}
	return FALSE;
}

/* Search for a RSN IE or WPA IE in the given IE data.
 * Returns 0 if a RSN or WPA IE was found, otherwise returns -1.
 */
int
p2papi_search_for_security_ies(uint8* cp, uint len)
{
	uint buflen;
	uint8 *ie;
	uint ielen = 0;

/*	p2papi_log_hexdata(log, "IE data buffer to search",	cp, len); */

	/* Search for RSN IE */
	ie = cp;
	buflen = len;
	while ((ie = p2papi_parse_tlvs(ie, &buflen, &ielen, DOT11_MNG_RSN_ID,
		BCMP2P_LOG_INFO)) != NULL) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_search_for_security_ies: found RSN IE\n"));
		return 0;
	}

	/* Search for WPA IE */
	ie = cp;
	buflen = len;
	while ((ie = p2papi_parse_tlvs(ie, &buflen, &ielen, DOT11_MNG_WPA_ID,
		BCMP2P_LOG_INFO)) != NULL) {
		if (p2papi_is_wpa_ie(ie)) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_search_for_security_ies: found WPA IE\n"));
			return 0;
		}
		ie = p2papi_next_tlv(ie, &buflen);
	}

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_search_for_security_ies: no security IEs found\n"));
	return -1;
}

/* Search for and decode P2P and WPS IEs in the given IE data.
 * Handles any number of P2P IEs and at most 1 WPS IE.
 * If IEs found, copies the IE data into out_p2p_ie and out_wps_ie.
 *
 * Returns 0 if any P2P IEs were found, otherwise returns -1.
 * (Returns -1 if WPS IEs were found but no P2P IEs.)
 */
int
p2papi_search_ies(uint8* cp, uint len, uint32 *out_channel,
	p2papi_p2p_ie_t *out_p2p_ie, p2papi_wps_ie_t *out_wps_ie,
	BCMP2P_LOG_LEVEL log)
{
	uint buflen;
	uint8 *ie;
	uint ielen = 0;
	int ret = -1;
	bool found;

	p2papi_log_hexdata(log, "IE data buffer to search",	cp, len);

	/* parse DS IE to get channel */
	found = FALSE;
	ie = cp;
	buflen = len;
	while ((ie = p2papi_parse_tlvs(ie, &buflen, &ielen, DOT11_MNG_DS_PARMS_ID,
		log)) != NULL) {
		if (ie != 0 && ielen == 1) {
			found = TRUE;
			*out_channel = ie[2];
			BCMP2PLOG((log, TRUE,
				"p2papi_search_ies: found DS IE, channel=%d\n",	*out_channel));
			break;
		}
		ie = p2papi_next_tlv(ie, &buflen);
	}
	if (!found) {
		BCMP2PLOG((log, TRUE, "p2papi_search_ies: no DS IE found\n"));
	}

	found = FALSE;
	memset(out_p2p_ie, 0, sizeof(*out_p2p_ie));
	ie = cp;
	buflen = len;
	while ((ie = p2papi_parse_tlvs(ie, &buflen, &ielen, DOT11_MNG_PROPR_ID,
		log)) != NULL) {
#ifndef SOFTAP_ONLY
		if (p2papi_is_p2p_ie(ie)) {
			found = TRUE;
			ret = 0;
			/* Note: if multiple P2P IEs are present, each one adds/overwrites
			 * info already in the out_p2p_ie structure.
			 */
			BCMP2PLOG((log, TRUE,
				"p2papi_search_ies: found P2P IE, len=%u offset=%d\n",
				ielen, ie - cp));
			p2papi_decode_p2p_ie(ie, out_p2p_ie, log);
		}
#endif /* not SOFTAP_ONLY */
		ie = p2papi_next_tlv(ie, &buflen);
	}
	if (!found) {
		BCMP2PLOG((log, TRUE,
			"p2papi_search_ies: no P2P IE found\n"));
	}
	else
		ret = 0;

	/* continue to search for WPS IE */
	found = FALSE;
	memset(out_wps_ie, 0, sizeof(*out_wps_ie));
	ie = cp;
	buflen = len;
	while ((ie = p2papi_parse_tlvs(ie, &buflen, &ielen, DOT11_MNG_PROPR_ID,
		log)) != NULL) {
		if (p2papi_is_wps_ie(ie)) {
			found = TRUE;
			BCMP2PLOG((log, TRUE,
				"p2papi_search_ies: found WPS IE, len=%u offset=%d\n",
				ielen, ie - cp));
			(void) p2papi_decode_wps_ie(ie, out_wps_ie, log);
		}
		ie = p2papi_next_tlv(ie, &buflen);
	}
	if (!found) {
		BCMP2PLOG((log, TRUE,
			"p2papi_search_ies: no WPS IE found\n"));
	}

	return ret;
}

#ifndef SOFTAP_ONLY
/* Get the P2P IE in a scan result item.
 *
 * If found, returns 0 and stores the P2P/WPS IE data in out_p2p_ie, out_wps_ie.
 * If not found, returns -1.
 */
int
p2papi_get_ie_from_bi(wl_bss_info_t *bi, uint32 *out_channel,
	p2papi_p2p_ie_t *out_p2p_ie, p2papi_wps_ie_t *out_wps_ie)
{
	int ret = -1;
	wl_bss_info_107_t *old_bi_107;
	uint16	ie_offset;	/* offset at which IEs start, from beginning */
	uint32	ie_length;	/* byte length of Information Elements */
	uint8 *ie_data;
	BCMP2P_LOG_LEVEL log = BCMP2P_LOG_VERB;


	/* Note: LEGACY2_WL_BSS_INFO_VERSION(108) and WL_BSS_INFO_VERSION(109) */
	/*       are compatible, LEGACY_WL_BSS_INFO_VERSION(107) is not */
	if (bi->version == LEGACY_WL_BSS_INFO_VERSION) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"found LEGACY_WL_BSS_INFO_VERSION(107) bssinfo"));
		old_bi_107 = (wl_bss_info_107_t *)bi;
		ie_length = dtoh32(old_bi_107->ie_length);
		ie_offset = sizeof(wl_bss_info_107_t);
	} else {
		ie_length = dtoh32(bi->ie_length);
		ie_offset = dtoh16(bi->ie_offset);
	}

	ie_data = ((uint8 *)bi) + ie_offset;

	/* first, clear the buffer */
	*out_channel = 0;
	memset(out_p2p_ie, 0, sizeof(*out_p2p_ie));
	memset(out_wps_ie, 0, sizeof(*out_wps_ie));
	if (ie_length) {
		ret = p2papi_search_ies(ie_data, ie_length,
			out_channel, out_p2p_ie, out_wps_ie, log);
	}

	return ret;
}

/* Add an entry to the peers list in the given P2P handle */
static void
p2papi_add_to_peers_list(p2papi_instance_t* hdl, uint8 *name,
	uint16 name_len, uint8 *grp_ssid, uint16 grp_ssid_len,
	uint8 *mac, p2papi_p2p_ie_t* p2p_ie,
	struct ether_addr *bssid, int16 rssi,
	BCMP2P_CHANNEL *listen_channel, BCMP2P_CHANNEL *op_channel,
	bool is_p2p_group, uint16 wps_devpwd, uint16 wps_cfg_methods,
	uint8 *ie_data, uint32 ie_data_len, int is_persistent_group)
{
	p2papi_peer_info_t *peer;

	peer = &hdl->peers[hdl->peer_count];

	if (name_len >= sizeof(peer->ssid))
		name_len = sizeof(peer->ssid) - 1;		/* should not happen */
	memcpy(peer->ssid, name, name_len);
	peer->ssid[name_len] = '\0';
	peer->ssid_len = (uint8) name_len;

	memcpy(&peer->mac, mac, sizeof(peer->mac));
	memcpy(&peer->p2p_ie, p2p_ie, sizeof(peer->p2p_ie));
	memcpy(&peer->bssid, bssid, sizeof(peer->bssid));
	memcpy(&peer->listen_channel, listen_channel, sizeof(peer->listen_channel));
	memcpy(&peer->op_channel, op_channel, sizeof(peer->op_channel));
	peer->is_p2p_group = is_p2p_group;
	peer->wps_device_pwd_id = wps_devpwd;
	peer->wps_cfg_methods = wps_cfg_methods;
	peer->expiry_count = P2PAPI_PEER_INFO_EXPIRY_COUNT;
	peer->rssi = rssi;

	memset(peer->grp_ssid, 0, sizeof(peer->grp_ssid));
	peer->grp_ssid_len = (uint8) grp_ssid_len;
	if (peer->grp_ssid_len > sizeof(peer->grp_ssid))
		peer->grp_ssid_len = sizeof(peer->grp_ssid);
	if (peer->grp_ssid_len > 0)
		memcpy(peer->grp_ssid, grp_ssid, peer->grp_ssid_len);

	peer->is_persistent_group = is_persistent_group;

	/* Set IE data */
	if (ie_data && ie_data_len > 0) {
		peer->ie_data = (uint8 *)P2PAPI_MALLOC(ie_data_len);
		memcpy(peer->ie_data, ie_data, ie_data_len);
		peer->ie_data_len = ie_data_len;
	}

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "...added peer %d: '%s'"
		" len=%u devAddr=%02x:%02x:%02x:%02x:%02x:%02x\n",
		hdl->peer_count, peer->ssid, peer->ssid_len,
		peer->mac.octet[0], peer->mac.octet[1], peer->mac.octet[2],
		peer->mac.octet[3], peer->mac.octet[4], peer->mac.octet[5]));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "  ch=%d:%d isgrp=%d isprstgrp:%d",
		peer->listen_channel.channel_class, peer->listen_channel.channel,
		peer->is_p2p_group,peer->is_persistent_group, peer->wps_cfg_methods));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "  rssi=%d ie_data_len=%d\n",
		peer->rssi, ie_data_len));
	p2papi_log_hexdata(BCMP2P_LOG_MED,
		"  grp_ssid",
		peer->grp_ssid, peer->grp_ssid_len);

	hdl->peer_count++;
}


/* Parse a set of scan results and update the peers list.
 * - Adds entries to the peers list for scan result items with a P2P IE.
 * - Deletes peers list entries that have not been seen for several scans.
 * - Returns TRUE if the peers list has been updated.
 */
static bool
p2papi_parse_scan_results(p2papi_instance_t* hdl, wl_scan_results_t* list,
	bool is_p2p_group_scan)
{
	bool list_updated = FALSE;
	wl_bss_info_t *bi;
	uint32 i, j;

	(void) is_p2p_group_scan;
	BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
		"p2papi_parse_scan_results: p2p_scan found %u prbresps\n",
		list->count));

	if (list == NULL || list->count == 0) {
		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
			"parse_scan_results: no peers\n"));
		return list_updated;
	}

	if (list->version != WL_BSS_INFO_VERSION &&
#ifdef LEGACY2_WL_BSS_INFO_VERSION
		list->version != LEGACY2_WL_BSS_INFO_VERSION &&
#endif /* LEGACY2_WL_BSS_INFO_VERSION */
		list->version != LEGACY_WL_BSS_INFO_VERSION) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"scan_results version mismatch: driver ver=%d BSS_INFO_VERSION=%d\n",
			list->version, WL_BSS_INFO_VERSION));
		return list_updated;
	}

	/* Traverse the scan results list to find items with P2P IEs.
	 * Copy the item into our peers list if the item's SSID is not already
	 * on the list.
	 */
	for (i = 0, bi = list->bss_info;
		i < list->count;
		i++, bi = (wl_bss_info_t*)((int8*)bi + dtoh32(bi->length))) {
		uint8 *name, *ssid;
		uint16 namelen, ssidlen;
		uint16 maclen;
		bool found;
		p2papi_p2p_ie_t	p2p_ie;
		p2papi_wps_ie_t wps_ie;
		uint8 group_cap_bm;
		bool is_p2p_group = FALSE;
		bool is_persistent_group = FALSE;
		uint32 ds_channel = 0;
		BCMP2P_CHANNEL listen_channel;
		BCMP2P_CHANNEL rx_prbrsp_channel;
		BCMP2P_CHANNEL op_channel;
		wl_bss_info_107_t *old_bi_107;
		uint16	ie_offset;	/* offset at which IEs start, from beginning */
		uint32	ie_length;	/* byte length of Information Elements */
		uint8 *ie_data;

		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
			"___i=%d BSSID=%02x:%02x:%02x:%02x:%02x:%02x SSID_len=%d\n", i,
			bi->BSSID.octet[0], bi->BSSID.octet[1], bi->BSSID.octet[2],
			bi->BSSID.octet[3], bi->BSSID.octet[4], bi->BSSID.octet[5],
			bi->SSID_len));

		if (bi->SSID_len == 0)
		{
			BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
				"  ==> ignore i=%d, SSID_len is 0.\n", i));
			continue;
		}

		/* Parse the probe response IEs. If no DS, WPS, or P2P IE, reject it */
		if (0 != p2papi_get_ie_from_bi(bi, &ds_channel, &p2p_ie, &wps_ie)) {
			BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
				"  ==> ignore i=%d, no DS/WPS/P2P IE. ssid=%s\n",
				i, bi->SSID));
			continue;
		}

		/* If no P2P IE, reject it */
		if (p2p_ie.p2p_ie.len == 0) {
			BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
				"  ==> ignore i=%d, no P2P IE. ssid=%s\n",
				i, bi->SSID));
			continue;
		}

		/* Find whether the peer is an existing P2P Group Owner */
		group_cap_bm = p2p_ie.capability_subelt.group;
		is_p2p_group = (group_cap_bm & P2P_CAPSE_GRP_OWNER) ? TRUE : FALSE;
		is_persistent_group = (group_cap_bm & P2P_CAPSE_PERSIST_GRP) ? TRUE : FALSE;

		if (is_p2p_group) {
			/* SSID is the name for GO */
			name = bi->SSID;
			namelen = bi->SSID_len;
		}
		else {
			/* Get the peer's name and truncate if too long */
			name = p2p_ie.devinfo_name;
			namelen = p2p_ie.devinfo_name_len;
			if (namelen == 0 || *name == '\0') {
				name = wps_ie.devname;
				namelen = wps_ie.devname_len;
			}
			if (namelen > SIZE_SSID_LENGTH-1)
				namelen = SIZE_SSID_LENGTH-1;
			if (namelen == 0 || *name == '\0') {
				BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
					"  ==> ignore i=%d due to no name: namelen=%d name=%s\n",
					i, namelen, name));
				continue;
			}
		}

		if (is_p2p_group) {
			ssid = bi->SSID;
			ssidlen = bi->SSID_len;
		}
		else {
			ssid = NULL;
			ssidlen = 0;
		}

		/* Discard if P2P IE has no Device Info attribute */
		maclen = p2papi_decode_p2p_ie_length(p2p_ie.devinfo_subelt.len);
		if (maclen == 0) {
			BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
				"  ==> ignore i=%d, no devinfo attr: namelen=%d name=%s\n",
				i, namelen, name));
			continue;
		}

		p2papi_chspec_to_channel(dtohchanspec(bi->chanspec), &rx_prbrsp_channel);

		/* The listen channel is obtained from the DS Param IE.  If there is
		 * no DS Param IE in the probe response, get the listen channel from
		 * the rx channel of the probe response.
		 */
		if (ds_channel != 0) {
			bool is_40mhz = dtoh32(bi->nbss_cap) & HT_CAP_40MHZ ? true : false;

			/* initialize listen channel */
			listen_channel.channel_class = BCMP2P_LISTEN_CHANNEL_CLASS;
			listen_channel.channel = ds_channel;

			/* update channel class based on channel and 40Mhz support */
			p2papi_find_channel_class(listen_channel.channel, is_40mhz,
				&listen_channel.channel_class);
		}
		else {
			memcpy(&listen_channel, &rx_prbrsp_channel, sizeof(listen_channel));
		}

		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
			"  ==> Accept i=%d ssid=%s devAddr=%02x:%02x:%02x:%02x:%02x:%02x\n",
			i, bi->SSID,
			p2p_ie.devinfo_subelt.mac[0],
			p2p_ie.devinfo_subelt.mac[1],
			p2p_ie.devinfo_subelt.mac[2],
			p2p_ie.devinfo_subelt.mac[3],
			p2p_ie.devinfo_subelt.mac[4],
			p2p_ie.devinfo_subelt.mac[5]));
		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
			"      ch=%d:%d rxch=%d:%d is_p2p_grp=%d is_persist=%d\n",
			listen_channel.channel_class, listen_channel.channel,
			rx_prbrsp_channel.channel_class, rx_prbrsp_channel.channel,
			is_p2p_group, is_persistent_group));

		/* op channel defaults to listen channel */
		/* unless not GO and op channel IE is available */
		memcpy(&op_channel, &listen_channel, sizeof(op_channel));
		if (!is_p2p_group &&
			p2papi_decode_p2p_ie_length(p2p_ie.op_chan_subelt.len) > 0) {
			op_channel.channel_class = (BCMP2P_CHANNEL_CLASS)p2p_ie.op_chan_subelt.band;
			op_channel.channel = p2p_ie.op_chan_subelt.channel;
		}

		/* Check if the device's MAC already appears in our peers list */
		found = FALSE;
		for (j = 0; j < (uint32) hdl->peer_count; j++) {
			if (memcmp(hdl->peers[j].mac.octet, p2p_ie.devinfo_subelt.mac,
				sizeof(hdl->peers[j].mac.octet)) == 0) {
				BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
					"...'%s' already in peers list at #%d (%s)\n",
					name, j, hdl->peers[j].ssid));
				found = TRUE;
				break;
			}
		}

		/* Get the peer IE data */
		/* Note: LEGACY2_WL_BSS_INFO_VERSION(108) and WL_BSS_INFO_VERSION(109) */
		/*       are compatible, LEGACY_WL_BSS_INFO_VERSION(107) is not */
		if (bi->version == LEGACY_WL_BSS_INFO_VERSION) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"found LEGACY_WL_BSS_INFO_VERSION(107) bssinfo"));
			old_bi_107 = (wl_bss_info_107_t *)bi;
			ie_length = dtoh32(old_bi_107->ie_length);
			ie_offset = sizeof(wl_bss_info_107_t);
		} else {
			ie_length = dtoh32(bi->ie_length);
			ie_offset = dtoh16(bi->ie_offset);
		}
		ie_data = ((uint8 *)bi) + ie_offset;

		/* If the discovered device is already in our peers list
		 *   Reset the peers list entry's expiry count.
		 *   Update the peer list entry's information if it has changed.
		 * else
		 *   Add the device to our peers list if it is not full.
		 */
		if (found) {
			BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
				"parse_scan_results: j=%d reset expiry_count %d to %d\n",
				j, hdl->peers[j].expiry_count, P2PAPI_PEER_INFO_EXPIRY_COUNT));
			hdl->peers[j].expiry_count = P2PAPI_PEER_INFO_EXPIRY_COUNT;
			if ((hdl->peers[j].ssid_len != namelen) ||
				memcmp(hdl->peers[j].ssid, name, namelen) != 0) {
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"parse_scan_results: j=%d update name %s to %s, len=%d\n",
					j, hdl->peers[j].ssid, name, namelen));
				memcpy(hdl->peers[j].ssid, name, namelen);
				hdl->peers[j].ssid[namelen] = '\0';
				hdl->peers[j].ssid_len = (uint8) namelen;
				list_updated = TRUE;
			}
			if (hdl->peers[j].grp_ssid_len != ssidlen ||
			    (ssidlen != 0 && memcmp(hdl->peers[j].grp_ssid, ssid, ssidlen) != 0)) {
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "parse_scan_results: j=%d updating grp_ssid...\n", j));
				p2papi_log_hexdata(BCMP2P_LOG_MED,
					"parse_scan_results: grp_ssid updated from",
					hdl->peers[j].grp_ssid, hdl->peers[j].grp_ssid_len);
				memset(hdl->peers[j].grp_ssid, 0, DOT11_MAX_SSID_LEN);
				hdl->peers[j].grp_ssid_len = (uint8) ssidlen;
				if (hdl->peers[j].grp_ssid_len > DOT11_MAX_SSID_LEN)
					hdl->peers[j].grp_ssid_len = DOT11_MAX_SSID_LEN;
				if (hdl->peers[j].grp_ssid_len)
					memcpy(hdl->peers[j].grp_ssid, ssid, hdl->peers[j].grp_ssid_len);
				p2papi_log_hexdata(BCMP2P_LOG_MED,
					"parse_scan_results: grp_ssid updated to",
					hdl->peers[j].grp_ssid, hdl->peers[j].grp_ssid_len);
			}
			if (hdl->peers[j].is_p2p_group != is_p2p_group) {
				hdl->peers[j].is_p2p_group = is_p2p_group;
				list_updated = TRUE;
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"parse_scan_results: j=%d update is_p2p_group to %u\n",
					j, hdl->peers[j].is_p2p_group));
			}
			if (hdl->peers[j].is_persistent_group != is_persistent_group) {
				hdl->peers[j].is_persistent_group = is_persistent_group;
				list_updated = TRUE;
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"parse_scan_results: j=%d update is_persist_grp to %u\n",
					j, hdl->peers[j].is_persistent_group));
			}
			if (memcmp(&hdl->peers[j].listen_channel, &listen_channel,
				sizeof(hdl->peers[j].listen_channel)) != 0) {
				memcpy(&hdl->peers[j].listen_channel, &listen_channel,
					sizeof(hdl->peers[j].listen_channel));
				list_updated = TRUE;
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"parse_scan_results: j=%d update channel to %d:%d\n",
					j, hdl->peers[j].listen_channel.channel_class,
					hdl->peers[j].listen_channel.channel));
			}
			if (memcmp(&hdl->peers[j].op_channel, &op_channel,
				sizeof(hdl->peers[j].op_channel)) != 0) {
				memcpy(&hdl->peers[j].op_channel, &op_channel,
					sizeof(hdl->peers[j].op_channel));
				list_updated = TRUE;
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"parse_scan_results: j=%d update op channel to %d:%d\n",
					j, hdl->peers[j].op_channel.channel_class,
					hdl->peers[j].op_channel.channel));
			}
			if (memcmp(&hdl->peers[j].bssid, &bi->BSSID,
				sizeof(hdl->peers[j].bssid)) != 0) {
				memcpy(&hdl->peers[j].bssid, &bi->BSSID,
					sizeof(hdl->peers[j].bssid));
				list_updated = TRUE;
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"parse_scan_results: j=%d update bssid to"
					" %02x:%02x:%02x:%02x:%02x:%02x\n",
					j, hdl->peers[j].bssid.octet[0],
					hdl->peers[j].bssid.octet[1], hdl->peers[j].bssid.octet[2],
					hdl->peers[j].bssid.octet[3], hdl->peers[j].bssid.octet[4],
					hdl->peers[j].bssid.octet[5]));
			}
			if (hdl->peers[j].wps_device_pwd_id != wps_ie.devpwd_id) {
				hdl->peers[j].wps_device_pwd_id = wps_ie.devpwd_id;
				list_updated = TRUE;
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"parse_scan_results: j=%d update wps_dev_pwd_id to %u\n",
					j, hdl->peers[j].wps_device_pwd_id));
			}
			if (p2p_ie.devinfo_subelt.wps_cfg_meths != 0) {
				if (hdl->peers[j].wps_cfg_methods != p2p_ie.devinfo_subelt.wps_cfg_meths) {
					hdl->peers[j].wps_cfg_methods = p2p_ie.devinfo_subelt.wps_cfg_meths;
					list_updated = TRUE;
					BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
						"parse_scan_results: j=%d update wps_cfg_methods to %u from p2p_ie\n",
						j, hdl->peers[j].wps_cfg_methods));
				}
			}
			else {
				if (hdl->peers[j].wps_cfg_methods != wps_ie.cfg_methods) {
					hdl->peers[j].wps_cfg_methods = wps_ie.cfg_methods;
					list_updated = TRUE;
					BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
						"parse_scan_results: j=%d update wps_cfg_methods to %u from wps_ie\n",
						j, hdl->peers[j].wps_cfg_methods));
				}
			}
			memcpy(&hdl->peers[j].p2p_ie, &p2p_ie, sizeof(p2papi_p2p_ie_t));

			/* Reset custom IE data in peer info */
			if (hdl->peers[j].ie_data != NULL) {
				P2PAPI_FREE(hdl->peers[j].ie_data);
				hdl->peers[j].ie_data_len = 0;
			}

			if (ie_data != NULL && ie_length > 0) {
				hdl->peers[j].ie_data = (uint8 *)P2PAPI_MALLOC(ie_length);
				memcpy(hdl->peers[j].ie_data, ie_data, ie_length);
				hdl->peers[j].ie_data_len = ie_length;
			}
		} else {
			if (hdl->peer_count < P2PAPI_MAX_PEERS) {
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"parse_scan_results:add %s liCh=%d:%d opCh=%d:%d isGO=%d\n",
					name, listen_channel.channel_class,
					listen_channel.channel, op_channel.channel_class,
					op_channel.channel, is_p2p_group));

				/* Set custom IE data in peer info from inside
				 * p2papi_add_to_peers_list function
				 */
				p2papi_add_to_peers_list(hdl, name, namelen,
					ssid, ssidlen,
					p2p_ie.devinfo_subelt.mac, &p2p_ie, &bi->BSSID,
					bi->RSSI, &listen_channel, &op_channel,
					is_p2p_group, wps_ie.devpwd_id, p2p_ie.devinfo_subelt.wps_cfg_meths,
					ie_data, ie_length,is_persistent_group);
				list_updated = TRUE;
			}
		}
		/* Print the detailed scan results */
/*		dump_bss_info(bi); */
	}

	return list_updated;
}

/* Prune stale entries from a peers list.  Decrements the expiry count
 * on each entry.  if it reaches 0 then delete the entry.
 *
 * Returns TRUE if the peers list has been updated.
 */
static bool
p2papi_prune_peers_list(p2papi_instance_t* hdl)
{
	bool list_updated = FALSE;
	p2papi_peer_info_t *peer;
	int i, j;

	BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
		"p2papi_prune_peers_list: peer_count=%d\n", hdl->peer_count));

	P2PAPI_DATA_LOCK_VERB(hdl);
	for (i = 0; i < hdl->peer_count; i++) {
		peer = &hdl->peers[i];
		if (!peer->is_p2p_group && peer->expiry_count > 0) {
			--peer->expiry_count;
			BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
				"p2papi_prune_peers_list: entry %d, --expiry_count=%d\n",
				i, peer->expiry_count));
			if (peer->expiry_count <= 0) {
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"p2papi_prune_peers_list: deleted entry %d ssid=%s\n",
					i, peer->ssid));

				/* Free service data */
/*				if (peer->svc_resp)
					P2PAPI_FREE(peer->svc_resp);
*/
				/* Free IE data for the pruned peer node */
				if (hdl->peers[i].ie_data) {
					P2PAPI_FREE(hdl->peers[i].ie_data);
					hdl->peers[i].ie_data = NULL;
					hdl->peers[i].ie_data_len = 0;
				}

				/* Shift up all subsequent entries to fill in the gap */
				for (j = i + 1;  j < hdl->peer_count;  j++) {
					hdl->peers[j-1] = hdl->peers[j];
				}

				/* Decrement the list size */
				hdl->peer_count--;
				if (hdl->peer_count < 0) {
					BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
						"p2papi_prune_peers_list: bad count=%d!\n",
						hdl->peer_count));
				}

				list_updated = TRUE;
			}
		}
	}
	P2PAPI_DATA_UNLOCK_VERB(hdl);

	return list_updated;
}

/* Do a P2P Search on the 3 given channels with the given channel dwell time.
 * A search consists of sending a probe request and then waiting for probe
 * responses.
 *
 * Returns the approximate amount of time used, in ms.
 *
 * This fn assumes dongle p2p device discovery is already enabled.
 */
static uint32
p2papi_discovery_search(p2papi_instance_t* hdl, uint32 chan_dwell_ms,
	BCMP2P_CHANNEL *channel1, BCMP2P_CHANNEL *channel2, BCMP2P_CHANNEL *channel3)
{
	P2PWL_HDL wl;
	int err;
	wl_scan_results_t *scanresults;
	uint16 old_peer_count = 0;
	int nprobes = 0;	/* 0 = use the default number of probes */
	BCMP2P_BOOL found_peers = FALSE;
	BCMP2P_STATUS escan_done;
	unsigned int starttime, endtime;
	uint32 time_used_ms = chan_dwell_ms * 3;
	int ch1 = channel1->channel;
	int ch2 = channel2->channel;
	int ch3 = channel3->channel;

	P2PAPI_CHECK_P2PHDL(hdl);
	if (!P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl))
		return 0;
	wl = P2PAPI_GET_WL_HDL(hdl);

	/* If this Search state is for the purpose of channel synchronization
	 * prior to sending an action frame
	 *    Scan only the tx target's listen channel
	 * else
	 *    Scan all 3 social channels
	 */
	if (hdl->pending_tx_act_frm != NULL) {
		ch1 = hdl->pending_tx_dst_listen_chan.channel;
		ch2 = 0;
		ch3 = 0;
	}
	if (ch2 == 0 && ch3 == 0) {
		chan_dwell_ms *= 3;
	}

	BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
		"p2papi_discovery_search: channels=%d,%d,%d dwell_ms=%u\n",
		ch1, ch2, ch3, chan_dwell_ms));

	/* Put the WL driver into P2P Search Mode */
	err = p2pwl_set_p2p_mode(wl, WL_P2P_DISC_ST_SEARCH, 0, 0,
		hdl->bssidx[P2PAPI_BSSCFG_DEVICE]);
	hdl->wl_p2p_state = WL_P2P_DISC_ST_SEARCH;
	if (err) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_discovery_search: p2p mode error %d\n", err));
		return 0;
	}

	/* Scan the 3 P2P social channels  */
	starttime = p2papi_osl_gettime();
	p2papi_osl_signal_escan_state(hdl, P2PAPI_OSL_ESCAN_STATE_START);
	err = p2pwlu_scan_channels(hdl, nprobes, chan_dwell_ms, ch1, ch2, ch3);

	if (err) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_discovery_search: scan error %d\n", err));
		p2papi_osl_signal_escan_state(hdl, P2PAPI_OSL_ESCAN_STATE_ABORT);
		return 0;
	}

	escan_done = (BCMP2P_STATUS)p2papi_osl_wait_for_escan_complete(hdl, 500);
	if (hdl->cancel_discovery || !hdl->discovery_search_enabled) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_discovery_search:discovery canceled\n"));
		return 0;
	} else if (BCMP2P_SUCCESS == escan_done) {
		/* Parse the scan results and update our peers list.
		 * If any new peers were added to the peers list
		 *   Deliver the updated peers list to the app discovery callback.
		 */
		old_peer_count = hdl->peer_count;
		P2PAPI_DATA_LOCK_VERB(hdl);
		scanresults = (wl_scan_results_t *)P2PAPI_SCANRESULT_BUF(hdl);
		found_peers = p2papi_parse_scan_results(hdl, scanresults, FALSE);
		P2PAPI_DATA_UNLOCK_VERB(hdl);
	} else {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_discovery_search:---failed to get scan results\n"));
	}

	/* One round of discovery is completed, try to send SD request to peers */
	if (hdl->svc_req_entries) {
		/* Send service request to found peer devices */
		p2plib_sd_on_peer_found(old_peer_count, hdl);
	}

	if (BCMP2P_SUCCESS == escan_done && found_peers) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"Discovery SEARCH phase: old count=%d new=%d, calling notif cb\n",
			old_peer_count, hdl->peer_count));

		/* If service is required, we won't trigger
		 * BCMP2P_NOTIF_DISCOVER_FOUND_PEERS until the peer's service
		 * data is discovered
		 */
		if (hdl->svc_req_entries == NULL)
			p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_DISCOVER,
				BCMP2P_NOTIF_DISCOVER_FOUND_PEERS);
	}

	/* Return the number of milliseconds of real time used for this discovery
	 * search.  If the OS has a function to get the current time in ms, obtain
	 * the duration by diffing the current time with the start time.
	 * Otherwise use the previously estimated time.
	 */
	endtime = p2papi_osl_gettime();
	if (endtime != 0) {
		time_used_ms = p2papi_osl_difftime(endtime, starttime);
	}
	BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
		"p2papi_discovery_search: time_used_ms=%u (%u - %u)\n",
		time_used_ms, endtime, starttime));
	return time_used_ms;
}

/* Do a P2P Listen on the given channel for the given duration.
 * A listen consists of sitting idle and responding to P2P probe requests
 * with a P2P probe response.
 *
 * Returns the approximate time used, in ms.
 *
 * This fn assumes dongle p2p device discovery is already enabled.
 */
uint32
p2papi_discovery_listen(p2papi_instance_t* hdl, BCMP2P_CHANNEL *channel, uint32 duration_ms)
{
	P2PWL_HDL wl;
	uint32 wait_ms = 50;
	uint32 time_used_ms = 0;
	uint32 sleep_ms = duration_ms;

	P2PAPI_CHECK_P2PHDL(hdl);
	if (!P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl))
		return 0;
	wl = P2PAPI_GET_WL_HDL(hdl);

	BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
		"p2papi_discovery_listen: chan=%d:%d ms=%u dse=%u\n",
		channel->channel_class, channel->channel,
		duration_ms, hdl->discovery_search_enabled));

	/* If we are already an active GO
	 *     Put the discovery BSSCFG into P2P Scan Mode to ensure it does not
	 *     respond to probe reqs.  Our active GO on the connection BSSCFG will
	 *     already respond to probe reqs.
	 * else
	 *     Put the discovery BSSCFG into P2P Listen Mode to respond to P2P
	 *     probe reqs.
	 */
	if (hdl->bssidx[P2PAPI_BSSCFG_CONNECTION] != 0 &&
		p2papi_is_softap_ready(hdl)) {
		p2pwl_set_p2p_mode(wl, WL_P2P_DISC_ST_SCAN, 0, 0,
			hdl->bssidx[P2PAPI_BSSCFG_DEVICE]);
		hdl->wl_p2p_state = WL_P2P_DISC_ST_SCAN;
	} else {
		chanspec_t chspec;
		p2papi_channel_to_chspec(channel, &chspec);
		p2pwl_set_p2p_mode(wl, WL_P2P_DISC_ST_LISTEN, chspec,
			(uint16) duration_ms, hdl->bssidx[P2PAPI_BSSCFG_DEVICE]);
		hdl->wl_p2p_state = WL_P2P_DISC_ST_LISTEN;
	}

	/* Wait for the listen interval.  Do the wait in units of wait_ms with
	 * cancellation checks in between.
	 */
	while (sleep_ms > 0 && !hdl->cancel_discovery &&
		hdl->discovery_search_enabled) {

		if (wait_ms > sleep_ms)
			wait_ms = sleep_ms;

		/* Wait for the listen duration */
		p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_DISCOVERY_LISTEN, wait_ms);
		time_used_ms += wait_ms;
		sleep_ms -= wait_ms;
	}

	if (hdl->cancel_discovery || !hdl->discovery_search_enabled) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_discovery_listen: cancelled (cd=%u dse=%u), %u ms remain\n",
			hdl->cancel_discovery, hdl->discovery_search_enabled, sleep_ms));
	} else {
		/* Wait for some extra time to prevent WLC_SCAN ioctl errors in
		 * subsequent scans.
		 */
		p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_DISCOVERY_LISTEN, 10);
		time_used_ms += 10;
	}

	return time_used_ms;
}

/* Do an 802.11 scan for Group Owners. */
BCMP2P_STATUS
p2papi_discovery_scan(p2papi_instance_t* hdl,
	BCMP2P_INT32 nprobes, BCMP2P_INT32 active_dwell_ms,
	BCMP2P_INT32 num_channels, BCMP2P_UINT16 *channels,
	BCMP2P_UINT32 *out_time_used_ms)
{
	wl_scan_results_t *scanresults;
	uint16 old_peer_count = 0;
	int i, j;
	int err;
	P2PWL_HDL wl;
	BCMP2P_BOOL found_peers = FALSE;
	BCMP2P_STATUS escan_done;
	BCMP2P_STATUS ret = BCMP2P_ERROR;
	unsigned int starttime = p2papi_osl_gettime();
	BCMP2P_UINT16 *default_chan_list = NULL;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		goto scan_ret;
	if (!P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl))
		goto scan_ret;
	wl = P2PAPI_GET_WL_HDL(hdl);

	if (active_dwell_ms == 0)
		active_dwell_ms = -1;
	if (nprobes == 0)
		nprobes = -1;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_discovery_scan: nprb=%d dwell=%d #ch=%d\n",
		nprobes, active_dwell_ms, num_channels));

	/* If no channel list was specified, get the driver's channel list */
	if (num_channels == 0) {
		p2p_chanlist_t *chanlist = &hdl->channel_list;
		BCMP2P_INT32 max_channels = P2P_CHANLIST_SE_MAX_ENTRIES * WL_NUMCHANNELS;

		default_chan_list = (BCMP2P_UINT16*)P2PAPI_MALLOC(max_channels *
			sizeof(*default_chan_list));
		if (default_chan_list == 0) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_discovery_scan: channel list malloc failed\n"));
			return BCMP2P_ERROR;
		}

		for (i = 0; i < chanlist->num_entries; i++) {
			for (j = 0; j < chanlist->entries[i].num_channels; j++) {
				default_chan_list[num_channels] =
					chanlist->entries[i].channels[j];
				if (++num_channels >= max_channels)
					break;
			}

			if (num_channels >= max_channels)
				break;

		}
		channels = default_chan_list;
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_discovery_scan: using default channel list (#ch=%d)\n",
			num_channels));
	}

	if (0 != p2pwl_set_p2p_mode(wl, WL_P2P_DISC_ST_SCAN, 0, 0,
		hdl->bssidx[P2PAPI_BSSCFG_DEVICE])) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_discovery_scan: unable to set driver p2p mode\n"));
		goto scan_ret;
	}
	hdl->wl_p2p_state = WL_P2P_DISC_ST_SCAN;
	p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_DISCOVER,
		BCMP2P_NOTIF_DISCOVER_START_80211_SCAN);
	p2papi_osl_signal_escan_state(hdl, P2PAPI_OSL_ESCAN_STATE_START);

	if (hdl->enable_multi_social_channels)	/* P2PAPI_ENABLE_MULTI_CHANNEL */
		err = p2pwlu_scan_nchannels(hdl, nprobes, active_dwell_ms,
			num_channels, channels);
	else
		err = p2pwlu_scan_channels(hdl, nprobes, active_dwell_ms,
			hdl->listen_channel.channel,
			hdl->listen_channel.channel,
			hdl->listen_channel.channel);

	if (err != 0) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_discovery_scan: scan channels failed\n"));
		p2papi_osl_signal_escan_state(hdl, P2PAPI_OSL_ESCAN_STATE_ABORT);
		goto scan_ret;
	}

#define P2PAPI_80211_SCAN_WAIT_DURATION 1500
#define P2PAPI_80211_SCAN_WAIT_RETRIES 7
	for (i = 0; i < P2PAPI_80211_SCAN_WAIT_RETRIES; i++) {
		escan_done = (BCMP2P_STATUS)p2papi_osl_wait_for_escan_complete(hdl,
			P2PAPI_80211_SCAN_WAIT_DURATION);
		if (hdl->cancel_discovery) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_discovery_scan: discovery cancelled\n"));
			if (BCMP2P_SUCCESS != escan_done)
				p2pwlu_escan_abort(hdl);
			ret = BCMP2P_SUCCESS;
			goto scan_ret;
		}
		if (BCMP2P_SUCCESS == escan_done) {
			break;
		}
	}

	if (BCMP2P_SUCCESS == escan_done) {
		/* Parse the scan results and update our peers list.
		 * If any new peers were added to the peers list
		 *   Deliver the updated peers list to the app discovery callback.
		 */
		old_peer_count = hdl->peer_count;
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_discovery_scan: complete.  old_peer_count=%d\n",
			old_peer_count));
		P2PAPI_DATA_LOCK(hdl);
		scanresults = (wl_scan_results_t *)P2PAPI_SCANRESULT_BUF(hdl);
		found_peers = p2papi_parse_scan_results(hdl, scanresults, TRUE);
		P2PAPI_DATA_UNLOCK(hdl);
		ret = BCMP2P_SUCCESS;
	}
	else {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_discovery_scan:---failed to get scan results: timeout\n"));
	}

	/* One round of discovery is completed, try to send SD request to peers */
	if (hdl->svc_req_entries) {
		/* Send service request to found peer devices */
		p2plib_sd_on_peer_found(old_peer_count, hdl);
	}

	if (BCMP2P_SUCCESS == escan_done && found_peers) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"Discovery SCAN phase: old count=%d new=%d, calling notif cb\n",
			old_peer_count, hdl->peer_count));
		p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_DISCOVER,
			BCMP2P_NOTIF_DISCOVER_FOUND_P2P_GROUPS);
	}

scan_ret:
	if (default_chan_list)
		P2PAPI_FREE(default_chan_list);
	*out_time_used_ms = p2papi_osl_difftime(p2papi_osl_gettime(), starttime);
	return ret;
}


/* Stop service discovery while device discovery stops */
void
p2papi_discover_cancel_svc_disc(p2papi_instance_t* hdl)
{
	p2plib_sd_disable_auto_req_svc(hdl);

	if (hdl->svc_req_entries) {
		P2PAPI_FREE(hdl->svc_req_entries);
		hdl->svc_req_entries = NULL;
	}
}

/* Free IE data of discovered peers */
void
p2papi_reset_peer_ie_data(p2papi_instance_t* hdl)
{
	int32 i;

	if (!P2PAPI_CHECK_P2PHDL(hdl)) {
		return;
	}

	P2PAPI_DATA_LOCK(hdl);

	for (i = 0; i < hdl->peer_count; i++) {
		if (hdl->peers[i].ie_data) {
			P2PAPI_FREE(hdl->peers[i].ie_data);
			hdl->peers[i].ie_data = NULL;
			hdl->peers[i].ie_data_len = 0;
		}
	}

	P2PAPI_DATA_UNLOCK(hdl);
}

/* Do P2P SIG discovery of peers. (blocking)
 * This fn blocks - it only returns when the discovery timeout has expired
 * or when hdl->cancel_discovery is set to FALSE.
 */
BCMP2P_STATUS
p2papi_discover(p2papi_instance_t* hdl, BCMP2P_DISCOVER_PARAM *params)
{
	BCMP2P_CHANNEL ch1 = {P2PAPI_SOCIAL_CHAN_CLASS, P2PAPI_SOCIAL_CHAN_1};
	BCMP2P_CHANNEL ch2 = {P2PAPI_SOCIAL_CHAN_CLASS, P2PAPI_SOCIAL_CHAN_2};
	BCMP2P_CHANNEL ch3 = {P2PAPI_SOCIAL_CHAN_CLASS, P2PAPI_SOCIAL_CHAN_3};
	P2PWL_HDL wl;
	uint32 discov_tmo_ms;
	BCMP2P_UINT32 time_used_ms = 0;
	uint32 ms;
	uint32 beacon_interval_ms = 100;
	uint32 search_ms = P2PAPI_SCAN_DWELL_TIME_MS;
	uint32 listen_ms;
	uint32 max_listen_interval = 3;
	uint16 old_peer_count;
	BCMP2P_STATUS ret = BCMP2P_ERROR;
	BCMP2P_STATUS result;
	BCMP2P_NOTIFICATION_CODE notif = BCMP2P_NOTIF_DISCOVER_FAIL;
	/*	int channel; */ /* TEMP debug: for showing what channel we are on */
	int	wl_status;
	struct ether_addr primary_bssid;

	if (!P2PAPI_CHECK_P2PHDL(hdl)) {
		ret = BCMP2P_INVALID_HANDLE;
		goto exit;
	}
	if (!P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl)) {
		ret = BCMP2P_INVALID_HANDLE;
		goto exit;
	}
	wl = P2PAPI_GET_WL_HDL(hdl);

	if (!hdl->enable_p2p) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_discover: p2p not enabled\n"));
		ret = BCMP2P_ERROR;
		goto exit;
	}
	hdl->cancel_discovery = FALSE;

	/* Save the discovery parameters */
	if (params->social_timeout != 0)
		hdl->discovery_timeout = params->social_timeout;
	if (params->socialChannel.channel != 0)
		memcpy(&hdl->listen_channel, &params->socialChannel,
			sizeof(hdl->listen_channel));
	if (params->scan_interval != 0)
		hdl->scan_duration_ms = params->scan_interval;
	memcpy(hdl->fname_ssid, params->ssid, sizeof(hdl->fname_ssid));
	hdl->fname_ssid[sizeof(hdl->fname_ssid) - 1] = '\0';
	hdl->fname_ssid_len = params->ssidLength;
	hdl->req_dev_type = params->reqDevType;
	hdl->req_dev_subcat = params->reqDevSubCat;
	hdl->is_listen_only = params->isListenOnly;
	hdl->skip_group_scan = params->skipGroupScan;

	/* Free service entries first */
	if (hdl->svc_req_entries != NULL) {
		P2PAPI_FREE(hdl->svc_req_entries);
		hdl->svc_req_entries = NULL;
	}

	/* Save the service query data */
	if (params->svcQueryListSize > 0 && params->svcQueryEntries != NULL) {
		hdl->svc_req_entries = (uint8*) P2PAPI_MALLOC(params->svcQueryListSize);
		memcpy(hdl->svc_req_entries, params->svcQueryEntries,
			params->svcQueryListSize);
	}

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_discover: tmo=%u sc=%u ch=%d:%d ssid=%s len=%u lo=%d k=%d opch=%d:%d\n",
		hdl->discovery_timeout, hdl->scan_duration_ms,
		hdl->listen_channel.channel_class, hdl->listen_channel.channel,
		hdl->fname_ssid, hdl->fname_ssid_len,
		hdl->is_listen_only, params->keepPrevPeersList,
		hdl->op_channel.channel_class, hdl->op_channel.channel));
	if (hdl->req_dev_type != 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"               : reqDevType=%u subcat=%u\n",
			hdl->req_dev_type, hdl->req_dev_subcat));
	}

	/* Ensure the wireless interface is up */
	if (!p2pwl_isup(wl)) {
		if (p2pwl_up(wl) != 0) {
			ret = BCMP2P_CANT_TALK_TO_DRIVER;
			notif = BCMP2P_NOTIF_DISCOVER_FAIL;
			goto exit;
		}
	}

	/* If running with the P2P Interface Address the same as the P2P Device
	 * Address and a P2P connection exists, do not allow enabling discovery.
	 * The driver does not allow both P2P discovery and connection bsscfgs
	 * to have the same MAC address.
	 */
	if (hdl->use_same_int_dev_addrs &&
		hdl->bssidx[P2PAPI_BSSCFG_CONNECTION] != 0) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"============================================================\n"));
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"Enabling P2P Discovery while a P2P connection exists is not\n"));
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"allowed when using the BCMP2P_CONFIG.sameIntDevAddrs option.\n"));
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"============================================================\n"));
		goto exit;
	}

	/* Enable P2P discovery in the WL driver */
	if (!hdl->cancel_discovery) {
		if (0 != p2papi_enable_discovery(hdl)) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
				"Discovery failed - unable to enable discovery\n"));
			ret = BCMP2P_ERROR;
			notif = BCMP2P_NOTIF_DISCOVER_FAIL;
			goto exit;
		}
	}

	/* Initialize the state information used by the discovery loop below */
	hdl->is_discovering = TRUE;
	hdl->discovery_search_enabled = BCMP2P_TRUE;

	/* Clear the previous discovered peers list, unless we are in listen-only
	 * mode or the app requested keeping the discovered peers list.
	 */
	if (!hdl->is_listen_only && !params->keepPrevPeersList) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_discover: clearing prev peers list\n"));
		hdl->peer_count = 0;

		/* Release IE data of old discovered peers */
		p2papi_reset_peer_ie_data(hdl);
	}

	hdl->scan_duration_ms = search_ms;

	if (hdl->is_listen_only) {
		p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_DISCOVER,
			BCMP2P_NOTIF_DISCOVER_START_LISTEN_ONLY);
	} else if (!hdl->skip_group_scan) {
		/* Do an initial 802.11 scan for existing P2P Groups or APs */
		result = p2papi_discovery_scan(hdl, -1, -1, 0, NULL, &time_used_ms);
		if (result != BCMP2P_SUCCESS) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_discover: 802.11 scan failed (ignore)\n"));
		}
	}
	p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_DISCOVER,
		BCMP2P_NOTIF_DISCOVER_START_SEARCH_LISTEN);


	/* Repeat until the discovery timeout or until discovery is cancelled:
	 * - Search each of the 3 possible social channels (send out probe
	 *   requests and wait a fixed time for probe responses.)
	 * - Listen for a random interval on our social channel and respond
	 *   to incoming probe requests.
	 */
	/* Note: Tests show mutual discovery occurs faster if the search time
	 * 'search_ms' is randomized in addition to randomizing the listen time.
	 * However, the P2P SIG spec does not specify randomizing the search time.
	 *
	 * Note: Tests show that mutual discovery generally occurs faster if the
	 * sum of the 3 search times is < the listen time.  This is because
	 * we only listen on 1 channel but search on 3 channels, so the
	 * probability of a search interval aligning with a peer's listen
	 * interval is greater when the listen interval is longer than the
	 * sum of the 3 search intervals.
	 */
	discov_tmo_ms = hdl->discovery_timeout * 1000;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_discover: loop begin: discov_tmo_ms=%u dse=%d\n",
		discov_tmo_ms, hdl->discovery_search_enabled));
	while ((time_used_ms < discov_tmo_ms || hdl->is_listen_only) &&
		!hdl->cancel_discovery) {
		listen_ms = (1 + (p2papi_osl_random() % max_listen_interval))
			* beacon_interval_ms;

		/* If search-listen is temporarily disabled
		 *     Don't do the search-listen
		 */
		if (!hdl->cancel_discovery && !hdl->discovery_search_enabled) {
			uint32 delay_ms = (search_ms + P2PAPI_SCAN_HOME_TIME_MS + 10) * 3
				+ listen_ms;

			BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
				"p2papi_discovery: search disabled, sleep %u ms instead\n",
				delay_ms));
			if (!p2papi_conditional_sleep_ms(P2PAPI_OSL_SLEEP_DISCOVERY_LISTEN,
				&hdl->cancel_discovery, delay_ms)) {
				time_used_ms += delay_ms;
				continue;
			}
		}

		/* Search */
		if (!hdl->cancel_discovery && hdl->discovery_search_enabled &&
			!hdl->is_listen_only) {
			if (hdl->enable_multi_social_channels) { /* P2PAPI_ENABLE_MULTI_CHANNEL */
				/* Scan the 3 social channels */
				ms = p2papi_discovery_search(hdl, search_ms, &ch1, &ch2, &ch3);
			}
			else {
				ch2.channel = 0;
				ch3.channel = 0;
				/* Scan only our social channel */
				ms = p2papi_discovery_search(hdl, search_ms, &hdl->listen_channel,
					&ch2, &ch3);
			}

			if (ms == 0) {
				ms = (search_ms + P2PAPI_SCAN_HOME_TIME_MS) * 3;
				BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
					"p2papi_discovery: after search, sleep %u ms\n", ms));
				p2papi_conditional_sleep_ms(P2PAPI_OSL_SLEEP_DISCOVERY_SEARCH,
					&hdl->cancel_discovery, ms);
			}
			time_used_ms += ms;
		}

		/* if a P2P connection is active on the P2P connection bsscfg or
		 * if a concurrent connection is active on the primary bsscfg
		 *     Give some home time to the connection
		 */
		if (!hdl->cancel_discovery && hdl->discovery_search_enabled &&
			(hdl->bssidx[P2PAPI_BSSCFG_CONNECTION] != 0 ||
			p2papi_osl_is_primary_bss_assoc(hdl, &primary_bssid))) {

			BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
				"p2papi_discover: connection home time\n"));
			p2pwl_set_p2p_mode(wl, WL_P2P_DISC_ST_SCAN, 0, 0,
				hdl->bssidx[P2PAPI_BSSCFG_DEVICE]);
			hdl->wl_p2p_state = WL_P2P_DISC_ST_SCAN;
			p2papi_conditional_sleep_ms(P2PAPI_OSL_SLEEP_GENERIC,
				&hdl->cancel_discovery, 150);
		}

		/* Listen */
		if (!hdl->cancel_discovery && hdl->discovery_search_enabled) {
			if (hdl->is_listen_only) {
				if (hdl->extended_listen.enabled) {
					listen_ms = hdl->extended_listen.period;
					BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
						"p2papi_discover: extended listen %d/%d\n",
						hdl->extended_listen.period,
						hdl->extended_listen.interval));
				}
				else
					listen_ms = 2000;
			}
			ms = p2papi_discovery_listen(hdl, &hdl->listen_channel, listen_ms);
			if (ms == 0) {
				ms = listen_ms;
				p2papi_conditional_sleep_ms(P2PAPI_OSL_SLEEP_DISCOVERY_LISTEN,
					&hdl->cancel_discovery, ms);
			}
			time_used_ms += ms;

			if (hdl->is_listen_only) {
				/* quiet period of extended listen timing */
				if (hdl->extended_listen.enabled) {
					ms = hdl->extended_listen.interval -
						hdl->extended_listen.period;
					BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
						"p2papi_discover: extended listen quiet %d\n", ms));
					p2papi_conditional_sleep_ms(
						P2PAPI_OSL_SLEEP_DISCOVERY_LISTEN,
						&hdl->cancel_discovery, ms);
				}
			}
		}

		/* Prune stale entries from the peers list */
		if (!hdl->cancel_discovery && hdl->discovery_search_enabled) {
			old_peer_count = hdl->peer_count;
			if (p2papi_prune_peers_list(hdl)) {
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"Pruned: old count=%d new=%d, calling notif cb\n",
					old_peer_count, hdl->peer_count));
			/* If service is required, we won't trigger
			 * BCMP2P_NOTIF_DISCOVER_FOUND_PEERS until the peer's service
			 * data is discovered
			 */
			if (hdl->svc_req_entries == NULL)
				p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_DISCOVER,
					BCMP2P_NOTIF_DISCOVER_FOUND_PEERS);
			}
		}

		/* If discovery has been cancelled, exit this loop */
		if (hdl->cancel_discovery) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_discover: cancelled\n"));
			break;
		}

		/* If discovery has timed out, exit this loop.
		 * However, do not exit if discovery has been suspended (eg. for
		 * action frame tx channel synchronization.)  Exiting and turning off
		 * discovery will break the channel sync mini-find.
		 */
		if (!hdl->is_listen_only && (time_used_ms >= discov_tmo_ms)) {
			if (hdl->discovery_search_enabled) {
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_discover: timeout\n"));
				break;
			}
			else {
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_discover: timeout"
					" deferred due to suspended discovery.\n"));
			}
		}

		p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_DISCOVER,
			BCMP2P_NOTIF_DISCOVER_SEARCH_LISTEN_ITERATION);
	}
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_discover: loop end\n"));

	/* Reset the driver's p2p mode */
	hdl->wl_p2p_state = WL_P2P_DISC_ST_SCAN;
	if (hdl->is_p2p_discovery_on) {
		wl_status = p2pwl_set_p2p_mode(wl, WL_P2P_DISC_ST_SCAN, 0, 0,
			hdl->bssidx[P2PAPI_BSSCFG_DEVICE]);
		if (wl_status < 0)
		{
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_discover: ignore p2pwl_set_p2p_mode failed,err=%d\n",
				wl_status));
		}
	}
	p2papi_disable_discovery(hdl);

	if (hdl->svc_req_entries)
		p2papi_discover_cancel_svc_disc(hdl);

	/* if BCMP2PCancelDiscover() has been called
	 *   Call the app discovery callback to indicate discovery cancelled.
	 * else
	 *   Call the app discovery callback to indicate discovery timed out.
	 */
	hdl->is_discovering = FALSE;
	if (hdl->cancel_discovery) {
		hdl->cancel_discovery = FALSE;
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_discover: discovery cancelled\n"));
		notif = BCMP2P_NOTIF_DISCOVER_CANCEL;
	} else {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_discover: discovery timed out\n"));
		notif = BCMP2P_NOTIF_DISCOVER_COMPLETE;
	}
	ret = BCMP2P_SUCCESS;

exit:
	hdl->is_discovering = FALSE;
	hdl->is_listen_only = FALSE;
	p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_DISCOVER, notif);
	return ret;
}

/* Cancel discovering peers - asynchronous.
 * Returns immediately without waiting for the cancel to complete.
 */
BCMP2P_STATUS
p2papi_discover_cancel(p2papi_instance_t* hdl)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_discover_cancel: cancel=%d isdis=%d iswldis=%d\n",
		hdl->cancel_discovery, hdl->is_discovering, hdl->is_p2p_discovery_on));
	if (!hdl->enable_p2p)
		return BCMP2P_ERROR;

	if (hdl->svc_req_entries)
		p2papi_discover_cancel_svc_disc(hdl);

	/* Set the discovery cancel flag.  This will cause p2papi_discover()
	 * to return when it wakes up for its next poll.
	 */
	hdl->cancel_discovery = TRUE;
	p2papi_osl_signal_escan_state(hdl, P2PAPI_OSL_ESCAN_STATE_ABORT);

	return BCMP2P_SUCCESS;
}


/* Cancel discovering peers - synchronous.
 * Returns after waiting for the cancel to complete.
 */
BCMP2P_STATUS
p2papi_discover_cancel_sync(p2papi_instance_t* hdl)
{
	uint32 sleep_ms;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_discover_cancel_sync: cancel=%d isdis=%d iswldis=%d\n",
		hdl->cancel_discovery, hdl->is_discovering, hdl->is_p2p_discovery_on));

	if (!hdl->enable_p2p)
		return BCMP2P_ERROR;

	/* If HSL discovery is in progress
	 *     Cancel HSL discovery.
	 *     Enter a polling loop to wait for the cancel to complete.
	 */
	if (hdl->is_discovering) {
		/* Initiate discovery cancel if not already done.
		 * (Call BCMP2PCancelDiscover() to do this instead of calling
		 * p2papi_discover_cancel() in case the OSL has overridden this
		 * function.)
		 */
		if (!hdl->cancel_discovery)
			BCMP2PCancelDiscover(hdl);

		/* Poll for the cancel to complete */
		for (sleep_ms = 0; sleep_ms < hdl->cancel_discovery_timeout_ms;
			sleep_ms += 500) {
			BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
				"p2papi_dis_can_sync: polling for discovery cancel...\n"));
			if (!hdl->is_discovering)
				break;
			p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_LINK_CREATE_CANCEL_POLL, 500);
		}

		if (hdl->is_discovering)
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
				"p2papi_dis_can_sync: discovery cancel timed out\n"));
		else
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_dis_can_sync: discovery cancel confirmed\n"));
	}

	/* If P2P discovery is still enabled in the driver for some reason
	 *     Disable it
	 */
	if (hdl->is_p2p_discovery_on) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_discover_cancel_sync: disabling driver P2P discovery\n"));
		p2papi_disable_discovery(hdl);
	}

	return BCMP2P_SUCCESS;
}

int
p2papi_discover_enable_search(p2papi_instance_t* hdl, BCMP2P_BOOL search_enable)
{
	P2PWL_HDL wl;

	P2PAPI_CHECK_P2PHDL(hdl);
	if (!P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl))
		return -1;
	wl = P2PAPI_GET_WL_HDL(hdl);

	if (!hdl->is_p2p_discovery_on) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_discover_enable_search: do nothing, discovery is off\n"));
		return 0;
	}

	if (hdl->discovery_search_enabled == search_enable) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_discover_enable_search: already %d\n", search_enable));
		return 0;
	}

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_discover_enable_search: %d\n", search_enable));
	hdl->discovery_search_enabled = search_enable;

	/* When disabling Search, reset the WL driver's p2p discovery state to
	 * WL_P2P_DISC_ST_SCAN.
	 */
	if (!search_enable) {
		if (hdl->wl_p2p_state != WL_P2P_DISC_ST_SCAN) {
			hdl->wl_p2p_state = WL_P2P_DISC_ST_SCAN;
			(void) p2pwl_set_p2p_mode(wl, WL_P2P_DISC_ST_SCAN, 0, 0,
				hdl->bssidx[P2PAPI_BSSCFG_DEVICE]);
		}
	}

	if (hdl->discovery_search_enabled) {
		p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_DISCOVER,
			BCMP2P_NOTIF_DISCOVER_RESUMED);
	} else {
		p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_DISCOVER,
			BCMP2P_NOTIF_DISCOVER_SUSPENDED);
	}

	return 0;
}

static void
p2papi_get_primary_devtype(BCMP2P_DISCOVER_ENTRY* dst, uint8* pri_devtype)

{
	/* primary device type:
	 *
	 * 	byte0	byte1	byte2	byte3
	 *	category	oui[0]	oui[1]
	 *
	 *	byte4	byte5	byte6	byte7
	 *	oui[2]	oui[3]	subcategory
	 */
	if (pri_devtype[5] == 0 ||
		memcmp(&pri_devtype[2], "\x00"WFA_OUI, sizeof("\x00"WFA_OUI)) == 0)
		/* use WFA default subcategory */
		memcpy(dst->primary_dev.oui, WFA_OUI,
			sizeof(dst->primary_dev.oui));
	else
		/* use vendor specific subcategory */
		memcpy(dst->primary_dev.oui, &pri_devtype[3],
			sizeof(dst->primary_dev.oui));

	/* category and subcategory are in big endian */
	dst->primary_dev.category = ((uint16)pri_devtype[0] << 8) + pri_devtype[1];
	dst->primary_dev.subcategory = ((uint16)pri_devtype[6] << 8) + pri_devtype[7];
}

/* Copy discover result
 *    -- if bDuplicateData is set to true, duplicate HSL copies will be allocated and
 *       it is caller's responsibility to free the svc-resp/ie-data associated later
 *       via p2papi_free_discover_result_data().
 *    -- if bDuplicateData is set to false, a pointer to HSL copy will be stored
 *       in BCMP2P_DISCOVERY_ENTRY. Caller should not free the svc-resp/ie-data associated.
 */
static void p2papi_copy_discover_result(p2papi_instance_t* hdl,
	p2papi_peer_info_t *src, BCMP2P_DISCOVER_ENTRY *dst, bool bDuplicateData)
{
	memset(dst, 0, sizeof(*dst));	/* clear the entry first */
	dst->length = sizeof(*dst);

	memset(dst->ssid, 0, sizeof(dst->ssid));	/* clear the data first */
	dst->ssidLength = src->ssid_len;
	if (dst->ssidLength > sizeof(dst->ssid))
		dst->ssidLength = sizeof(dst->ssid);
	memcpy(dst->ssid, src->ssid, dst->ssidLength);

	memcpy(dst->mac_address, src->mac.octet, sizeof(dst->mac_address));
	memcpy(dst->int_address, src->bssid.octet, sizeof(dst->int_address));
	memcpy(&dst->channel, &src->listen_channel,
		sizeof(dst->channel));
	dst->rssi = src->rssi;
	dst->wps_device_pwd_id = src->wps_device_pwd_id;
	dst->wps_cfg_methods = src->wps_cfg_methods;
	dst->is_p2p_group = src->is_p2p_group;
	dst->is_persistent_go = src->is_persistent_group;

	memset(dst->grp_ssid, 0, sizeof(dst->grp_ssid));
	dst->grp_ssidLength = src->grp_ssid_len;
	if (dst->grp_ssidLength > sizeof(dst->grp_ssid))
		dst->grp_ssidLength = sizeof(dst->grp_ssid);
	if (dst->grp_ssidLength > 0)
		memcpy(dst->grp_ssid, src->grp_ssid, dst->grp_ssidLength);

	if (hdl->svc_req_entries) {
		/* Set service response data */
		BCMP2P_SVC_LIST *pSvcResp = p2plib_sd_get_peer_svc(
			(struct ether_addr *)dst->mac_address);
		if (pSvcResp != NULL && pSvcResp->dataSize > 0)
		{
			uint32 svc_list_size = sizeof(BCMP2P_SVC_LIST) + pSvcResp->dataSize - 1;
			if (bDuplicateData)
			{	/* duplicate a HSL copy */
				dst->svc_resp = (BCMP2P_UINT8 *) P2PAPI_MALLOC(svc_list_size);
				if (dst->svc_resp)
				{
					memcpy(dst->svc_resp, pSvcResp, svc_list_size);

					BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
						"p2papi_copy_discover_result: duplicate svc_list_size=%d, svc_resp=0x%lx\n",
						svc_list_size, dst->svc_resp));
				}
			}
			else
				dst->svc_resp = (BCMP2P_UINT8 *) pSvcResp;	/* HSL copy */

			if (dst->svc_resp != NULL)
				p2papi_log_hexdata(BCMP2P_LOG_MED,
					"p2papi_copy_discover_result: service response data",
					dst->svc_resp, svc_list_size);
		}
	}

	p2papi_get_primary_devtype(dst, src->p2p_ie.devinfo_subelt.pri_devtype);

	dst->device_capability = src->p2p_ie.capability_subelt.dev;
	dst->group_capability = src->p2p_ie.capability_subelt.group;

	/* Set peer IE data */
	if (src->ie_data_len > 0)
	{
		if (bDuplicateData)
		{
			/* duplicate a HSL copy */
			dst->ie_data = (uint8 *) P2PAPI_MALLOC(src->ie_data_len);
			if (dst->ie_data)
			{
				memcpy(dst->ie_data, src->ie_data, src->ie_data_len);
				dst->ie_data_len = src->ie_data_len;

				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"p2papi_copy_discover_result: duplicate ie_data_len=%d, ie_data=0x%lx\n",
					dst->ie_data_len, dst->ie_data));
			}
		}
		else
		{	/* use HSL copy */
			dst->ie_data_len = src->ie_data_len;
			dst->ie_data = src->ie_data;
		}
	}

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"     len=%u chan=%d:%d grp=%d ssidlen=%u ssid=%s\n",
		dst->length, dst->channel.channel_class, dst->channel.channel,
		dst->is_p2p_group, dst->ssidLength, dst->ssid));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"     mac=0x%02x:%02x:%02x:%02x:%02x:%02x svc=0x%x\n",
		dst->mac_address[0], dst->mac_address[1], dst->mac_address[2],
		dst->mac_address[3], dst->mac_address[4], dst->mac_address[5]));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"     device_cap=0x%x group_cap=0x%x, wps(PwdId=0x%x,cfgMethods=0x%x)\n",
		dst->device_capability, dst->group_capability,
		dst->wps_device_pwd_id, dst->wps_cfg_methods));

}

/* This function stores a list of discoverred entries to caller-provided buffer
 * (pointed by pBuffer).
 * For each discovered entry, 'bDuplicateData' flag determines if HSL duplicate coipes
 * should be returned/stored in BCMP2P_DISCOVER_ENTRY:
 *    -- if bDuplicateData is set to true, duplicate HSL copies will be allocated and
 *       it is caller's responsibility to free the svc-resp/ie-data associated later
 *       via p2papi_free_discover_result_data().
 *    -- if bDuplicateData is set to false, a pointer to HSL copy will be stored
 *       in BCMP2P_DISCOVERY_ENTRY. Caller should not free the svc-resp/ie-data associated.
 */
BCMP2P_STATUS
p2papi_get_discover_result(p2papi_instance_t* hdl,
	bool bPrunedList, PBCMP2P_DISCOVER_ENTRY pBuffer, uint32 buffLength,
	uint32 *numEntries, bool bDuplicateData)
{
	BCMP2P_DISCOVER_ENTRY *dst;
	p2papi_peer_info_t *src;
	uint32 i, total;
	bool bKeep = true;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	P2PAPI_DATA_LOCK(hdl);

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_get_discover_result: numEntries=%d\n", hdl->peer_count));

	/* Check if the dst buffer is big enough to hold all entries */
	*numEntries = hdl->peer_count;
	if (buffLength < *numEntries * sizeof(*dst)) {

		P2PAPI_DATA_UNLOCK(hdl);

		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_get_discover_result: ignore buf(size=%d)too small "
			"for %u entries(%d bytes)\n",
			buffLength, *numEntries, *numEntries * sizeof(*dst)));
		return BCMP2P_NOT_ENOUGH_SPACE;
	}

	/* Copy each discovery entry from our p2papi_peer_info_t structure to the
	 * app's BCMP2P_DISCOVER_ENTRY structure.
	 */
	total = *numEntries;
	*numEntries = 0;
	dst = pBuffer;
	for (i = 0; i < total; i++) {
		src = &hdl->peers[i];

		/* When service is required, we only return device with expected
		 * service data
		 */
		if (hdl->svc_req_entries != NULL)
			bKeep = p2plib_sd_is_svc_discovered(&src->mac);

		if (bKeep) {
			p2papi_copy_discover_result(hdl, src, dst, bDuplicateData);
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_get_discover_result: dst %s", dst->ssid));
			dst++;
			(*numEntries)++;
		}
	}
	P2PAPI_DATA_UNLOCK(hdl);

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_get_discover_result: Total returned entries %d", *numEntries));
	return BCMP2P_SUCCESS;
}

/* This function returns a discoverred entry to caller-provided buffer
 * (pointed by pBuffer), however, the svc-resp/ie_data associated with this discovery-entry
 * (if apply) will not be stored in caller-provided buffer, instead, this function
 * will allocate a copy of svc-resp/ie_data and return a pointer in BCMP2P_DISCOVERY_ENTRY
 * it is caller's responsibility to free the svc-resp/ie-data buffer via
 * p2papi_free_discover_result_data() when it is no longer needed
 */
BCMP2P_STATUS
p2papi_get_discover_peer(p2papi_instance_t* hdl,
	struct ether_addr *dev_addr, PBCMP2P_DISCOVER_ENTRY pBuffer)
{
	BCMP2P_STATUS status = BCMP2P_ERROR;
	uint32 i;
	p2papi_peer_info_t *peer;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	P2PAPI_DATA_LOCK(hdl);

	for (i = 0; i < (uint32) hdl->peer_count; i++) {
		peer = &hdl->peers[i];
		if (memcmp(peer->mac.octet, dev_addr->octet, sizeof(peer->mac.octet)) == 0) {
			p2papi_copy_discover_result(hdl, peer, pBuffer, true);
			status = BCMP2P_SUCCESS;
			break;
		}
	}

	P2PAPI_DATA_UNLOCK(hdl);

	return status;
}

/* This function walk thru each discover-entry in pBuffer (returned via p2papi_get_discover_result)
 * and free the 'ie_data/svc_resp' associated with each discovery-entry
 */
BCMP2P_STATUS
p2papi_free_discover_result_data(p2papi_instance_t* hdl, PBCMP2P_DISCOVER_ENTRY pBuffer, uint32 numEntries)
{
	BCMP2P_DISCOVER_ENTRY *pEntry;
	uint32 i;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	if (pBuffer == NULL || numEntries == 0)
		return BCMP2P_INVALID_PARAMS;

	/* walk thru each entry */
	pEntry = pBuffer;
	for(i = 0; i < numEntries; i++)
	{
		if (pEntry->ie_data && pEntry->ie_data_len > 0)
		{
			P2PAPI_FREE(pEntry->ie_data);
			pEntry->ie_data_len = 0;
			pEntry->ie_data = NULL;
		}

		if (pEntry->svc_resp)
		{
			P2PAPI_FREE(pEntry->svc_resp);
			pEntry->svc_resp = NULL;
		}

		/* next entry */
		pEntry++;
	}

	return BCMP2P_SUCCESS;
}

/* Get the information about a specific client of a GO in our discovered peers
 * list.
 */
BCMP2P_STATUS
p2papi_get_discovered_go_client(p2papi_instance_t *hdl,
	PBCMP2P_DISCOVER_ENTRY go, int client_index,
	struct ether_addr *out_dev_addr)
{
	struct ether_addr *go_devaddr = (struct ether_addr*) go->mac_address;
	p2papi_peer_info_t *go_info = NULL;
	wifi_p2p_client_info_desc_t *cinfo;
	struct ether_addr *caddr;
	uint32 i;
	BCMP2P_STATUS status = BCMP2P_ERROR;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	if (client_index >= P2PAPI_GRPINFO_MAX_CIDS) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_get_discovered_go_client: bad client_index %d\n",
			client_index));
		return status;
	}

	P2PAPI_DATA_LOCK(hdl);

	/* Search for the GO in our discovered peers list */
	for (i = 0; i < (uint32)hdl->peer_count; i++) {
		if (memcmp(&hdl->peers[i].mac, go_devaddr, sizeof(*go_devaddr)) == 0) {
			go_info = &hdl->peers[i];
			break;
		}
	}

	/* If found GO, get client info from GO's probe response P2P IE */
	if (go_info != NULL) {
		cinfo = go_info->p2p_ie.grpinfo_subelt.client_info;
		caddr = (struct ether_addr*)cinfo->p2p_dev_addr;
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"found GO at [%d], client addr=%02x:%02x:%02x:%02x:%02x:%02x\n",
			i, caddr->octet[0], caddr->octet[1], caddr->octet[2],
			caddr->octet[3], caddr->octet[4], caddr->octet[5]));
		memcpy(out_dev_addr, caddr, sizeof(*out_dev_addr));
		status = BCMP2P_SUCCESS;
	} else {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_get_discovered_go_client: GO not found\n"));
	}

	P2PAPI_DATA_UNLOCK(hdl);
	return status;
}

BCMP2P_STATUS
p2papi_get_peer_go_client_list(p2papi_instance_t *hdl,
        BCMP2P_DISCOVER_ENTRY *peer_go,
        BCMP2P_CLIENT_LIST *client_list,
        BCMP2P_UINT32 client_list_len,
        BCMP2P_UINT32 *client_list_count)
{
	int i;
	p2papi_peer_info_t *peer;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	peer = p2papi_find_peer(hdl, peer_go->mac_address);

	if (peer == NULL) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_get_peer_go_client_list:"
			" GO not found: %02x:%02x:%02x:%02x:%02x:%02x\n",
			peer_go->mac_address[0], peer_go->mac_address[1],
			peer_go->mac_address[2], peer_go->mac_address[3],
			peer_go->mac_address[4], peer_go->mac_address[5]));
		return BCMP2P_ERROR;
	}

	*client_list_count = 0;
	for (i = 0; i < peer->p2p_ie.grpinfo_subelt.num_clients;
		i++, client_list++) {
		memcpy((void *)&client_list->dev_addr,
			peer->p2p_ie.grpinfo_subelt.client_info[i].p2p_dev_addr,
			sizeof(BCMP2P_ETHER_ADDR));

		memcpy((void *)&client_list->int_addr,
			peer->p2p_ie.grpinfo_subelt.client_info[i].p2p_int_addr,
			sizeof(BCMP2P_ETHER_ADDR));

		client_list->discoverable =
		peer->p2p_ie.grpinfo_subelt.client_info[i].dev_cap_bitmap &
			P2P_CAPSE_DEV_CLIENT_DIS ? TRUE : FALSE;
		BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
                        "p2papi_get_peer_go_client_list: client index %d - "
			"%02x:%02x:%02x:%02x:%02x:%02x\n",
			i,
			client_list->dev_addr.octet[0],
			client_list->dev_addr.octet[1],
			client_list->dev_addr.octet[2],
			client_list->dev_addr.octet[3],
			client_list->dev_addr.octet[4],
			client_list->dev_addr.octet[5]));
		if (++(*client_list_count) >= client_list_len/sizeof(BCMP2P_CLIENT_LIST) - 1)
			/* Buffer full */
			break;
	}

	BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
		"p2papi_get_peer_go_client_list: number of clients = %d %d\n",
		*client_list_count, peer->p2p_ie.grpinfo_subelt.num_clients));

	return BCMP2P_SUCCESS;
}


/* Event handler for discovery and channel synchronization. */
void
p2papi_wl_event_handler_discover(p2papi_instance_t *hdl, BCMP2P_BOOL is_primary,
                                 wl_event_msg_t *event, void* data, uint32 data_len)
{
}
#endif /* SOFTAP_ONLY */
