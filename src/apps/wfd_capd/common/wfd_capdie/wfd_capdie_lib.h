/* WFD lib IE core
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: $
 */
#ifndef _WFDLIB_IE_H_
#define _WFDLIB_IE_H_


#ifndef __cplusplus
enum bool {false, true};
#endif

#include "wfd_capdie_proto.h"

#define WFD_CAPDIE_MAX_IE_LEN  P2PAPI_MAX_VNDR_IE_SIZE

/* WFD Information Element data extracted from peer's probe response */
typedef struct wfd_capdie_ie_s {
	/* WFD IE */
	wifi_wfd_ie_t			wifi_wfd_ie;

	/* Device Info attribute */
	wifi_wfd_devinfo_se_t	devinfo_subelt; 
	
	/* Associated bssid attribute */
	wifi_wfd_associated_bssid_se_t assocbssid_subelt;

	/* Local IP address */
	wifi_wfd_local_ip_se_t	localip_subelt;
	
	/* Session Info attribute */
	uint8					sess_dev_total;
	wifi_wfd_sesinfo_se_t	sessinfo_subelt;

	/* Coupled Sink Information attribute */
	wifi_wfd_cpl_sink_info_se_t	cplsinkinfo_subelt;

	/* Alternative Mac attribute */
	wifi_wfd_altmac_se_t	altmac_subelt;

} wfd_capdie_ie_t;

typedef struct wfd_capdie_dev_info_s {
	/* WFD device type */
	WFDCAPD_DEVICE_TYPE	dev_type;

	/* Is coupled sink supported by source or sink */
	WFDCAPD_BOOL	support_cpl_sink;		
	
	/* Is available for session */
	WFDCAPD_BOOL	sess_avl;

	/* Is WFD Servive Discovery supported */
	WFDCAPD_BOOL	support_wsd;		

	/* Preferred connection:  P2P or TDLS */
	WFDCAPD_CONNECTION_TYPE preferred_connection;
	
	/* Is content protection via HDCP2.0/2.1 is supported */
	WFDCAPD_BOOL	content_protected;		
	
	/* Time synchronization using 802.1AS supported or not */
	WFDCAPD_BOOL	support_time_sync;		
} wfd_capdie_dev_info_t;

/* Encode a beacon WFD IE */
void
capdie_encode_beacon_wfd_ie(const WFDCAPD_CAP_CONFIG *cap_cfg,
	uint8 *ie_buf, uint16 *ie_len);

/* Encode a probe request WFD IE */
void
capdie_encode_prbreq_wfd_ie(const WFDCAPD_CAP_CONFIG *cap_cfg,
	uint8 *ie_buf, uint16 *ie_buf_len);

/* Encode a probe response WFD IE */
void
capdie_encode_prbresp_wfd_ie(const WFDCAPD_CAP_CONFIG *cap_cfg,
	const wfd_capdie_dev_ie_t *group_dev_ie_list, uint8 group_dev_total,
	uint8 *ie_buf, uint16 *ie_len);

void
capdie_encode_assocreq_wfd_ie(const WFDCAPD_CAP_CONFIG *cap_cfg,
	uint8 *ie_buf, uint16 *ie_len);
void
capdie_encode_assocresp_wfd_ie(const WFDCAPD_CAP_CONFIG *cap_cfg,
	const wfd_capdie_dev_ie_t *group_dev_ie_list, uint8 group_dev_total,
	uint8 *ie_buf, uint16 *ie_len);
#define capdie_encode_inv_wfd_ie capdie_encode_assocresp_wfd_ie

void
capdie_encode_gon_wfd_ie(const WFDCAPD_CAP_CONFIG *cap_cfg,
	uint8 *ie_buf, uint16 *ie_len);

void
capdie_encode_provdis_wfd_ie(const WFDCAPD_CAP_CONFIG *cap_cfg,
	const wfd_capdie_dev_ie_t *group_dev_ie_list, uint8 group_dev_total,
	uint8 *ie_buf, uint16 *ie_len);

void
capdie_encode_tdls_setup_wfd_ie(const WFDCAPD_CAP_CONFIG *cap_cfg,
	uint8 *ie_buf, uint16 *ie_len);

bool
capdie_search_wfd_ies(const uint8* cp, uint len, wfd_capdie_ie_t *out_wfd_ie);

bool
capdie_decode_dev_cap_bitmap(uint16 dev_info_bmp, wfd_capdie_dev_info_t *dev_info);

#endif  /* _WFDLIB_IE_H_ */
