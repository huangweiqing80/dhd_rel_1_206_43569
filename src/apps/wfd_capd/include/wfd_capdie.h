/* WFD Capability IE managment library API header file
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
#ifndef _WFD_CAPDIE_H_
#define _WFD_CAPDIE_H_

#if defined(__cplusplus)
extern "C" {
#endif /* __cpluscplus */

#include "wfd_capd.h"

#define WFD_CAPDIE_MAX_VNDR_IE_SIZE	2048
#define WFD_CAPDIE_VNDR_IE_HDR_SIZE	6
#define WFD_CAPDIE_MAX_WFD_IE_LEN	(WFD_CAPDIE_VNDR_IE_HDR_SIZE+WFD_CAPDIE_MAX_VNDR_IE_SIZE)

/** WFD management IE flag */
typedef enum { 
	WFD_CAPD_IE_FLAG_BEACON,
	WFD_CAPD_IE_FLAG_PRBREQ,
	WFD_CAPD_IE_FLAG_PRBRSP,
	WFD_CAPD_IE_FLAG_ASSOCREQ,
	WFD_CAPD_IE_FLAG_ASSOCRSP,
	WFD_CAPD_IE_FLAG_GONREQ,
	WFD_CAPD_IE_FLAG_GONRSP,
	WFD_CAPD_IE_FLAG_GONCONF,
	WFD_CAPD_IE_FLAG_INVREQ,
	WFD_CAPD_IE_FLAG_INVRSP,
	WFD_CAPD_IE_FLAG_PDREQ,
	WFD_CAPD_IE_FLAG_PDRSP,
	WFD_CAPD_IE_FLAG_TDLS_SETUPREQ,
	WFD_CAPD_IE_FLAG_TDLS_SETUPRSP,
	WFD_CAPD_IE_FLAG_TOTAL
} WFD_CAPD_IE_FLAG;

/** Device address and IE data */
typedef struct wfd_capdie_dev_ie {
	WFDCAPD_UINT8 peer_addr[6];
	WFDCAPD_UINT8 *ie_data;
	WFDCAPD_UINT16 ie_data_len;
} wfd_capdie_dev_ie_t;

/** Device address and WFD capability configuration information */
typedef struct wfd_capdie_dev_cfg_info {
	WFDCAPD_UINT8 peer_addr[6];
	WFDCAPD_CAP_CONFIG wfd_cfg;
} wfd_capdie_dev_cfg_info_t;

/**
 * Initialize the library. Need to call before calling other APIs.
 *
 * @return WFDCAPD_SUCCESS if successful, otherwise an error code.
 */
WFDCAPD_STATUS
wfd_capdie_open();

/**
 * Uninitialize the library.
 *
 * @return WFDCAPD_SUCCESS if successful, otherwise an error code.
 */
WFDCAPD_STATUS
wfd_capdie_close();

/**
 * Given device configuration and group IE information, create WFD IE data.
 *
 * @param peer_addr			Local device's mac address.
 * @param dev_cap_cfg		Local device's WFD configuration.
 * @param group_dev_ie_list	The IE list of associated devices in the group.
 *							Applied to GO only and GO not included
 * @param group_dev_total	Total number of devices in the group.
 *							Applied to GO only and GO not included
 * @param ie_flag			Flag of the WFD management IE to create.
 * @param wfd_ie_buf		Buffer passed in to hold the created WFD IE.
 * @param wfd_ie_buf_len	Size of buffer passed in.
 *
 * @return WFDCAPD_SUCCESS if successful, otherwise an error code.
 */
WFDCAPD_STATUS
wfd_capdie_create_custom_ie(const WFDCAPD_CAP_CONFIG *dev_cap_cfg,
							const wfd_capdie_dev_ie_t *group_dev_ie_list,
							WFDCAPD_UINT8 group_dev_total,
							WFD_CAPD_IE_FLAG ie_flag,
							WFDCAPD_UINT8 *wfd_ie_buf,
							WFDCAPD_UINT16 *wfd_ie_buf_len);

/**
 * Given the device's IE data, get the device's WFD configuraiton information.
 *
 * @param ie_buf 			Device custom IE data.
 * @param ie_buf_len		Size of device custom IE data.
 * @param wfd_cfg			Device WFD configuration
 *
 * @return WFDCAPD_SUCCESS if successful, otherwise an error code.
 */
WFDCAPD_STATUS
wfd_capdie_get_dev_cfg(const WFDCAPD_UINT8 *ie_buf, 
					   WFDCAPD_UINT16 ie_buf_len,
					   WFDCAPD_CAP_CONFIG *wfd_cfg);

/**
 * Given the device's IE data, get the device's WFD configuraiton information.
 *
 * @param ie_buf 			Device custom IE data.
 * @param ie_buf_len		Size of device custom IE data.
 * @param sess_cfg_list		List of the configuration info of devices in the group.
 *							Applied to GO only and GO not included
 * @param sess_buf_len		Buffer size of sess_cfg_list
 *							Applied to GO only and GO itself not included
 * @param entry_num			Number of entries in sess_cfg_list list
 *							Applied to GO only and GO itself not included
 *
 * @return WFDCAPD_SUCCESS if successful, otherwise an error code.
 */
WFDCAPD_STATUS
wfd_capdie_get_group_sess_info(const WFDCAPD_UINT8 *ie_buf, 
						   WFDCAPD_UINT16 ie_buf_len,
						   wfd_capdie_dev_cfg_info_t *sess_cfg_list,
						   WFDCAPD_UINT32 sess_buf_len,
						   WFDCAPD_UINT8 *entry_num);

#if defined(__cplusplus)
}
#endif /* __cplusplus */

#endif  /* _WFD_CAPDIE_H_ */
