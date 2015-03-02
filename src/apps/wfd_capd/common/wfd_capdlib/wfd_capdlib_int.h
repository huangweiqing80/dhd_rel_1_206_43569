/* WFD IE library internal API definitions
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
#ifndef _WFDLIB_INT_H_
#define _WFDLIB_INT_H_

#include "p2plib_api.h"

extern void
p2papi_encode_prbresp_wfd_ie(capdlib_instance_t* hdl,
	uint16 dev_cap_bitmap, uint16 dev_cap_tcp_port, uint16 dev_cap_max_tput,
	uint16 max_ie_len, wifi_wfd_ie_t *wfd_ie, uint16 *ie_len);

extern BCMP2P_BOOL
p2papi_is_wfd_ie(uint8 *ie);

extern uint16
p2papi_decode_wfd_ie(uint8* buf, p2papi_wfd_ie_t *out_wfd_ie, BCMP2P_LOG_LEVEL log);

extern void
p2papi_copy_wfd_info(BCMP2P_WFD_CONFIG *dst, p2papi_wfd_ie_t *src);

extern void
p2papi_encode_provdis_wfd_ie(capdlib_instance_t* hdl,
	uint32 local_ip, wifi_wfd_ie_t *wfd_ie, uint16 *ie_len);

extern void
p2papi_encode_gon_wfd_ie(capdlib_instance_t* hdl, wifi_p2p_ie_t *wfd_ie, uint16 *ie_len);

extern bool
p2papi_search_wfd_ies(uint8* cp, uint len, p2papi_wfd_ie_t *out_wfd_ie,
	BCMP2P_LOG_LEVEL log);

#endif  /* #ifndef _WFDLIB_INT_H_ */
