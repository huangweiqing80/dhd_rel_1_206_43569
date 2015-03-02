/*****************************************************************************
 * WPA service definitions (private)
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *****************************************************************************
*/

#include <typedefs.h>
#include <bcmutils.h>

#include <bcmwpa.h>

#include <bind_skp.h>
#define WPA_CFG_PRIVATE
#include <wpa_cfg.h>
#define WPA_SVC_PRIVATE
#include <wpa_svcp.h>


extern struct wpa_dat *
wpa_svc_wpa_dat(struct wpa_svc_dat *svc)
{
	return &svc->wpa_dat;
}
