/*****************************************************************************
 * WPA adaptation layer
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

#include <bcmwpa.h>			/* for PMK_LEN and WPA_MAX_PSK_LEN */

#include <bind_sk.h>
#include <bind_skp.h>

#define WPA_CFG_PRIVATE
#include <wpa_cfg.h>


void
wpa_sk_init(struct wpa_dat *dat, struct bind_sk **eapol,
			struct bind_sk **wlss)
{
	bind_sk_init(&dat->eapol, wpa_handle_8021x, dat);
	bind_sk_init(&dat->wlss, wpa_handle_event, dat);
	
	bind_sk_ins(eapol, &dat->eapol);
	bind_sk_ins(wlss, &dat->wlss);
}

void
wpa_sk_deinit(struct wpa_dat *dat, struct bind_sk **eapol,
			struct bind_sk **wlss)
{
	bind_sk_del(eapol, &dat->eapol);
	bind_sk_del(wlss, &dat->wlss);
}

void
common_sk_init(struct wpa_dat *dat, struct bind_sk **eapol,
			  int (*eapol_fun)(void *, void *, int), struct bind_sk **wlss,
			  int (*wlss_fun)(void *, void *, int))
			  
{
	if (NULL != eapol_fun) {
		bind_sk_init(&dat->eapol, eapol_fun, dat);
		bind_sk_ins(eapol, &dat->eapol);
	}

	if (NULL != wlss_fun) {
		bind_sk_init(&dat->wlss, wlss_fun, dat);
		bind_sk_ins(wlss, &dat->wlss);
	}
}

void
common_sk_deinit(struct wpa_dat *dat, struct bind_sk **eapol, struct bind_sk **wlss)
{
	if (eapol)
		bind_sk_del(eapol, &dat->eapol);
	if (wlss)
		bind_sk_del(wlss, &dat->wlss);
}
