/*
 * wpa_auth.c
 * Adaptation file for in-driver wpa authenticator
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wpa_auth.c,v 1.3 2010-05-05 21:02:59 $
*/

typedef struct cfg_ctx cfg_ctx_t;

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <typedefs.h>
#include <bcmsec_types.h>
#include <bcmendian.h>
#include <netinet/in.h>
#include <proto/802.11.h>
#include <bcmwpa.h>
#include <bcmutils.h>
#include <wlioctl.h>
#include <wlutils.h>

#include <bcmseclib_api.h>
#include <l2.h>
#include <l2b.h>
#include <wlss.h>
#include <wlssb.h>
#include <cfg.h>
#include <methods.h>
#include <hal.h>
#include <dispatcher.h>
#include <bcm_osl.h>
#include <debug.h>

#include <bcmseclib_timer.h>
#include <bcm_supenv.h>
#include <wlc_wpa.h>
#include <bcm_authenv.h>
#include <wpaif_auth.h>
#include <mth_events.h>
#include <wlssev.h>

#define WPA_CFG_PRIVATE
#include <bind_skp.h>
#include <wpa_cfg.h>


/* cb function:
 * called from wpa_handle_event
 * The ctx & event event have been validated,
 * now process it.
 * 
 */
int 
wpa_auth_process_event(struct wpa_dat *dat, struct seclib_ev *pevt, int evlen)
{
	uint8 buf[WLC_IOCTL_MAXLEN];
	int status;
	char *funstr = "wpa_auth_process_event";
	struct cfg_ctx *ctx = wpa_get_ctx(dat);

	CTXPRT((ctx, "%s\n", funstr));
	CTXPRT((ctx, "%s event type 0x%x\n", funstr,ntoh32(SECLIB_BCM_EVENT_TYPE(pevt)) ));
	switch (ntoh32(SECLIB_BCM_EVENT_TYPE(pevt))) {

		case WLC_E_ASSOC_IND:
		case WLC_E_REASSOC_IND:
			/* auth_ies we get from the ap */
			status = wlss_get_wpaie(ctx, buf, WLC_IOCTL_MAXLEN,
			                        &dat->cur_etheraddr);
			if (status) {
				CTXERR((ctx, "%s: failed to retrieve wpaie, status %d "
							 "bailing\n", funstr, status));
				goto DONE;
			}

			/* grab the sup_ies from the event */
			/* grab the sta's ea from the event */
			wpaif_auth_ctx_set_sta(dat->svc_ctx,
				(uint8 *)SECLIB_BCM_EVENT_DATA(pevt), ntoh32(SECLIB_BCM_EVENT_DATALEN(pevt)),
				buf, WLC_IOCTL_MAXLEN,
				SECLIB_BCM_EVENT_ADDR(pevt),
				dat->pmk, PMK_LEN);
			break;

		case WLC_E_DISASSOC_IND:
			/* clean up this sta */
			wpaif_auth_cleanup_ea(dat->svc_ctx, SECLIB_BCM_EVENT_ADDR(pevt));
			break;

		default:
			break;
	}

DONE:
	return 0;
}

/* cb funs registered with authenticator by wpa_auth_init */
/* All are common with supplicant except following */

/* handshake result: success/fail with reason
 * authorize or deauthenticate [for reason] as appropriate
 */
void wpa_auth_result(void *arg, unsigned char success,
					 struct ether_addr *ea, unsigned char reason)
{
	struct wpa_dat *dat = arg;
	struct cfg_ctx *ctx = wpa_get_ctx(arg);
	char eabuf[32];

	CTXPRT((ctx, "wpa_auth_result: success %d ea %s reason %d\n",
				 success, bcm_ether_ntoa(ea, eabuf), reason));
	if (dat->result) 
		(*dat->result)(ctx->client_data, success, reason);

	/* issue WLC_SCB_AUTHORIZE or WLC_SCB_DEAUTHENTICATE for reason */
	if (success)
		wlss_authorize(ctx, ea);
	else
		wlss_deauthenticate(ctx, ea, reason);
}

/* Get key sequence */
void wpa_get_key_seq(void *arg, void *buf, int buflen)
{
	struct cfg_ctx *ctx = ((struct wpa_dat *)arg)->ctx;

	wlss_get_key_seq(ctx, buf, buflen);
}

static struct auth_cbs cbfuns = {
	wpa_auth_result,	/* NOT common with supplicant */
	wpa_plumb_ptk,	/* common with supplicant */
	wpa_plumb_gtk,		/* common with supplicant */
	wpa_tx_frame,		/* common with supplicant */
	wpa_get_key_seq,
};

/* Top level supplicant init: called when library is starting up */
int
wpa_auth_init()
{
	wpaif_auth_init(&cbfuns);
	return BCME_OK;
}
/* Top level supplicant de-init: called when library is shutting down */
int
wpa_auth_deinit()
{
	wpaif_auth_cleanup();
	return BCME_OK;
}

/* Init an authenticator instance */
int
wpa_auth_cfg(struct wpa_dat *dat)
{
	struct ctx *authctx;
	char *funstr = "wpa_auth_cfg";
	char ea_str[32];
	struct cfg_ctx *ctx = wpa_get_ctx(dat);

	if (wlss_get_cur_etheraddr(ctx,
							   (uint8 *)&dat->cur_etheraddr,
							   sizeof dat->cur_etheraddr))
	{
		CTXERR((ctx, "%s: failed to get hwaddr\n", funstr));
		goto err_done;
	}

	/* Init and record the returned supp ctx pointer */
	authctx = wpaif_auth_ctx_init(dat, dat->WPA_auth, dat->btamp_enabled,
								  dat->wsec, dat->pmk, dat->pmk_len,
								  &dat->cur_etheraddr);

	if (authctx == NULL) {
		CTXERR((ctx, "%s: unable to init ctx for authenticator " \
					 "(ea %s)\n", funstr, \
					 bcm_ether_ntoa(&dat->cur_etheraddr, ea_str)));
		goto err_done;
	}
	dat->svc_ctx = authctx;

	return BCME_OK;

err_done:
	wpa_auth_cleanup(dat);
	return BCME_ERROR;
}

/* De-init an authenticator instance */
int
wpa_auth_cleanup(struct wpa_dat *dat)
{
	/* May be called to cleanup failed config attempt: be defensive */
	if (NULL != dat->svc_ctx) {
		wpaif_auth_ctx_cleanup(dat->svc_ctx);
		dat->svc_ctx = NULL;
	}

	return BCME_OK;
}
