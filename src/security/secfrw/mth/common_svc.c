/*****************************************************************************
 * Common service definitions
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

#include <debug.h>

#include <proto/802.11.h>		/* for DOT11_MAX_SSID_LEN */
#include <bcmsec_types.h>		/* for clientdata_t */
#include <bcmseclib_api.h>		/* for struct ctxcbs */
#include <cfg.h>

#include <l2.h>
#include <l2b.h>
#include <wlssb.h>

#include <bind_skp.h>
#include <wpa_svcp.h>
#include <wpa_cfg.h>

#include <wpa_svc.h>

#include <disp_alg.h>
#include <common_svc.h>
#include <common_cfg.h>

/* forward */
extern int
common_svc_deinit(struct cfg_ctx *ctx, const struct wpa_al *wpa);


extern int
common_svc_init(struct cfg_ctx *ctx, const struct wpa_al *wpa)
{
	int status = BCME_OK;
	struct wpa_svc_dat *svc = ctx->svc_dat;
	struct wpa_dat *dat = wpa_svc_wpa_dat(ctx->svc_dat);

	/* set the all important back pointer */
	wpa_set_ctx(dat, ctx);

	/* configure adaptation layer */
	if (NULL != wpa && NULL != wpa->cfg)
		status = (*wpa->cfg)(dat);
	if (BCME_OK != status)
		goto ERR0;

	/* init stacks */
	common_sk_init(dat, &svc->eapol_sk, wpa->frame_rx_handler,
			&svc->wlss_sk, wpa->event_rx_handler);
	/* init event stack */
	/* bind the wireless event stack */
	if (wpa->event_rx_handler) {
		svc->wlss_binding = wlss_bind(ctx, wpa->events, bind_sk_dispatch_alg,
								  svc->wlss_sk);
		if (NULL == svc->wlss_binding) {
			CTXPRT((ctx, "wlss_bind FAILED\n"));
			status = BCME_ERROR;
			goto ERR1;
		}
	}

	/* init l2 stack */
	/* bind the layer-2 stack */
	if (wpa->frame_rx_handler) {
		svc->eapol_binding = l2_bind(ctx, common_eapol_type(wpa->proto_index),
			bind_sk_dispatch_alg, svc->eapol_sk);
		if (NULL == svc->eapol_binding) {
			status = BCME_ERROR;
			goto ERR1;
		}
	}

	/* set the eapol tx path */
	wpa_set_eapol_tx(dat, svc->eapol_binding);
	
	goto ERR0;

ERR1:
	(void)common_svc_deinit(ctx, wpa);
ERR0:
	return status;
}

extern int
common_svc_deinit(struct cfg_ctx *ctx, const struct wpa_al *wpa)
{
	int status = BCME_OK;
	struct wpa_svc_dat *svc = ctx->svc_dat;
	struct wpa_dat *dat = wpa_svc_wpa_dat(ctx->svc_dat);
	
	/* unbind the wireless event stack */
	if (NULL != svc->wlss_binding) {
		wlss_unbind(ctx, svc->wlss_binding);
		svc->wlss_binding = NULL;
	}

	/* unbind the layer-2 stack */
	if (NULL != svc->eapol_binding) {
		l2_unbind(ctx, svc->eapol_binding, svc->eapol_sk);
		svc->eapol_binding = NULL;
	}

	/* deinit stacks */
	common_sk_deinit(dat, &svc->eapol_sk, &svc->wlss_sk);

	/* cleanup adaptation layer */
	if (NULL != wpa && NULL != wpa->cleanup)
		status = (*wpa->cleanup)(dat);

	return status;
}
