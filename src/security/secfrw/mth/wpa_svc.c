/*****************************************************************************
 * WPA service definitions
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


/* forward */
extern int
wpa_svc_deinit(struct cfg_ctx *ctx, const struct wpa *wpa);


extern int
wpa_svc_init(struct cfg_ctx *ctx, const struct wpa *wpa)
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
	wpa_sk_init(dat, &svc->eapol_sk, &svc->wlss_sk);

	/* bind the layer-2 stack */
	svc->eapol_binding = l2_bind(ctx, eapol_type(), bind_sk_dispatch_alg,
								 svc->eapol_sk);
	if (NULL == svc->eapol_binding) {
		status = BCME_ERROR;
		goto ERR1;
	}

	/* set the eapol tx path */
	wpa_set_eapol_tx(dat, svc->eapol_binding);
	
	/* bind the wireless event stack */
	svc->wlss_binding = wlss_bind(ctx, wpa_events, bind_sk_dispatch_alg,
								  svc->wlss_sk);
	if (NULL == svc->wlss_binding) {
		status = BCME_ERROR;
		goto ERR1;
	}

	goto ERR0;

ERR1:
	(void)wpa_svc_deinit(ctx, wpa);
ERR0:
	return status;
}

extern int
wpa_svc_deinit(struct cfg_ctx *ctx, const struct wpa *wpa)
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
	wpa_sk_deinit(dat, &svc->eapol_sk, &svc->wlss_sk);

	/* cleanup adaptation layer */
	if (NULL != wpa && NULL != wpa->cleanup)
		status = (*wpa->cleanup)(dat);

	return status;
}

/*
 * wpa sup
*/

static const struct wpa _wpa_sup = {
	wpa_sup_cfg,
	wpa_sup_cleanup,
};

static const struct wpa *
wpa_sup(void)
{
	return &_wpa_sup;
}

extern int
wpa_sup_svc_init(struct cfg_ctx *ctx)
{
	return wpa_svc_init(ctx, wpa_sup());
}

extern int
wpa_sup_svc_deinit(struct cfg_ctx *ctx)
{
	return wpa_svc_deinit(ctx, wpa_sup());
}

/*
 * wpa auth
*/

static const struct wpa _wpa_auth = {
	wpa_auth_cfg,
	wpa_auth_cleanup,
};

static const struct wpa *
wpa_auth(void)
{
	return &_wpa_auth;
}

extern int
wpa_auth_svc_init(struct cfg_ctx *ctx)
{
	return wpa_svc_init(ctx, wpa_auth());
}

extern int
wpa_auth_svc_deinit(struct cfg_ctx *ctx)
{
	return wpa_svc_deinit(ctx, wpa_auth());
}

/*
 * common
*/

extern int
wpa_svc_cfg(struct cfg_ctx *ctx, const struct cfg_ctx_set_cfg *cfg)
{
	return wpa_cfg(ctx, wpa_svc_wpa_dat(ctx->svc_dat), cfg);
}
