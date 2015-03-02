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

#include <proto/802.11.h>		/* for DOT11_MAX_SSID_LEN */
#include <bcmsec_types.h>		/* for clientdata_t */
#include <bcmseclib_api.h>		/* for struct ctxcbs */
#include <cfg.h>

#include <bind_sk.h>
#include <bind_skp.h>
#define WPS_CFG_PRIVATE
#include <wps_al.h>

#include <wps_svc.h>
#define WPS_SVC_PRIVATE
#include <wps_svcp.h>

#include <l2b.h>
#include <l2.h>
#include <wlssb.h>
#include <disp_alg.h>

struct wps_fn {
	int (*cfg)(struct wps_dat *);
	int (*cleanup)(struct wps_dat *);
	int (*eapol)(void *, void *, int);
	int (*event)(void *, void *, int);
};

static int
wps_svc_deinit(struct cfg_ctx *ctx, const struct wps_fn *fn);

static void
wps_ev_forwarder(struct cfg_ctx *ctx, const struct bcmseclib_ev_wps *ev_data);

const static struct wps_cbs s_cbs = { wps_ev_forwarder };

/*
 * wps service interface
*/

static void
wps_ev_forwarder(struct cfg_ctx *ctx, const struct bcmseclib_ev_wps *ev_data)
{
	if (NULL == ctx->ctx_cb.event)
		return;
		
	(*ctx->ctx_cb.event)(ctx, ctx->client_data, ev_data);
}

static int
wps_svc_init(struct cfg_ctx *ctx, const struct wps_fn *fn)
{
	int status = BCME_OK;
	struct wps_svc_dat *svc = ctx->svc_dat;
	struct wps_dat *dat = wps_svc_wps_dat(ctx->svc_dat);

	/* set the all important back pointer */
	wps_set_ctx(dat, ctx);

	/* register callbacks */
	wps_cbs(dat, &s_cbs);

	/* configure adaptation layer */
	status = (*fn->cfg)(dat);
	if (BCME_OK != status)
		goto ERR0;

	/* init stacks */
	bind_sk_init(&dat->eapol, fn->eapol, dat);
	bind_sk_ins(&svc->eapol_sk, &dat->eapol);
	bind_sk_init(&dat->wlss, fn->event, dat);
	bind_sk_ins(&svc->wlss_sk, &dat->wlss);

	/* bind the layer-2 stack */
	svc->eapol_binding = l2_bind(ctx, eapol_type(), bind_sk_dispatch_alg,
								 svc->eapol_sk);
	if (NULL == svc->eapol_binding) {
		status = BCME_ERROR;
		goto ERR1;
	}

	/* set the eapol tx path */
	wps_set_eapol_tx(dat, svc->eapol_binding);
	
	/* bind the wireless event stack */
	svc->wlss_binding = wlss_bind(ctx, wps_events, bind_sk_dispatch_alg,
								  svc->wlss_sk);
	if (NULL == svc->wlss_binding) {
		status = BCME_ERROR;
		goto ERR1;
	}

	goto ERR0;

ERR1:
	(void)wps_svc_deinit(ctx, fn);
ERR0:
	return status;
}

static int
wps_svc_deinit(struct cfg_ctx *ctx, const struct wps_fn *fn)
{
	int status = BCME_OK;
	struct wps_svc_dat *svc = ctx->svc_dat;
	struct wps_dat *dat = wps_svc_wps_dat(ctx->svc_dat);
	
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
	bind_sk_del(&svc->eapol_sk, &dat->eapol);
	bind_sk_del(&svc->wlss_sk, &dat->wlss);

	/* cleanup adaptation layer */
	status = (*fn->cleanup)(dat);

	return status;
}

/*
 * wps service interface
*/

const static struct wps_fn s_wps_sup_fn = {
	wps_sup_enr_cfg,
	wps_sup_enr_cleanup,
	wps_sup_eapol_hdlr,
	wps_sup_handle_event
};

extern int
wps_sup_svc_init(struct cfg_ctx *ctx)
{
	return wps_svc_init(ctx, &s_wps_sup_fn);
}

extern int
wps_sup_svc_deinit(struct cfg_ctx *ctx)
{
	return wps_svc_deinit(ctx, &s_wps_sup_fn);
}

extern int
wps_sup_svc_cfg(struct cfg_ctx *ctx, const struct cfg_ctx_set_cfg *cfg)
{
	return wps_sup_unpack(ctx, wps_svc_wps_dat(ctx->svc_dat), cfg);
}

const static struct wps_fn s_wps_auth_fn = {
	wps_auth_cfg,
	wps_auth_cleanup,
	wps_auth_eapol_hdlr,
	wps_auth_handle_event
};

extern int
wps_auth_svc_init(struct cfg_ctx *ctx)
{
	return wps_svc_init(ctx, &s_wps_auth_fn);
}

extern int
wps_auth_svc_deinit(struct cfg_ctx *ctx)
{
	return wps_svc_deinit(ctx, &s_wps_auth_fn);
}

extern int
wps_auth_svc_cfg(struct cfg_ctx *ctx, const struct cfg_ctx_set_cfg *cfg)
{
	return wps_auth_unpack(ctx, wps_svc_wps_dat(ctx->svc_dat), cfg);
}

/*
 * private access to al dat
*/

#include <string.h>

int wps_sup_unpack(struct cfg_ctx *ctx, struct wps_dat *dat,
				   const struct cfg_ctx_set_cfg *cfg)
{
	const struct sec_args *args;

	UNUSED_PARAMETER(ctx);

	args = &cfg->args;

	memcpy(dat->ssid, args->ssid, MIN(sizeof(dat->ssid), args->ssid_len));
	dat->ssid_len = args->ssid_len;
	memcpy(dat->pin, args->pin, MIN(sizeof(dat->pin), sizeof(args->pin)));
	memcpy(dat->peer_mac_addr, args->peer_mac_addr, 6);

	return 0;
}

int wps_auth_unpack(struct cfg_ctx *ctx, struct wps_dat *dat,
					const struct cfg_ctx_set_cfg *cfg)
{
	const struct sec_args *args;

	UNUSED_PARAMETER(ctx);

	args = &cfg->args;

	{
	size_t len = MIN(args->psk_len, sizeof(dat->nw_key)-1);
	memcpy(dat->nw_key, args->psk, len);
	dat->nw_key[len] = '\0';
	}
	
	memcpy(dat->ssid, args->ssid, MIN(sizeof(dat->ssid), args->ssid_len));
	dat->ssid_len = args->ssid_len;
	memcpy(dat->pin, args->pin, MIN(sizeof(dat->pin), sizeof(args->pin)));
	dat->auth_type = args->WPA_auth;
	dat->encr_type = args->wsec;
	dat->wep_index = args->key_index;

	return 0;
}

struct wps_dat *
wps_svc_wps_dat(struct wps_svc_dat *svc_dat)
{
	return &svc_dat->wps_dat;
}
