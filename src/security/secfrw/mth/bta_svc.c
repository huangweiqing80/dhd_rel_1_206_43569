/*****************************************************************************
 * BTA service definitions
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
#include <wpa_cfg.h>
#include <common_svc.h>
#include <bta_al.h>
#include <bta_cfg.h>
#include <wpa_svc.h>

#include <disp_alg.h>



/* Parent */
struct wpa_al _bta_parent = {
	btaparent_cfg,
	btaparent_cleanup,
	NULL,		/* no rx frame fun needed */
	btaparent_event_rx_handler,	/* have to receive WLC_E_IF events */
	0,		/* use regular wlan dev */
	bta_parent_events,
};


extern int
btaparent_svc_init(struct cfg_ctx *ctx)
{
	return common_svc_init(ctx, &_bta_parent);
}

extern int
btaparent_svc_deinit(struct cfg_ctx *ctx)
{
	return common_svc_deinit(ctx, &_bta_parent);
}

extern int
btaparent_svc_cfg(struct cfg_ctx *ctx, const struct cfg_ctx_set_cfg *cfg)
{
	return wpa_cfg(ctx, wpa_svc_wpa_dat(ctx->svc_dat), cfg);
}

/* Child */

struct wpa_al _child_al_sup = {
	wpa_sup_cfg,
	wpa_sup_cleanup,
	btachild_frame_rx_handler,
	btachild_event_rx_handler,
	1,		/* 802.3 encap */
	bta_events,
};

extern int
btachild_svc_sup_init(struct cfg_ctx *ctx)
{
	return common_svc_init(ctx, &_child_al_sup);
}

extern int
btachild_svc_sup_deinit(struct cfg_ctx *ctx)
{
	return common_svc_deinit(ctx, &_child_al_sup);
}

struct wpa_al _child_al_auth = {
	wpa_auth_cfg,
	wpa_auth_cleanup,
	btachild_frame_rx_handler,
	btachild_event_rx_handler,
	1,		/* 802.3 encap */
	bta_events,
};
extern int
btachild_svc_auth_init(struct cfg_ctx *ctx)
{
	return common_svc_init(ctx, &_child_al_auth);
}

extern int
btachild_svc_auth_deinit(struct cfg_ctx *ctx)
{
	return common_svc_deinit(ctx, &_child_al_auth);
}

extern int
btachild_svc_cfg(struct cfg_ctx *ctx, const struct cfg_ctx_set_cfg *cfg)
{
	return wpa_cfg(ctx, wpa_svc_wpa_dat(ctx->svc_dat), cfg);
}
