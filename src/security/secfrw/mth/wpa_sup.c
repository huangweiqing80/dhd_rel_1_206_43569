/*
 * wpa_sup.c
 * Adaptation file for in-driver wpa supplicant
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wpa_sup.c,v 1.4 2010-09-02 21:15:53 $
*/

typedef struct cfg_ctx cfg_ctx_t;

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <typedefs.h>
#include <bcmsec_types.h>
#include <bcmendian.h>
#include <proto/802.11.h>
#include <bcmwpa.h>
#include <bcmutils.h>
#include <wlutils.h>

#include <bcmseclib_api.h>
#include <l2.h>
#include <l2b.h>
#include <wlss.h>
#include <wlssb.h>
#include <cfg.h>
#include <bcm_osl.h>
#include <debug.h>

#include <bcmseclib_timer.h>
#include <bcm_supenv.h>
#include <wlc_wpa.h>
#include <bcm_authenv.h>
#include <wpaif.h>
#include <wpaif_auth.h>
#include <mth_events.h>
#include <wlssev.h>

#define WPA_CFG_PRIVATE
#include <bind_skp.h>
#include <wpa_cfg.h>

#define ASSOC_REQ_FIXED_LEN(reassoc) \
	((reassoc) ? DOT11_REASSOC_REQ_FIXED_LEN : DOT11_ASSOC_REQ_FIXED_LEN)


int wpa_sup_cleanup(struct wpa_dat *);
static int wpa_sup_process_event(struct wpa_dat *, struct seclib_ev *, int evlen);

/* CB functions invoked by the supplicant:
 * These get registered by the [top level] init
 * in the struct cbs arg
 */
/* handshake result: success/fail with reason
 * authorize or deauthenticate [for reason] as appropriate
 */
void wpa_result(void *arg, unsigned char success, unsigned char reason)
{
	struct wpa_dat *dat = arg;
	struct cfg_ctx *ctx = wpa_get_ctx(arg);
	char eabuf[32];

	CTXPRT((ctx, "wpa_result: success %d ea %s reason %d\n", \
				 success, bcm_ether_ntoa(&dat->BSSID, eabuf), \
				 reason));
	if (dat->result)
		(*dat->result)(ctx->client_data, success, reason);
	/* issue WLC_SCB_AUTHORIZE or WLC_SCB_DEAUTHENTICATE for reason */
	if (success)
		wlss_authorize(ctx, &dat->BSSID);
	else
		wlss_deauthenticate(ctx, &dat->BSSID, reason);
}

/* wlc_wpa_plumb_tk */
void wpa_plumb_ptk(void *arg, uint8 *key, uint32 keylen, uint32 algo,
				   struct ether_addr *ea)
{
	struct cfg_ctx *ctx = wpa_get_ctx(arg);

	wlss_plumb_ptk(ctx, ea, key, keylen, algo);
}

/* wlc_wpa_plumb_gtk */
void wpa_plumb_gtk(void *arg, uint8 *key, uint32 keylen, uint32 index,
				   uint32 algo, uint16 rsc_lo, uint32 rsc_hi, bool primary)
{
	struct cfg_ctx *ctx = wpa_get_ctx(arg);

	wlss_plumb_gtk(ctx, key, keylen, index, algo, rsc_lo, rsc_hi,
				   primary);
}

/* wlc_sendpkt */
void wpa_tx_frame(void *arg, void *pkt, int len)
{
	struct cfg_ctx *ctx = wpa_get_ctx(arg);

	l2_tx(ctx, pkt, len);
}

/* wlc_mac_event */
void wpa_fwd_supp_status(void *arg, uint32 reason, uint32 status)
{
	struct cfg_ctx *ctx = wpa_get_ctx(arg);

	CTXPRT((ctx, "wpa_fwd_supp_status: stubbed\n"));
}

/* pmkid cache */
void wpa_set_pmkid_cache(void *arg, struct _pmkid *p, unsigned val)
{
	struct cfg_ctx *ctx = wpa_get_ctx(arg);

	CTXPRT((ctx, "wpa_set_pmkid_cache: stubbed\n"));
}


/* Used by top level init call */
static struct cbs cbfuns =
{
	wpa_result,
	wpa_plumb_ptk,
	wpa_plumb_gtk,
	wpa_tx_frame,
	wpa_fwd_supp_status,
	wpa_set_pmkid_cache,
};

/* cb function:
 * registered with dispatcher to handle mac events for supplicant
 */
int
wpa_handle_event(void *arg, void *pkt, int len)
{
	int consumed = 0;
	struct cfg_ctx *ctx = wpa_get_ctx(arg);
	struct wpa_dat *dat = arg;
#ifdef DEBUG
	char *funstr = "wpa_handle_event";
#endif

	/* validate the ctx first */
	if (cfg_validate_ctx(ctx) == FALSE) {
		CTXERR((NULL, "%s: called with invalid arg %p\n", funstr, arg));
		goto done;
	}


	/* process it ... */
	if (dat->role == 0)
		consumed = wpa_sup_process_event(dat, pkt, len);
	else
		consumed = wpa_auth_process_event(dat, pkt, len);

done:
	return consumed;
}

static int
wpa_sup_process_event(struct wpa_dat *dat, struct seclib_ev *pevt, int evlen)
{
	union {
		wl_assoc_info_t assoc_info;
		uint8			bytes[WLC_IOCTL_MAXLEN];
	} buf;
	unsigned			assoc_req_ies_len, assoc_resp_ies_len;
	int					is_reassoc;
	pmkid_cand_list_t	*pmkid_cand_list;
	struct cfg_ctx		*ctx = wpa_get_ctx(dat);
	char *funstr = "wpa_sup_process_event";
	char eabuf[32];

	/* Avoid unused parameter compiler warning when logs are compiled out. */
	UNUSED_PARAMETER(eabuf);

	CTXPRT((ctx, "%s: SECLIB_BCM_EVENT_TYPE(pevt) %d\n", __FUNCTION__, \
				 ntoh32(SECLIB_BCM_EVENT_TYPE(pevt))));

	switch (ntoh32((SECLIB_BCM_EVENT_TYPE(pevt))))
	{
	case WLC_E_LINK:
		/* Only interested in link up */
		if (!SECLIB_BCM_EVENT_FLAG_LINK_UP(pevt))
			goto DONE;

		/* determine association IE lengths and if we're reassoc'ing */
		if (wlss_get_assoc_info(ctx, (uchar *)&buf.assoc_info,
								sizeof buf.assoc_info)) {
			CTXERR((ctx, "%s: could not determine association " \
						 "information", funstr));
			goto DONE;
		}
		is_reassoc =
			(WLC_ASSOC_REQ_IS_REASSOC == buf.assoc_info.flags);
		assoc_req_ies_len =
			buf.assoc_info.req_len - ASSOC_REQ_FIXED_LEN(is_reassoc);
		assoc_resp_ies_len =
			buf.assoc_info.resp_len - DOT11_ASSOC_RESP_FIXED_LEN;

		CTXTRC((ctx, "%s: is_reassoc=%d\n", funstr, is_reassoc));

		CTXTRC((ctx, "%s: Authenticator's MAC addr: %s\n", funstr, \
				bcm_ether_ntoa(SECLIB_BCM_EVENT_ADDR(pevt), eabuf)));

		{

			/* get the association request IEs */
			if (wlss_get_assoc_req_ies(ctx, buf.bytes, sizeof buf.bytes)) {
				CTXERR((ctx, "%s: could not retrieve association request " \
							 "IEs", funstr));
				goto DONE;
			}

			/* set pmk */
			wpaif_ctx_set_pmk(dat->svc_ctx, dat->pmk, dat->pmk_len);

			/* apply general configuration to user-mode supplicant */
			/* auth_type follows wlioctl.h values */
			memcpy(&dat->BSSID, SECLIB_BCM_EVENT_ADDR(pevt),
				   sizeof(struct ether_addr));
			prhex(NULL, buf.bytes, 76);
			wpaif_ctx_set_cfg(dat->svc_ctx, dat->WPA_auth,
							  SECLIB_BCM_EVENT_ADDR(pevt),
							  buf.bytes, assoc_req_ies_len,
		(unsigned char *)SECLIB_BCM_EVENT_DATA(pevt), ntoh32(SECLIB_BCM_EVENT_DATALEN(pevt)),
	&dat->cur_etheraddr, dat->btamp_enabled);

		}
		break;

	case WLC_E_MIC_ERROR:
		CTXTRC((ctx, "%s: WLC_E_MIC_ERROR\n", funstr));
		break;

	case WLC_E_DEAUTH:
		CTXTRC((ctx, "%s: WLC_E_DEAUTH\n", funstr));
		/* zero pmk: resets everything */
		wpaif_ctx_set_pmk(dat->svc_ctx, dat->pmk, 0);
		break;

	case WLC_E_PMKID_CACHE:
		pmkid_cand_list = ((pmkid_cand_list_t *)SECLIB_BCM_EVENT_DATA(pevt));
		CTXTRC((ctx, "%s: WLC_E_PMKID_CACHE\n", funstr));
		break;

	} /* switch (SECLIB_BCM_EVENT_TYPE(pevt)) */

DONE:
	return 0;
}

/* cb function:
 * registered with dispatcher to handle 8021x frames for supplicant
 */
int
wpa_handle_8021x(void *arg, void *pkt, int len)
{
	struct wpa_dat *dat = arg;

	if (0 == dat->role)
		wpaif_ctx_dispatch(dat->svc_ctx, pkt, len);
	else
		wpaif_auth_dispatch(dat->svc_ctx, pkt, len);

	return 0;
}

/* Top level supplicant init: called when library is starting up */
void
wpa_sup_init()
{
	wpaif_init(&cbfuns);
}
/* Top level supplicant de-init: called when library is shutting down */
int
wpa_sup_deinit()
{
	wpaif_cleanup();
	return 0;
}

/* Init a supplicant instance */
int
wpa_sup_cfg(struct wpa_dat *dat)
{
	char *funstr = "wpa_sup_cfg";
	struct ctx *suppctx;
	struct cfg_ctx *ctx = wpa_get_ctx(dat);

	/* Init and record the returned supp ctx pointer */
	suppctx = wpaif_ctx_init(dat);
	if (NULL == suppctx) {
		CTXERR((ctx, "%s: failed to init supp ctx\n", funstr));
		goto err_done;
	}
	dat->svc_ctx = suppctx;

	if (wlss_get_cur_etheraddr(ctx, (uint8 *)&dat->cur_etheraddr,
							   sizeof(dat->cur_etheraddr)))
	{
		CTXERR((ctx, "%s: failed to get hwaddr\n", funstr));
		goto err_done;
	}

	return BCME_OK;

err_done:
	(void)wpa_sup_cleanup(dat);
	return BCME_ERROR;
}

/* De-init a supplicant instance */
int
wpa_sup_cleanup(struct wpa_dat *dat)
{
	/* May be called to cleanup failed config attempt: be defensive */
	if (NULL != dat->svc_ctx) {
		wpaif_ctx_cleanup(dat->svc_ctx);
		dat->svc_ctx = NULL;
	}

	return BCME_OK;
}
