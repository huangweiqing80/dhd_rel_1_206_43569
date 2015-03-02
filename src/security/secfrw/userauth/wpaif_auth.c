/*
 * wpaif_auth.c -- interface to wpa authenticator library
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wpaif_auth.c,v 1.4 2010-12-11 00:06:36 $
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <typedefs.h>
#include <bcmsec_types.h>
#include <wlioctl.h>
#include <bcm_supenv.h>
#include <proto/eapol.h>
#include <proto/eap.h>
#include <bcmwpa.h>

#include <bcmendian.h>
#include <bcmcrypto/prf.h>

#if defined(BCM_OSL)
#include "osl.h"
#else
#include <bcm_osl.h>
#endif

#include <wlc_security.h>
#include <bcmseclib_timer.h>
#include <bcm_supenv.h> /* for those pesky wlc defs in wlc_wpa.h et al */
#include <wlc_wpa.h>
#include <bcm_authenv.h>

#include <wpaif_auth.h>
#include <wlc_auth.h>
#include <bcmutils.h>
#include <bcm_llist.h>
#include <debug.h>

#ifdef TARGETENV_android
#include <android.h>
#endif


static struct auth_cbs auth_cbfuns;

/* forward */
sta_parms_t *
wpaif_auth_find_sta_by_ea(auth_info_t *pauth, struct ether_addr *ea, bool srch);

/* general (de)initialization */
void wpaif_auth_init(struct auth_cbs* cbfuns)
{
	auth_cbfuns.result = cbfuns->result;
	auth_cbfuns.plumb_ptk = cbfuns->plumb_ptk;
	auth_cbfuns.plumb_gtk = cbfuns->plumb_gtk;
	auth_cbfuns.tx_frame = cbfuns->tx_frame;
	auth_cbfuns.get_key_seq = cbfuns->get_key_seq;

}

/* Make sure all ctx's have been properly disposed first! */
void wpaif_auth_cleanup(void)
{
	memset((char *)&auth_cbfuns, 0, sizeof(struct auth_cbs));
}

/* context (de)initialization */
struct ctx* wpaif_auth_ctx_init(clientdata_t *clientdata,
	int WPA_auth, int btamp_enabled, int wsec, uint8 *pmk, int pmk_len,
	struct ether_addr *auth_ea)
{
	struct auth_info *pauth;
	char *funstr = "wpaif_auth_ctx_init";

	/* Allocate an auth_ctx structure, init it */
	pauth = (struct auth_info *)malloc(sizeof(struct auth_info));
	if (pauth == NULL) {
		PRINT_ERR(("%s: failed to allocate auth structure, bailing\n", funstr));
		goto err_done;
	}
	memset(pauth, 0, sizeof(struct auth_info));
	/* init basic config for this authenticator */
	pauth->WPA_auth = WPA_auth;
	pauth->btamp_enabled = btamp_enabled;
	pauth->wsec = wsec;
	memcpy(&pauth->psk, pmk, pmk_len);
	pauth->psk_len = pmk_len;

	memcpy(pauth->auth_ea.octet, auth_ea->octet, ETHER_ADDR_LEN);


	/* set ctx pointers */
	pauth->ctx.supctx = (void *)pauth;
	pauth->ctx.client = clientdata;

	PRINT(("wpaif_auth_ctx_init: created pauth %p, returning ctx %p\n",
			pauth, &pauth->ctx));
	return (&pauth->ctx);

err_done:
	return NULL;
}
void wpaif_auth_ctx_cleanup(struct ctx* ctx)
{
	struct auth_info *pauth;
	sta_parms_t * psta;

	pauth = ctx->supctx;
	psta = pauth->sta_list;

	PRINT(("wpaif_auth_ctx_cleanup: processing ctx %p, pauth %p sta_list %p\n",
			ctx, pauth, pauth->sta_list));

	/* Walk sta list: free allocated memory & timers */
	for (psta = pauth->sta_list; psta; psta = pauth->sta_list) {
		 wpaif_auth_cleanup_sta(psta);
	}
	/* De-Allocate the auth_ctx structure */
	free(pauth);
}

/* Handle inputs from WLC_E_DISASSOC_IND */
void
wpaif_auth_cleanup_ea(struct ctx* ctx, struct ether_addr *ea)
{
	auth_info_t *pauth;
	sta_parms_t *sta_info;
	char *funstr = "wpaif_auth_cleanup_ea";
	char eabuf[32];

	PRINT(("%s: ea %s\n", funstr,bcm_ether_ntoa(ea, eabuf)));

	pauth = ctx->supctx;
	/* Is sta at ea on our list? If not we're done*/
	sta_info = wpaif_auth_find_sta_by_ea(pauth, ea, TRUE);
	if (sta_info == NULL)
		return;

	wpaif_auth_cleanup_sta(sta_info);
}

/* Handle inputs from WLC_E_ASSOC_IND */
/* Remember translate auth_type to AUTH_WPAPSK for wlc_set_auth */
void wpaif_auth_ctx_set_sta(struct ctx *ctx, uint8 *sup_ies,
		uint sup_ies_len, uint8 *auth_ies, uint auth_ies_len,
		struct ether_addr *ea, unsigned char *key, int key_len)
{
	auth_info_t *pauth;
	sta_parms_t *sta_info;
	char sta_ea_str[32];
	char auth_ea_str[32];
	char *funstr = "wpaif_auth_ctx_set_sta";

	PRINT(("%s:\n", funstr));
	pauth = ctx->supctx;

	/* Is sta at ea on our list? If not add it */
	sta_info = wpaif_auth_find_sta_by_ea(pauth, ea, FALSE);

	/* Failed (for some reason)? */
	if (sta_info == NULL) {
		PRINT_ERR(("%s: failed to find/allocate sta for ea %s auth_ea %s \n",
				funstr, bcm_ether_ntoa(&pauth->auth_ea, auth_ea_str),
					bcm_ether_ntoa(&sta_info->sta_ea, sta_ea_str)));
		return;
	}

	/* what needs to be filled into sta_info ? */
	sta_info->wpa_info.pmk_len = key_len;
	/* This had better be PMK_LEN long! */
	memcpy(sta_info->wpa_info.pmk, key, key_len);

	/* Init the retry timer for this sta */
	sta_info->wpa_info.retry_timer =
		bcmseclib_init_timer(wlc_auth_retry_timer, sta_info, "auth_retry");

	if (sta_info->wpa_info.retry_timer == NULL) {
		PRINT_ERR((
			"%s: failed to allocate retry timer for auth ea %s, sta ea %s\n",
			funstr, bcm_ether_ntoa(&pauth->auth_ea, auth_ea_str),
			bcm_ether_ntoa(&sta_info->sta_ea, sta_ea_str)));
		return;
	}
	wlc_auth_initialize_gkc(pauth);


	wlc_set_auth(pauth, AUTH_WPAPSK, sup_ies, sup_ies_len,
			auth_ies, auth_ies_len, sta_info);
}

/* EAPOL key pkts destined for authenticator processing.
 * NB: p is a PKT
 */
void wpaif_auth_dispatch(struct ctx *ctx, unsigned char *p, int len)
{
	sta_parms_t *sta_info;
	auth_info_t *pauth = ctx->supctx;
	eapol_header_t *phdr;

	PRINT(("wpaif_auth_dispatch\n"));
	phdr = (eapol_header_t *)p;
	/* lookup the sta_info by ea, if not found bail out */
	sta_info = wpaif_auth_find_sta_by_ea(pauth, (struct ether_addr *)phdr->eth.ether_shost, TRUE);
	if (sta_info == NULL) {
		return;
	}

	wlc_auth_eapol(pauth, phdr, sta_info->have_keys, sta_info);
}


void
wpaif_auth_plumb_ptk(sta_parms_t *sta_info, uint8 *pkey, int keylen, ushort cipher)
{
	/* wlc_wpa_plumb_tk */
	if (auth_cbfuns.plumb_ptk == NULL) {
		PRINT_ERR(("wpaif_auth_plumb_ptk: cb fun not initialized!\n"));
		return;
	}
	(*auth_cbfuns.plumb_ptk)(sta_info->auth->ctx.client, pkey, keylen, cipher,
			&sta_info->sta_ea);
}

void
wpaif_auth_plumb_gtk(sta_parms_t *sta_info, uint8 *gtk, uint32 gtk_len,
	uint32 key_index, uint32 cipher, uint8 *rsc, bool primary_key)
{
	uint16 rsc_lo;
	uint32 rsc_hi;


	/* Extract the Key RSC in an Endian independent format */
	if (rsc == NULL) {
		rsc_lo = 0;
		rsc_hi = 0;
	} else {
		rsc_lo = (((rsc[1] << 8) & 0xFF00) |
	               (rsc[0] & 0x00FF));
		rsc_hi = (((rsc[5] << 24) & 0xFF000000) |
	               ((rsc[4] << 16) & 0x00FF0000) |
	               ((rsc[3] << 8) & 0x0000FF00) |
	               ((rsc[2]) & 0x000000FF));
	}
	/* wlc_wpa_plumb_gtk */
	if (auth_cbfuns.plumb_gtk == NULL) {
		PRINT_ERR(("wpaif_auth_plumb_gtk: cb fun not initialized!\n"));
		return;
	}
   (*auth_cbfuns.plumb_gtk)(sta_info->auth->ctx.client, gtk, gtk_len,
		   key_index, cipher, rsc_lo, rsc_hi, primary_key);
}

/* free timers and allocated memory and mark sta inactive */
void
wpaif_auth_cleanup_sta(struct sta_parms *sta_info)
{
	auth_info_t *auth = sta_info->auth;
	struct sta_parms *plist;

	PRINT(("wpaif_auth_cleanup_sta sta_info %p\n", sta_info));
	/* Free timer */
	bcmseclib_free_timer(sta_info->wpa_info.retry_timer);

	/* free allocated memory */
	bcm_authenv_cleanup_wpa(NULL, &sta_info->wpa);

	/* remove this sta from auth list */

	for (plist = auth->sta_list; plist; plist = plist->next ) {
		if (sta_info == plist) {
			/* found it, remove it */
			bcm_llist_del_member(&auth->sta_list, plist);

			/* free it */
			free(plist);
			break;
		}
	}
}

/* a simple deauth for this sta */
void
wpaif_auth_deauth_sta(sta_parms_t *sta_info, int reason)
{
	if (auth_cbfuns.result == NULL) {
		PRINT_ERR(("wpaif_auth_deauth_sta: cb fun not initialized!\n"));
		return;
	}
	(*auth_cbfuns.result)(sta_info->auth->ctx.client, FALSE, &sta_info->sta_ea, reason);

	sta_info->have_keys = FALSE;
}

/* WLC_SCB_AUTHORIZE this sta */
void
wpaif_auth_authorize_sta(sta_parms_t *sta_info)
{
	if (auth_cbfuns.result == NULL) {
		PRINT_ERR(("wpaif_auth_authorize_sta: cb fun not initialized!\n"));
		return;
	}
	/* reason is irrelevant when we're authorizing */
	(*auth_cbfuns.result)(sta_info->auth->ctx.client, TRUE, &sta_info->sta_ea, 0);
	sta_info->have_keys = TRUE;
}

void
wpaif_auth_get_key_seq(sta_parms_t *sta_info, void *buf, int buflen)
{
	if (auth_cbfuns.get_key_seq == NULL) {
		PRINT_ERR(("wpaif_auth_authorize_sta: cb fun not initialized!\n"));
		return;
	}
	(*auth_cbfuns.get_key_seq)(sta_info->auth->ctx.client, buf, buflen);
}

/* Send a pkt using the registered callback from init */
void
wpaif_auth_tx_frame(sta_parms_t *sta_info, void *p)
{
	eapol_header_t *eapol_hdr;
	auth_info_t *pauth = sta_info->auth;

	if (auth_cbfuns.tx_frame == NULL) {
		PRINT_ERR(("wpaif_auth_authorize_sta: cb fun not initialized!\n"));
		return;
	}
	/* Attach etherheader
	 * NB: BTAMP uses BT-SIG encapsulation, TODO
	 */
	eapol_hdr = (eapol_header_t *)PKTDATA(NULL, p);
	bcopy((char *)&sta_info->sta_ea, (char *)&eapol_hdr->eth.ether_dhost,
	      ETHER_ADDR_LEN);
	bcopy((char *)&pauth->auth_ea, (char *)&eapol_hdr->eth.ether_shost,
	      ETHER_ADDR_LEN);
	eapol_hdr->eth.ether_type = hton16(ETHER_TYPE_802_1X);

	(*auth_cbfuns.tx_frame)(sta_info->auth->ctx.client, p, PKTLEN(NULL, p));

	PKTFREE(NULL, p, FALSE);
}

/* Look for a sta_info element in the authenticator with the supplied ea.
 * If not found, create one.
 */
sta_parms_t *
wpaif_auth_find_sta_by_ea(auth_info_t *pauth, struct ether_addr *ea, bool search_only)
{
	sta_parms_t *psta = pauth->sta_list;
	sta_parms_t *pnew, *plist;
	char *funstr = "wpaif_auth_find_sta_by_ea";

	for (plist = psta; plist; plist = plist->next) {
		if (!bcmp(ea->octet, psta->sta_ea.octet, ETHER_ADDR_LEN))
			return plist;
	}

	/* not found:
	 * just report not found if not requested to add new one
	 */
	if (search_only)
		return NULL;

	pnew = malloc(sizeof(sta_parms_t));

	if (pnew == NULL) {
		PRINT_ERR(("%s: failed to malloc new sta_info element\n", funstr));
		return NULL;
	}

	memset(pnew, 0, sizeof(sta_parms_t));
	memcpy(pnew->sta_ea.octet, ea->octet, ETHER_ADDR_LEN);
	pnew->auth = pauth;

	/* add it to the list */
	pnew->next = pauth->sta_list;
	pauth->sta_list = pnew;

	return pnew;
}
