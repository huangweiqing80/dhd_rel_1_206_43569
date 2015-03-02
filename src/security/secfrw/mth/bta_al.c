/*****************************************************************************
 * bta adaptation layer
 * bta_al.c
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 * $Id: bta_al.c,v 1.5 2010-12-11 00:06:35 $
 *****************************************************************************
 */


/* Discussion:
 * BTAMP uses wpa2-psk-aes _only_
 * It's very similar to regular wlan operation except:
 * -- role (auth/supp) isn't known until receipt of WLC_E_IF event
 * -- pmk isn't known until receipt of WLC_E_LINK (sup)
 *   or WLC_E_ASSOC_IND (auth) events
 * -- eapol frames are encap'd in 802.3 frames with BTSIG snap header
 * -- no group keys sent or plumbed
 *
 * Hence this file is brief. Most of the work is done by invoking
 * existing wpa_{auth, sup} funs.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <typedefs.h>
#include <bcmsec_types.h>
#include <bcmendian.h>
#include <proto/802.11.h>
#include <proto/ethernet.h>
#include <proto/802.11_bta.h>
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

/* forward */
extern int
btachild_auth_process_event(struct wpa_dat *arg, struct seclib_ev *pevt, int evlen);
extern int
btachild_sup_process_event(struct wpa_dat *arg, struct seclib_ev *pevt, int evlen);

extern int
btachild_frame_tx_prep(const void *pkt)
{
	struct ether_header ethhdr;
	char *p;

	/* convert the DIX ethernet frame to an 802.3 with BTSIG encap */
	/* OUr lbufs are allocated with 170 (?) bytes of headroom */

	/* squirrel away the ether header */
	memcpy(&ethhdr, PKTDATA(NULL, pkt), sizeof(struct ether_header));
	ethhdr.ether_type = hton16(PKTLEN(NULL, pkt) - ETHER_HDR_LEN + DOT11_LLC_SNAP_HDR_LEN);

	PKTPUSH(NULL, pkt, DOT11_LLC_SNAP_HDR_LEN);
	p = (char *)PKTDATA(NULL, pkt);
	memcpy(p, &ethhdr, ETHER_HDR_LEN);

	p += ETHER_HDR_LEN;

	memcpy(p, BT_SIG_SNAP_MPROT, DOT11_LLC_SNAP_HDR_LEN - 2);
	p += (DOT11_LLC_SNAP_HDR_LEN - 2);
	*((uint16 *)p) = hton16(BTA_PROT_SECURITY);

	return 0;
}
extern int
btachild_frame_rx_handler(void *arg, void *pkt, int len)
{
	struct wpa_dat *dat = arg;
	char *p = (char *)pkt;
	uint16 frtype;
	struct ether_header ether_hdr;

	PRINT(("btachild_frame_rx_handler:\n"));
	/* Verify it's for us: we get _all_ 802.3 frames
	 * It's ours iff:
	 * snap hdr == BT_SIG_SNAP_MPROT
	 * type (last byte) == BTA_PROT_SECURITY
	 */
	p += ETHER_HDR_LEN;
	frtype = *((uint16 *)(p + DOT11_LLC_SNAP_HDR_LEN - 2));

	if (memcmp(p, BT_SIG_SNAP_MPROT, DOT11_LLC_SNAP_HDR_LEN - 2) ||
		BTA_PROT_SECURITY != ntoh16(frtype))
		return 0;

	/* Remove the snap header, re-encap with DIX frame header,
	 * ether type ETHER_TYPE_802_1X
	 */
	p = (char *)pkt;
	memcpy(&ether_hdr, p, ETHER_HDR_LEN);
	ether_hdr.ether_type = hton16(ETHER_TYPE_802_1X);
	p += DOT11_LLC_SNAP_HDR_LEN;
	memcpy(p, &ether_hdr, ETHER_HDR_LEN);
	len -= DOT11_LLC_SNAP_HDR_LEN;

	/* give it to the supp or auth */
	if (0 == dat->role)
		wpaif_ctx_dispatch(dat->svc_ctx, (void *)p, len);
	else
		wpaif_auth_dispatch(dat->svc_ctx, (void *)p, len);

	return 0;
}

extern int
btachild_event_rx_handler(void *arg, void *pkt, int len)
{

	/* fetch and apply the pmk when we see WLC_E_LINK, WLC_E_ASSOC_IND */

	/* invoke supp/auth processing as appropriate */

	int consumed = 0;
	struct cfg_ctx *ctx = wpa_get_ctx(arg);
	struct wpa_dat *dat = arg;
#ifdef DEBUG
	char *funstr = "btachild_event_rx_handler";
#endif

	/* validate the ctx first */
	if (cfg_validate_ctx(ctx) == FALSE) {
		CTXERR((NULL, "%s: called with invalid arg %p\n", funstr, arg));
		goto done;
	}


	/* process it ... */
	if (dat->role == 0)
		consumed = btachild_sup_process_event(dat, pkt, len);
	else
		consumed = btachild_auth_process_event(dat, pkt, len);

done:
	return consumed;
}
extern int
btachild_sup_process_event(struct wpa_dat *dat, struct seclib_ev *pevt, int evlen)
{
	union {
		wl_assoc_info_t		assoc_info;
		uint8				bytes[WLC_IOCTL_MAXLEN];
	} buf;
	unsigned			assoc_req_ies_len, assoc_resp_ies_len;
	int					is_reassoc;
	struct cfg_ctx		*ctx = wpa_get_ctx(dat);
	char *funstr = "btachild_sup_process_event";
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
			int status;

			/* get the association request IEs */
			if (wlss_get_assoc_req_ies(ctx, buf.bytes, sizeof buf.bytes)) {
				CTXERR((ctx, "%s: could not retrieve association request " \
							 "IEs", funstr));
				goto DONE;
			}

			/* Finally we can get the pmk */
			status = wlss_get_btampkey(ctx, dat->pmk, dat->pmk_len,
				SECLIB_BCM_EVENT_ADDR(pevt));

			if (status) {
				CTXERR((ctx, "%s: could not retrieve btamp key ", funstr));
				goto DONE;
			}

			/* set pmk */
			wpaif_ctx_set_pmk(dat->svc_ctx, dat->pmk, dat->pmk_len);

			/* apply general configuration to user-mode supplicant */
			/* auth_type follows wlioctl.h values */
			memcpy(&dat->BSSID, SECLIB_BCM_EVENT_ADDR(pevt),
				sizeof(struct ether_addr));

			wpaif_ctx_set_cfg(dat->svc_ctx, dat->WPA_auth,
							  SECLIB_BCM_EVENT_ADDR(pevt), buf.bytes,
							  assoc_req_ies_len,
		(unsigned char *)SECLIB_BCM_EVENT_DATA(pevt), ntoh32(SECLIB_BCM_EVENT_DATALEN(pevt)),
	&dat->cur_etheraddr, dat->btamp_enabled);

		}
		break;

		case WLC_E_DEAUTH:
		CTXTRC((ctx, "%s: WLC_E_DEAUTH\n", funstr));
		/* zero pmk: resets everything */
		wpaif_ctx_set_pmk(dat->svc_ctx, dat->pmk, 0);
		break;

		default:
		break;

	} /* switch (SECLIB_BCM_EVENT_TYPE(pevt)) */

DONE:
	return 0;
}

extern int
btachild_auth_process_event(struct wpa_dat *dat, struct seclib_ev *pevt, int evlen)
{
	uint8 buf[WLC_IOCTL_MAXLEN];
	int status;
	char *funstr = "btachild_auth_process_event";
	struct cfg_ctx *ctx = wpa_get_ctx(dat);

	CTXPRT((ctx, "%s event type 0x%x\n", funstr,ntoh32(SECLIB_BCM_EVENT_TYPE(pevt)) ));
	switch (ntoh32(SECLIB_BCM_EVENT_TYPE(pevt))) {

		case WLC_E_ASSOC_IND:
		case WLC_E_REASSOC_IND:
			/* auth_ies we get from the ap */
			status = wlss_get_wpaie(ctx, buf, WLC_IOCTL_MAXLEN,
									SECLIB_BCM_EVENT_ADDR(pevt));
			if (status) {
				CTXERR((ctx, "%s: failed to retrieve wpaie, status %d "
							 "bailing\n", funstr, status));
				goto DONE;
			}

			/* Finally we can get the pmk */
			status = wlss_get_btampkey(ctx, dat->pmk, dat->pmk_len,
				SECLIB_BCM_EVENT_ADDR(pevt));

			if (status) {
				CTXERR((ctx, "%s: could not retrieve btamp key ", funstr));
				goto DONE;
			}

			/* Do we need to set the auth's pmk? */

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

extern int
btaparent_event_rx_handler(void *arg, struct seclib_ev *pevt, int evlen)
{
	int consumed = 0;
	struct cfg_ctx *ctx = wpa_get_ctx(arg);
#ifdef DEBUG
	char *funstr = "btaparent_event_rx_handler";
#endif
	wl_event_data_if_t *evdat;

	/* Verify it's an event */
	/* validate the ctx first */
	if (cfg_validate_ctx(ctx) == FALSE) {
		CTXERR((NULL, "%s: called with invalid arg %p\n", funstr, arg));
		goto done;
	}


	CTXPRT((ctx, "%s\n", funstr));
	/* Only the WLC_E_IF interests us */
	PRINT(("%s: processing event type 0x%x\n", __FUNCTION__, ntoh32(SECLIB_BCM_EVENT_TYPE(pevt))));
	if (WLC_E_IF != ntoh32(SECLIB_BCM_EVENT_TYPE(pevt)))
		goto done;

#if NEVER
	   /* WLC_E_IF event data */
typedef struct wl_event_data_if {
	uint8 ifidx;
	uint8 opcode;		/* see I/F opcode */
	uint8 reserved;
	uint8 bssidx;		/* bsscfg index */
	uint8 role;		/* see I/F role */
} wl_event_data_if_t;
#endif

	/* interface UP:
	 * create child ctx (if it doesn't already exist)
	 * config with appropriate role (sup or auth)
	 * Use dummy pmk: we don't know it yet
	 *
	 * interface DOWN: destroy child ctx (if it exists)
	 */
	evdat = (wl_event_data_if_t *)SECLIB_BCM_EVENT_DATA(pevt);

	PRINT(("%s: opcode %d\n", __FUNCTION__, evdat->opcode));
	PRINT(("bssidx %d, role %d\n", evdat->bssidx, evdat->role));

	switch (evdat->opcode) {

		case WLC_E_IF_ADD:
		/* UP */
			consumed = btaparent_create_child(ctx, evdat->bssidx, evdat->role);
			break;
		case WLC_E_IF_DEL:
		/* DOWN */
			consumed = btaparent_destroy_child(ctx, evdat->bssidx, evdat->role);
			break;
		default:
			goto done;
	}
done:
	return consumed;
}


/*
 * The bta parent exists only to listen for WLC_E_IF events and
 * create/destroy child ctx's accordingly.
 * The same capability should be available in a "regular" wlan ctx but
 * we deemed it desireable to [be able to] listen for these events
 * without creating a wlan capable ctx.
 * NB:
 * Since there's no outside entity awaiting a callback
 * with context info etc, we've got to keep all of that stuff in
 * the parent's ctx.
 * Should the parent be removed we'll have to destroy all
 * of the created child ctx's along with it
 */
extern int
btaparent_cfg(struct wpa_dat *dat)
{
	return 0;
}

extern int
btaparent_cleanup(struct wpa_dat *dat)
{
	return 0;
}
