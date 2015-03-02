/*****************************************************************************
 * Wireless User Tools
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: dev_wlan.c,v 1.11 2010-08-09 19:20:32 $
 *
 * Per-port WLAN device
 *****************************************************************************
*/

#include <stdio.h>				/* for printf */
#include <string.h>
#include <stddef.h>				/* offsetof */

#include <typedefs.h>			/* UNUSED_PARAMETER and for bcmutils.h */
#include <bcmutils.h>			/* BCME_XXX */
#include <bcmendian.h>
#include <bcm_osl.h>			/* OS_MALLOC */

#include <proto/802.11.h>		/* for DOT11_MAX_SSID_LEN */
#include <bcmsec_types.h>		/* for clientdata_t */
#include <bcmseclib_api.h>		/* for struct ctxcbs */
#include <cfg.h>

#include <debug.h>

#include <devp.h>
#include <l2p.h>
#include <wlioctl.h>			/* WL_EVENTING_MASK_LEN */
#include "pp_dat.h"

#include <dispatcher.h>

#define PP(ctx) (((struct cfg_ctx *)(ctx))->pp_dat)

#ifdef TARGETENV_android
#include <android.h>
#endif

/*****************************************************************************
 * il2 definitions
 *****************************************************************************
*/

#include <l2p.h>
#include <il2.h>
#include <bcm_lbuf.h>
#include <bta_al.h>

/* forward */
static int
iwlss_send_frame(void *ctx, void *pkt, int len);

static void *
il2_bind(void *ctx, const struct l2 *l2, \
		 int (*rx)(void *arg, void *frame, int), void *arg)
{
	void *hdl;

	hdl = disp_register_proto(arg, PP(ctx)->ifname, rx, l2->proto);
	if (NULL == hdl)
		CTXERR((ctx, "failed to bind %s\n", l2->name));
    return hdl;
}
			 
static int
il2_unbind(void *ctx, void *ref, void *svc_ctx)
{
	UNUSED_PARAMETER(ctx);
	return disp_unregister(ref, svc_ctx);
}

static int
il2_tx(void *ctx, const void *pkt, const size_t datasz)
{
	return iwlss_send_frame(ctx, PKTDATA(NULL, pkt), PKTLEN(NULL, pkt));
}

static int
bta_il2_tx(void *ctx, const void *pkt, const size_t datasz)
{

	btachild_frame_tx_prep(pkt);
	return iwlss_send_frame(ctx, PKTDATA(NULL, pkt), PKTLEN(NULL, pkt));
}

static const struct il2 il2_vtbl =
	IL2_INITIALIZER_LIST( \
		il2_bind, \
		il2_unbind, \
		il2_tx \
	);

static const struct il2 bta_il2_vtbl =
	IL2_INITIALIZER_LIST( \
		il2_bind, \
		il2_unbind, \
		bta_il2_tx \
	);

/*****************************************************************************
 * iwlss definitions
 *****************************************************************************
*/

#include <hal.h>
#define WLSSEV_PRIVATE
#include <wlssev.h>
#include <iwlss.h>
#include <proto/ethernet.h>		/* for struct ether_addr */

#include <proto/bcmevent.h>
#include <ctype.h>	/* isdigit */
#include <stdlib.h>	/* strtoul */

/* Verify incoming pkt is Broadcom event:
 * return TRUE/FALSE accordingly
 */
bool
wpa_validate_event_msg(bcm_event_t *evpkt, int len)
{
#ifdef DEBUG
	char *funstr = "wpa_validate_event_msg";
#endif

	/* the message should be at least the header to even look at it */
	if (len < sizeof(bcm_event_t) + 2) {
		CTXERR((NULL, "%s: invalid message length: %d\n", funstr, len));
		goto error_exit;
	}
	if (ntoh16(evpkt->bcm_hdr.subtype) != BCMILCP_SUBTYPE_VENDOR_LONG) {
		CTXERR((NULL, "%s: %s: %d: not vendor specific subtype\n", funstr, \
					  evpkt->event.ifname, ntoh16(evpkt->bcm_hdr.subtype)));
		goto error_exit;
	}
	if (evpkt->bcm_hdr.version != BCMILCP_BCM_SUBTYPEHDR_VERSION) {
		CTXERR((NULL, "%s: %s: %d: subtype header version mismatch\n", \
					  funstr, evpkt->event.ifname, evpkt->bcm_hdr.version));
		goto error_exit;
	}
	if (ntoh16(evpkt->bcm_hdr.length) < BCMILCP_BCM_SUBTYPEHDR_MINLENGTH) {
		CTXERR((NULL, "%s: %s: %d: subtype hdr length too short\n", funstr, \
					  evpkt->event.ifname, evpkt->bcm_hdr.length));
		goto error_exit;
	}
	if (bcmp(&evpkt->bcm_hdr.oui[0], BRCM_OUI, DOT11_OUI_LEN) != 0) {
		CTXERR((NULL, "%s: %s: oui: 0x%2x: 0x%2x : 0x%2x not BRCM OUI\n", \
					  funstr, evpkt->event.ifname, evpkt->bcm_hdr.oui[0], \
					  evpkt->bcm_hdr.oui[1], evpkt->bcm_hdr.oui[2] \
			  ));
		goto error_exit;
	}
	/* check for wl nas message types */
	switch (ntoh16(evpkt->bcm_hdr.usr_subtype)) {
		case BCMILCP_BCM_SUBTYPE_EVENT:
			/* wl nas message */
			/* if (evpkt->version != BCM_MSG_VERSION) {
			 * atleast a debug message
			 * }
			 */
			break;
		default:
			goto error_exit;
			break;
	}

	return TRUE;

error_exit:
	return FALSE;
}

static int
nas_get_ifindex_from_ifname(const char *ifname, int len)
{
	uint32 ifindex;
	int i;

	/* "wlx, x = 0-9 */
	if (ifname[0] != 'w' && ifname[1] != 'l' && !isdigit(ifname[2]))
		return -1;

	/* find the '.' */
	for (i = 3; i < len; i++) {
		if (ifname[i] == '.')
			break;
	}
	if (i == len)
		return -1;

	ifindex = strtoul(&ifname[i+1], NULL, 0);

	return ifindex;
}

#if !defined(BCM_MSG_LEN_V1)
#define BCM_MSG_LEN_V1 46
#endif /* !defined(BCM_MSG_LEN_V1) */

#if !defined(BCM_MSG_LEN_V2)
#define BCM_MSG_LEN_V2 BCM_MSG_LEN_V1+2
#endif /* !defined(BCM_MSG_LEN_V2) */

#if !defined(BCM_EVENT_BSSCFGIDX)
#define BCM_EVENT_BSSCFGIDX(p) \
	(*((uint8 *)(p) + BCM_MSG_LEN_V1 + 1))
#endif /* !defined(BCM_EVENT_BSSCFGIDX) */

static void *
bcm_event_data(void *ctx, bcm_event_t *bcmev)
{
	uint16 v = ntoh16_ua(&bcmev->event.version);
	size_t offset;
	
	/* for backward compatibility */
	if (v < 2) 
		offset = BCM_MSG_LEN_V1;
	else
	if (v < 3)
		offset = BCM_MSG_LEN_V2;

	/* always support the most recent version */
	else
	{
		/* there's a more recent version that we can't handle */
		if (BCM_EVENT_MSG_VERSION != v) {
			CTXERR((ctx, "event version mismatch (support:%d, rcvd:%d)\n", \
				BCM_EVENT_MSG_VERSION, v));
			return NULL;
		}
		offset = BCM_MSG_LEN;
	}
	return (uint8 *)bcmev + offsetof(bcm_event_t, event) + offset;
}

static uint8
bcm_event_bsscfgidx(void *ctx, bcm_event_t *bcmev)
{
	uint16 v = ntoh16_ua(&bcmev->event.version);
	
	if (v < 2)
		return nas_get_ifindex_from_ifname(bcmev->event.ifname,
			BCM_MSG_IFNAME_MAX);

	return BCM_EVENT_BSSCFGIDX(&bcmev->event);
}

/* event demux */
/* ifname field in bcm_event_t follows this naming convention:
 *   regular-if events (ifname=<os-ifname>,bsscfg_idx=z)
 *   virtual-if events (ifname=wlx.y,bsscfg_idx=y,y!=z)
*/
static int
wlss_handler(void *arg, void *data, int len)
{
	bcm_event_t *bcmev = data;
	int ifindex;
	const char *ifname;
	struct cfg_ctx *ctx = arg;

	/* sanity check */
	if (NULL == PP(ctx)->wlss_rx)
		goto DONE; /* don't care for events (should be impossible) */

	/* Make sure it's an event */
	if (FALSE == wpa_validate_event_msg(data, len)) {
		CTXERR((ctx, "wlss_handler: invalid event message, bailing\n"));
		goto DONE;
	}
	CTXPRT((ctx, \
		"wlss_handler: event(ver=%d,type=%d) ifname %s bsscfgindex %d\n", \
		ntoh16_ua(&bcmev->event.version), ntoh32(bcmev->event.event_type), \
		bcmev->event.ifname, BCM_EVENT_BSSCFGIDX(&bcmev->event)));

	/* virtual-if case */
	if (PP(ctx)->is_vif) {
		/* get the ifindex which is synonymous with the bsscfg_index */
		ifname = bcmev->event.ifname;
		/* Events from virtual interfaces must always "come up" with the
		 * ifname format "wlx.y".  This makes it easy to parse the bsscfg_idx.
		 * Note that this format may be inconsistent with the OS interface
		 * name but that's fine.
		*/
		ifindex = bcm_event_bsscfgidx(ctx, bcmev);
		if (ifindex < 0) {
			CTXERR((ctx, "ifname unusable: ignoring event\n"));
			goto DONE;
		}
		/* does this match the ctx? */
		if (PP(ctx)->bsscfg_index != ifindex) {
			CTXERR((ctx, \
					"wlss_handler: dropping event type %d ifname %s " \
					"ifindex %d (ctx)->bsscfg_index %d\n",
					ntoh32(bcmev->event.event_type),
					bcmev->event.ifname,
					ifindex,
					PP(ctx)->bsscfg_index));

			goto DONE; /* not for us: silently drop it */
		}
	}
	
	/* regular-if case */
	/* We specifically registered for events on this interface.
	 * Okay to dispatch w/o further checking.
	*/

	/* dispatch */
	/* ignore return value since we're not chaining event
	 * handlers at this level
	*/
	{
		struct seclib_ev ev;
		ev.event = &bcmev->event;
		if (NULL == (ev.data = bcm_event_data(ctx, bcmev))) {
			CTXERR((ctx, "wlss_handler: dropping event type %d " \
				"(couldn't get data)\n", \
				ntoh32(bcmev->event.event_type)));
			goto DONE;
		}
		
		(void)(*PP(ctx)->wlss_rx)(PP(ctx)->wlss_rx_arg, &ev, len);
	}

DONE:
	return 0;
}

static void *
iwlss_bind(void *ctx, void (*interest_vector)(void *ctx, void *priv), \
		   int (*rx)(void *arg, void *event, int), void *arg)
{
	void *hdl;
	int i;
	static uint8 newvec[WL_EVENTING_MASK_LEN];
	
	if (NULL != rx) {
		hdl = disp_register_proto(ctx, PP(ctx)->ifname, wlss_handler,
								  ETHER_TYPE_BRCM);
		if (NULL == hdl) {
			CTXERR((ctx, "failed to bind wlss\n"));
			return NULL;
		}
		PP(ctx)->disp_handle = hdl;
		PP(ctx)->wlss_rx = rx;
		PP(ctx)->wlss_rx_arg = arg;
		(void)hal_get_event_mask(PP(ctx)->ifname, PP(ctx)->bsscfg_index,
								 PP(ctx)->bitvec, sizeof(PP(ctx)->bitvec));
		memset(newvec, 0, sizeof newvec);
		interest_vector(ctx, newvec);
		for (i=0; i<WL_EVENTING_MASK_LEN; i++)
			newvec[i] |= PP(ctx)->bitvec[i];
		(void)hal_set_event_mask(PP(ctx)->ifname, PP(ctx)->bsscfg_index,
								 newvec, sizeof newvec);
	}
	return ctx;
}

static int
iwlss_unbind(void *ctx, void *ref)
{
	if (NULL != PP(ctx)->disp_handle) {
		int error = disp_unregister(PP(ctx)->disp_handle, ctx);
		if (BCME_OK != error)
			return error;
		PP(ctx)->disp_handle = NULL;
		PP(ctx)->wlss_rx = NULL;
		PP(ctx)->wlss_rx_arg = NULL;
		(void)hal_set_event_mask(PP(ctx)->ifname, PP(ctx)->bsscfg_index,
								 PP(ctx)->bitvec, sizeof(PP(ctx)->bitvec));
	}
	return BCME_OK;
}

static int
iwlss_get_key_seq(void *ctx, void *buf, int buflen)
{
	return hal_get_key_seq(PP(ctx)->ifname, buf, buflen);
}
static int
iwlss_authorize(void *ctx, struct ether_addr *ea)
{
	return hal_authorize(PP(ctx)->ifname, PP(ctx)->bsscfg_index, ea);
}

static int
iwlss_deauthorize(void *ctx, struct ether_addr *ea)
{
	return hal_deauthorize(PP(ctx)->ifname, PP(ctx)->bsscfg_index, ea);
}

static int
iwlss_deauthenticate(void *ctx, struct ether_addr *ea, int reason)
{
	return hal_deauthenticate(PP(ctx)->ifname, PP(ctx)->bsscfg_index, ea,
							  reason);
}

static int
iwlss_get_group_rsc(void *ctx, uint8 *buf, int index)
{
	return hal_get_group_rsc(PP(ctx)->ifname, buf, index);
}

static int
iwlss_plumb_ptk(void *ctx, struct ether_addr *ea, uint8 *tk, int tk_len, \
				int cipher)
{
	return hal_plumb_ptk(PP(ctx)->ifname, PP(ctx)->bsscfg_index, ea, tk,
						 tk_len, cipher);
}

static void
iwlss_plumb_gtk(void *ctx, uint8 *gtk, uint32 gtk_len, uint32 key_index, \
				uint32 cipher, uint16 rsc_lo, uint32 rsc_hi, bool primary_key)
{
	hal_plumb_gtk(PP(ctx)->ifname, PP(ctx)->bsscfg_index, gtk, gtk_len,
				  key_index, cipher, rsc_lo, rsc_hi, primary_key);
}

static int
iwlss_wl_tkip_countermeasures(void *ctx, int enable)
{
	return hal_wl_tkip_countermeasures(PP(ctx)->ifname, enable);
}

static int
iwlss_set_ssid(void *ctx, char *ssid)
{
	return hal_set_ssid(PP(ctx)->ifname, ssid);
}

static int
iwlss_disassoc(void *ctx)
{
	return hal_disassoc(PP(ctx)->ifname);
}

static int
iwlss_get_wpacap(void *ctx, uint8 *cap)
{
	return hal_get_wpacap(PP(ctx)->ifname, cap);
}

static int
iwlss_get_stainfo(void *ctx, char *macaddr, int len, char *ret_buf, \
				  int ret_buf_len)
{
	return hal_get_stainfo(PP(ctx)->ifname, macaddr, len, ret_buf, \
						   ret_buf_len);
}

static int
iwlss_send_frame(void *ctx, void *pkt, int len)
{
	return hal_send_frame(PP(ctx)->ifname, PP(ctx)->bsscfg_index, pkt, len);
}

static int
iwlss_get_bssid(void *ctx, char *ret_buf, int ret_buf_len)
{
	return hal_get_bssid(PP(ctx)->ifname, PP(ctx)->bsscfg_index, ret_buf,
						 ret_buf_len);
}

static int
iwlss_get_assoc_info(void *ctx, unsigned char *buf,
					 int length)
{
	return hal_get_assoc_info(PP(ctx)->ifname, PP(ctx)->bsscfg_index, buf,
							  length);
}

static int
iwlss_get_assoc_req_ies(void *ctx, unsigned char *buf, int length)
{
	return hal_get_assoc_req_ies(PP(ctx)->ifname, PP(ctx)->bsscfg_index,
								 buf, length);
}

static int
iwlss_get_cur_etheraddr(void *ctx, uint8 *ret_buf, int ret_buf_len)
{
	return hal_get_cur_etheraddr(PP(ctx)->ifname, PP(ctx)->bsscfg_index,
								 ret_buf, ret_buf_len);
}

static int
iwlss_get_wpaie(void *ctx, uint8 *ret_buf, int ret_buf_len, \
				struct ether_addr *ea)
{
	return hal_get_wpaie(PP(ctx)->ifname, PP(ctx)->bsscfg_index, ret_buf,
						 ret_buf_len, ea);
}

static int
iwlss_get_btampkey(void *ctx, uint8 *ret_buf, int ret_buf_len, \
				struct ether_addr *ea)
{
	return hal_get_btampkey(PP(ctx)->ifname, ea, (void *)ret_buf, ret_buf_len);
}

static int
iwlss_add_wpsie(void *ctx, void *ie, int ie_len, unsigned type)
{
	return hal_add_wpsie(PP(ctx)->ifname, PP(ctx)->bsscfg_index, ie, ie_len,
						 type);
}
	
static int
iwlss_del_wpsie(void *ctx, unsigned type)
{
	return hal_del_wpsie(PP(ctx)->ifname, PP(ctx)->bsscfg_index, type);
}

const struct iwlss iwlss_vtbl =
	IWLSS_INITIALIZER_LIST( \
		iwlss_bind, \
		iwlss_unbind, \
		iwlss_get_key_seq, \
		iwlss_authorize, \
		iwlss_deauthorize, \
		iwlss_deauthenticate, \
		iwlss_get_group_rsc, \
		iwlss_plumb_ptk, \
		iwlss_plumb_gtk, \
		iwlss_wl_tkip_countermeasures, \
		iwlss_set_ssid, \
		iwlss_disassoc, \
		iwlss_get_wpacap, \
		iwlss_get_stainfo, \
		iwlss_send_frame, \
		iwlss_get_bssid, \
		iwlss_get_assoc_info, \
		iwlss_get_assoc_req_ies, \
		iwlss_get_cur_etheraddr, \
		iwlss_get_wpaie, \
		iwlss_get_btampkey, \
		iwlss_add_wpsie, \
		iwlss_del_wpsie
	);

/*****************************************************************************
 * WLAN device definitions
 *****************************************************************************
*/

static int
wlan_init(struct cfg_ctx *ctx, const void *priv)
{
	struct {
		char ifname[MAX_IF_NAME_SIZE+1];
		int bsscfg_index;
	} const *info = priv;
	struct pp_dat *dat = ctx->pp_dat;

	memcpy(dat->ifname, info->ifname, sizeof(dat->ifname));
	dat->bsscfg_index = info->bsscfg_index;
	dat->disp_handle = NULL;

	return BCME_OK;
}

static int
bta_init (struct cfg_ctx *ctx, const void *priv)
{
	struct pp_dat *dat = ctx->pp_dat;

	dat->is_vif = TRUE;

	return wlan_init(ctx, priv);
}

static void
wlan_deinit(struct cfg_ctx *ctx)
{
	UNUSED_PARAMETER(ctx);
}

static const struct dev dev =
	DEV_INITIALIZER_LIST( \
		wlan_init, \
		wlan_deinit, \
		&il2_vtbl, \
		&iwlss_vtbl \
	);

extern const struct dev *
dev_wlan(void)
{
	return &dev;
}

/*****************************************************************************
 * BTAMP device definitions
 *****************************************************************************
*/


/* Shares its members with the dev_wlan */
static const struct dev _btamp_dev =
	DEV_INITIALIZER_LIST( \
		bta_init, \
		wlan_deinit, \
		&bta_il2_vtbl, \
		&iwlss_vtbl \
	);

extern const struct dev *
dev_btamp(void)
{
	return &_btamp_dev;
}
