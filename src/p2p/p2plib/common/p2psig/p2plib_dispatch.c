/*
 * P2P Library API - Event dispatch (OS-independent)
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: p2plib_dispatch.c,v 1.12 2011-01-18 17:58:57 $
 */

/* ---- Include Files ---------------------------------------------------- */

#include <stdlib.h>
#include <ctype.h>

/* P2P Library include files */
#include <BcmP2PAPI.h>
#include <p2plib_int.h>
#include <p2plib_sd.h>
#include <p2pwl.h>

/* WL driver include files */
#include <bcmendian.h>
#include <wlioctl.h>
#include <bcmutils.h>


/* ---- Public Variables ------------------------------------------------- */
/* ---- Private Constants and Types -------------------------------------- */
/* ---- Private Variables ------------------------------------------------ */
/* ---- Private Function Prototypes -------------------------------------- */

static int p2papi_is_brcm_event_frm(p2papi_instance_t *hdl, void *frame,
	uint32 *event_type);
static void p2plib_event_to_host_order(wl_event_msg_t * evt);
static void p2papi_dispatch_event(p2papi_instance_t *hdl, BCMP2P_BOOL is_primary,
	wl_event_msg_t *event, void* data, uint32 data_len);


/* ---- Functions -------------------------------------------------------- */

/* Check if a received frame is a BRCM event from the driver */
static int
p2papi_is_brcm_event_frm(p2papi_instance_t *hdl, void *frame,
	uint32 *event_type)
{
	bcm_event_t *pvt_data = (bcm_event_t *)frame;
	uint16 ether_type;
	wl_event_msg_t *event;
/*
	uint32 status;
	uint16 flags;
*/
	(void)hdl;
	ether_type = ntoh16_ua((void*)&pvt_data->eth.ether_type);
	if (ether_type != ETHER_TYPE_BRCM) {
		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
			"p2papi_is_brcm_event_frm: no, ether type=0x%04x\n", ether_type));
		return FALSE;
	}
	if (memcmp(BRCM_OUI, &pvt_data->bcm_hdr.oui[0], DOT11_OUI_LEN)) {
		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
			"p2papi_is_brcm_event_frm: no, OUI=0x%02x %02x %02x\n",
			pvt_data->bcm_hdr.oui[0], pvt_data->bcm_hdr.oui[1],
			pvt_data->bcm_hdr.oui[2]));
		return FALSE;
	}
	if (ntoh16_ua((void *)&pvt_data->bcm_hdr.usr_subtype)
		!= BCMILCP_BCM_SUBTYPE_EVENT) {
		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
			"p2papi_is_brcm_event_frm: no, usr_subtype=0x%02x\n",
			pvt_data->bcm_hdr.usr_subtype));
		return FALSE;
	}

	event = &pvt_data->event;
	*event_type = ntoh32_ua((void *)&event->event_type);
/*
	flags = ntoh16_ua((void *)&event->flags);
	status = ntoh32_ua((void *)&event->status);

	BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
		"p2papi_is_brcm_event_frm: yes, type=%u flags=%u status=%u\n",
		*event_type, flags, status));
*/

	return TRUE;
}


/* Event struct members passed from dongle to host are stored in network
 * byte order. Convert all members to host-order.
 */
static void
p2plib_event_to_host_order(wl_event_msg_t * evt)
{
	evt->event_type = ntoh32(evt->event_type);
	evt->flags = ntoh16(evt->flags);
	evt->status = ntoh32(evt->status);
	evt->reason = ntoh32(evt->reason);
	evt->auth_type = ntoh32(evt->auth_type);
	evt->datalen = ntoh32(evt->datalen);
	evt->version = ntoh16(evt->version);
}

/*
 * Process a raw rx frame to look for group owner negotiation Wi-fi Action
 * Frames.  This fn should be called by an OSL to deliver raw received frames
 * after the core code has called p2papi_osl_start_raw_rx_mgr() to start
 * receiving raw frames.
 */
void
p2papi_process_raw_rx_frame(p2papi_instance_t *hdl, uint8 *frame,
	uint32 frame_nbytes)
{
	uint32 event_type = 0;

	/* Check parameters */
	P2PAPI_CHECK_P2PHDL(hdl);
	if (frame_nbytes == 0 || frame == NULL) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"proc_raw_rx_frm: no data! frame=%p len=%u\n",
			frame, frame_nbytes));
		return;
	}

	if (p2papi_is_brcm_event_frm(hdl, frame, &event_type)) {
		bcm_event_t *pvt_data = (bcm_event_t *)frame;
		wl_event_msg_t *event = &pvt_data->event;
		uint32 datalen = ntoh32(event->datalen);
		uint32 framelen = frame_nbytes - sizeof(bcm_event_t);
		if (datalen > framelen) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_process_raw_rx_frame: %d > %d, data truncated\n",
			datalen, framelen));
			/* truncate data */
			datalen = framelen;
		}
		p2papi_rx_wl_event(hdl, event, &pvt_data[1], datalen);
	} else {
		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
			"proc_raw_rx_frm: %02x:%02x:%02x:%02x:%02x:%02x"
			" %02x:%02x:%02x:%02x:%02x:%02x %02x%02x",
			frame[0], frame[1], frame[2], frame[3], frame[4], frame[5],
			frame[6], frame[7], frame[8], frame[9], frame[10], frame[11],
			frame[12], frame[13]));
		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
			"  %02x %02x %02x %02x  %02x %02x %02x %02x"
			"  %02x %02x %02x %02x  %02x %02x %02x %02x\n",
			frame[14], frame[15], frame[16], frame[17],
			frame[18], frame[19], frame[20], frame[21],
			frame[22], frame[23], frame[24], frame[25],
			frame[26], frame[27], frame[28], frame[29]));
	}
}


/* Process a received WL driver event.
 */
#define CASE_EVENT(evt, verbose_print) \
	case ((evt)): \
	{ \
		name = #evt; \
		verbose = (verbose_print); \
		break; \
	}

void
p2papi_rx_wl_event(p2papi_instance_t *hdl, wl_event_msg_t *event, void* data,
	uint32 data_len)
{
	const char *bsscfg = NULL;
	BCMP2P_BOOL is_primary = FALSE;
	const char *name = NULL;
	uint32 event_type;
#if P2PLOGGING
	bool verbose = FALSE;
#endif /* P2PLOGGING */
	BCMP2P_BOOL from_unknown_bsscfg = FALSE;

	(void) data; /* some builds may not use this parameter */
	/* assert(data) */

	if (!event) {
		return; /* Nothing to do. */
	}

	/* Convert the event data fields from dongle to host order */
	p2plib_event_to_host_order(event);

	if (hdl->bssidx[P2PAPI_BSSCFG_PRIMARY] == event->bsscfgidx) {
		is_primary = TRUE;
		bsscfg = "primary";
	}
	else if (hdl->bssidx[P2PAPI_BSSCFG_DEVICE] &&
		hdl->bssidx[P2PAPI_BSSCFG_DEVICE] == event->bsscfgidx)
		bsscfg = "device";
	else if (hdl->bssidx[P2PAPI_BSSCFG_CONNECTION] &&
		hdl->bssidx[P2PAPI_BSSCFG_CONNECTION] == event->bsscfgidx)
		bsscfg = "connection";
	else
	{
		bsscfg = "";
		from_unknown_bsscfg = TRUE;
	}

	event_type = event->event_type;

#if P2PLOGGING
	/* Log the event */
	switch (event_type) {
		CASE_EVENT(WLC_E_SET_SSID, 0);
		CASE_EVENT(WLC_E_AUTH, 0);
		CASE_EVENT(WLC_E_LINK, 0);
		CASE_EVENT(WLC_E_ASSOC, 0);
		CASE_EVENT(WLC_E_ASSOC_IND, 0);
		CASE_EVENT(WLC_E_REASSOC, 0);
		CASE_EVENT(WLC_E_DISASSOC, 0);
		CASE_EVENT(WLC_E_DISASSOC_IND, 0);
		CASE_EVENT(WLC_E_DEAUTH, 0);
		CASE_EVENT(WLC_E_DEAUTH_IND, 0);
		CASE_EVENT(WLC_E_EAPOL_MSG, 0);
		CASE_EVENT(WLC_E_JOIN_START, 0);
		CASE_EVENT(WLC_E_PROBREQ_MSG, 1);
		CASE_EVENT(WLC_E_P2P_PROBREQ_MSG, 1);
		CASE_EVENT(WLC_E_SCAN_COMPLETE, 1);
		CASE_EVENT(WLC_E_PSK_SUP, 0);
		CASE_EVENT(WLC_E_IF, 0);
		CASE_EVENT(WLC_E_ACTION_FRAME, 0);
		CASE_EVENT(WLC_E_ACTION_FRAME_RX, 0);
		CASE_EVENT(WLC_E_ACTION_FRAME_COMPLETE, 0);
		CASE_EVENT(WLC_E_ACTION_FRAME_OFF_CHAN_COMPLETE, 0);
		CASE_EVENT(WLC_E_TXFAIL, 1);
		CASE_EVENT(WLC_E_ESCAN_RESULT, 1);
		CASE_EVENT(WLC_E_ASSOC_REQ_IE, 0);
		CASE_EVENT(WLC_E_ASSOC_RESP_IE, 0);
		default:
			name = "";
			verbose = TRUE;
			break;
	}

	BCMP2PLOG((verbose ? BCMP2P_LOG_VERB_EVENT : BCMP2P_LOG_MED, TRUE,
		"p2papi_rx_wl_event: rx %s %d bsscfgidx=%d(%s) "
		"stat=0x%x reas=0x%x auth=%u data_len=%d\n",
		name, event_type, event->bsscfgidx, bsscfg,
		event->status, event->reason, event->auth_type,
		data_len));
	if (event->datalen) {
		p2papi_log_hexdata(verbose ? BCMP2P_LOG_VERB_EVENT : BCMP2P_LOG_MED,
			"p2papi_rx_wl_event: event data",
			(unsigned char *)&event[1], (event->datalen > 16) ? 16:event->datalen);
	}
#endif /* P2PLOGGING */


#if defined(D11AC_IOTYPES) && defined(BCM_P2P_IOTYPECOMPAT)

	switch (event_type) {

		case WLC_E_ESCAN_RESULT:
		{
			wl_escan_result_t *edata = data;
			int i;
			chanspec_t  chanspec;
			for (i = 0; i < dtoh16(edata->bss_count); i++) {
				wl_bss_info_t *bss_info = &edata->bss_info[i];
				chanspec = dtohchanspec(bss_info->chanspec);
				chanspec = htodchanspec(P2PWL_CHSPEC_IOTYPE_DTOH(chanspec));
				bss_info->chanspec = chanspec;
			}
		}
		break;

#ifndef SOFTAP_ONLY
		case WLC_E_ACTION_FRAME_RX:
		{
			wl_event_rx_frame_data_t *rxframe = (wl_event_rx_frame_data_t*) data;

			rxframe->channel = ntoh16(rxframe->channel);
			rxframe->channel = P2PWL_CHSPEC_IOTYPE_DTOH(rxframe->channel);
			rxframe->channel = hton16(rxframe->channel);
		}
		break;
#endif
	}
#endif /* defined(D11AC_IOTYPES) && defined(BCM_P2P_IOTYPECOMPAT) */

	if (from_unknown_bsscfg && event_type != WLC_E_IF)
		BCMP2PLOG((verbose ? BCMP2P_LOG_VERB_EVENT : BCMP2P_LOG_MED, TRUE,
		"p2papi_rx_wl_event: no need to dispatch %s %d from bsscfgidx=%d(%s)\n",
		name, event_type, event->bsscfgidx, bsscfg));
	else
		/* Run event dispatcher. */
		p2papi_dispatch_event(hdl, is_primary, event, data, data_len);
}

/****************************************************************************
* Function:   p2papi_dispatch_event
*
* Purpose:    Dispatch event to each registered event handler.
*
* Parameters: hdl        (mod) P2P handle.
*             is_primary (in)  Is primary interface.
*             event      (in)  Received WLAN driver event.
*             data       (in)  Received WLAN driver event data.
*             data_len   (in)  Received WLAN driver event data length.
*
* Returns:    Nothing.
*****************************************************************************
*/
static void
p2papi_dispatch_event(p2papi_instance_t *hdl, BCMP2P_BOOL is_primary,
	wl_event_msg_t *event, void* data, uint32 data_len)
{
	/* Give each module a chance to handle the event. */

	/* Action Frame tx */
	p2papi_wl_event_handler_aftx(hdl->provdis_aftx_hdl, is_primary,
		event, data, data_len);
	p2papi_wl_event_handler_aftx(hdl->gon_aftx_hdl, is_primary,
		event, data, data_len);
	p2papi_wl_event_handler_aftx(hdl->invite_aftx_hdl, is_primary,
		event, data, data_len);
	p2papi_wl_event_handler_aftx(hdl->presence_aftx_hdl, is_primary,
		event, data, data_len);
	p2papi_wl_event_handler_aftx(hdl->discb_aftx_hdl, is_primary, event,
		data, data_len);
	p2papi_wl_event_handler_aftx(hdl->sd_aftx_hdl, is_primary, event,
		data, data_len);

#ifndef SOFTAP_ONLY
	/* Discovery and channel synchronization */
	p2papi_wl_event_handler_discover(hdl, is_primary, event, data, data_len);

	/* Service discovery */
	p2plib_sd_wl_event_handler(hdl, is_primary, event, data, data_len);
#endif /* SOFTAP_ONLY */

	/* Group Owner Negotiation */
	p2papi_wl_event_handler_negotiate(hdl, is_primary, event, data, data_len);

	/* Transient group formation phase */
	p2papi_wl_event_handler_formation(hdl, is_primary, event, data, data_len);

	/* Operational phase (independent state-machine) */
	p2papi_wl_event_handler_connect(hdl, is_primary, event, data, data_len);
}


/* Create the static event masks needed by p2papi_enable_driver_events() */
void
p2papi_init_driver_event_masks(p2papi_instance_t *hdl)
{
	/* Get the existing event mask in the driver */
	p2pwlu_get_event_mask(hdl, hdl->orig_event_mask, sizeof(hdl->orig_event_mask));

	/* Use this as the starting point of our event mask */
	memcpy(hdl->event_mask, hdl->orig_event_mask, sizeof(hdl->event_mask));

	/* Uncomment this to enable msg tracing on older chips.  Msg tracing
	 * sends firmware debug prints to DHD that would normally go out the
	 * serial port.
	 */


	/* Add to our event mask the events we want to see */
	hdl->event_mask[WLC_E_SET_SSID/8] |= 1 << (WLC_E_SET_SSID % 8);
	hdl->event_mask[WLC_E_AUTH/8] |= 1 << (WLC_E_AUTH % 8);
	hdl->event_mask[WLC_E_DISASSOC/8] |= 1 << (WLC_E_DISASSOC % 8);
	hdl->event_mask[WLC_E_DEAUTH/8] |= 1 << (WLC_E_DEAUTH % 8);
	hdl->event_mask[WLC_E_DEAUTH_IND/8] |= 1 << (WLC_E_DEAUTH_IND % 8);
	hdl->event_mask[WLC_E_REASSOC/8] |= 1 << (WLC_E_REASSOC % 8);
/*	hdl->event_mask[WLC_E_SCAN_COMPLETE/8] |= 1 << (WLC_E_SCAN_COMPLETE % 8); */
	hdl->event_mask[WLC_E_EAPOL_MSG/8] |= 1 << (WLC_E_EAPOL_MSG % 8);
	hdl->event_mask[WLC_E_JOIN_START/8] |= 1 << (WLC_E_JOIN_START % 8);
	hdl->event_mask[WLC_E_ASSOC/8] |= 1 << (WLC_E_ASSOC % 8);
	hdl->event_mask[WLC_E_REASSOC/8] |= 1 << (WLC_E_REASSOC % 8);
	hdl->event_mask[WLC_E_ASSOC_IND/8] |= 1 << (WLC_E_ASSOC_IND % 8);

	hdl->event_mask[WLC_E_ASSOC_REQ_IE/8] |= 1 << (WLC_E_ASSOC_REQ_IE % 8);
	hdl->event_mask[WLC_E_ASSOC_RESP_IE/8] |= 1 << (WLC_E_ASSOC_RESP_IE % 8);

	hdl->event_mask[WLC_E_DISASSOC_IND/8] |= 1 << (WLC_E_DISASSOC_IND % 8);
					/* Needed by SoftAP to detect STA assoc/disassoc */
	hdl->event_mask[WLC_E_LINK/8] |= 1 << (WLC_E_LINK % 8);
					/* Needed by STA to detect AP disappeared */

	hdl->event_mask[WLC_E_PSK_SUP/8] |= 1 << (WLC_E_PSK_SUP % 8);
					/* Needed to detect wpa2-psk connection complete */
	hdl->event_mask[WLC_E_IF/8] |= 1 << (WLC_E_IF % 8);
					/* Needed for APSTA mode to work with DHD */
	hdl->event_mask[WLC_E_DEAUTH_IND/8] |= 1 << (WLC_E_DEAUTH_IND % 8);
					/* TEMP: debug */
	hdl->event_mask[WLC_E_ESCAN_RESULT/8] |= 1 << (WLC_E_ESCAN_RESULT % 8);
					/* Needed for escan */
	hdl->event_mask[WLC_E_ACTION_FRAME_RX/8] |=
		1 << (WLC_E_ACTION_FRAME_RX % 8);
					/* Needed for GON - action frame rx indication */
	hdl->event_mask[WLC_E_ACTION_FRAME_COMPLETE/8] |=
		1 << (WLC_E_ACTION_FRAME_COMPLETE% 8);
					/* Needed for GON - action frame tx complete */
	hdl->event_mask[WLC_E_ACTION_FRAME_OFF_CHAN_COMPLETE/8] |=
		1 << (WLC_E_ACTION_FRAME_OFF_CHAN_COMPLETE% 8);
					/* Needed for GON - action frame tx complete */

#if P2PAPI_ENABLE_WPS
	/* This is needed for WPSCLI to detect WPS PBC overlap */
	if (!hdl->disable_pbc_overlap) {
		hdl->event_mask[WLC_E_PROBREQ_MSG/8] |= 1 << (WLC_E_PROBREQ_MSG % 8);
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_init_driver_event_masks: enab WLC_E_PROBREQ_MSG\n"));
	} else {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_init_driver_event_masks: no WLC_E_PROBREQ_MSG\n"));
	}
#endif /* P2PAPI_ENABLE_WPS */


	/* Create a copy of the event mask that adds WLC_E_PROBREQ_MSG for the
	 * GO negotiation channel synchronization procedure.
	 */
	memcpy(hdl->event_mask_prb, hdl->event_mask, sizeof(hdl->event_mask));
	hdl->event_mask_prb[WLC_E_P2P_PROBREQ_MSG/8] |=
		1 << (WLC_E_P2P_PROBREQ_MSG % 8);
}

/* Restore original event mask */
void
p2papi_deinit_driver_event_masks(p2papi_instance_t *hdl)
{
	(void) p2pwlu_set_event_mask(hdl, hdl->orig_event_mask,
		sizeof(hdl->orig_event_mask));
}

/* Enable the reception of selected WLC_E_* driver events needed by
 * p2papi_process_raw_rx_frame()
 */
int
p2papi_enable_driver_events(p2papi_instance_t *hdl, bool enab_probe_req)
{
	int err;
	uint8 *event_mask;

	P2PAPI_CHECK_P2PHDL(hdl);

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_enable_driver_events: enab_prob_req=%u\n", enab_probe_req));
	event_mask = enab_probe_req ? hdl->event_mask_prb : hdl->event_mask;

	err = p2pwlu_set_event_mask(hdl, event_mask, WL_EVENTING_MASK_LEN);

	if (err != 0) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_enable_driver_events failed!\n"));
	}
	return err;
}
