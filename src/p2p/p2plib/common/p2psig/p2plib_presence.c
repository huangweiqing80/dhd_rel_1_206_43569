/*
 * P2P Library API - Group-Owner-Negotiation-related functions (OS-independent)
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: p2plib_presence.c,v 1.8 2011-01-07 02:30:17 $
 */

#ifndef SOFTAP_ONLY
/* ---- Include Files ---------------------------------------------------- */

#include <stdlib.h>
#include <ctype.h>

#include "p2plib_api.h"
#include "p2plib_int.h"


/* ---- Public Variables ------------------------------------------------- */
/* ---- Private Constants and Types -------------------------------------- */
/* ---- Private Variables ------------------------------------------------ */
/* ---- Private Function Prototypes -------------------------------------- */

static int
p2plib_send_presence_frame(p2papi_instance_t* hdl, bool do_chan_sync,
	struct ether_addr *dst_ea, BCMP2P_CHANNEL *dst_listen_channel,
	uint8 dialog_token,	uint8 frame_type, wifi_p2p_ie_t *p2p_ie,
	uint16 p2p_ie_len, char* dbg_caller_name);

static int
p2plib_tx_presence_req_frame(p2papi_instance_t* hdl,
	struct ether_addr *dst_ea, BCMP2P_CHANNEL *channel,
	uint8 dialog_token,	uint8 index, BCMP2P_BOOL oppps, uint8 ctwindow,
	uint8 num_noa_desc, wifi_p2p_noa_desc_t *noa_desc);

static int
p2plib_tx_presence_rsp_frame(p2papi_instance_t* hdl,
	struct ether_addr *dst_ea, BCMP2P_CHANNEL *channel, uint8 dialog_token,
	uint8 status, uint8 index, BCMP2P_BOOL oppps, uint8 ctwindow,
	uint8 num_noa_desc, wifi_p2p_noa_desc_t *noa_desc);


/* ---- Functions -------------------------------------------------------- */

/* Callback function called when a P2P presence action frame tx completes. */
static void
p2papi_presence_tx_done_cb(void *handle, p2papi_aftx_instance_t *aftx_hdl,
	BCMP2P_BOOL acked, wl_af_params_t *af_params)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*)handle;

	P2PLIB_ASSERT(P2PAPI_CHECK_P2PHDL(hdl));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_presence_tx_done_cb: acked=%d aftx_hdl=%p,%p\n",
		acked, aftx_hdl, hdl->presence_aftx_hdl));

	/* Do the generic AF tx complete actions */
	p2papi_aftx_complete_callback_core(handle, aftx_hdl, acked, af_params);
	hdl->presence_aftx_hdl = NULL;
}

static int
p2plib_send_presence_frame(p2papi_instance_t* hdl, bool do_chan_sync,
	struct ether_addr *dst_ea, BCMP2P_CHANNEL *dst_listen_channel,
	uint8 dialog_token, uint8 frame_type, wifi_p2p_ie_t *p2p_ie,
	uint16 p2p_ie_len, char* dbg_caller_name)
{
	wl_af_params_t *af_params;
	int status = -1;

	if (p2p_ie == NULL) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "%s: no P2P IE\n", dbg_caller_name));
		return status;
	}
	if (hdl->presence_aftx_hdl != NULL) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"%s: Nested af tx!\n", dbg_caller_name));
	}
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
	   "%s: dt=%u txch=%d:%d ielen=%u dst=%02x:%02x:%02x:%02x:%02x:%02x\n",
		dbg_caller_name, dialog_token, dst_listen_channel->channel_class,
		dst_listen_channel->channel, p2p_ie_len,
		dst_ea->octet[0], dst_ea->octet[1], dst_ea->octet[2],
		dst_ea->octet[3], dst_ea->octet[4], dst_ea->octet[5]));
	p2papi_log_hexdata(BCMP2P_LOG_INFO, dbg_caller_name, (uint8*)p2p_ie,
		p2p_ie_len);

	af_params = p2plib_build_p2p_act_frm(hdl, dst_ea, (uint8*) P2P_OUI,
		P2P_VER, frame_type, dialog_token, (uint8*)p2p_ie, p2p_ie_len,
		NULL, 0, NULL, 0, dst_listen_channel, P2PAPI_AF_DWELL_TIME);
	if (af_params) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		   "%s: AF len=%u\n", dbg_caller_name, af_params->action_frame.len));
		{
			/* Send the action frame immediately.  The target device must be in
			 * Listen state.
			 */
			hdl->presence_aftx_hdl = p2papi_aftx_send_frame(hdl, af_params,
				hdl->bssidx[P2PAPI_BSSCFG_CONNECTION], hdl->af_tx_max_retries,
				hdl->af_tx_retry_ms, p2papi_presence_tx_done_cb, (void*)hdl,
				"presence");
			P2PLIB_ASSERT(hdl->presence_aftx_hdl != NULL);
		}
	}

	return status;
}

static int
p2plib_tx_presence_req_frame(p2papi_instance_t* hdl,
	struct ether_addr *dst_ea, BCMP2P_CHANNEL *channel, uint8 dialog_token,
	uint8 index, BCMP2P_BOOL oppps, uint8 ctwindow,
	uint8 num_noa_desc, wifi_p2p_noa_desc_t *noa_desc)
{
	wifi_p2p_ie_t *p2p_ie;
	uint16 p2p_ie_len = 0;
	int ret = -1;

	p2p_ie = (wifi_p2p_ie_t*) P2PAPI_MALLOC(WL_WIFI_ACTION_FRAME_SIZE);
	if (p2p_ie) {
		p2papi_encode_presence_req_p2p_ie(hdl,
			index, oppps, ctwindow, num_noa_desc, noa_desc,
			p2p_ie, &p2p_ie_len);
		ret = p2plib_send_presence_frame(hdl, FALSE, dst_ea, channel,
			dialog_token, P2P_AF_PRESENCE_REQ, p2p_ie, p2p_ie_len,
			"p2plib_tx_presence_req_frame");
		P2PAPI_FREE(p2p_ie);
	}

	return ret;
}

static int
p2plib_tx_presence_rsp_frame(p2papi_instance_t* hdl,
	struct ether_addr *dst_ea, BCMP2P_CHANNEL *channel, uint8 dialog_token,
	uint8 status, uint8 index, BCMP2P_BOOL oppps, uint8 ctwindow,
	uint8 num_noa_desc, wifi_p2p_noa_desc_t *noa_desc)
{
	wifi_p2p_ie_t *p2p_ie;
	uint16 p2p_ie_len = 0;
	int ret = -1;

	p2p_ie = (wifi_p2p_ie_t*) P2PAPI_MALLOC(WL_WIFI_ACTION_FRAME_SIZE);
	if (p2p_ie) {
		p2papi_encode_presence_rsp_p2p_ie(hdl, status,
			index, oppps, ctwindow, num_noa_desc, noa_desc,
			p2p_ie, &p2p_ie_len);
		ret = p2plib_send_presence_frame(hdl, FALSE, dst_ea, channel,
			dialog_token, P2P_AF_PRESENCE_RSP, p2p_ie, p2p_ie_len,
			"p2plib_tx_presence_rsp_frame");
		P2PAPI_FREE(p2p_ie);
	}
	return ret;
}

/* Process a received Presence Request action frame at a GO */
int
p2papi_rx_presence_req_frame(p2papi_instance_t* hdl,
	struct ether_addr *src_mac, wifi_p2p_action_frame_t *act_frm,
	uint32 act_frm_len, BCMP2P_CHANNEL *channel)
{
	uint32 ie_len = act_frm_len - P2P_AF_FIXED_LEN;
	p2papi_p2p_ie_t p2p_ie;
	p2papi_wps_ie_t wps_ie;
	bool curr_ops_enable = FALSE;
	uint8 curr_ops_ctwindow = 0;
	int curr_num_desc = 0;
	wl_p2p_sched_t curr_noa;
	wl_p2p_sched_desc_t *curr_desc = &curr_noa.desc[0];
	wl_p2p_sched_desc_t merge_desc;
	int merge_num_desc = 0;
	int resp_num_desc = 0;
	wifi_p2p_noa_desc_t noa_resp_desc;
	uint8 noa_resp_status = P2P_STATSE_SUCCESS;
	int ret;

	P2PAPI_CHECK_P2PHDL(hdl);
	if (!P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl))
		return -1;

	if (!hdl->enable_p2p) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_rx_presence_req_frame: ignored, P2P not enabled\n"));
		return -1;
	}

	memset(&merge_desc, 0, sizeof(merge_desc));
	memset(&noa_resp_desc, 0, sizeof(noa_resp_desc));

	/* decode IEs */
	(void) p2papi_decode_p2pwps_ies(act_frm->elts, ie_len, &p2p_ie, &wps_ie);

	/* update notification params */
	hdl->presence.notify_params.status = P2P_STATSE_SUCCESS;

	/* notification to the app */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_rx_presence_req_frame: delivering BCMP2P_NOTIF_P2P_PRESENCE_REQ to app\n"));
	p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_PRESENCE,
		BCMP2P_NOTIF_P2P_PRESENCE_REQ);

	/* get the current opportunistic power save and noa schedule */
	p2pwlu_get_ops(hdl, &curr_ops_enable, &curr_ops_ctwindow);
	p2pwlu_get_noa(hdl, &curr_noa.type,	&curr_noa.action, &curr_noa.option,
		1, &curr_num_desc, curr_desc);

	/* attempt to merge if there is a current schedule */
	if (curr_num_desc > 0) {
		int noa_ie_len = p2papi_decode_p2p_ie_length(p2p_ie.noa_subelt.len);
		int i;
		wifi_p2p_noa_desc_t *preferred = 0, *acceptable = 0;
		wifi_p2p_noa_desc_t *ordered_req[P2P_NOA_SE_MAX_DESC] = {0, 0};

		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"current NoA duration=%d interval=%d start=%d count=%d\n",
			curr_desc->duration, curr_desc->interval,
			curr_desc->start, curr_desc->count));

		/* not success until merged and plumbed */
		noa_resp_status = P2P_STATSE_FAIL_UNABLE_TO_ACCOM;

		/* find preferred and acceptable desc */
		for (i = 0; i < P2P_NOA_SE_MAX_DESC; i++) {
			wifi_p2p_noa_desc_t *req;

			/* check ie length */
			if (noa_ie_len < (int)(2 + (i + 1) * sizeof(wifi_p2p_noa_desc_t)))
				break;

			req = &p2p_ie.noa_subelt.desc[i];

			if (req->cnt_type == P2P_NOA_DESC_TYPE_PREFERRED)
				preferred = req;
			else if (req->cnt_type == P2P_NOA_DESC_TYPE_ACCEPTABLE)
				acceptable = req;
		}

		/* sort preferred then acceptable if present */
		i = 0;
		if (preferred)
			ordered_req[i++] = preferred;
		if (acceptable)
			ordered_req[i++] = acceptable;

		/* attempt to merge preferred then acceptable presence request */
		for (i = 0; i < P2P_NOA_SE_MAX_DESC; i++) {
			wifi_p2p_noa_desc_t *req = ordered_req[i];
			uint32 duration = 0;
			uint32 interval;

			if (req == 0)
				break;

			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"presence req duration=%d interval=%d\n",
				req->duration, req->interval));

			/* merge wrt to current interval */
			interval = curr_desc->interval;

			/* intervals must be non-zero */
			if (interval == 0 || req->interval == 0)
				continue;

			/* duration must be less than interval */
			if (req->duration > req->interval)
				continue;

			/* intervals are the same */
			if (interval == req->interval) {
				/* convert presence to absence duration */
				duration = interval - req->duration;
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"interval same, duration=%d\n",
					duration));
			}
			/* interval is a multiple of pref interval */
			else if ((interval % req->interval) == 0) {
				/* convert presence to absence duration */
				duration = interval -
					(req->duration * (interval / req->interval));
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"interval multiple of pref, duration=%d\n",
					duration));
			}
			/* pref is a multiple of current interval */
			else if ((req->interval % interval) == 0) {
				/* convert presence to absence duration */
				duration = interval -
					(req->duration / (req->interval / interval));
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"pref multiple of interval, duration=%d\n",
					duration));
			}
			else {
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"p2papi_rx_presence_req_frame: not able to merge\n"));
				continue;
			}

			/* new absence must be less than current */
			if (duration < curr_desc->duration) {
				/* update new schedule */
				merge_num_desc = 1;
				merge_desc.start = curr_desc->start;	/* use current start */
				merge_desc.interval = interval;
				merge_desc.duration = duration;
				merge_desc.count = curr_desc->count;	/* use current count */
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"merge duration=%d interval=%d start=%d count=%d\n",
					merge_desc.duration, merge_desc.interval,
					merge_desc.start, merge_desc.count));
				break;
			}
			else {
				/* requested presence is less than current absence schedule */
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"current NoA unchanged\n"));
				noa_resp_status = P2P_STATSE_SUCCESS;
				break;
			}
		}
	}

	if (merge_num_desc > 0) {
		/* plumb driver with new schedule */
		ret = p2pwlu_set_noa(hdl, WL_P2P_SCHED_TYPE_ABS,
			WL_P2P_SCHED_ACTION_DOZE, WL_P2P_SCHED_OPTION_NORMAL,
			1, &merge_desc);
		if (ret == 0) {
			uint8 type, action, option;
			int num_desc = 0;
			wl_p2p_sched_desc_t desc;

			/* read back to get start time and count */
			p2pwlu_get_noa(hdl, &type,	&action, &option, 1, &num_desc, &desc);
			if (num_desc == 1) {
				if (merge_desc.duration != desc.duration)
					BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
						"read back duration doesn't match %d %d\n",
						merge_desc.duration, desc.duration));
				if (merge_desc.interval != desc.interval)
					BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
						"read back interval doesn't match %d %d\n",
						merge_desc.interval, desc.interval));

				/* update start time and count */
				merge_desc.start = desc.start;
				merge_desc.count = desc.count;

				noa_resp_status = P2P_STATSE_SUCCESS;
			}
		}
	}

	/* successful merge or no merge required (i.e. no current schedule) */
	if (noa_resp_status == P2P_STATSE_SUCCESS) {
		/* respond with new schedule if available */
		if (merge_num_desc > 0) {
			resp_num_desc = 1;
			noa_resp_desc.cnt_type = merge_desc.count;
			noa_resp_desc.duration = merge_desc.duration;
			noa_resp_desc.interval = merge_desc.interval;
			noa_resp_desc.start = merge_desc.start;
		}
	}
	/* fail - unable to accommodate */
	else {
		/* respond with current schedule if available */
		if (curr_num_desc > 0) {
			resp_num_desc = 1;
			noa_resp_desc.cnt_type = curr_desc->count;
			noa_resp_desc.duration = curr_desc->duration;
			noa_resp_desc.interval = curr_desc->interval;
			noa_resp_desc.start = curr_desc->start;
		}
	}

	if (resp_num_desc == 1)
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"response NoA duration=%d interval=%d start=%d count=%d\n",
			noa_resp_desc.duration, noa_resp_desc.interval,
			noa_resp_desc.start, noa_resp_desc.cnt_type));

	p2plib_tx_presence_rsp_frame(hdl, src_mac, channel, act_frm->dialog_token,
		noa_resp_status, 0, curr_ops_enable, curr_ops_ctwindow,
		resp_num_desc, &noa_resp_desc);

	return 0;
}

/* Process a received Presence Response action frame at a GC */
int
p2papi_rx_presence_rsp_frame(p2papi_instance_t* hdl,
	struct ether_addr *src_mac, wifi_p2p_action_frame_t *act_frm,
	uint32 act_frm_len, BCMP2P_CHANNEL *channel)
{
	uint32 ie_len = act_frm_len - P2P_AF_FIXED_LEN;
	p2papi_p2p_ie_t p2p_ie;
	p2papi_wps_ie_t wps_ie;
	int ret = 0;

	P2PAPI_CHECK_P2PHDL(hdl);
	if (!P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl))
		return -1;

	if (!hdl->enable_p2p) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_rx_presence_rsp_frame: ignored, P2P not enabled\n"));
		return -1;
	}

	if (act_frm->dialog_token != hdl->presence.dialog_token) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_rx_presence_rsp_frame: ignored, dialog token mismatch\n"));
		return -1;
	}

	if (hdl->presence_aftx_hdl != NULL) {
		p2papi_aftx_cancel_send(hdl->presence_aftx_hdl);
		hdl->presence_aftx_hdl = NULL;
	}

	/* decode IEs */
	(void) p2papi_decode_p2pwps_ies(act_frm->elts, ie_len, &p2p_ie, &wps_ie);

	if (p2papi_decode_p2p_ie_length(p2p_ie.status_subelt.len) == 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_rx_presence_rsp_frame: ignored, no status attribute\n"));
		return -1;
	}

	/* update notification params */
	hdl->presence.notify_params.status = p2p_ie.status_subelt.status;

	/* notification to the app */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_rx_presence_rsp_frame: delivering BCMP2P_NOTIF_P2P_PRESENCE_RSP to app\n"));
	p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_PRESENCE,
		BCMP2P_NOTIF_P2P_PRESENCE_RSP);

	return ret;
}

/* Send a Presence Request action frame from a GC to a connected GO */
int p2papi_presence_request(p2papi_instance_t* hdl,
	bool isPreferred, uint32 preferredDuration, uint32 preferredInterval,
	bool isAcceptable, uint32 acceptableDuration, uint32 acceptableInterval)
{
	int num_noa_desc;
	wifi_p2p_noa_desc_t noa_desc[2];

	/* group owner cannot send presence request */
	if (hdl->is_p2p_group)
		return -1;

	/* must be connected */
	if (!hdl->is_connected)
		return -1;

	/* generate dialog token */
	hdl->presence.dialog_token =
		p2papi_create_dialog_token(hdl->presence.dialog_token);

	num_noa_desc = 0;
	memset(noa_desc, 0, 2 * sizeof(wifi_p2p_noa_desc_t));

	/* update preferred duration/interval */
	if (isPreferred) {
		noa_desc[num_noa_desc].cnt_type = P2P_NOA_DESC_TYPE_PREFERRED;
		noa_desc[num_noa_desc].duration = preferredDuration;
		noa_desc[num_noa_desc].interval = preferredInterval;
		num_noa_desc++;
	}

	/* updated acceptable duration/interval */
	if (isAcceptable) {
		noa_desc[num_noa_desc].cnt_type = P2P_NOA_DESC_TYPE_ACCEPTABLE;
		noa_desc[num_noa_desc].duration = acceptableDuration;
		noa_desc[num_noa_desc].interval = acceptableInterval;
		num_noa_desc++;
	}

	p2plib_tx_presence_req_frame(hdl, &hdl->peer_int_addr, &hdl->op_channel,
		hdl->presence.dialog_token, 0, FALSE, 0, num_noa_desc, noa_desc);

	return 0;
}
#endif /* SOFTAP_ONLY */
