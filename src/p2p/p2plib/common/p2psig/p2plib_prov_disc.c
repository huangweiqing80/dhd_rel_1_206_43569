/*
 * P2P Library API - Provision discovery functions.
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: p2plib_prov_disc.c,v 1.21 2011-01-25 04:27:01 $
 */

#ifndef SOFTAP_ONLY
/* ---- Include Files ---------------------------------------------------- */

#include <stdlib.h>
#include <ctype.h>

/* P2P Library include files */
#include "p2plib_api.h"
#include "p2plib_int.h"


/* ---- Public Variables ------------------------------------------------- */
/* ---- Private Constants and Types -------------------------------------- */
/* ---- Private Variables ------------------------------------------------ */
/* ---- Private Function Prototypes -------------------------------------- */


/* ---- Functions -------------------------------------------------------- */


/* Callback function called when a ProvDisReq action frame tx completes */
static void
p2papi_provdis_req_tx_done_cb(void *handle, p2papi_aftx_instance_t *aftx_hdl,
	BCMP2P_BOOL acked, wl_af_params_t *af_params)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*)handle;
	P2PLIB_ASSERT(P2PAPI_CHECK_P2PHDL(hdl));

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_provdis_req_tx_done_cb: acked=%d aftx_hdl=%p,%p\n",
		acked, aftx_hdl, hdl->provdis_aftx_hdl));

	p2papi_aftx_complete_callback_core(handle, aftx_hdl, acked, af_params);
	hdl->provdis_aftx_hdl = NULL;
}

/* Callback function called when a ProvDisRsp action frame tx completes */
static void
p2papi_provdis_rsp_tx_done_cb(void *handle, p2papi_aftx_instance_t *aftx_hdl,
	BCMP2P_BOOL acked, wl_af_params_t *af_params)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*)handle;
	P2PLIB_ASSERT(P2PAPI_CHECK_P2PHDL(hdl));

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_provdis_rsp_tx_done_cb: acked=%d aftx_hdl=%p,%p\n",
		acked, aftx_hdl, hdl->provdis_aftx_hdl));

	/* Do the generic AF tx complete actions */
	p2papi_aftx_complete_callback_core(handle, aftx_hdl, acked, af_params);
	hdl->provdis_aftx_hdl = NULL;

	/* resume discovery */
	if (hdl->is_discovering) {
		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
			"p2papi_send_provdis_rsp: p2papi_discover_enable_search(true)\n"));
		p2papi_discover_enable_search(hdl, TRUE);
	}
}

/* Create and send a Provision Discovery Request/Response P2P public action
 * frame.
 */
static int
p2plib_send_provdis_frame(p2papi_instance_t* hdl, struct ether_addr *dst_ea,
	uint8 frame_type, uint16 config_methods,
	uint8 *ssid, int ssid_len, BCMP2P_CHANNEL *channel,
	uint8 dialog_token,	bool send_immed, int32 dwell_time_ms,
	BCMP2P_AFTX_CALLBACK aftx_result_cb_func)
{
	int ret = BCME_ERROR;
	wifi_p2p_ie_t *p2p_ie;
	uint16 p2p_ie_len = 0;
	p2papi_p2p_ie_enc_t *wps_ie;
	uint16 wps_ie_len = 0;
	int bssidx;
	wl_af_params_t *af_params;

	p2p_ie = (wifi_p2p_ie_t*) P2PAPI_MALLOC(WL_WIFI_ACTION_FRAME_SIZE);
	if (frame_type == P2P_PAF_PROVDIS_REQ) {
		p2papi_encode_provdis_p2p_ie(hdl, hdl->p2p_dev_addr.octet,
			hdl->fname_ssid, hdl->fname_ssid_len, ssid, ssid_len,
			dst_ea->octet, p2p_ie, &p2p_ie_len);
	}

	wps_ie = (p2papi_p2p_ie_enc_t*) P2PAPI_MALLOC(sizeof(*wps_ie));
	p2papi_encode_provdis_wps_ie(hdl, wps_ie, hdl->fname_ssid, hdl->fname_ssid_len,
		TRUE, config_methods, &wps_ie_len);

	/* CUSTOM_IE: Attach custom IE to provision discovery action frame */
	if (frame_type == P2P_PAF_PROVDIS_REQ)
		af_params = p2plib_build_p2p_pub_act_frm(hdl, dst_ea,
			(uint8*) P2P_OUI, P2P_VER, frame_type, dialog_token,
			(uint8*)p2p_ie, p2p_ie_len, (uint8*)&wps_ie->id, wps_ie_len,
			(uint8*)hdl->custom_acf_ie[BCMP2P_ACF_IE_FLAG_PDREQ].ie_buf,
			hdl->custom_acf_ie[BCMP2P_ACF_IE_FLAG_PDREQ].ie_buf_len,
			channel, dwell_time_ms);
	else if (frame_type == P2P_PAF_PROVDIS_RSP)
		af_params = p2plib_build_p2p_pub_act_frm(hdl, dst_ea,
			(uint8*) P2P_OUI, P2P_VER, frame_type, dialog_token,
			(uint8*)p2p_ie, p2p_ie_len, (uint8*)&wps_ie->id, wps_ie_len,
			(uint8*)hdl->custom_acf_ie[BCMP2P_ACF_IE_FLAG_PDRSP].ie_buf,
			hdl->custom_acf_ie[BCMP2P_ACF_IE_FLAG_PDRSP].ie_buf_len,
			channel, dwell_time_ms);

	P2PAPI_FREE(p2p_ie);
	P2PAPI_FREE(wps_ie);

	if (af_params == NULL) {
		return BCME_ERROR;
	}

	if (hdl->provdis_aftx_hdl != NULL) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2plib_send_provdis_frame: Nested af tx!\n"));
		return BCME_ERROR;	/* ignore to avoid confusion */
	}
	if (send_immed) {
		/* Send the frame immediately */
		bssidx = hdl->bssidx[P2PAPI_BSSCFG_DEVICE];

		/* in the case that P2P Interface Address is the same as the P2P Device Address, */
		/* caller may fail to create a discovery-bsscfg if device is connected (as GO) */
		/* To allow sending PD-request if 'discovery-bsscfg' is not created, */
		/* use a default-bssidx from OSL */
		if (bssidx == 0)	/* not in 'discovery' mode */
		{
			bssidx = hdl->default_bsscfg_idx;
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2plib_send_provdis_frame:no disc-bsscfg,use default bssidx=%d\n",
				bssidx));
		}
		else
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2plib_send_provdis_frame: via disc-bsscfg idx=%d\n", bssidx));

		hdl->provdis_aftx_hdl = p2papi_aftx_send_frame(hdl, af_params,
			bssidx, hdl->af_tx_max_retries, hdl->af_tx_retry_ms,
			aftx_result_cb_func, (void*)hdl, "provdis");
		P2PLIB_ASSERT(hdl->provdis_aftx_hdl != NULL);
		if (hdl->provdis_aftx_hdl != NULL)
			ret = BCME_OK;
	} else {
		/* Send the frame after arriving on a common channel with the peer */
		memcpy(&hdl->peer_dev_addr, dst_ea, sizeof(hdl->peer_dev_addr));
		ret = p2papi_send_at_common_channel(hdl, channel, af_params,
			aftx_result_cb_func, BCMP2P_TRUE, &hdl->provdis_aftx_hdl,
			"provdis");
	}

	return ret;
}

/*
 * Wait for receiving a Provision Discovery Response frame
 * use_signal: set to 1 to use 'signal', otherwise use 'polling'
 */
static void
wait_for_rx_provdis_response(p2papi_instance_t* hdl, bool use_signal)
{
	int total_delay_ms;
	int delay_interval_ms;

	if (use_signal)
	{
		/* use signal mechanism, wait for response or timeout */
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"wait_for_rx_provdis_response: waiting for PD rsp signal (timeout=%d ms)\n",
			hdl->provdis_retry_delay_ms));

		p2papi_osl_wait_for_rx_provdis_response(hdl, hdl->provdis_retry_delay_ms);
	}
	else
	{
		/* use polling */
		total_delay_ms = hdl->provdis_retry_delay_ms;
		delay_interval_ms = 100;		/* in milliseconds */
		while (total_delay_ms > 0)
		{
			/* If a response was received, exit the loop */
			if (hdl->pd.response_received) {
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"wait_for_rx_provdis_response: received PD rsp\n"));
				break;
			}

			/* Do a sleep to wait for response */
			if (delay_interval_ms > total_delay_ms)
				delay_interval_ms = total_delay_ms;
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"wait_for_rx_provdis_response: waiting for PD rsp (sleep %d ms)\n",
				delay_interval_ms));
			p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_GENERIC,
				delay_interval_ms);

			total_delay_ms -= delay_interval_ms;
		}
	}

	return;
}

/* send a provision discovery request */
BCMP2P_STATUS
p2papi_send_provdis_req(p2papi_instance_t* hdl,	BCMP2P_UINT32 configMethods,
	BCMP2P_BOOL isPeerGo, uint8 *ssid, int ssid_len,
	BCMP2P_CHANNEL *channel, struct ether_addr *peerMac)
{
	uint8 req_dialog_token;
	int i, bssidx;
	bool send_immed = FALSE;
	bool do_create_tmp_discover_bsscfg = false;
	bool use_signal = false; /* default: use polling */

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	/* Do not do channel sync if the target is a GO */
	if (isPeerGo)
		send_immed = TRUE;

	/* don't reset the dialog token */
	req_dialog_token = hdl->pd.req_dialog_token;

	/* Set up the data to put in the provdis request frame */
	memset(&hdl->pd, 0, sizeof(hdl->pd));
	hdl->pd.req_dialog_token = req_dialog_token;
	hdl->pd.config_methods = configMethods;
	if (isPeerGo) {
		memcpy(hdl->pd.ssid, ssid, ssid_len);
		hdl->pd.ssid_len = ssid_len;
	}
	memcpy(&hdl->pd.channel, channel, sizeof(hdl->pd.channel));
	memcpy(hdl->pd.peer_mac.octet, peerMac,
		sizeof(hdl->pd.peer_mac.octet));

	hdl->pd.response_received = FALSE;

	/* if discovery-bsscfg does not exist, create a temp discovery-bsscfg to allow */
	/* sending 'prov-discovery' request action frame using device's P2P device address */
	/* as a 'source' */
	bssidx = hdl->bssidx[P2PAPI_BSSCFG_DEVICE];
	if (!hdl->is_p2p_discovery_on || (bssidx == 0)) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_send_provdis_req:cr a disc-bss for AF tx(ig if err,bssidx=%d)\n",
			bssidx));
		p2papi_enable_discovery(hdl);
		do_create_tmp_discover_bsscfg = true;
		if (bssidx == 0) /* wait till disc-bsscfg is up (i.e. rx WLC_E_IF) */
			p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_GENERIC, 100);
	}

	/* suspend discovery */
	if (hdl->is_discovering) {
		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
			"p2papi_send_provdis_req:p2papi_discover_enable_search(false)\n"));
		p2papi_discover_enable_search(hdl, FALSE);
	}

	/* Send the PD request to the target peer and wait for a response.
	 * If no response is received from the peer, retry up to N times D ms apart.
	 * N and D are selected to ensure the frame can be received by the target
	 * even if the target is a GO running cycling in and out of power save.
	 */
	for (i = 0; i < hdl->max_provdis_retries; i++) {
		hdl->pd.req_dialog_token =
			p2papi_create_dialog_token(hdl->pd.req_dialog_token);

		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_send_provdis_req: ch=%d:%d immed=%u tok=%u attempt %d\n",
			hdl->pd.channel.channel_class, hdl->pd.channel.channel,
			send_immed, hdl->pd.req_dialog_token, i + 1));

		/* Clear the duplicate rx action frame detection history */
		p2papi_clear_duplicate_rx_actframe_detect(hdl);

		/* reset the signal if available */
		if (p2papi_osl_signal_provdis_state(hdl, P2PAPI_OSL_PROVDIS_STATE_TX_REQUEST_START)
			== BCMP2P_SUCCESS)
			use_signal = true;

		/* Send request */
		(void) p2plib_send_provdis_frame(hdl, &hdl->pd.peer_mac,
			P2P_PAF_PROVDIS_REQ, hdl->pd.config_methods,
			hdl->pd.ssid, hdl->pd.ssid_len,
			&hdl->pd.channel, hdl->pd.req_dialog_token,
			send_immed, hdl->provdis_resp_wait_ms,
			p2papi_provdis_req_tx_done_cb);

		/* wait for response or timeout */
		wait_for_rx_provdis_response(hdl, use_signal);

		/* If a response was received, exit the loop */
		if (hdl->pd.response_received) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_send_provdis_req: received PD rsp\n"));
			break;
		}
	}

	/* resume discovery */
	if (hdl->is_discovering) {
		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
			"p2papi_send_provdis_req:p2papi_discover_enable_search(true)\n"));
		p2papi_discover_enable_search(hdl, TRUE);
	}

	/* clean up the temp discovery bsscfg */
	if (do_create_tmp_discover_bsscfg == true) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_send_provdis_req: delete a temp discovery bsscfg for AF tx\n"));
			p2papi_disable_discovery(hdl);
	}

	if (hdl->pd.response_received) {
		/* A response was received */
		return BCMP2P_SUCCESS;
	} else {
		/* No response was received */
		p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_PROVISION_DISCOVERY,
			BCMP2P_NOTIF_PROVISION_DISCOVERY_TIMEOUT);
		return BCMP2P_ERROR;
	}
}

/* Send a Provision Discovery response to accept or reject a previously
 * received PD request.
 */
BCMP2P_STATUS
p2papi_send_provdis_rsp(p2papi_instance_t* hdl, BCMP2P_UINT32 configMethods)
{
	int ret, bssidx;
	bool send_immed = TRUE; 	/* response sent back immediately */
	bool do_create_tmp_discover_bsscfg = false;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	/* if discovery-bsscfg does not exist, create a temp discovery-bsscfg to allow */
	/* sending 'prov-discovery' request action frame using device's P2P device address */
	/* as a 'source' */
	bssidx = hdl->bssidx[P2PAPI_BSSCFG_DEVICE];
	if (!hdl->is_p2p_discovery_on || (bssidx == 0)) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_send_provdis_rsp:create a disc-bsscfg for AF tx(ingore if err)\n"));
		p2papi_enable_discovery(hdl);
		do_create_tmp_discover_bsscfg = true;

		/* suspend discovery */
		p2papi_discover_enable_search(hdl, FALSE);
	}

	if (configMethods == BCMP2P_WPS_KEYPAD)
		hdl->wps_device_pwd_id = BCMP2P_WPS_REG_SPEC;
	else if (configMethods == BCMP2P_WPS_DISPLAY)
		hdl->wps_device_pwd_id = BCMP2P_WPS_USER_SPEC;
	else if (configMethods == BCMP2P_WPS_PUSHBUTTON)
		hdl->wps_device_pwd_id = BCMP2P_WPS_PUSH_BTN;
	else
		hdl->wps_device_pwd_id = BCMP2P_WPS_DEFAULT;

	/* Send the PD response to the target peer, retrying up to 10 times
	 * 50ms apart.
	 */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_send_provdis_rsp: ch=%u imm=%u cm=%u tok=%u\n",
		hdl->pd.channel, send_immed, configMethods,
		hdl->pd.rsp_dialog_token));

	ret = p2plib_send_provdis_frame(hdl,
		(struct ether_addr*) &hdl->pd.peer_mac, P2P_PAF_PROVDIS_RSP,
		configMethods, 0, 0, &hdl->pd.channel, hdl->pd.rsp_dialog_token,
		send_immed, 0, p2papi_provdis_rsp_tx_done_cb);

	/* clean up the temp discovery bsscfg */
	if (do_create_tmp_discover_bsscfg == true) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_send_provdis_rsp: delete a temp discovery bsscfg for AF tx\n"));
			p2papi_disable_discovery(hdl);
	}

	/* Clear the duplicate rx action frame detection history */
	p2papi_clear_duplicate_rx_actframe_detect(hdl);

	return (ret == 0) ? BCMP2P_SUCCESS : BCMP2P_ERROR;
}

/* send a provision discovery request on invitation */
BCMP2P_STATUS
p2papi_send_provdis_req_on_invite(p2papi_instance_t* hdl,
	BCMP2P_UINT32 configMethods, uint8 *ssid, int ssid_len,
	BCMP2P_ETHER_ADDR *dstDevAddr, BCMP2P_CHANNEL *channel)
{
	int i;
	bool send_immed = TRUE;
	uint8 old_dialog_token;
	bool use_signal = false; /* default: use polling */

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	/* Set up the data to put in the provdis request frame */
	old_dialog_token = hdl->pd.req_dialog_token;
	memset(&hdl->pd, 0, sizeof(hdl->pd));
	hdl->pd.req_dialog_token = old_dialog_token;
	hdl->pd.config_methods = configMethods;
	if (ssid != 0) {
		memcpy(hdl->pd.ssid, ssid, ssid_len);
		hdl->pd.ssid_len = ssid_len;
	}
	memcpy(&hdl->pd.channel, channel, sizeof(hdl->pd.channel));
	memcpy(hdl->pd.peer_mac.octet, dstDevAddr, sizeof(hdl->pd.peer_mac.octet));

	hdl->pd.response_received = FALSE;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_tx_provdis_req_on_invite: "
		"meth=%d ch=%u dst=%02x:%02x:%02x:%02x:%02x:%02x\n",
		hdl->pd.config_methods, hdl->pd.channel,
		hdl->pd.peer_mac.octet[0], hdl->pd.peer_mac.octet[1],
		hdl->pd.peer_mac.octet[2], hdl->pd.peer_mac.octet[3],
		hdl->pd.peer_mac.octet[4], hdl->pd.peer_mac.octet[5]));

	/* suspend discovery */
	if (hdl->is_discovering) {
		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
			"p2papi_tx_provdis_req_on_invite:call p2papi_discover_enable_search(0)\n"));
		p2papi_discover_enable_search(hdl, FALSE);
	}

	/* Send the PD request to the target peer and wait for a response.
	 * If no response is received from the peer, retry up to N times D ms apart.
	 * N and D are selected to ensure the frame can be received by the target
	 * even if the target is a GO running cycling in and out of power save.
	 */
	for (i = 0; i < hdl->max_provdis_retries; i++) {
		hdl->pd.req_dialog_token =
			p2papi_create_dialog_token(hdl->pd.req_dialog_token);

		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_send_provdis_req_oi: ch=%d:%d immed=%u tok=%u attempt %d\n",
			hdl->pd.channel.channel_class, hdl->pd.channel.channel,
			send_immed, hdl->pd.req_dialog_token, i + 1));

		/* reset the signal if available */
		if (p2papi_osl_signal_provdis_state(hdl, P2PAPI_OSL_PROVDIS_STATE_TX_REQUEST_START)
			== BCMP2P_SUCCESS)
			use_signal = true;

		/* Send request */
		(void) p2plib_send_provdis_frame(hdl, &hdl->pd.peer_mac,
			P2P_PAF_PROVDIS_REQ, hdl->pd.config_methods,
			hdl->pd.ssid, hdl->pd.ssid_len,
			&hdl->pd.channel, hdl->pd.req_dialog_token,
			send_immed, hdl->provdis_resp_wait_ms,
			p2papi_provdis_req_tx_done_cb);

		/* wait for response or timeout */
		wait_for_rx_provdis_response(hdl, use_signal);

		/* If a response was received, exit the loop */
		if (hdl->pd.response_received)
			break;
	}

	/* resume discovery */
	if (hdl->is_discovering) {
		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
			"p2papi_send_provdis_req_oi:call p2papi_discover_enable_search(true)\n"));
		p2papi_discover_enable_search(hdl, TRUE);
	}

	if (hdl->pd.response_received) {
		/* A response was received */
		return BCMP2P_SUCCESS;
	} else {
		/* No response was received */
		p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_PROVISION_DISCOVERY,
			BCMP2P_NOTIF_PROVISION_DISCOVERY_TIMEOUT);
		return BCMP2P_ERROR;
	}
}


/* Process a received Provision Discovery frame */
int
p2papi_rx_provdis_frame(p2papi_instance_t *hdl,	struct ether_addr *src_mac,
	wifi_p2p_pub_act_frame_t *act_frm, uint32 act_frm_len, BCMP2P_CHANNEL *channel)
{
	uint32 ie_len = act_frm_len - P2P_PUB_AF_FIXED_LEN;
	p2papi_p2p_ie_t p2p_ie;
	p2papi_wps_ie_t wps_ie;
	uint16 configMethods;
	BCMP2P_NOTIFICATION_CODE notif = BCMP2P_NOTIF_NONE;
	uint8 old_dialog_token;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_rx_provdis_frame: state=%u, frame: len=%u subtype=%u token=%u\n",
		hdl->conn_state, act_frm_len, act_frm->subtype, act_frm->dialog_token));

	if (p2papi_is_duplicate_rx_frame(hdl, src_mac, act_frm->subtype,
		act_frm->dialog_token)) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"rx_provdis: discarding duplicate rx frame, token=%u\n",
			act_frm->dialog_token));
		return 0;
	}

	(void) p2papi_decode_p2pwps_ies(act_frm->elts, ie_len, &p2p_ie, &wps_ie);
	configMethods = wps_ie.cfg_methods;

	old_dialog_token = hdl->pd.req_dialog_token;
	memset(&hdl->pd, 0, sizeof(hdl->pd));
	hdl->pd.req_dialog_token = old_dialog_token;
	hdl->pd.config_methods = configMethods;
	hdl->pd.rsp_dialog_token = act_frm->dialog_token;
	memcpy(&hdl->pd.channel, channel, sizeof(hdl->pd.channel));
	memcpy(&hdl->pd.peer_mac, src_mac, sizeof(hdl->pd.peer_mac));
	strncpy((char *)hdl->pd.device_name, (char *)p2p_ie.devinfo_name,
		BCMP2P_MAX_SSID_LEN);

	if (act_frm->subtype == P2P_PAF_PROVDIS_REQ) {
		notif = BCMP2P_NOTIF_PROVISION_DISCOVERY_REQUEST;
	} else if (act_frm->subtype == P2P_PAF_PROVDIS_RSP) {
		if (hdl->provdis_aftx_hdl != NULL) {
			p2papi_aftx_cancel_send(hdl->provdis_aftx_hdl);
			hdl->provdis_aftx_hdl = NULL;
		}

		notif = BCMP2P_NOTIF_PROVISION_DISCOVERY_RESPONSE;

		if (configMethods == BCMP2P_WPS_KEYPAD)
			hdl->wps_device_pwd_id = BCMP2P_WPS_REG_SPEC;
		else if (configMethods == BCMP2P_WPS_DISPLAY)
			hdl->wps_device_pwd_id = BCMP2P_WPS_USER_SPEC;
		else if (configMethods == BCMP2P_WPS_PUSHBUTTON)
			hdl->wps_device_pwd_id = BCMP2P_WPS_PUSH_BTN;
		else
			hdl->wps_device_pwd_id = BCMP2P_WPS_DEFAULT;

		hdl->pd.response_received = TRUE;

		/* signal recevied a PD-response */
		p2papi_osl_signal_provdis_state(hdl, P2PAPI_OSL_PROVDIS_STATE_RX_RESPONSE);

	}
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "rx_provdis %s: cm=0x%04x ch=%d:%d lch=%d:%d"
		" src=%02x:%02x:%02x:%02x:%02x:%02x\n",
		act_frm->subtype == P2P_PAF_PROVDIS_REQ ? "req" : "rsp",
		configMethods, channel->channel_class, channel->channel,
		hdl->listen_channel.channel_class, hdl->listen_channel.channel,
		src_mac->octet[0], src_mac->octet[1], src_mac->octet[2],
		src_mac->octet[3], src_mac->octet[4], src_mac->octet[5]));

	p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_PROVISION_DISCOVERY, notif);

	return 0;
}
#endif /* SOFTAP_ONLY */
