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
 * $Id: p2plib_device_disc.c,v 1.7 2011-01-07 02:30:16 $
 */

/* ---- Include Files ---------------------------------------------------- */

#include <stdlib.h>
#include <ctype.h>

#include "p2plib_api.h"
#include "p2plib_int.h"
#include "p2pwl.h"


/* ---- Public Variables ------------------------------------------------- */
/* ---- Private Constants and Types -------------------------------------- */
/* ---- Private Variables ------------------------------------------------ */
/* ---- Private Function Prototypes -------------------------------------- */
static int
p2plib_send_go_discb_frame(p2papi_instance_t* hdl, int bssidx,
	struct ether_addr *dst_ea, BCMP2P_CHANNEL *dst_channel, uint8 dialog_token,
	uint8 frame_type, wifi_p2p_ie_t *p2p_ie, uint16 p2p_ie_len,
	char* dbg_caller_name);

static int
p2plib_send_discb_frame(p2papi_instance_t* hdl, int bssidx,
	struct ether_addr *dst_ea, BCMP2P_CHANNEL *dst_channel, uint8 dialog_token,
	uint8 frame_type, wifi_p2p_ie_t *p2p_ie, uint16 p2p_ie_len,
	char* dbg_caller_name, int dwell_time);

static int
p2papi_tx_go_discb_req(p2papi_instance_t* hdl, struct ether_addr* gc_dev_addr);

static int
p2papi_tx_dev_discb_rsp(p2papi_instance_t* hdl,
	struct ether_addr *dst_requestor, uint8 status);


/* ---- Functions -------------------------------------------------------- */

/* Callback function called when a Device Discoverability Request/Response
 * (P2P_PAF_DEVDIS_REQ/RSP) P2P action frame tx completes.
 */
static void
p2papi_discb_tx_done_cb(void *handle, p2papi_aftx_instance_t *aftx_hdl,
	BCMP2P_BOOL acked, wl_af_params_t *af_params)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*)handle;

	P2PLIB_ASSERT(P2PAPI_CHECK_P2PHDL(hdl));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_discb_tx_done_cb: acked=%d aftx_hdl=%p,%p\n",
		acked, aftx_hdl, hdl->discb_aftx_hdl));

	/* Do the generic AF tx complete actions */
	p2papi_aftx_complete_callback_core(handle, aftx_hdl, acked, af_params);
	hdl->discb_aftx_hdl = NULL;
}

/* Callback function called when a GO Device Discoverability Request
 * (P2P_AF_GO_DISC_REQ) P2P action frame tx completes.
 */
static void
p2papi_go_discb_req_tx_done_cb(void *handle, p2papi_aftx_instance_t *aftx_hdl,
	BCMP2P_BOOL acked, wl_af_params_t *af_params)
{
	BCMP2P_UINT8 status;
	p2papi_instance_t* hdl = (p2papi_instance_t*)handle;

	P2PLIB_ASSERT(P2PAPI_CHECK_P2PHDL(hdl));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_go_discb_req_tx_done_cb: acked=%d aftx_hdl=%p,%p\n",
		acked, aftx_hdl, hdl->discb_aftx_hdl));

	/* Do the generic AF tx complete actions */
	p2papi_aftx_complete_callback_core(handle, aftx_hdl, acked, af_params);
	hdl->discb_aftx_hdl = NULL;

	/* If an ack was received from the group client
	 *     Send back a Device Discoverability Response(success) to the
	 *     requesting device.
	 * else
	 *     Send back a Device Discoverability Response(fail) to the
	 *     requesting device.
	 */

	/* Send back a Device Discoverability Response to the requesting device */
	if (acked)
		status = P2P_STATSE_SUCCESS;
	else
		status = P2P_STATSE_FAIL_UNABLE_TO_ACCOM;

	p2papi_tx_dev_discb_rsp(hdl, &hdl->rx_discb_requestor, status);
}


/* Send a GO Device Discoverability P2P action frame */
static int
p2plib_send_go_discb_frame(p2papi_instance_t* hdl, int bssidx,
	struct ether_addr *dst_ea, BCMP2P_CHANNEL *dst_channel, uint8 dialog_token,
	uint8 frame_type, wifi_p2p_ie_t *p2p_ie, uint16 p2p_ie_len,
	char* dbg_caller_name)
{
	wl_af_params_t *af_params;
	int status = -1;

	if (hdl->discb_aftx_hdl != NULL) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"%s: Nested af tx!\n", dbg_caller_name));
	}
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
	   "%s: dt=%u ch=%d:%d ielen=%u dst=%02x:%02x:%02x:%02x:%02x:%02x\n",
		dbg_caller_name, dialog_token, dst_channel->channel_class,
		dst_channel->channel, p2p_ie_len,
		dst_ea->octet[0], dst_ea->octet[1], dst_ea->octet[2],
		dst_ea->octet[3], dst_ea->octet[4], dst_ea->octet[5]));
	p2papi_log_hexdata(BCMP2P_LOG_INFO, dbg_caller_name, (uint8*)p2p_ie,
		p2p_ie_len);

	af_params = p2plib_build_p2p_act_frm(hdl, dst_ea, (uint8*) P2P_OUI,
		P2P_VER, frame_type, dialog_token, (uint8*)p2p_ie, p2p_ie_len,
		NULL, 0, NULL, 0, dst_channel, P2PAPI_AF_DWELL_TIME);
	if (af_params) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		   "%s: AF len=%u\n", dbg_caller_name, af_params->action_frame.len));

		/* Send the action frame immediately.  No channel synchronization is
		 * needed because we are an active GO and the destination is a client
		 * connected to us.
		 */
		hdl->discb_aftx_hdl = p2papi_aftx_send_frame(hdl, af_params,
			bssidx, hdl->af_tx_max_retries, hdl->af_tx_retry_ms,
			p2papi_go_discb_req_tx_done_cb, (void*)hdl, "go_discb");
		P2PLIB_ASSERT(hdl->discb_aftx_hdl != NULL);
	}

	return status;
}

/* Send a Device Discoverability P2P public action frame */
static int
p2plib_send_discb_frame(p2papi_instance_t* hdl, int bssidx,
	struct ether_addr *dst_ea, BCMP2P_CHANNEL *dst_channel, uint8 dialog_token,
	uint8 frame_type, wifi_p2p_ie_t *p2p_ie, uint16 p2p_ie_len,
	char* dbg_caller_name, int dwell_time)
{
	wl_af_params_t *af_params;
	int status = -1;

	if (p2p_ie == NULL) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "%s: no P2P IE\n", dbg_caller_name));
		return status;
	}
	if (hdl->discb_aftx_hdl != NULL) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"%s: Nested af tx!\n", dbg_caller_name));
	}
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
	   "%s: dt=%u ch=%d:%d ielen=%u dst=%02x:%02x:%02x:%02x:%02x:%02x\n",
		dbg_caller_name, dialog_token, dst_channel->channel_class,
		dst_channel->channel, p2p_ie_len,
		dst_ea->octet[0], dst_ea->octet[1], dst_ea->octet[2],
		dst_ea->octet[3], dst_ea->octet[4], dst_ea->octet[5]));
	p2papi_log_hexdata(BCMP2P_LOG_INFO, dbg_caller_name, (uint8*)p2p_ie,
		p2p_ie_len);

	af_params = p2plib_build_p2p_pub_act_frm(hdl, dst_ea, (uint8*) P2P_OUI,
		P2P_VER, frame_type, dialog_token, (uint8*)p2p_ie, p2p_ie_len,
		NULL, 0, NULL, 0, dst_channel, dwell_time);
	if (af_params) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		   "%s: AF len=%u\n", dbg_caller_name, af_params->action_frame.len));

		/* Send the action frame immediately.  No channel synchronization is
		 * needed because:
		 * - for a discb request frame, the destination is an active GO.
		 * - for a discb response frame, the destination is waiting for our
		 *   response on the same channel that it sent the discb req to us on.
		 */
		hdl->discb_aftx_hdl = p2papi_aftx_send_frame(hdl, af_params,
			bssidx, hdl->af_tx_max_retries, hdl->af_tx_retry_ms,
			p2papi_discb_tx_done_cb, (void*)hdl, "discb");
		P2PLIB_ASSERT(hdl->discb_aftx_hdl != NULL);
	}

	return status;
}

/* Send a Device Discoverability Request action frame to a discovered P2P Group
 * Owner to request a client of that group to become available for
 * communication with us.
 */
int
p2papi_tx_dev_discb_req(p2papi_instance_t* hdl, struct ether_addr *dest_go,
	uint8 *go_ssid, int go_ssid_len, BCMP2P_CHANNEL *dest_channel,
	struct ether_addr *target_client)
{
	wifi_p2p_ie_t *p2p_ie;
	uint16 p2p_ie_len = 0;
	int ret = -1;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "tx_discb_req_frame:"
		" dstGO=%02x:%02x:%02x:%02x:%02x:%02x"
		" client=%02x:%02x:%02x:%02x:%02x:%02x\n",
		dest_go->octet[0], dest_go->octet[1], dest_go->octet[2],
		dest_go->octet[3], dest_go->octet[4], dest_go->octet[5],
		target_client->octet[0], target_client->octet[1],
		target_client->octet[2], target_client->octet[3],
		target_client->octet[4], target_client->octet[5]));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"                  : go_ssid=%s len=%d dstCh=%d:%d\n",
		go_ssid, go_ssid_len, dest_channel->channel_class,
		dest_channel->channel));

	hdl->tx_discb_dialog_token = p2papi_create_dialog_token(
		hdl->tx_discb_dialog_token);
	p2p_ie = (wifi_p2p_ie_t*) P2PAPI_MALLOC(WL_WIFI_ACTION_FRAME_SIZE);
	if (p2p_ie) {
		p2papi_encode_discb_req_p2p_ie(hdl, target_client->octet,
			dest_go->octet, go_ssid, go_ssid_len, p2p_ie, &p2p_ie_len);
	}
	ret = p2plib_send_discb_frame(hdl, hdl->bssidx[P2PAPI_BSSCFG_DEVICE],
		dest_go, dest_channel, hdl->tx_discb_dialog_token, P2P_PAF_DEVDIS_REQ,
		p2p_ie, p2p_ie_len, "tx_discb_req_frm", 500 /* P2PAPI_AF_DWELL_TIME */);

	P2PAPI_FREE(p2p_ie);
	return ret;
}

/* Send a GO Discoverability Request action frame from a Group Owner to a
 * Group Client.
 */
static int
p2papi_tx_go_discb_req(p2papi_instance_t* hdl, struct ether_addr* gc_dev_addr)
{
	int ret = -1;
	ret = p2plib_send_go_discb_frame(hdl, hdl->bssidx[P2PAPI_BSSCFG_CONNECTION],
		gc_dev_addr, &hdl->op_channel, hdl->rx_discb_dialog_token,
		P2P_AF_GO_DISC_REQ, NULL, 0, "tx_go_discb_req");
	return ret;
}

/* Send a Device Discoverability Response action frame from a Group Owner to
 * the device that originated the device discoverability req frame exchange.
 */
static int
p2papi_tx_dev_discb_rsp(p2papi_instance_t* hdl,
	struct ether_addr *dst_requestor, uint8 status)
{
	wifi_p2p_ie_t *p2p_ie;
	uint16 p2p_ie_len = 0;
	int ret = -1;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "tx_discb_rsp_frame:"
		" dt=%u status=%u dst=%02x:%02x:%02x:%02x:%02x:%02x\n",
		hdl->rx_discb_dialog_token, status,
		dst_requestor->octet[0], dst_requestor->octet[1],
		dst_requestor->octet[2], dst_requestor->octet[3],
		dst_requestor->octet[4], dst_requestor->octet[5]));

	p2p_ie = (wifi_p2p_ie_t*) P2PAPI_MALLOC(WL_WIFI_ACTION_FRAME_SIZE);
	if (p2p_ie) {
		p2papi_encode_discb_rsp_p2p_ie(hdl, status, p2p_ie, &p2p_ie_len);
		ret = p2plib_send_discb_frame(hdl,
			hdl->bssidx[P2PAPI_BSSCFG_DEVICE],
			dst_requestor, &hdl->op_channel, hdl->rx_discb_dialog_token,
			P2P_PAF_DEVDIS_RSP, p2p_ie, p2p_ie_len, "tx_discb_rsp_frm", 0);
		P2PAPI_FREE(p2p_ie);
	}
	return ret;
}

/* Process a received Device Discoverability Request action frame at a GO */
int
p2papi_rx_dev_discb_req_frame(p2papi_instance_t* hdl,
	struct ether_addr *src_mac, wifi_p2p_pub_act_frame_t *act_frm,
	uint32 act_frm_len, BCMP2P_CHANNEL *channel)
{
	uint32 ie_len = act_frm_len - P2P_PUB_AF_FIXED_LEN;
	p2papi_p2p_ie_t p2p_ie;
	p2papi_wps_ie_t wps_ie;
	int ret = 0;
	p2papi_client_info_t* cinfo;

	P2PAPI_CHECK_P2PHDL(hdl);
	if (!P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl))
		return -1;
	P2PAPI_GET_WL_HDL(hdl);

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_rx_discb_req:"
		" len=%u token=%u src=%02x:%02x:%02x:%02x:%02x:%02x\n",
		act_frm_len, act_frm->dialog_token,
		src_mac->octet[0], src_mac->octet[1], src_mac->octet[2],
		src_mac->octet[3], src_mac->octet[4], src_mac->octet[5]));

	hdl->rx_discb_dialog_token = act_frm->dialog_token;

	if (!hdl->enable_p2p) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_rx_discb_req: ignored, P2P not enabled\n"));
		p2papi_tx_dev_discb_rsp(hdl, src_mac, P2P_STATSE_FAIL_UNKNOWN_GROUP);
		return -1;
	}

	if (!hdl->is_ap) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_rx_discb_req: reject, not a GO\n"));
		p2papi_tx_dev_discb_rsp(hdl, src_mac, P2P_STATSE_FAIL_UNKNOWN_GROUP);
		return -1;
	}


	/* Decode the received action frame's P2P IE */
	ret = p2papi_decode_p2pwps_ies(act_frm->elts, ie_len, &p2p_ie, &wps_ie);
	if (ret != 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_rx_discb_req: reject, no P2P IE\n"));
		p2papi_tx_dev_discb_rsp(hdl, src_mac, P2P_STATSE_FAIL_INVALID_PARAMS);
		return -1;
	}

	/* Save information from the received request */
	memcpy(&hdl->rx_discb_client, p2p_ie.devid_subelt.addr.octet,
		sizeof(hdl->rx_discb_client));
	memcpy(&hdl->rx_discb_requestor, src_mac, sizeof(hdl->rx_discb_requestor));
	hdl->rx_discb_dialog_token = act_frm->dialog_token;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_rx_discb_req: target client=%02x:%02x:%02x:%02x:%02x:%02x\n",
		hdl->rx_discb_client.octet[0], hdl->rx_discb_client.octet[1],
		hdl->rx_discb_client.octet[2], hdl->rx_discb_client.octet[3],
		hdl->rx_discb_client.octet[4], hdl->rx_discb_client.octet[5]));

	/* If the target client is not associated to us
	 *    Send back a Discoverability Response(fail) to the requesting device.
	 */
	cinfo = p2papi_find_group_client(hdl, &hdl->rx_discb_client);
	if (cinfo == NULL) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"====> p2papi_rx_discb_req: target client not associated!\n"));
		p2papi_tx_dev_discb_rsp(hdl, &hdl->rx_discb_requestor,
			P2P_STATSE_FAIL_UNABLE_TO_ACCOM);
		return -1;
	}

	/* Notify the app that we received a Device Discoverability Request */
	p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_DEVICE_DISCOVERABILITY,
		BCMP2P_NOTIF_DEV_DISCOVERABILITY_REQ);

	/* Send a GO Discoverability Request action frame to the target client */
	p2papi_tx_go_discb_req(hdl, (struct ether_addr*)&cinfo->p2p_int_addr);

	return ret;
}

/* Process a received Device Discoverability Response action frame */
int
p2papi_rx_discb_rsp_frame(p2papi_instance_t* hdl,
	struct ether_addr *src_mac, wifi_p2p_pub_act_frame_t *act_frm,
	uint32 act_frm_len, BCMP2P_CHANNEL *channel)
{
	uint32 ie_len = act_frm_len - P2P_PUB_AF_FIXED_LEN;
	p2papi_p2p_ie_t p2p_ie;
	p2papi_wps_ie_t wps_ie;
	int ret = 0;

	P2PAPI_CHECK_P2PHDL(hdl);
	if (!P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl))
		return -1;
	P2PAPI_GET_WL_HDL(hdl);

	if (!hdl->enable_p2p) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_rx_discb_rsp: ignored, P2P not enabled\n"));
		return 0;
	}

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_rx_discb_rsp: len=%u subtype=%u token=%u\n",
		act_frm_len, act_frm->subtype, act_frm->dialog_token));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"         : src_mac=%02x:%02x:%02x:%02x:%02x:%02x ch=%d:%d\n",
		src_mac->octet[0], src_mac->octet[1], src_mac->octet[2],
		src_mac->octet[3], src_mac->octet[4], src_mac->octet[5],
		channel->channel_class, channel->channel));

	if (hdl->discb_aftx_hdl != NULL) {
		p2papi_aftx_cancel_send(hdl->discb_aftx_hdl);
		hdl->discb_aftx_hdl = NULL;
	}

	/* Decode the frame's P2P IE */
	(void) p2papi_decode_p2pwps_ies(act_frm->elts, ie_len, &p2p_ie, &wps_ie);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_rx_discb_rsp: p2p IE stat=%d\n",
		p2p_ie.status_subelt.status));


	/* TODO: Add more actions here */

	/* Save status code */
	hdl->status_code = p2p_ie.status_subelt.status;

	/* Notify the app that we received a Device Discoverability Response */
	p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_DEVICE_DISCOVERABILITY,
		BCMP2P_NOTIF_DEV_DISCOVERABILITY_RSP);

	return ret;
}

/* Process a received GO Discoverability Request action frame */
int
p2papi_rx_go_discb_req_frame(p2papi_instance_t* hdl,
	struct ether_addr *src_mac, wifi_p2p_action_frame_t *act_frm,
	uint32 act_frm_len, BCMP2P_CHANNEL *channel)
{
	uint32 ie_len = act_frm_len - P2P_AF_FIXED_LEN;
	p2papi_p2p_ie_t p2p_ie;
	p2papi_wps_ie_t wps_ie;
	int ret = -1;

	P2PAPI_CHECK_P2PHDL(hdl);
	if (!P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl))
		return ret;

	if (!hdl->enable_p2p) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_rx_go_discb_req: ignored, P2P not enabled\n"));
		return ret;
	}
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_rx_go_discb_req\n"));

	/* decode IEs */
	(void) p2papi_decode_p2pwps_ies(act_frm->elts, ie_len, &p2p_ie, &wps_ie);


	/* TODO: Add more actions here */
	/* Disable power save for 100ms to receive action frames from the
	 * requestor device.
	 */

	/* Disbale power saving to wake up device */
	p2pwlu_set_PM(hdl, 0, hdl->bssidx[P2PAPI_BSSCFG_CONNECTION]);

	/* Notify the app that we received a GO Discoverability Response */
	p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_DEVICE_DISCOVERABILITY,
		BCMP2P_NOTIF_GO_DISCOVERABILITY_REQ);

	ret = 0;
	return ret;
}
