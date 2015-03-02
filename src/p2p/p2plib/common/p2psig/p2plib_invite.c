/*
 * P2P Library API - Invite functions.
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: p2plib_invite.c,v 1.10 2011-01-07 02:30:16 $
 */

#ifndef SOFTAP_ONLY
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

static void
p2papi_log_invite_params(char *prefix, BCMP2P_INVITE_PARAM *inv);

static void
p2papi_save_rx_invite_data(BCMP2P_INVITE_PARAM *dst,
	struct ether_addr *src_mac, wifi_p2p_pub_act_frame_t *src_act_frm,
	BCMP2P_CHANNEL *src_channel, p2papi_p2p_ie_t *src_p2p_ie);

static int
p2plib_send_invite_frame(p2papi_instance_t* hdl, bool do_chan_sync,
	struct ether_addr *dst_ea, BCMP2P_CHANNEL *dst_listen_channel,
	uint8 dialog_token,	uint8 frame_type, wifi_p2p_ie_t *p2p_ie,
	uint16 p2p_ie_len, char* dbg_caller_name);

static int
p2plib_tx_invite_req_frame(p2papi_instance_t* hdl,
	struct ether_addr *dst, BCMP2P_CHANNEL *dst_listen_channel,
	uint8 dialog_token,	uint16 go_cfg_tmo_ms, uint16 gc_cfg_tmo_ms,
	BCMP2P_CHANNEL *op_channel, uint8 *p2p_grp_bssid, uint8 invite_flags,
	char *country, p2p_chanlist_t *chanlist,
	uint8 *p2pgrpid_dev_addr, char *p2pgrpid_ssid, int p2pgrpid_ssid_len);

static int
p2plib_tx_invite_rsp_frame(p2papi_instance_t* hdl,
	struct ether_addr *dst_ea, BCMP2P_CHANNEL *tx_channel,
	uint8 dialog_token,	uint8 status, uint16 go_cfg_tmo_ms,
	uint16 gc_cfg_tmo_ms, BCMP2P_CHANNEL *op_channel,
	struct ether_addr *p2p_grp_bssid, char *country,
	p2p_chanlist_t *chanlist);


/* ---- Functions -------------------------------------------------------- */

static void
p2papi_log_invite_params(char *prefix, BCMP2P_INVITE_PARAM *inv)
{
	/* BCMP2PLOG expands to nothing if P2PLOGGING is undefined */
	(void) prefix;
	(void) inv;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "%s: dt=%u afCh=%d:%d opCh=%d:%d\n",
		prefix, inv->dialogToken,
		inv->afChannel.channel_class, inv->afChannel.channel,
		inv->operatingChannel.channel_class, inv->operatingChannel.channel));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"    srcDevAddr=%02x:%02x:%02x:%02x:%02x:%02x"
		" grpBssid=%02x:%02x:%02x:%02x:%02x:%02x\n",
		inv->srcDevAddr.octet[0], inv->srcDevAddr.octet[1],
		inv->srcDevAddr.octet[2], inv->srcDevAddr.octet[3],
		inv->srcDevAddr.octet[4], inv->srcDevAddr.octet[5],
		inv->groupBssid.octet[0], inv->groupBssid.octet[1],
		inv->groupBssid.octet[2], inv->groupBssid.octet[3],
		inv->groupBssid.octet[4], inv->groupBssid.octet[5]));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"    grpDevAddr=%02x:%02x:%02x:%02x:%02x:%02x grpSsid=%s (len %u)\n",
		inv->groupDevAddr.octet[0], inv->groupDevAddr.octet[1],
		inv->groupDevAddr.octet[2], inv->groupDevAddr.octet[3],
		inv->groupDevAddr.octet[4], inv->groupDevAddr.octet[5],
		inv->groupSsid, inv->groupSsidLength));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"    goCfgTimeoutMs=%u clientCfgTimoutMs=%u flags=0x%x status=%d devName=%s\n",
		inv->goConfigTimeoutMs, inv->gcConfigTimeoutMs, inv->inviteFlags,
		inv->status, inv->devName));
	BCMP2PLOG((BCMP2P_LOG_MED, FALSE, "\n"));
}

static void
p2papi_save_rx_invite_data(BCMP2P_INVITE_PARAM *dst,
	struct ether_addr *src_mac, wifi_p2p_pub_act_frame_t *src_act_frm,
	BCMP2P_CHANNEL *src_channel, p2papi_p2p_ie_t *src_p2p_ie)
{
	/* These fields are common to both Invitation Req and Rsp frames */
	dst->dialogToken = src_act_frm->dialog_token;
	memcpy(dst->srcDevAddr.octet, src_mac->octet, sizeof(dst->srcDevAddr));
	memcpy(&dst->afChannel, src_channel, sizeof(dst->afChannel));
	memcpy(dst->groupBssid.octet, src_p2p_ie->grp_bssid_subelt.bssid.octet,
		sizeof(dst->groupBssid));
	memcpy(dst->groupDevAddr.octet, src_p2p_ie->grpid_subelt.devaddr.octet,
		sizeof(dst->groupDevAddr));
	memcpy(dst->groupSsid, src_p2p_ie->grpid_subelt.ssid,
		sizeof(dst->groupSsid));
	dst->groupSsidLength = src_p2p_ie->grpid_subelt.ssid_len;
	dst->operatingChannel.channel_class = (BCMP2P_CHANNEL_CLASS)src_p2p_ie->op_chan_subelt.band;
	dst->operatingChannel.channel = src_p2p_ie->op_chan_subelt.channel;
	dst->goConfigTimeoutMs = src_p2p_ie->cfg_tmo_subelt.go_tmo * 10;
	dst->gcConfigTimeoutMs = src_p2p_ie->cfg_tmo_subelt.client_tmo * 10;
	dst->inviteFlags = src_p2p_ie->invflags_subelt.inv_flags;

	/* These fields are valid only for Invitation Rsp frames */
	dst->status = src_p2p_ie->status_subelt.status;

	if (src_p2p_ie->devinfo_name_len > 0) {
		memcpy(dst->devName, src_p2p_ie->devinfo_name, src_p2p_ie->devinfo_name_len);
		dst->devName[src_p2p_ie->devinfo_name_len] = 0;
	}
	else
		dst->devName[0] = 0;
}

int
p2papi_rx_invite_req_frame(p2papi_instance_t* hdl,
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
			"p2papi_rx_inv_req: ignored, P2P not enabled\n"));
		return 0;
	}

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_rx_inv_req: state=%u, frame: len=%u subtype=%u token=%u\n",
		hdl->conn_state, act_frm_len, act_frm->subtype, act_frm->dialog_token));

	/* Decode the GO Negotiation action frame's P2P IE */
	(void) p2papi_decode_p2pwps_ies(act_frm->elts, ie_len, &p2p_ie, &wps_ie);
/*
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_rx_inv_req: p2p IE ch=%d(b=%d)\n",
		p2p_ie.op_chan_subelt.channel, p2p_ie.op_chan_subelt.band));
*/

	/* negotiate channel list */
	p2papi_negotiate_chanlist(&hdl->negotiated_channel_list,
		p2papi_get_non_dfs_channel_list(hdl), &p2p_ie.chanlist_subelt.chanlist);

	/* Save the information from the invite req frame */
	p2papi_save_rx_invite_data(&hdl->invite_req, src_mac, act_frm, channel,
		&p2p_ie);

	/* Log the saved invite request params */
	p2papi_log_invite_params("p2papi_rx_invite_req_frame", &hdl->invite_req);

	/* Send a Invite Request notification to the app */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_rx_inv_req: delivering BCMP2P_NOTIF_P2P_INVITE_REQ to app\n"));
	p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_CREATE_LINK,
		BCMP2P_NOTIF_P2P_INVITE_REQ);

	return ret;
}

int
p2papi_rx_invite_rsp_frame(p2papi_instance_t* hdl,
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
			"p2papi_rx_inv_rsp: ignored, P2P not enabled\n"));
		return 0;
	}

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_rx_inv_rsp: state=%u, frame: len=%u subtype=%u token=%u\n",
		hdl->conn_state, act_frm_len, act_frm->subtype, act_frm->dialog_token));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"                : src_mac=%02x:%02x:%02x:%02x:%02x:%02x ch=%d:%d\n",
		src_mac->octet[0], src_mac->octet[1], src_mac->octet[2],
		src_mac->octet[3], src_mac->octet[4], src_mac->octet[5],
		channel->channel_class, channel->channel));

	if (hdl->invite_aftx_hdl != NULL) {
		p2papi_aftx_cancel_send(hdl->invite_aftx_hdl);
		hdl->invite_aftx_hdl = NULL;
	}

	/* Decode the frame's P2P IE */
	(void) p2papi_decode_p2pwps_ies(act_frm->elts, ie_len, &p2p_ie, &wps_ie);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_rx_inv_rsp: p2p IE int=0x%02x stat=%d ch=%d(b=%d)\n",
		p2p_ie.intent_subelt.intent, p2p_ie.status_subelt.status,
		p2p_ie.op_chan_subelt.channel, p2p_ie.op_chan_subelt.band));

	/* update negotiated channel list from response */
	p2papi_update_chanlist(&hdl->negotiated_channel_list,
		&p2p_ie.chanlist_subelt.chanlist);

	/* Save the information from the invite rsp frame */
	p2papi_save_rx_invite_data(&hdl->invite_rsp, src_mac, act_frm, channel,
		&p2p_ie);

	/* Log the saved invite response params */
	p2papi_log_invite_params("p2papi_rx_invite_rsp_frame", &hdl->invite_rsp);

	/* Send a Invite Response notification to the app */
	p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_CREATE_LINK,
		BCMP2P_NOTIF_P2P_INVITE_RSP);

	return ret;
}

/* Callback function called when an Invite P2P action frame tx completes. */
static void
p2papi_invite_tx_done_cb(void *handle, p2papi_aftx_instance_t *aftx_hdl,
	BCMP2P_BOOL acked, wl_af_params_t *af_params)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*)handle;

	P2PLIB_ASSERT(P2PAPI_CHECK_P2PHDL(hdl));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_invite_tx_done_cb: acked=%d aftx_hdl=%p,%p\n",
		acked, aftx_hdl, hdl->invite_aftx_hdl));

	/* Do the generic AF tx complete actions */
	p2papi_aftx_complete_callback_core(handle, aftx_hdl, acked, af_params);
	hdl->invite_aftx_hdl = NULL;
}

/* Build a P2P Invitation P2P public action frame */
static int
p2plib_send_invite_frame(p2papi_instance_t* hdl, bool do_chan_sync,
	struct ether_addr *dst_ea, BCMP2P_CHANNEL *dst_listen_channel, uint8 dialog_token,
	uint8 frame_type, wifi_p2p_ie_t *p2p_ie, uint16 p2p_ie_len,
	char* dbg_caller_name)
{
	wl_af_params_t *af_params;
	int status = -1;

	if (p2p_ie == NULL) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "%s: no P2P IE\n", dbg_caller_name));
		return status;
	}
	if (hdl->invite_aftx_hdl != NULL) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"%s: Nested af tx!\n", dbg_caller_name));
	}
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
	   "%s: dt=%u ch=%d:%d ielen=%u dst=%02x:%02x:%02x:%02x:%02x:%02x\n",
		dbg_caller_name, dialog_token, dst_listen_channel->channel_class,
		dst_listen_channel->channel, p2p_ie_len,
		dst_ea->octet[0], dst_ea->octet[1], dst_ea->octet[2],
		dst_ea->octet[3], dst_ea->octet[4], dst_ea->octet[5]));
	p2papi_log_hexdata(BCMP2P_LOG_INFO, dbg_caller_name, (uint8*)p2p_ie,
		p2p_ie_len);

	af_params = p2plib_build_p2p_pub_act_frm(hdl, dst_ea, (uint8*) P2P_OUI,
		P2P_VER, frame_type, dialog_token, (uint8*)p2p_ie, p2p_ie_len,
		NULL, 0, NULL, 0, dst_listen_channel, P2PAPI_AF_DWELL_TIME);
	if (af_params) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		   "%s: AF len=%u\n", dbg_caller_name, af_params->action_frame.len));
		/* Send the action frame after synchronizing channels with the target
		 * device.  The target device must be in Listen state or alternating
		 * between Search and Listen state.
		 */
		if (do_chan_sync) {
			status = p2papi_send_at_common_channel(hdl, dst_listen_channel,
				af_params, p2papi_invite_tx_done_cb, BCMP2P_TRUE,
				&hdl->invite_aftx_hdl, "invite");
		}
		else
		{
			/* Send the action frame immediately.  The target device must be in
			 * Listen state.
			 */
			hdl->invite_aftx_hdl = p2papi_aftx_send_frame(hdl, af_params,
				hdl->bssidx[P2PAPI_BSSCFG_DEVICE], hdl->af_tx_max_retries,
				hdl->af_tx_retry_ms, p2papi_invite_tx_done_cb, (void*)hdl,
				"invite");
			P2PLIB_ASSERT(hdl->invite_aftx_hdl != NULL);
			if (hdl->invite_aftx_hdl != NULL)
				status = 0;
		}
	}

	return status;
}

/* Build and send a P2P Invitation Request P2P public action frame.
 * - dst_ea: destination device's Device MAC Address.
 * - tx_channel: channel to transmit the action frame on.
 * - dialog_token: dialog token to put in the action frame header.
 * - cfg_tmo_ms: Configuration Timeout to encode in the P2P IE.
 * - op_channel: preferred operating channel to encode in the P2P IE.
 * - p2p_grp_bssid: P2P Group BSSID  to encode in the P2P IE.
 *                  This is required if we are the Persistent Group GO,
 *                  optional (may be NULL) if we are a PG GC.
 */
static int
p2plib_tx_invite_req_frame(p2papi_instance_t* hdl,
	struct ether_addr *dst, BCMP2P_CHANNEL *dst_listen_channel,
	uint8 dialog_token,	uint16 go_cfg_tmo_ms, uint16 gc_cfg_tmo_ms,
	BCMP2P_CHANNEL *op_channel, uint8 *p2p_grp_bssid, uint8 invite_flags,
	char *country, p2p_chanlist_t *chanlist,
	uint8 *p2pgrpid_dev_addr, char *p2pgrpid_ssid, int p2pgrpid_ssid_len)
{
	wifi_p2p_ie_t *p2p_ie;
	uint16 p2p_ie_len = 0;
	int ret = -1;

/*
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"tx_invite_req_frame: dst=%02x:%02x:%02x:%02x:%02x:%02x ch=%d:%d\n",
		dst->octet[0], dst->octet[1], dst->octet[2], dst->octet[3],
		dst->octet[4], dst->octet[5], dst_listen_channel->channel_class,
		dst_listen_channel->channel));
*/
	if (p2p_grp_bssid)
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "tx_invite_req_frame:"
			" grbssid=%02x:%02x:%02x:%02x:%02x:%02x ssid=%s\n",
			p2p_grp_bssid[0], p2p_grp_bssid[1], p2p_grp_bssid[2],
			p2p_grp_bssid[3], p2p_grp_bssid[4], p2p_grp_bssid[5],
			p2pgrpid_ssid));
	else
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"tx_invite_req_frame: grbssid=NULL ssid=%s\n",
			p2pgrpid_ssid));

	p2p_ie = (wifi_p2p_ie_t*) P2PAPI_MALLOC(WL_WIFI_ACTION_FRAME_SIZE);

	if (p2p_ie) {
		/* reset the memory first */
		memset(p2p_ie, 0, WL_WIFI_ACTION_FRAME_SIZE);

		/* Save peer device address */
		memcpy(&hdl->peer_dev_addr, p2pgrpid_dev_addr, sizeof(hdl->peer_dev_addr));

		p2papi_encode_inv_req_p2p_ie(hdl, go_cfg_tmo_ms, gc_cfg_tmo_ms,
			op_channel, p2p_grp_bssid, invite_flags,
			country, chanlist,
			p2pgrpid_dev_addr, (uint8*) p2pgrpid_ssid, p2pgrpid_ssid_len,
			hdl->p2p_dev_addr.octet, hdl->fname_ssid, hdl->fname_ssid_len,
			p2p_ie, &p2p_ie_len);

		ret = p2plib_send_invite_frame(hdl, TRUE, dst, dst_listen_channel,
			dialog_token, P2P_PAF_INVITE_REQ, p2p_ie, p2p_ie_len,
			"tx_invite_req_frm");

		P2PAPI_FREE(p2p_ie);
	}
	return ret;
}

/* Build and send a P2P Invitation Request P2P public action frame. */
int
p2plib_tx_invite_req(p2papi_instance_t* hdl,
	struct ether_addr *dst, BCMP2P_CHANNEL *dst_listen_channel,
	BCMP2P_CHANNEL *op_channel, struct ether_addr *p2p_grp_bssid, uint8 invite_flags,
	struct ether_addr *p2pgrpid_dev_addr, char *p2pgrpid_ssid, int p2pgrpid_ssid_len)
{
	wifi_p2p_ie_t *p2p_ie;
	uint16 p2p_ie_len = 0;
	int ret = -1;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"tx_invite_req_frame: dst=%02x:%02x:%02x:%02x:%02x:%02x ch=%d:%d\n",
		dst->octet[0], dst->octet[1], dst->octet[2], dst->octet[3],
		dst->octet[4], dst->octet[5], dst_listen_channel->channel_class,
		dst_listen_channel->channel));

	p2p_ie = (wifi_p2p_ie_t*) P2PAPI_MALLOC(WL_WIFI_ACTION_FRAME_SIZE);

	if (p2p_ie) {
		/* Save peer device address */
		memcpy(&hdl->peer_dev_addr, dst, sizeof(hdl->peer_dev_addr));

		hdl->inv_dialog_token = p2papi_create_dialog_token(hdl->inv_dialog_token);
		p2papi_encode_inv_req_p2p_ie(hdl, 0, 0,
			op_channel, p2p_grp_bssid->octet, invite_flags,
			hdl->country, p2papi_get_non_dfs_channel_list(hdl),
			p2pgrpid_dev_addr->octet, (uint8*) p2pgrpid_ssid, p2pgrpid_ssid_len,
			hdl->p2p_dev_addr.octet, hdl->fname_ssid, hdl->fname_ssid_len,
			p2p_ie, &p2p_ie_len);

		ret = p2plib_send_invite_frame(hdl, TRUE, dst, dst_listen_channel,
			hdl->inv_dialog_token, P2P_PAF_INVITE_REQ, p2p_ie, p2p_ie_len,
			"p2plib_tx_invite_req");

		P2PAPI_FREE(p2p_ie);
	}
	return ret;
}

/* Send a P2P Invitation Request from a GO to a target device */
int
p2papi_tx_invite_req_from_active_go(p2papi_instance_t* hdl,
	struct ether_addr* dst, BCMP2P_CHANNEL *dst_listen_channel)
{
	bool is_go_active = TRUE;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"tx_invite_req_from_active_go: dst=%02x:%02x:%02x:%02x:%02x:%02x\n",
		dst->octet[0], dst->octet[1], dst->octet[2], dst->octet[3],
		dst->octet[4], dst->octet[5]));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"    bssid=%02x:%02x:%02x:%02x:%02x:%02x\n",
		hdl->conn_ifaddr.octet[0], hdl->conn_ifaddr.octet[1],
		hdl->conn_ifaddr.octet[2], hdl->conn_ifaddr.octet[3],
		hdl->conn_ifaddr.octet[4], hdl->conn_ifaddr.octet[5]));

	hdl->inv_dialog_token = p2papi_create_dialog_token(hdl->inv_dialog_token);
	p2plib_tx_invite_req_frame(hdl, dst, dst_listen_channel,
		hdl->inv_dialog_token, (is_go_active ? 0 : hdl->peer_wps_go_cfg_tmo_ms),
		0, &hdl->op_channel, hdl->conn_ifaddr.octet,
		P2P_INVSE_JOIN_ACTIVE_GRP,
		hdl->country, p2papi_get_non_dfs_channel_list(hdl),
		hdl->p2p_dev_addr.octet,
		hdl->credentials.ssid, strlen(hdl->credentials.ssid));

	return BCMP2P_SUCCESS;
}

/* Send a P2P Invitation Request from an inactive GO to a target device */
int
p2papi_tx_invite_req_from_inactive_go(p2papi_instance_t* hdl,
	uint8 *ssid, uint8 ssidLen,
	struct ether_addr* grpid_dev_addr,
	struct ether_addr* dst, BCMP2P_CHANNEL *dst_listen_channel)
{
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"tx_invite_req_from_inactive_go: dst=%02x:%02x:%02x:%02x:%02x:%02x\n",
		dst->octet[0], dst->octet[1], dst->octet[2], dst->octet[3],
		dst->octet[4], dst->octet[5]));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"    bssid=%02x:%02x:%02x:%02x:%02x:%02x\n",
		hdl->conn_ifaddr.octet[0], hdl->conn_ifaddr.octet[1],
		hdl->conn_ifaddr.octet[2], hdl->conn_ifaddr.octet[3],
		hdl->conn_ifaddr.octet[4], hdl->conn_ifaddr.octet[5]));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"    grpid_dev_addr=%02x:%02x:%02x:%02x:%02x:%02x\n",
		grpid_dev_addr->octet[0], grpid_dev_addr->octet[1],
		grpid_dev_addr->octet[2], grpid_dev_addr->octet[3],
		grpid_dev_addr->octet[4], grpid_dev_addr->octet[5]));

	hdl->inv_dialog_token = p2papi_create_dialog_token(hdl->inv_dialog_token);
	p2plib_tx_invite_req_frame(hdl, dst, dst_listen_channel,
		hdl->inv_dialog_token, hdl->peer_wps_go_cfg_tmo_ms, 0,
		&hdl->op_channel, hdl->conn_ifaddr.octet,
		P2P_INVSE_REINVOKE_PERSIST_GRP,
		hdl->country, p2papi_get_non_dfs_channel_list(hdl),
		grpid_dev_addr->octet, (char*)ssid, ssidLen);

	return BCMP2P_SUCCESS;
}

/* Send a P2P Invitation Request from an connected or unconnected GC to a
 * target device.
 *
 * If GC is connected, the Invitation Req's P2P Group BSSID field will contain
 * the GO's BSSID.this will restore a persisent GC.  Else (GC is unconnected)
 * the P2P Group BSSID field will not be encoded.
 *
 * Parameters:
 * dst - If the destination is an active GO, this should be the target GO's
 *       Interface Address.  Otherwise this is the target device's Device
 *       Address.
 */
int
p2papi_tx_invite_req_from_gc(p2papi_instance_t* hdl,
	uint8 *ssid, uint8 ssidLen,
	struct ether_addr* grpid_dev_addr,
	struct ether_addr* dst, BCMP2P_CHANNEL *dst_listen_channel)
{
	uint8 *bssid = NULL;
	uint8 invite_type;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"tx_invite_req_from_gc: grpid_dev_addr=%02x:%02x:%02x:%02x:%02x:%02x\n",
		grpid_dev_addr->octet[0], grpid_dev_addr->octet[1],
		grpid_dev_addr->octet[2], grpid_dev_addr->octet[3],
		grpid_dev_addr->octet[4], grpid_dev_addr->octet[5]));
	if (hdl->is_ap) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"tx_invite_req_from_gc: not allowed from GO\n"));
		return BCMP2P_ERROR;
	}

	hdl->inv_dialog_token = p2papi_create_dialog_token(hdl->inv_dialog_token);

	if (hdl->is_connected) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"tx_invite_req_from_gc: from connected GC\n"));
		bssid = hdl->peer_int_addr.octet;
		invite_type = P2P_INVSE_JOIN_ACTIVE_GRP;
	} else {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"tx_invite_req_from_gc: from unconnected GC\n"));
		invite_type = P2P_INVSE_REINVOKE_PERSIST_GRP;
	}

	p2plib_tx_invite_req_frame(hdl, dst, dst_listen_channel,
		hdl->inv_dialog_token, 0, 0,
		&hdl->op_channel, bssid, invite_type,
		hdl->country, p2papi_get_non_dfs_channel_list(hdl),
		grpid_dev_addr->octet,
		(char*)ssid, ssidLen);

	return BCMP2P_SUCCESS;
}

/* Build and send a P2P Invitation Response P2P public action frame */
static int
p2plib_tx_invite_rsp_frame(p2papi_instance_t* hdl,
	struct ether_addr *dst_ea, BCMP2P_CHANNEL *tx_channel, uint8 dialog_token,
	uint8 status, uint16 go_cfg_tmo_ms, uint16 gc_cfg_tmo_ms,
	BCMP2P_CHANNEL *op_channel, struct ether_addr *p2p_grp_bssid,
	char *country, p2p_chanlist_t *chanlist)
{
	wifi_p2p_ie_t *p2p_ie;
	uint16 p2p_ie_len = 0;
	int ret = -1;

	p2p_ie = (wifi_p2p_ie_t*) P2PAPI_MALLOC(WL_WIFI_ACTION_FRAME_SIZE);
	if (p2p_ie) {
		p2papi_encode_inv_rsp_p2p_ie(hdl, status, go_cfg_tmo_ms, gc_cfg_tmo_ms,
			op_channel, (uint8*)p2p_grp_bssid,
			country, chanlist,
			p2p_ie, &p2p_ie_len);
		ret = p2plib_send_invite_frame(hdl, FALSE, dst_ea, tx_channel,
			dialog_token, P2P_PAF_INVITE_RSP, p2p_ie, p2p_ie_len,
			"tx_invite_rsp_frm");
		P2PAPI_FREE(p2p_ie);
	}
	return ret;
}

/* Send a P2P Invitation Response to the device who sent us the Invitation
 * Request.
 */
int
p2papi_tx_invite_rsp(p2papi_instance_t* hdl,
	BCMP2P_INVITE_PARAM *invite_req, BCMP2P_INVITE_RESPONSE response,
	bool isGO)
{
	uint8 status = P2P_STATSE_FAIL_UNABLE_TO_ACCOM;
	BCMP2P_CHANNEL op_channel;
	struct ether_addr *bssid = NULL;

	memcpy(&op_channel, &invite_req->operatingChannel,
		sizeof(op_channel));

	if (isGO)
		bssid = &hdl->conn_ifaddr;

	if (bssid)
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"tx_invite_rsp: isGO=%d, bssid=%02x:%02x:%02x:%02x:%02x:%02x\n",
			isGO, bssid->octet[0], bssid->octet[1], bssid->octet[2],
			bssid->octet[3], bssid->octet[4], bssid->octet[5]));
	else
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"tx_invite_rsp: isGO=%d, no bssid\n", isGO));

	switch (response) {
	case BCMP2P_INVITE_PENDING:
		status = P2P_STATSE_FAIL_INFO_CURR_UNAVAIL;
		break;
	case BCMP2P_INVITE_ACCEPT:
		/* Save peer device address */
		memcpy(&hdl->peer_dev_addr, &invite_req->srcDevAddr, sizeof(hdl->peer_dev_addr));
		status = P2P_STATSE_SUCCESS;
		break;
	case BCMP2P_INVITE_REJECT:
		status = P2P_STATSE_FAIL_UNABLE_TO_ACCOM;
		break;
	case BCMP2P_INVITE_REJECT_UNKNOWN_GROUP:
		status = P2P_STATSE_FAIL_UNKNOWN_GROUP;
		break;
	case BCMP2P_INVITE_REJECT_NO_COMMON_CHANNEL:
		status = P2P_STATSE_FAIL_NO_COMMON_CHAN;
		break;
		
	default:
		break;
	}

	if (isGO) {
		memcpy(&op_channel, &hdl->op_channel, sizeof(op_channel));
	}

	return p2plib_tx_invite_rsp_frame(hdl,
		(struct ether_addr*)&invite_req->srcDevAddr, &invite_req->afChannel,
		invite_req->dialogToken, status, hdl->peer_wps_go_cfg_tmo_ms, 0,
		&op_channel, bssid, hdl->country, &hdl->negotiated_channel_list);
}
#endif /* SOFTAP_ONLY */
