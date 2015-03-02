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
 * $Id: p2plib_negotiate.c,v 1.325 2011-01-18 17:43:25 $
 */

#include <stdlib.h>
#include <ctype.h>

/* P2P Library include files */
#include <BcmP2PAPI.h>
#include "p2plib_api.h"
#include <p2plib_int.h>
#include "p2pwl.h"
#include <p2plib_sd.h>

/* WL driver include files */
#include <bcmendian.h>
#include <wlioctl.h>
#include <bcmutils.h>

#if P2PAPI_ENABLE_DHCPD
#include <dhcp.h>
#endif /* P2PAPI_ENABLE_DHCPD */

/* WPS include files */
#include <reg_prototlv.h>


void
p2plib_assert(char *fmt, int line)
{
	BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, fmt, line));
}


#ifndef SOFTAP_ONLY


/* Do a P2P discovery-like search prior to sending a Group Owner Negotiation
 * Request frame.  The purpose is to send out probe requests to the peer
 * on its listen channel to trigger it to send us a GO Negotiate Request
 * if it is waiting to do so.
 * Returns the time spent sleeping in this function.
 */
static uint32
p2papi_go_neg_search(p2papi_instance_t* hdl, uint32 chan_dwell_ms, BCMP2P_CHANNEL *channel)
{
	int nprobes = 0;	/* 0 = use the default number of probes */
	uint32 sleep_ms = chan_dwell_ms * 3;
	int ch = channel->channel;

	P2PAPI_CHECK_P2PHDL(hdl);
	if (!P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl))
		return 0;
	P2PAPI_GET_WL_HDL(hdl);

	BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
		"p2papi_go_neg_search: channel=%d dwell_ms=%u\n",
		ch, chan_dwell_ms));

	if (ch == 0)
		ch = hdl->listen_channel.channel;

	(void) p2pwlu_set_p2p_mode(hdl, WL_P2P_DISC_ST_SEARCH, 0, 0);

	/* Scan the given channel (the peer's listen channel) */
	p2pwlu_scan_channels(hdl, nprobes, chan_dwell_ms, ch, ch, ch);

	p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_DISCOVERY_SEARCH, sleep_ms);
	BCMP2PLOG((BCMP2P_LOG_INFO, TRUE, "p2papi_go_neg_search: exit\n"));
	return sleep_ms;
}

static void
p2papi_go_neg_listen(p2papi_instance_t* hdl, BCMP2P_CHANNEL *channel, uint16 ms)
{
	uint32 time_used_ms = 0;
	chanspec_t chspec;

	P2PAPI_CHECK_P2PHDL(hdl);
	if (!P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl))
		return;
	P2PAPI_GET_WL_HDL(hdl);

	BCMP2PLOG((BCMP2P_LOG_INFO, TRUE, "p2papi_go_neg_listen: chan=%d:%d ms=%u\n",
		channel->channel_class, channel->channel, ms));

	/* Put the WL driver into P2P Listen Mode to respond to P2P probe reqs */
	p2papi_channel_to_chspec(channel, &chspec);
	(void) p2pwlu_set_p2p_mode(hdl, WL_P2P_DISC_ST_LISTEN, chspec, ms);

	/* Wait for the listen duration in small increments with checks in between
	 * for p2papi_send_at_common_channel() exit conditions.
	 */
	while (time_used_ms < ms &&
		!hdl->cancel_link_create &&
		hdl->pending_tx_act_frm != NULL) {

		p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_DISCOVERY_LISTEN, 50);
		time_used_ms += 50;
	}

	BCMP2PLOG(((time_used_ms < ms) ? BCMP2P_LOG_MED : BCMP2P_LOG_INFO, TRUE,
		"p2papi_go_neg_listen: exit, time_used_ms=%u ms=%u\n",
		time_used_ms, ms));
}

/*
 * Compare 2 MAC addresses A and B.
 * Returns:
 *     -1 if A < B
 *      1 if A > B
 *      0 if A == B
 */
static int
compare_mac_addr(struct ether_addr* mac_a, struct ether_addr* mac_b)
{
	uint8* a = &mac_a->octet[0];
	uint8* b = &mac_b->octet[0];
	uint32 ua = (a[0] << 16) | (a[1] << 8) | a[2];
	uint32 ub = (b[0] << 16) | (b[1] << 8) | b[2];
	uint32 la;
	uint32 lb;

	/* Compare the upper 3 OUI octets */
	if (ua < ub)
		return -1;
	else if (ua > ub)
		return 1;
	else /* ua == ub */
	{
		/* Compare the lower 3 OUI octets */
		la = (a[3] << 16) | (a[4] << 8) | a[5];
		lb = (b[3] << 16) | (b[4] << 8) | b[5];
		if (la < lb)
			return -1;
		else if (la > lb)
			return 1;
		else /* la == lb */
			return 0;
	}
}

/* Create a new dialog token based on the old dialog token. */
uint8
p2papi_create_dialog_token(uint8 token)
{
	/* For ease of debugging, start the token value at 5 instead of 1
	 * because it easier to find in a sniffer trace.
	 */
	++token;
	if (token < 5)
		token = 5;
	return token;
}

/* Generate our Group Owner Intent value based on our connection state */
uint8
p2papi_generate_go_intent(p2papi_instance_t* hdl)
{
	BCMP2P_BOOL is_ap = p2papi_is_ap(hdl);
	uint8 intent = hdl->ap_config.grp_owner_intent;

	/* If we are already associated to an AP as a STA or if we are already
	 * acting as a P2P AP, then we can only act as an AP (intent=15).
	 * Otherwise use the intent from our configuration data.
	 */
	if (is_ap)
		intent = 15;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_generate_go_intent: is_ap=%d is_grp=%d, intent=%d\n",
		is_ap, hdl->is_p2p_group, intent));
	return intent;
}

/* Determine if we should act as an AP or a STA based on the peer's
 * group owner intent, our group owner intent, and both MAC addresses.
 * Outputs the result in hdl->is_ap.
 * Returns: 0=success, BCMP2P_CANT_ACT_AS_AP, or BCMP2P_PEER_HAS_SAME_MAC_ADDR.
 */
BCMP2P_STATUS
p2papi_determine_ap_or_sta(p2papi_instance_t* hdl, bool peer_is_p2p_group)
{
	/* Look at the group owner intent values of ourself and the peer to decide
	 * who will act as the AP in this connection:
	 * - If we are already associated to an AP as a STA then we can only
	 *   act as an AP.
	 * - If both peers are already associated as a STA to an AP then no P2P
	 *   connection is possible since both can only act as APs.
	 * - Otherwise decide based on MAC addresses:
	 *   the one with the greater MAC address will act as the AP.
	 */
	hdl->intent = p2papi_generate_go_intent(hdl);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_ap_or_sta: our intent=%d peer_intent=%d\n",
		hdl->intent, hdl->peer_intent));
	if (hdl->intent > hdl->peer_intent) {
		hdl->is_ap = TRUE;
	} else if (hdl->intent < hdl->peer_intent) {
		hdl->is_ap = FALSE;
	} else if (hdl->intent == 15 && hdl->intent == hdl->peer_intent) {
		/* Reject the connection if both peers have Group Owner-only intent */
		P2PERR("p2papi_ap_or_sta: can't connect, both have GO intent!\n");
		return BCMP2P_BOTH_GROUP_OWNER_INTENT;
	} else if (hdl->intent == hdl->peer_intent) {
		/* Decide to act as an AP or STA based on the Tie Breaker bit we sent.
		 * If we have just received a GONreq
		 *   Our tx tie breaker bit is the inverse of our received GONreq
		 *   breaker bit.
		 * else
		 *   Our tx tie breaker bit is our last sent tie breaker bit.
		 */
		if (hdl->conn_state == P2PAPI_ST_NEG_REQ_RECVD) {
			hdl->tx_tie_breaker = !hdl->rx_tie_breaker;
		}

		/* If our tx Tie Breaker bit is 1, we become the AP */
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_ap_or_sta: state=%u rxtb=%u txtb=%u\n",
			hdl->conn_state, hdl->rx_tie_breaker, hdl->tx_tie_breaker));
		hdl->is_ap = hdl->tx_tie_breaker ? true : false;
	}
	P2PLOG1("p2papi_ap_or_sta: acting as %s\n", (hdl->is_ap ? "AP" : "STA"));
	return BCMP2P_SUCCESS;
}

/* Enable P2P discovery before AF tx channel synchronization */
void
p2papi_chsync_discov_enable(p2papi_instance_t* hdl)
{
	/* If P2P discovery is already in progress
	 *    No need to enable discovery for channel sync
	 * else
	 *    Enable discovery for channel sync
	 */
	if (p2papi_is_discovery_enabled(hdl)) {
		hdl->chsync_discov_enabled = FALSE;
	} else {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_chsync_discov_enable: enabling discovery\n"));
		hdl->chsync_discov_enabled = TRUE;
		p2papi_enable_discovery(hdl);
	}
}

/* Disable P2P discovery after AF tx channel synchronization */
void
p2papi_chsync_discov_disable(p2papi_instance_t* hdl)
{
	/* If P2P discovery was already running before the AF tx channel sync
	 *   Do not turn off discovery.  Re-enable P2P discovery Search.
	 * else (discovery loop is not running)
	 *   if discovery was turned on for channel sync, turn it off.
	 */
	if (hdl->is_discovering) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_chsync_discov_disable: re-enable discov search (cde=%d)\n",
			hdl->chsync_discov_enabled));
		p2papi_discover_enable_search(hdl, TRUE);
	} else {
		if (hdl->chsync_discov_enabled) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_chsync_discov_disable: disabling discovery\n"));
			p2papi_disable_discovery(hdl);
		}
	}
	hdl->chsync_discov_enabled = FALSE;
}

static void
p2papi_gon_end(p2papi_instance_t* hdl)
{
	int ret;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_gon_end\n"));

	/* Disable P2P device discovery if we had enabled it for the
	 * purpose of synchronizing channels with the peer.
	 */
	p2papi_chsync_discov_disable(hdl);

	/* Notify the app of the GO negotiation result */
	p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION,
		hdl->gon_notif);

	/* If GO Negotiation was not successful
	 *     Resume P2P Discovery if discovery is active
	 */
	if (hdl->gon_notif != BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_COMPLETE) {
		p2papi_fsm_reset(hdl);
		if (hdl->is_discovering) {
			BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
				"p2papi_gon_end: call p2papi_discover_enable_search(true)\n"));
			p2papi_discover_enable_search(hdl, BCMP2P_TRUE);
		}
	}

	/* Signal that the GO negotiation is finished, unblocking any
	 * waiting threads.
	 */
	ret = p2papi_osl_signal_go_negotiation(hdl, P2PAPI_OSL_GO_STATE_DONE);
	if (BCMP2P_SUCCESS != ret) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_gon_end: signal GON error %d\n", ret));
	}

}


/* Callback function called when a GONreq action frame tx completes */
static void
p2papi_gonreq_tx_complete_callback(void *handle, p2papi_aftx_instance_t *aftx_hdl,
	BCMP2P_BOOL acked, wl_af_params_t *af_params)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*)handle;

	P2PLIB_ASSERT(P2PAPI_CHECK_P2PHDL(hdl));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_gonreq_tx_complete_callback: acked=%d aftx_hdl=%p,%p\n",
		acked, aftx_hdl, hdl->gon_aftx_hdl));

	/* Do the generic AF tx complete actions */
	p2papi_aftx_complete_callback_core(handle, aftx_hdl, acked, af_params);
	hdl->gon_aftx_hdl = NULL;

	if (acked) {
	}
	else {
		/* Disable P2P device discovery if we had enabled it for the
		 * purpose of synchronizing channels with the peer.
		 */
		p2papi_chsync_discov_disable(hdl);
	}
}

/* Callback function called when a GONrsp-accept action frame tx completes */
static void
p2papi_gonrsp_accept_tx_done_cb(void *handle, p2papi_aftx_instance_t *aftx_hdl,
	BCMP2P_BOOL acked, wl_af_params_t *af_params)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*)handle;
	P2PLIB_ASSERT(P2PAPI_CHECK_P2PHDL(hdl));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_gonrsp_accept_tx_done_cb: acked=%d aftx_hdl=%p,%p\n",
		acked, aftx_hdl, hdl->gon_aftx_hdl));

	/* Do the generic AF tx complete actions */
	p2papi_aftx_complete_callback_core(handle, aftx_hdl, acked, af_params);
	hdl->gon_aftx_hdl = NULL;

	if (acked) {
		/* Notify the app of our AP/STA role */
		p2papi_osl_do_notify_cb(hdl,
			BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION,
			hdl->is_ap ? BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_AP_ACK
					   : BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_STA_ACK);
	}
}

/* Callback function called when a GONrsp-reject frame tx completes */
static void
p2papi_gonrsp_reject_tx_done_cb(void *handle, p2papi_aftx_instance_t *aftx_hdl,
	BCMP2P_BOOL acked, wl_af_params_t *af_params)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*)handle;
	P2PLIB_ASSERT(P2PAPI_CHECK_P2PHDL(hdl));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_gonrsp_reject_tx_done_cb: acked=%d aftx_hdl=%p,%p\n",
		acked, aftx_hdl, hdl->gon_aftx_hdl));

	/* Do the generic AF tx complete actions */
	p2papi_aftx_complete_callback_core(handle, aftx_hdl, acked, af_params);
	hdl->gon_aftx_hdl = NULL;

	/* Resume P2P Discovery if it is active */
	if (hdl->is_discovering) {
		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
		"p2papi_gonrsp_reject_tx_done_cb:call p2papi_discover_enable_search(true)\n"));
		p2papi_discover_enable_search(hdl, TRUE);
	}

}

/* Callback function called when a GONconf action frame tx completes */
static void
p2papi_gonconf_tx_done_cb(void *handle, p2papi_aftx_instance_t *aftx_hdl,
	BCMP2P_BOOL acked, wl_af_params_t *af_params)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*)handle;
	P2PLIB_ASSERT(P2PAPI_CHECK_P2PHDL(hdl));

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_gonconf_tx_done_cb: acked=%d aftx_hdl=%p,%p\n",
		acked, aftx_hdl, hdl->gon_aftx_hdl));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"                         : GON %s, notif=%d\n",
		(hdl->gon_notif == BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_COMPLETE && acked)
		? "completed" : "failed",
		hdl->gon_notif));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "    : aftx_hdl=%p,%p\n",
		aftx_hdl, hdl->gon_aftx_hdl));

	/* Do the generic AF tx complete actions */
	p2papi_aftx_complete_callback_core(handle, aftx_hdl, acked, af_params);
	hdl->gon_aftx_hdl = NULL;

	/* Do the GO Negotiation completion actions */
	p2papi_gon_end(hdl);
}


/* Send the given action frame to the peer after performing the Find Phase's
 * search-listen procedure to arrive on a common channel with the peer.
 * This assumes P2P Discovery is already running in another thread.
 */
int
p2papi_send_at_common_channel(p2papi_instance_t* hdl, BCMP2P_CHANNEL *search_channel,
	wl_af_params_t *tx_act_frame, BCMP2P_AFTX_CALLBACK tx_complete_cb,
	BCMP2P_BOOL do_scans, p2papi_aftx_instance_t** aftx_hdlp,
	const char* dbg_af_name)
{
	uint32 time_used_ms = 0;
	uint32 tmo_ms = P2PAPI_CHANNEL_SYNC_TMO_MS;
	uint32 beacon_interval_ms = 100;
	uint32 search_ms = 50;
	uint32 max_listen_interval = 3;
	uint32 listen_ms = 0;
	uint32 ms;

	/* Store the given action frame to be transmitted when a probe response is
	 * received from the target peer.  The actual transmit is done in
	 * p2papi_fsm_send_pending_tx_act_frm().
	 */
	hdl->pending_tx_act_frm = tx_act_frame;
	hdl->pending_tx_complete_cb = tx_complete_cb;
	memcpy(hdl->pending_tx_dst_addr.octet, tx_act_frame->BSSID.octet,
		sizeof(hdl->pending_tx_dst_addr.octet));
	memcpy(&hdl->pending_tx_dst_listen_chan, search_channel,
		sizeof(hdl->pending_tx_dst_listen_chan));
	hdl->pending_tx_dbg_name = dbg_af_name;
	hdl->pending_tx_aftx_hdlp = aftx_hdlp;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_send_comm_ch: begin, st=%d ch=%d:%d do=%d txaf=%p tmo=%u\n",
		hdl->conn_state, hdl->pending_tx_dst_listen_chan.channel_class,
		hdl->pending_tx_dst_listen_chan.channel, do_scans,
		hdl->pending_tx_act_frm, tmo_ms));

	p2papi_chsync_discov_enable(hdl);

	/* If we are doing our own search-listen find phase here in this fn
	 *    Disable the search-listen find phase in the Discovery thread's
	 *    p2papi_discover().
	 * else
	 *    Enable the search-listen find phase in the Discovery thread's
	 *    p2papi_discover().
	 */
	BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
		"p2papi_send_common_ch: call p2papi_discover_enable_search(%d)\n",
		!do_scans));
	p2papi_discover_enable_search(hdl, !do_scans);

	/* Enable reception of the probe request WLC event */
	(void) p2papi_enable_driver_events(hdl, TRUE);

	/* Loop to wait until we have sent the pending tx action frame or the
	 * pending action frame tx is cancelled.
	 */
	while (time_used_ms < tmo_ms && hdl->pending_tx_act_frm != NULL) {
		if (do_scans) {
			/* Search state - send out probe reqs.
			 * NOTE: while we are blocked in the call to
			 * p2papi_go_neg_search(), we could receive a GONREQ action frame.
			 * This race condition is handled in p2papi_fsm_rx_go_neg_frame().
			 */
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"    p2papi_send_comm_ch: search, ms=%u ch=%d:%d ptaf=%p\n",
				search_ms, search_channel->channel_class,
				search_channel->channel, hdl->pending_tx_act_frm));
			ms = p2papi_go_neg_search(hdl, search_ms, search_channel);
			time_used_ms += ms;

			/* Check all loop exit conditions here in case any of them became
			 * true while we were waiting for the Search state.  The Listen
			 * state below takes a long time to complete.  We want to exit the
			 * loop ASAP if any loop exit conditions are already true.
			 */
			if (!(time_used_ms < tmo_ms && hdl->pending_tx_act_frm != NULL)) {
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"p2papi_send_comm_ch: after search, time_used=%u of %u\n",
					time_used_ms, ms));
				break;
			}

			/* Listen state - while we are blocked in the call to
			 * p2papi_go_neg_listen(), we could receive a probe req/rsp from
			 * the peer.  That is handled in p2papi_fsm_send_pending_tx_act_frm
			 * where we send to the peer the GONREQ action frame previously
			 * prepared by p2papi_fsm_tx_go_neg_req().
			 */
			listen_ms = (1 + (p2papi_osl_random() % max_listen_interval))
				* beacon_interval_ms;
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"    p2papi_send_comm_ch: listen, ms=%u ch=%d:%d ptaf=%p\n",
				listen_ms, hdl->listen_channel.channel_class,
				hdl->listen_channel.channel, hdl->pending_tx_act_frm));
			p2papi_go_neg_listen(hdl, &hdl->listen_channel, (uint16) listen_ms);
			time_used_ms += listen_ms;
		} else {
			BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
				"    p2papi_send_comm_ch: do nothing, dse=%d ptaf=%p\n",
				hdl->discovery_search_enabled, hdl->pending_tx_act_frm));
			p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_GENERIC, 100);
			time_used_ms += 100;
		}
	}

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_send_comm_ch: end, state=%d ptaf=%p time_used=%u\n",
		hdl->conn_state, hdl->pending_tx_act_frm, time_used_ms));

	/* Disable reception of the probe request WLC event */
	(void) p2papi_enable_driver_events(hdl, FALSE);

	/* if we enabled P2P device discovery to sync channels and nothing was
	 * sent (a timeout occurred)
	 *     Disable driver P2P device discovery
	 * (else driver P2P device discovery will be disabled upon receiving
	 * the WLC_E_ACTION_FRAME_COMPLETE event.)
	 */
	if (time_used_ms >= tmo_ms) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_send_comm_ch: timeout\n"));
		p2papi_cancel_send_at_common_channel(hdl);
		p2papi_chsync_discov_disable(hdl);
	}

	return 0;
}

int
p2papi_cancel_send_at_common_channel(p2papi_instance_t* hdl)
{
	void *freed = NULL;

	P2PAPI_DATA_LOCK_VERB(hdl);
	if (hdl->pending_tx_act_frm) {
		P2PAPI_FREE(hdl->pending_tx_act_frm);
		freed = hdl->pending_tx_act_frm;
		hdl->pending_tx_act_frm = NULL;
	}
	P2PAPI_DATA_UNLOCK_VERB(hdl);

	if (freed)
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_cancel_send_at_common_channel: freed %p\n", freed));
	return 0;
}

static wl_af_params_t *
build_action_frame(int category, int action_field,
	p2papi_instance_t* hdl, struct ether_addr *dst_ea,
	uint8 *oui, uint8 oui_type, uint8 oui_subtype, uint8 dialog_token,
	uint8 *ie, uint16 ie_len, uint8 *ie2, uint16 ie2_len,uint8 *ie3, uint16 ie3_len,
	BCMP2P_CHANNEL *channel, int32 dwell_time_ms)
{
	wifi_p2p_action_frame_t *af_data;
	wifi_p2p_pub_act_frame_t *paf_data;
	uint16 frame_data_len;
	wl_action_frame_t *action_frame;
	wl_af_params_t *af_params;
	uint8 *elts;

	P2PAPI_CHECK_P2PHDL(hdl);
	P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "build_action_frame: "
		"oui=%02x:%02x:%02x typ=%u sub=%u, ielen=%u len2=%u\n",
		oui[0], oui[1], oui[2], oui_type, oui_subtype, ie_len, ie2_len));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "    ch=%d:%d dwell=%d "
		"cat=%d tok=%u dst_ea=%02x:%02x:%02x:%02x:%02x:%02x\n",
		channel->channel_class, channel->channel,
		dwell_time_ms, category, dialog_token,
		dst_ea->octet[0], dst_ea->octet[1], dst_ea->octet[2],
		dst_ea->octet[3], dst_ea->octet[4], dst_ea->octet[5]));

	af_params = (wl_af_params_t*) P2PAPI_MALLOC(sizeof(*af_params));
	if (af_params == NULL) {
		P2PERR("build_action_frame: can't allocate action frame\n");
		return NULL;
	}
	action_frame = &af_params->action_frame;

	/* Add the packet Id */
	action_frame->packetId = (uint32) (uintptr)action_frame;

	/* Fill in the destination MAC addr */
	memcpy(&action_frame->da, dst_ea, ETHER_ADDR_LEN);

	/* Fill action frame or public action frame */
	if (category == P2P_AF_CATEGORY) {
		af_data = (wifi_p2p_action_frame_t*) action_frame->data;
		frame_data_len = 7; /* length not including IEs */
		af_data->category = category;
		af_data->OUI[0] = oui[0];
		af_data->OUI[1] = oui[1];
		af_data->OUI[2] = oui[2];
		af_data->type = oui_type;
		af_data->subtype = oui_subtype;
		af_data->dialog_token = dialog_token;
		elts = af_data->elts;
	}
	else {
		paf_data = (wifi_p2p_pub_act_frame_t*) action_frame->data;
		frame_data_len = 8; /* length not including IEs */
		paf_data->category = category;
		paf_data->action = action_field;
		paf_data->oui[0] = oui[0];
		paf_data->oui[1] = oui[1];
		paf_data->oui[2] = oui[2];
		paf_data->oui_type = oui_type;
		paf_data->subtype = oui_subtype;
		paf_data->dialog_token = dialog_token;
		elts = paf_data->elts;
	}

	/* Add the 1st set of IE data */
	if (ie_len > 0) {
		if (ie_len + frame_data_len > ACTION_FRAME_SIZE) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"build_action_frame: AF len %u+%u too large!\n",
				frame_data_len, ie_len));
			P2PAPI_FREE(af_params);
			return NULL;
		}
		memcpy(elts, ie, ie_len);
		frame_data_len += ie_len;
	}

	/* Add the 2nd set of IE data */
	if (ie2_len > 0) {
		if (ie2_len + frame_data_len > ACTION_FRAME_SIZE) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"build_action_frame: AF len2 %u+%u too large!\n",
				frame_data_len, ie2_len));
			P2PAPI_FREE(af_params);
			return NULL;
		}
		memcpy(elts + ie_len, ie2, ie2_len);
		frame_data_len += ie2_len;
	}

	if (ie3_len > 0) {
		if (ie3_len + frame_data_len > ACTION_FRAME_SIZE) {
			BCMP2PLOG((BCMP2P_LOG_ALWAYS, TRUE,
				"build_action_frame: AF len3 %u+%u too large!\n",
				frame_data_len, ie3_len));
			P2PAPI_FREE(af_params);
			return NULL;
		}
		memcpy(elts + ie_len + ie2_len, ie3, ie3_len);
		frame_data_len += ie3_len;
	}

	action_frame->len = frame_data_len;
	af_params->channel = channel->channel;
	af_params->dwell_time = dwell_time_ms;
	memcpy(af_params->BSSID.octet, dst_ea, sizeof(af_params->BSSID));

	return af_params;
}

wl_af_params_t *
p2plib_build_p2p_act_frm(p2papi_instance_t* hdl, struct ether_addr *dst_ea,
	uint8 *oui, uint8 oui_type, uint8 oui_subtype, uint8 dialog_token,
	uint8 *ie, uint16 ie_len, uint8 *ie2, uint16 ie2_len, uint8 *ie3, uint16 ie3_len,
	BCMP2P_CHANNEL *channel, int32 dwell_time_ms)
{
	return build_action_frame(P2P_AF_CATEGORY, 0,
		hdl, dst_ea, oui, oui_type, oui_subtype, dialog_token,
		ie, ie_len, ie2, ie2_len, ie3, ie3_len, channel, dwell_time_ms);
}

/* Build an action frame that is formatted like a P2P public action frame.
 * The frame will be a valid P2P public action frame if 'oui' is P2P_OUI
 * and 'oui_type' is P2P_VER.
 *
 * Returns a pointer to the created action frame if succes, NULL if failure.
 * The caller is responsible for freeing the returned action frame.
 */
wl_af_params_t *
p2plib_build_p2p_pub_act_frm(p2papi_instance_t* hdl, struct ether_addr *dst_ea,
	uint8 *oui, uint8 oui_type, uint8 oui_subtype, uint8 dialog_token,
	uint8 *ie, uint16 ie_len, uint8 *ie2, uint16 ie2_len, uint8 *ie3, uint16 ie3_len, BCMP2P_CHANNEL *channel,
	int32 dwell_time_ms)
{
	return build_action_frame(P2P_PUB_AF_CATEGORY, P2P_PUB_AF_ACTION,
		hdl, dst_ea, oui, oui_type, oui_subtype, dialog_token,
		ie, ie_len, ie2, ie2_len, ie3, ie3_len, channel, dwell_time_ms);
}

/* Send an action frame immediately without doing channel synchronization.
 *
 * This function does not wait for a completion event before returning.
 * The WLC_E_ACTION_FRAME_COMPLETE event will be received when the action
 * frame is transmitted.
 * The WLC_E_ACTION_FRAME_OFFCHAN_COMPLETE event will be received when an
 * 802.11 ack has been received for the sent action frame.
 */
int
p2papi_tx_af(p2papi_instance_t* hdl, wl_af_params_t *af_params, int bssidx)
{
	wl_action_frame_t *action_frame = &af_params->action_frame;
	int err;

	if (hdl->is_in_discovery_disable) { 
	   printf("@@@@%s: prevented stale actframe tx\n"); 
	   BCMP2PLOG((BCMP2P_LOG_MED, TRUE, 
		   "p2papi_tx_af: disallowed stale actframe tx\n")); 
	   return BCME_NOTFOUND; 
	} 

	/* Suspend P2P discovery search-listen to prevent it from changing the
	 * channel.
	 */
	BCMP2PLOG((BCMP2P_LOG_VERB, TRUE, "p2papi_tx_af:p2papi_discover_enable_search(false)\n"));
	p2papi_discover_enable_search(hdl, FALSE);

	/* Abort the dwell time of any previous off-channel action frame that may
	 * be still in effect.  Sending off-channel action frames relies on the
	 * driver's scan engine.  If a previous off-channel action frame tx is
	 * still in progress (including the dwell time), then this new action
	 * frame will not be sent out.
	 */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_tx_af: do scan abort\n"));
	p2pwlu_scan_abort(hdl, FALSE);


	/* Send the action frame */
	p2papi_log_hexdata(BCMP2P_LOG_MED, "TX action frame",
		action_frame->data, action_frame->len);
	err = p2pwlu_send_act_frame(hdl, af_params, bssidx);
	return err;
}



/* Clear the duplicate rx action frame detector */
void
p2papi_clear_duplicate_rx_actframe_detect(p2papi_instance_t* hdl)
{
	hdl->prev_rx_frame_subtype = 0;
	hdl->prev_rx_dialog_token = 0;
	memset(hdl->prev_rx_src_mac.octet, 0, sizeof(hdl->prev_rx_src_mac));
}

/* Check if a received frame is a duplicate of the previously received frame */
BCMP2P_BOOL
p2papi_is_duplicate_rx_frame(p2papi_instance_t *hdl,
	struct ether_addr *src_mac, uint8 frame_subtype, uint8 dialog_token)
{
	bool match = FALSE;

	/* If the frame's key fields matches the previously received frame's */
	if (frame_subtype == hdl->prev_rx_frame_subtype &&
		dialog_token == hdl->prev_rx_dialog_token &&
		memcmp(src_mac->octet, hdl->prev_rx_src_mac.octet,
		sizeof(src_mac->octet)) == 0) {
		match = TRUE;
	/* else overwrite the previous received frame key fields with the
	 * information from this frame
	 */
	} else {
		hdl->prev_rx_frame_subtype = frame_subtype;
		hdl->prev_rx_dialog_token = dialog_token;
		memcpy(hdl->prev_rx_src_mac.octet, src_mac->octet,
			sizeof(src_mac->octet));
	}

	return match;
}


/* Build a Group Owner Negotiation P2P public action frame */
static wl_af_params_t*
p2plib_build_go_neg_frame(p2papi_instance_t* hdl, struct ether_addr *dst_ea,
	uint8 frame_type, uint8 intent, uint8 status, BCMP2P_CHANNEL *op_channel,
	BCMP2P_CHANNEL *tx_channel, uint8 dialog_token, uint16 dev_pwd_id)
{
	wifi_p2p_ie_t *p2p_ie;
	uint16 p2p_ie_len = 0;
	p2papi_p2p_ie_enc_t *wps_ie;
	uint16 wps_ie_len = 0;
	wl_af_params_t *af_params;
	uint8 *custom_ie;
	uint16 custom_ie_len = 0;

	/* Add the Tie Breaker bit to the GON req/rsp Intent value */
	intent <<= 1;
	if (frame_type == P2P_PAF_GON_REQ) {
		/* GONreq: use current tie breaker bit.  This bit will be toggled only
		 * on each new GON, not on GONreq retransmits.
		 */
		if (hdl->tx_tie_breaker)
			intent |= 0x1;

		custom_ie = hdl->custom_acf_ie[BCMP2P_ACF_IE_FLAG_GONREQ].ie_buf;
		custom_ie_len = hdl->custom_acf_ie[BCMP2P_ACF_IE_FLAG_GONREQ].ie_buf_len;

	} else if (frame_type == P2P_PAF_GON_RSP) {
		/* GONrsp: use inverse of tie breaker bit from received GONreq */
		if (!hdl->rx_tie_breaker)
			intent |= 0x1;

		custom_ie = hdl->custom_acf_ie[BCMP2P_ACF_IE_FLAG_GONRSP].ie_buf;
		custom_ie_len = hdl->custom_acf_ie[BCMP2P_ACF_IE_FLAG_GONRSP].ie_buf_len;
	}
	else {
		/* GON Confirmation frame */
		custom_ie = hdl->custom_acf_ie[BCMP2P_ACF_IE_FLAG_GONCONF].ie_buf;
		custom_ie_len = hdl->custom_acf_ie[BCMP2P_ACF_IE_FLAG_GONCONF].ie_buf_len;
	}

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2plib_bld_gon_frm: dt=%u txtb=%d rxtb=%d status=%u\n",
		hdl->gon_dialog_token, hdl->tx_tie_breaker, hdl->rx_tie_breaker,
		status));

	p2p_ie = (wifi_p2p_ie_t*) P2PAPI_MALLOC(WL_WIFI_ACTION_FRAME_SIZE);
	if (frame_type == P2P_PAF_GON_REQ) {
		p2papi_encode_gon_req_p2p_ie(hdl, intent, &hdl->listen_channel,
			op_channel, status, hdl->p2p_dev_addr.octet,
			hdl->extended_listen.enabled,
			hdl->extended_listen.period, hdl->extended_listen.interval,
			hdl->country, p2papi_get_non_dfs_channel_list(hdl),
			hdl->fname_ssid, hdl->fname_ssid_len, p2p_ie, &p2p_ie_len);
	} else if (frame_type == P2P_PAF_GON_RSP) {
		p2papi_encode_gon_rsp_p2p_ie(hdl,
			hdl->credentials.ssid,
			hdl->is_ap ? strlen(hdl->credentials.ssid) : 0,
			intent, op_channel, status,
			hdl->p2p_dev_addr.octet,
			hdl->country, &hdl->negotiated_channel_list,
			hdl->fname_ssid, hdl->fname_ssid_len, p2p_ie, &p2p_ie_len);
	} else {	/* frame_type == P2P_PAF_GON_CONF */
		p2papi_encode_gon_conf_p2p_ie(hdl, intent, op_channel, status,
			hdl->p2p_dev_addr.octet,
			hdl->country, &hdl->negotiated_channel_list,
			hdl->credentials.ssid,
			hdl->is_ap ? strlen(hdl->credentials.ssid) : 0,
			p2p_ie, &p2p_ie_len);
	}
	p2papi_log_hexdata(BCMP2P_LOG_VERB, "GON P2P IE", (uint8*) p2p_ie,
		p2p_ie_len);

	wps_ie = (p2papi_p2p_ie_enc_t*) P2PAPI_MALLOC(sizeof(*wps_ie));
	p2papi_encode_gon_wps_ie(hdl, wps_ie, hdl->fname_ssid, hdl->fname_ssid_len,
		FALSE, 0, dev_pwd_id, &wps_ie_len);

	/* CUSTOM_IE: Attach custom IE GON frame */
	P2PLOG1("p2plib_build_go_neg_frame: custom_ie_len=%d\n", custom_ie_len);
	p2papi_log_hexdata(BCMP2P_LOG_VERB, "p2plib_build_go_neg_frame: Custom IE",
		custom_ie, custom_ie_len);

	af_params = p2plib_build_p2p_pub_act_frm(hdl, dst_ea, (uint8*) P2P_OUI,
		P2P_VER, frame_type, dialog_token, (uint8*)p2p_ie, p2p_ie_len,
		(uint8*)&wps_ie->id, wps_ie_len, custom_ie, custom_ie_len,
		tx_channel, P2PAPI_AF_DWELL_TIME);

	P2PAPI_FREE(p2p_ie);
	P2PAPI_FREE(wps_ie);
	return af_params;
}

/* Create and send a Group Owner Negotiation P2P public action frame */
static int
p2plib_send_go_neg_frame(p2papi_instance_t* hdl, struct ether_addr *dst_ea,
	uint8 frame_type, uint8 intent, uint8 status, BCMP2P_CHANNEL *op_channel,
	BCMP2P_CHANNEL *tx_channel, uint8 dialog_token, uint16 dev_pwd_id,
	BCMP2P_AFTX_CALLBACK tx_complete_cb)
{
	int err = -1;
	wl_af_params_t *af_params;

	if (hdl->gon_aftx_hdl != NULL) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2plib_send_go_neg_frame: Nested af tx!\n"));
	}

	af_params = p2plib_build_go_neg_frame(hdl, dst_ea, frame_type, intent,
		status, op_channel, tx_channel, dialog_token, dev_pwd_id);
	if (af_params) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2plib_send_go_neg_frame: Sending GON AF\n"));
		hdl->gon_aftx_hdl = p2papi_aftx_send_frame(hdl, af_params,
			hdl->bssidx[P2PAPI_BSSCFG_DEVICE], hdl->af_tx_max_retries,
			hdl->af_tx_retry_ms, tx_complete_cb, (void*)hdl, "gon");
		P2PLIB_ASSERT(hdl->gon_aftx_hdl != NULL);
	}

	return err;
}


/* Group Owner Negotiation FSM: Reset the GO negotiation FSM. */
int
p2papi_fsm_reset(p2papi_instance_t* hdl)
{
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_fsm_reset\n"));
	hdl->conn_state = P2PAPI_ST_IDLE;

	/* Set a default value for the peer intent.  This will be overwritten
	 * when we receive a peer's GO negotiation frame.
	 */
	hdl->peer_intent = 8;

	/* Clear the GON duplicate rx frame detection history */
	p2papi_clear_duplicate_rx_actframe_detect(hdl);

	/* Reset hdl->af_last_src_mac */
	memset(hdl->af_last_src_mac.octet, 0, sizeof(hdl->af_last_src_mac.octet));

	return 0;
}

/* Group Owner Negotiation FSM: abort any GO negotiation in progress. */
void
p2papi_fsm_abort(p2papi_instance_t* hdl)
{
	if (hdl->conn_state == P2PAPI_ST_START_NEG ||
		hdl->conn_state == P2PAPI_ST_NEG_REQ_SENT ||
		hdl->conn_state == P2PAPI_ST_NEG_RSP_SENT) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_fsm_abort: unblocking GO negotiation wait.\n"));
		(void) p2papi_osl_signal_go_negotiation(hdl,
			P2PAPI_OSL_GO_STATE_CANCEL);
	}
}

/* Group Owner Negotiation FSM:
 * Start a GO negotiation by sending a GO negotiation request to the peer.
 * Parameters:
 *   peer_mac - Destination device's ethernet address
 *   intent - Group Owner intent of this device on a scale of 0 to 15.
 *            0 means this device can only be a client.
 *            15 means this device can only be a group owner.
 *   peer_listen_channel - channel to send probe requests on during the
 *                         channel synchronization Search/Listen procedure.
 */
int
p2papi_fsm_tx_go_neg_req(p2papi_instance_t* hdl, struct ether_addr *peer_mac,
	bool send_immed, BCMP2P_CHANNEL *peer_listen_channel)
{
	wl_af_params_t *af_params;
	int status;

	/* If we are not in the idle state
	 *    Disallow starting a GO negotiation.
	 */
	if (!(hdl->conn_state == P2PAPI_ST_START_NEG ||
		hdl->conn_state == P2PAPI_ST_NEG_REQ_SENT)) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_fsm_tx_go_neg_req: not allowed in state %d\n",
			hdl->conn_state));
		return -1;
	}

	/* Generate our group owner intent value */
	hdl->intent = p2papi_generate_go_intent(hdl);

	/* Generate the dialog token for this req/rsp transaction */
	hdl->gon_dialog_token = p2papi_create_dialog_token(hdl->gon_dialog_token);

	if (send_immed) {
		/* Send a GO Negotiation Request action frame */
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_fsm_tx_go_neg_req: sending GONREQ dt=%u\n",
			hdl->gon_dialog_token));
		status = p2plib_send_go_neg_frame(hdl, peer_mac, P2P_PAF_GON_REQ,
			hdl->intent, P2P_STATSE_SUCCESS, &hdl->op_channel,
			&hdl->gon_channel, hdl->gon_dialog_token, hdl->wps_device_pwd_id,
			p2papi_gonreq_tx_complete_callback);
		if (0 != status) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
				"p2papi_fsm_tx_go_neg_req failed, err=%d\n", status));
			return status;
		} else {
			/* If successful, change to Negotiation Request Sent state */
			hdl->conn_state = P2PAPI_ST_NEG_REQ_SENT;

			p2papi_osl_do_notify_cb(hdl,
				BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION,
				BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_START);
		}
	} else {
		/* Build the GON request action frame */
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_fsm_tx_go_neg_req: bld GONREQ plch=%d:%d gonch=%d:%d opch=%d:%d\n",
			peer_listen_channel->channel_class, peer_listen_channel->channel,
			hdl->gon_channel.channel_class, hdl->gon_channel.channel,
			hdl->op_channel.channel_class, hdl->op_channel.channel));
		if (hdl->gon_aftx_hdl != NULL) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
				"p2papi_fsm_tx_go_neg_req: Nested af tx!\n"));
		}
		af_params = p2plib_build_go_neg_frame(hdl, peer_mac, P2P_PAF_GON_REQ,
			hdl->intent, P2P_STATSE_SUCCESS, &hdl->op_channel,
			&hdl->gon_channel, hdl->gon_dialog_token, hdl->wps_device_pwd_id);
		if (!af_params) {
			return -3;
		}

		/* Enter the GONreq-Sent state to wait for the GONrsp */
		hdl->conn_state = P2PAPI_ST_NEG_REQ_SENT;

		/* Enqueue the frame to be sent after arriving on a common channel
		 * with the peer.
		 */
		status = p2papi_send_at_common_channel(hdl, peer_listen_channel,
			af_params, p2papi_gonreq_tx_complete_callback, BCMP2P_TRUE,
			&hdl->gon_aftx_hdl, "gon");

		/* Notify the app that GON has started */
		p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION,
			BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_START);
	}
	return status;
}

/* Group Owner Negotiation FSM:
 * Accept a received Group Owner Negotiation request by sending a Group Owner
 * Negotiation Response frame with a status of success.
 */
BCMP2P_STATUS
p2papi_fsm_accept_negotiation(p2papi_instance_t* hdl,
	PBCMP2P_DISCOVER_ENTRY pPeerInfo, uint16 dev_pwd_id)
{
	if (!hdl->enable_p2p)
		return BCMP2P_ERROR;

	BCMP2PLOG((BCMP2P_LOG_VERB, TRUE, "Enter p2papi_fsm_accept_negotiation\n"));

	if (pPeerInfo != NULL) {
		memcpy(&hdl->peer_dev_addr, &pPeerInfo->mac_address,
			sizeof(hdl->peer_dev_addr));
	}

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;
	P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl);

	/* Disallow this negotiation accept if we are not in the Negotiation
	 * Request Received state.
	 */
	if (hdl->conn_state != P2PAPI_ST_NEG_REQ_RECVD) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_fsm_accept_neg: not in NEG_REQ_RECVD state (state=%d)!\n",
			hdl->conn_state));
		return BCMP2P_NO_GO_NEGOTIATE_REQ;
	}

	/* The GONRSP frame must be sent on the channel that the GONREQ frame
	 * was received on.
	 */
	if (hdl->gon_channel.channel == 0) {
		memcpy(&hdl->gon_channel, &hdl->default_listen_channel,
			sizeof(hdl->gon_channel));
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_fsm_accept_neg: no GON channel! Using %d:%d\n",
			hdl->gon_channel.channel_class, hdl->gon_channel.channel));
	}

	/* Send a GO Negotiation Response action frame to the peer */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_fsm_accept_neg: sending GONRSP intent=%u ch=%d:%d dt=%u stat=%u\n",
		hdl->intent, hdl->gon_channel.channel_class, hdl->gon_channel.channel,
		hdl->gon_dialog_token, P2P_STATSE_SUCCESS));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"  to peer_dev_addr=%02x:%02x:%02x:%02x:%02x:%02x\n",
		hdl->peer_dev_addr.octet[0], hdl->peer_dev_addr.octet[1],
		hdl->peer_dev_addr.octet[2], hdl->peer_dev_addr.octet[3],
		hdl->peer_dev_addr.octet[4], hdl->peer_dev_addr.octet[5]));
	p2plib_send_go_neg_frame(hdl, &hdl->peer_dev_addr, P2P_PAF_GON_RSP,
		hdl->intent, P2P_STATSE_SUCCESS, &hdl->op_channel,
		&hdl->gon_channel, hdl->gon_dialog_token, dev_pwd_id,
		p2papi_gonrsp_accept_tx_done_cb);

	/* Change our connection state to Negotiation Response Sent */
	hdl->conn_state = P2PAPI_ST_NEG_RSP_SENT;

	return BCMP2P_SUCCESS;
}

/* Group Owner Negotiation FSM:
 * Reject a group owner negotiation by sending a GO Negotiation Response
 * frame with a status of failure.
 */
BCMP2P_STATUS
p2papi_fsm_reject_negotiation(p2papi_instance_t* hdl,
	wifi_p2p_pub_act_frame_t *act_frm, uint8 reason,
	PBCMP2P_DISCOVER_ENTRY pPeerInfo, uint16 dev_pwd_id)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	if (!hdl->enable_p2p)
		return BCMP2P_ERROR;

	BCMP2PLOG((BCMP2P_LOG_VERB, TRUE, "Enter p2papi_fsm_reject_negotiation\n"));

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	/* Send a GO Negotiation Response action frame to the peer */
	p2plib_send_go_neg_frame(hdl, &hdl->peer_dev_addr, P2P_PAF_GON_RSP,
		hdl->intent, reason, &hdl->op_channel, &hdl->gon_channel,
		act_frm->dialog_token, dev_pwd_id, p2papi_gonrsp_reject_tx_done_cb);

	/* Change our connection state to Idle regardless of whether the tx
	 * succeeds or fails.
	 */
	p2papi_fsm_reset(hdl);
	return BCMP2P_SUCCESS;
}

/* Decode a GO Negotiation action frame's P2P IE.
 * Input: act_frm
 * Output: p2p_ie, ie_len
 */
int
p2papi_fsm_decode_p2p_ie(p2papi_instance_t* hdl,
	wifi_p2p_pub_act_frame_t *act_frm,
	p2papi_p2p_ie_t *p2p_ie, uint16 *ie_len)
{
	memset(p2p_ie, 0, sizeof(*p2p_ie));
	*ie_len = p2papi_decode_p2p_ie(act_frm->elts, p2p_ie, BCMP2P_LOG_VERB);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_fsm_decode_p2p_ie: P2P IE\n"));

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"    status_se: len=%u status=0x%02x\n",
		p2papi_decode_p2p_ie_length(p2p_ie->status_subelt.len),
		p2p_ie->status_subelt.status));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"    minorrc_se: len=%u rc=%u\n",
		p2papi_decode_p2p_ie_length(p2p_ie->minor_rc_subelt.len),
		p2p_ie->minor_rc_subelt.minor_rc));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"    capability_se: len=%u bm=0x%02x\n",
		p2papi_decode_p2p_ie_length(p2p_ie->capability_subelt.len),
		p2p_ie->capability_subelt.dev));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"    devid_se: len=%u addr=%02x:%02x:%02x:%02x:%02x:%02x\n",
		p2papi_decode_p2p_ie_length(p2p_ie->devid_subelt.len),
		p2p_ie->devid_subelt.addr.octet[0], p2p_ie->devid_subelt.addr.octet[1],
		p2p_ie->devid_subelt.addr.octet[2], p2p_ie->devid_subelt.addr.octet[3],
		p2p_ie->devid_subelt.addr.octet[4],
		p2p_ie->devid_subelt.addr.octet[5]));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"    intent_se: len=%u intent=0x%x\n",
		p2papi_decode_p2p_ie_length(p2p_ie->intent_subelt.len),
		p2p_ie->intent_subelt.intent));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"    cfg_tmo_se: len=%u go_tmo=%u client_tmo=%u\n",
		p2papi_decode_p2p_ie_length(p2p_ie->cfg_tmo_subelt.len),
		p2p_ie->cfg_tmo_subelt.go_tmo,
		p2p_ie->cfg_tmo_subelt.client_tmo));

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"    listen_chan_se: len=%u chan=%u\n",
		p2papi_decode_p2p_ie_length(p2p_ie->listen_chan_subelt.len),
		p2p_ie->listen_chan_subelt.channel));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"    op_chan_se: len=%u chan=%u\n",
		p2papi_decode_p2p_ie_length(p2p_ie->op_chan_subelt.len),
		p2p_ie->op_chan_subelt.channel));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"    devinfo_se: len=%u mac=%02x:%02x:%02x:%02x:%02x:%02x name=%s\n",
		p2papi_decode_p2p_ie_length(p2p_ie->devinfo_subelt.len),
		p2p_ie->devinfo_subelt.mac[0], p2p_ie->devinfo_subelt.mac[1],
		p2p_ie->devinfo_subelt.mac[2], p2p_ie->devinfo_subelt.mac[3],
		p2p_ie->devinfo_subelt.mac[4], p2p_ie->devinfo_subelt.mac[5],
		p2p_ie->devinfo_name));

	return 0;
}


/* Search for and decode P2P and WPS IEs in the given GON IE data.
 * Currently only correctly handles at most 1 P2P IE and 1 WPS IE.
 * If IEs found, copies the IE data into out_p2p_ie and out_wps_ie.
 * Returns 0 if any P2P or WPS IEs were found and decoded.
 */
int
p2papi_decode_p2pwps_ies(uint8* data, uint32 data_len,
	p2papi_p2p_ie_t *out_p2p_ie, p2papi_wps_ie_t *out_wps_ie)
{
	int ret = -1;
	uint8 *ie = data;
	uint buflen = data_len;
	uint ielen = 0;
	BCMP2P_LOG_LEVEL log = BCMP2P_LOG_VERB;

	p2papi_log_hexdata(BCMP2P_LOG_MED, "p2papi_decode_p2pwps_ies", ie, buflen);

	memset(out_p2p_ie, 0, sizeof(*out_p2p_ie));
	memset(out_wps_ie, 0, sizeof(*out_wps_ie));

	while ((ie = p2papi_parse_tlvs(ie, &buflen, &ielen, DOT11_MNG_PROPR_ID, log))) {
		if (p2papi_is_p2p_ie(ie)) {
			ret = 0;
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_decode_p2pwps_ies: found P2P IE, len=%u offset=%d\n",
				ielen, ie - data));
			p2papi_decode_p2p_ie(ie, out_p2p_ie, log);
		}
		else if (p2papi_is_wps_ie(ie)) {
			ret = 0;
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_decode_p2pwps_ies: found WPS IE, len=%u offset=%d\n",
				ielen, ie - data));
			(void) p2papi_decode_wps_ie(ie, out_wps_ie, log);
		}
		ie = p2papi_next_tlv(ie, &buflen);
	}

	return ret;
}

/* convert from GON request device password id to GON response device password id */
static uint16
gon_resp_dev_pwd_id(uint16 gon_req_dev_pwd_id)
{
	uint16 dev_pwd_id = BCMP2P_WPS_DEFAULT;
	if (gon_req_dev_pwd_id == BCMP2P_WPS_REG_SPEC)
		dev_pwd_id = BCMP2P_WPS_USER_SPEC;
	else if (gon_req_dev_pwd_id == BCMP2P_WPS_USER_SPEC)
		dev_pwd_id = BCMP2P_WPS_REG_SPEC;
	else if (gon_req_dev_pwd_id == BCMP2P_WPS_PUSH_BTN)
		dev_pwd_id = BCMP2P_WPS_PUSH_BTN;

	return dev_pwd_id;
}

/* Log a channel list
 */
void
p2papi_log_chanlist(p2p_chanlist_t* list, char *prefix_str)
{
	int i, k;

	for (i = 0; i < list->num_entries; i++) {
		p2p_chanlist_entry_t *se = &list->entries[i];
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "%s [band %u] ",
			prefix_str, se->band));
		for (k = 0; k < se->num_channels; k++) {
			BCMP2PLOG((BCMP2P_LOG_MED, FALSE, "%u ", se->channels[k]));
		}
		BCMP2PLOG((BCMP2P_LOG_MED, FALSE, "\n"));
	}
}

/* Group Owner Negotiation FSM: process a received GONREQ that starts an
 * incoming GO negotiation.
 * Parameters:
 *   act_frm - received GONREQ wifi action frame
 *   act_frm_len - length of received wifi action frame
 */
static int
p2papi_fsm_start_incoming_gon(p2papi_instance_t* hdl,
	wifi_p2p_pub_act_frame_t *act_frm, uint32 act_frm_len,
	BCMP2P_CHANNEL *channel)
{
	int ret = 0;
	uint32 ie_len = act_frm_len - P2P_PUB_AF_FIXED_LEN;
	p2papi_p2p_ie_t p2p_ie;
	p2papi_wps_ie_t wps_ie;
	BCMP2P_STATUS status = BCMP2P_SUCCESS;
	BCMP2P_BOOL our_persist_grp_cap = FALSE;
	BCMP2P_BOOL peer_persist_grp_cap = FALSE;
	BCMP2P_BOOL strict_persistence_match = FALSE;
	uint8 reason;
	BCMP2P_NOTIFICATION_CODE code;
	BCMP2P_BOOL is_sta, is_ap;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_fsm_start_incoming_gon: aflen=%u\n", act_frm_len));

	/* If we are already in a P2P connection, reject the incoming connection */
	is_sta = p2papi_is_sta(hdl);
	is_ap = p2papi_is_ap(hdl);

	/* Decode the GO Negotiation action frame's P2P and WPS IEs */
	(void) p2papi_decode_p2pwps_ies(act_frm->elts, ie_len, &p2p_ie, &wps_ie);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_fsm_start_inc_gon: int=0x%02x stat=%d opch=%d(b=%d) lch=%d\n",
		p2p_ie.intent_subelt.intent, p2p_ie.status_subelt.status,
		p2p_ie.op_chan_subelt.channel, p2p_ie.op_chan_subelt.band,
		p2p_ie.listen_chan_subelt.channel));


	/* Disable reception of the probe request WLC event */
	if (hdl->conn_state == P2PAPI_ST_START_NEG) {
		(void) p2papi_enable_driver_events(hdl, FALSE);
	}

	/* Disable P2P device discovery if we had enabled it for the
	 * purpose of synchronizing channels with the peer.
	 */
	if (hdl->chsync_discov_enabled) {
		p2papi_chsync_discov_disable(hdl);
	}

	/* Suspend P2P Discovery if it is active.  P2P Discovery's scans can
	 * change the channel in the background and interfere with sending
	 * action frames.
	 */
	if (hdl->is_discovering) {
		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
			"p2papi_fsm_start_incoming_gon:call p2papi_discover_enable_search(0)\n"));
		p2papi_discover_enable_search(hdl, FALSE);
	}

	hdl->conn_state = P2PAPI_ST_NEG_REQ_RECVD;

	/* Cancel any action frame tx retries in progress */
	if (hdl->gon_aftx_hdl != NULL) {
		p2papi_aftx_cancel_send(hdl->gon_aftx_hdl);
		hdl->gon_aftx_hdl = NULL;
	}

	/* Cancel any GO Negotiation action frame waiting to be sent after channel
	 * synchronization.
	 */
	p2papi_cancel_send_at_common_channel(hdl);

	/* Save the requestor peer's information (mac addr, name, channel,
	 * intent, capability, status, group info).
	 */
	hdl->gon_dialog_token = act_frm->dialog_token;
	memcpy(&hdl->peer_dev_addr, &p2p_ie.devinfo_subelt.mac,
		sizeof(hdl->peer_dev_addr));
	memcpy(&hdl->peer_int_addr, &p2p_ie.intintad_subelt.mac,
		sizeof(hdl->peer_int_addr));
	memset(&hdl->peer_ssid, 0, sizeof(hdl->peer_ssid));
	hdl->peer_ssid_len = p2p_ie.devinfo_name_len;
	if (hdl->peer_ssid_len > sizeof(hdl->peer_ssid)) /* just in case */
		hdl->peer_ssid_len = sizeof(hdl->peer_ssid);
	memcpy(&hdl->peer_ssid, p2p_ie.devinfo_name, hdl->peer_ssid_len);
	hdl->peer_intent = p2papi_decode_intent(p2p_ie.intent_subelt.intent);
	hdl->rx_tie_breaker =
		p2papi_decode_tie_breaker(p2p_ie.intent_subelt.intent) ? TRUE : FALSE;
	hdl->peer_go_cfg_tmo_ms = p2p_ie.cfg_tmo_subelt.go_tmo * 10;
	hdl->peer_cl_cfg_tmo_ms = p2p_ie.cfg_tmo_subelt.client_tmo * 10;
	hdl->peer_channel.channel_class = (BCMP2P_CHANNEL_CLASS)p2p_ie.op_chan_subelt.band;
	hdl->peer_channel.channel = p2p_ie.op_chan_subelt.channel;
	hdl->peer_gon_device_pwd_id = (BCMP2P_WPS_DEVICE_PWD_ID) wps_ie.devpwd_id;
	hdl->gon_peer_listen_channel.channel_class = (BCMP2P_CHANNEL_CLASS)p2p_ie.listen_chan_subelt.band;
	hdl->gon_peer_listen_channel.channel = p2p_ie.listen_chan_subelt.channel;
	memcpy(&hdl->gon_channel, channel, sizeof(hdl->gon_channel));
	hdl->gon_peer_wants_persist_grp =
		(p2p_ie.capability_subelt.group & P2P_CAPSE_PERSIST_GRP) != 0;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"  peer_wants_persist_grp=%u peer_devpwdid=%d\n",
		hdl->gon_peer_wants_persist_grp, wps_ie.devpwd_id));
	our_persist_grp_cap = (hdl->persistent_grp != 0);
	peer_persist_grp_cap =
		((p2p_ie.capability_subelt.group & P2P_CAPSE_PERSIST_GRP) != 0);

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"  peer int=0x%02x rxtb=%d ch=%d:%d gch=%d:%d tmo=%u,%u\n",
		hdl->peer_intent, hdl->rx_tie_breaker,
		hdl->peer_channel.channel_class, hdl->peer_channel.channel,
		hdl->gon_channel.channel_class, hdl->gon_channel.channel,
		hdl->peer_go_cfg_tmo_ms, hdl->peer_cl_cfg_tmo_ms));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "  peer ssid=%s\n", hdl->peer_ssid));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"  peer devaddr=%02x:%02x:%02x:%02x:%02x:%02x"
		" intaddr=%02x:%02x:%02x:%02x:%02x:%02x\n",
		hdl->peer_dev_addr.octet[0], hdl->peer_dev_addr.octet[1],
		hdl->peer_dev_addr.octet[2], hdl->peer_dev_addr.octet[3],
		hdl->peer_dev_addr.octet[4], hdl->peer_dev_addr.octet[5],
		hdl->peer_int_addr.octet[0], hdl->peer_int_addr.octet[1],
		hdl->peer_int_addr.octet[2], hdl->peer_int_addr.octet[3],
		hdl->peer_int_addr.octet[4], hdl->peer_int_addr.octet[5]));

	/* Notify the app of the received GO neg req */
	p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION,
		BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_REQUEST_RECEIVED);


	if (is_sta || is_ap) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_fsm_start_incoming_gon: reject, is_sta=%d is_ap=%d\n",
			is_sta, is_ap));
		status = BCMP2P_CONNECT_ALREADY_IN_PROGRESS;
		goto gon_reject;
	}


	/* Generate a random "DIRECT-xy"-prefixed SSID to be used if we become a
	 * GO.  This SSID is used in encoding the Group ID attribute of our
	 * GONrsp frame.
	 */
	p2papi_generate_go_ssid(hdl, &hdl->credentials);

	/* Check provisioning info is configured */
	if (!p2papi_is_provision(hdl)) {
		status = BCMP2P_GON_FAILED_NO_PROVIS_INFO;
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_fsm_start_incoming_gon:"
		"no provisioning info (pin/pbc not active)\n"));
	}

	/* If we are in PIN mode but peer requested PBC mode */
	if (wps_ie.devpwd_id == WPS_DEVICEPWDID_PUSH_BTN &&
		hdl->ap_config.WPSConfig.wpsPinMode) {
		status = BCMP2P_GON_FAILED_NO_PROVIS_INFO;
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_fsm_start_incoming_gon: peer req PBC but we are PIN\n"));
	}

	if (BCMP2P_SUCCESS == status) {
		/* Determine our AP/STA role in the connection */
		status = p2papi_determine_ap_or_sta(hdl, FALSE);
		if (status == BCMP2P_SUCCESS) {
			if (hdl->is_ap) {
				/* GO - negotiate channel list */
				p2papi_negotiate_chanlist(&hdl->negotiated_channel_list,
					p2papi_get_non_dfs_channel_list(hdl),
					&p2p_ie.chanlist_subelt.chanlist);

				/* check that peers have common channels in channel list */
				if (hdl->negotiated_channel_list.num_entries == 0) {
					BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
						"p2papi_fsm_start_incoming_gon:"
						" no common channel list\n"));
					status = BCMP2P_INVALID_CHANNEL;
				}

#ifdef BCM_P2P_OPTEXT
				if (hdl->peer_channel.channel != 0 && hdl->opch_force == 0 &&
					p2papi_find_channel(&hdl->peer_channel, &hdl->negotiated_channel_list)) {
					memcpy(&hdl->op_channel, &hdl->peer_channel,
						sizeof(hdl->op_channel));
					BCMP2PLOG((BCMP2P_LOG_MED, TRUE,"====> adopting the peer op_channel = %d class = %d\n",
						hdl->peer_channel.channel, hdl->peer_channel.channel_class));
				} else {

					if (hdl->opch_force) {
						memcpy(&hdl->opch_force_store, &hdl->op_channel,
							sizeof(hdl->op_channel));
						if (!p2papi_find_channel(&hdl->op_channel,
							&hdl->negotiated_channel_list)) {
							/* down grade to 20Mhz channel class */
						if (hdl->op_channel.channel >=1 && hdl->op_channel.channel<= 15)
							hdl->op_channel.channel_class = 81;
						else if (hdl->op_channel.channel >=36 && hdl->op_channel.channel<= 48)
							hdl->op_channel.channel_class = 115;
						else if (hdl->op_channel.channel >=149 && hdl->op_channel.channel<= 161)
							hdl->op_channel.channel_class = 124;
						}
					}
					else
#endif
					{

				        /* reset operating channel */
						memcpy(&hdl->op_channel, &hdl->ap_config.operatingChannel,
							sizeof(hdl->op_channel));

						/* check operating channel is in channel list */
						if (!p2papi_find_channel(&hdl->op_channel,
							&hdl->negotiated_channel_list)) {
							/* select operating channel from channel list */
							p2papi_select_channel(&hdl->op_channel,
								&hdl->negotiated_channel_list);
							BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
								"p2papi_fsm_start_incoming_gon:"
								" using operating channel"
								" %d:%d from channel list\n",
								hdl->op_channel.channel_class,
								hdl->op_channel.channel));
						}
					}
#ifdef BCM_P2P_OPTEXT
				} /* !peer opch */
#endif
			}
			else {
				/* STA - use own channel list */
				p2papi_update_chanlist(&hdl->negotiated_channel_list,
					p2papi_get_non_dfs_channel_list(hdl));
			}
		}

		/* If we have strict persistent group settings matching turned on
		 * and we are not acting as the AP
		 *   If the peer has Persistent Group capability and we don't
		 *     Reject the GO negotiation
		 */
		if (strict_persistence_match && !hdl->is_ap) {
			if (peer_persist_grp_cap && !our_persist_grp_cap) {
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"fsm_start_inc_gon: persgrp cap mismatch: us=%d peer=%d\n",
					our_persist_grp_cap, peer_persist_grp_cap));
				status = BCMP2P_CONNECT_REJECTED;
				reason = P2P_STATSE_FAIL_INCOMPAT_PARAMS;
			}
		}

		if (BCMP2P_SUCCESS == status) {
			if (hdl->is_ap)
				hdl->in_persist_grp = hdl->persistent_grp;
			else
				hdl->in_persist_grp = hdl->gon_peer_wants_persist_grp;

			/* Reply to the peer with an Accept GO negotiation response. */
			ret = p2papi_fsm_accept_negotiation(hdl, NULL,
				gon_resp_dev_pwd_id(wps_ie.devpwd_id));
		}
	}

gon_reject:
	if (BCMP2P_SUCCESS != status) {
		/* Reply to the peer with a Reject GO negotiation response */
		code = BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_FAIL;
		if (status == BCMP2P_BOTH_GROUP_OWNER_INTENT)
			reason = P2P_STATSE_FAIL_INTENT;
		else if (status == BCMP2P_GON_FAILED_NO_PROVIS_INFO) {
			reason = P2P_STATSE_FAIL_INFO_CURR_UNAVAIL;
			code = BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_NO_PROV_INFO;
		}
		else if (our_persist_grp_cap != peer_persist_grp_cap)
			reason = P2P_STATSE_FAIL_INCOMPAT_PARAMS;
		else if (status == BCMP2P_CONNECT_ALREADY_IN_PROGRESS) {
			reason = P2P_STATSE_FAIL_UNABLE_TO_ACCOM;
			code = BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_ALREADY_CONNECTED;
		}
		else if (status == BCMP2P_INVALID_CHANNEL) {
			reason = P2P_STATSE_FAIL_NO_COMMON_CHAN;
			code = BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_FAIL;
		}
		else
			reason = P2P_STATSE_FAIL_UNABLE_TO_ACCOM;

		ret = p2papi_fsm_reject_negotiation(hdl, act_frm, reason, NULL,
			BCMP2P_WPS_DEFAULT);

		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_fsm_start_inc_gon: ap_or_sta fail, status=%d\n", status));

		/* Notify the app of the failed GO neg req */
		p2papi_osl_do_notify_cb(hdl,
			BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION, code);

		/* DO NOT re-start discovery here, do it in p2papi_gonrsp_reject_tx_done_cb() */
	}

	return ret;
}

/* Group Owner Negotiation FSM: process a received GONREQ that overlaps with
 * a GONREQ we have just transmitted.
 */
static int
p2papi_fsm_gonreq_collision(p2papi_instance_t* hdl,
	struct ether_addr *src_mac, wifi_p2p_pub_act_frame_t *act_frm,
	uint32 act_frm_len, BCMP2P_CHANNEL *channel, uint16 dev_pwd_id)
{
	int ret = 0;
	p2papi_p2p_ie_t p2p_ie;
	uint16 ie_len;
	int result;

	/* Process this GONREQ only if we have a higher MAC addr than the sender */
	result = compare_mac_addr(&hdl->conn_ifaddr, src_mac);
	if (result != 1) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_fsm_gonreq_collision: ignore incoming GONREQ\n"));
		return ret;
	}

	/* Decode the GO Negotiation action frame's P2P IE */
	p2papi_fsm_decode_p2p_ie(hdl, act_frm, &p2p_ie, &ie_len);

	/* If the GO Intent is 15 in this GONreq and in the GONreq we sent,
	 *   Respond with a GONrsp/status=Fail.
	 * else
	 *   Abandon the previous incomplete outgoing GO negotiation and
	 *   start a new incoming GO negotiation.
	 */
	if (hdl->intent == 15 &&
		p2papi_decode_intent(p2p_ie.intent_subelt.intent) == 15) {
		/* Reply to the peer with a GO negotiation response/status=Fail */
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_fsm_gonreq_collision: reject incoming GONREQ\n"));
		ret = p2papi_fsm_reject_negotiation(hdl, act_frm,
			P2P_STATSE_FAIL_INTENT, NULL, dev_pwd_id);
	} else {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_fsm_gonreq_collision: process incoming GONREQ\n"));
		ret = p2papi_fsm_start_incoming_gon(hdl, act_frm, act_frm_len, channel);
	}

	return ret;
}

/* Find channel in channel list.
 * Parameters:
 *   channel - channel to find
 *	 chanlist - channel list
 *
 */
bool
p2papi_find_channel(BCMP2P_CHANNEL *channel, p2p_chanlist_t *chanlist)
{
	int i, j;

	for (i = 0; i < chanlist->num_entries; i++) {
		p2p_chanlist_entry_t *e = &chanlist->entries[i];
		for (j = 0; j < e->num_channels; j++) {
			if (channel->channel_class == e->band &&
				channel->channel == e->channels[j]) {
				return TRUE;
			}
		}
	}
	return FALSE;
}

/* Find channel in channel list.
 * Parameters:
 *   channel - selected channel returned
 *	 chanlist - channel list
 *
 */
bool
p2papi_select_channel(BCMP2P_CHANNEL *channel, p2p_chanlist_t *chanlist)
{
	int i;

	/* first 5Ghz channel in channel list */
	for (i = 0; i < chanlist->num_entries; i++) {
		p2p_chanlist_entry_t *e = &chanlist->entries[i];
		if ((e->band == IEEE_5GHZ_20MHZ_CLASS_1 ||
			e->band == IEEE_5GHZ_20MHZ_CLASS_3 ||
			e->band == IEEE_5GHZ_20MHZ_CLASS_5) &&
			e->num_channels > 0) {
			channel->channel_class = (BCMP2P_CHANNEL_CLASS)e->band;
			channel->channel = e->channels[0];
			return TRUE;
		}
	}

	/* first channel in channel list */
	if (chanlist->num_entries > 0) {
		p2p_chanlist_entry_t *e = &chanlist->entries[0];
		if (e->num_channels > 0) {
			channel->channel_class = (BCMP2P_CHANNEL_CLASS)e->band;
			channel->channel = e->channels[0];
			return TRUE;
		}
	}

	return FALSE;
}

/* Update channel list from channel list IE.
 * Parameters:
 *	 dst - destination channel list
 *   src - source channel list
 *
 */
void
p2papi_update_chanlist(
	p2p_chanlist_t *dst, p2p_chanlist_t *src)
{
	int i, j;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_update_chanlist:\n"));
	p2papi_log_chanlist(src, " src:");

	dst->num_entries = src->num_entries;
	if (dst->num_entries > P2P_CHANLIST_SE_MAX_ENTRIES)
		dst->num_entries = P2P_CHANLIST_SE_MAX_ENTRIES;
	for (i = 0; i < dst->num_entries; i++) {
		p2p_chanlist_entry_t *de = &dst->entries[i];
		p2p_chanlist_entry_t *se = &src->entries[i];
		de->band = se->band;
		de->num_channels = se->num_channels;
		if (de->num_channels > P2P_CHANNELS_MAX_ENTRIES)
			de->num_channels = P2P_CHANNELS_MAX_ENTRIES;
		for (j = 0; j < de->num_channels; j++) {
			de->channels[j] = se->channels[j];
		}
	}
	p2papi_log_chanlist(dst, " dst:");
}

/* Negotiate channel list from channel list IE.
 * Parameters:
 *	 dst - destination channel list
 *	 self - self channel list
 *   peer - peer channel list
 */
void
p2papi_negotiate_chanlist(
	p2p_chanlist_t *dst, p2p_chanlist_t *self, p2p_chanlist_t *peer)
{
	int i, j, k, l;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_negotiate_chanlist:\n"));
	p2papi_log_chanlist(self, " self:");
	p2papi_log_chanlist(peer, " peer:");

	dst->num_entries = 0;
	for (i = 0; i < self->num_entries; i++) {
		p2p_chanlist_entry_t *de = &dst->entries[dst->num_entries];
		p2p_chanlist_entry_t *se = &self->entries[i];
		for (j = 0; j < peer->num_entries; j++) {
			p2p_chanlist_entry_t *pe = &peer->entries[j];
			/* check if rate class match */
			if (se->band == pe->band) {
				de->num_channels = 0;
				for (k = 0; k < se->num_channels; k++) {
					for (l = 0; l < pe->num_channels; l++) {
						/* channel intersection within a rate class */
						if (se->channels[k] == pe->channels[l]) {
							if (de->num_channels < P2P_CHANNELS_MAX_ENTRIES)
								de->channels[de->num_channels++] =
									pe->channels[l];
						}
					}
				}
				if (de->num_channels) {
					/* channel intersection occured */
					de->band = pe->band;
					dst->num_entries++;
				}
			}
		}
	}
	p2papi_log_chanlist(dst, "  dst :");
}

/* Group Owner Negotiation FSM: process a received GONRSP.
 * Parameters:
 *   src_mac - src mac addr from the received frame.  Note this cannot be used
 *             as the peer's P2P Device Address.  The peer P2P Device Address
 *             should be obtained from p2p_ie.devinfo_subelt.mac.
 *   act_frm - received wifi action frame
 *   act_frm_len - length of received wifi action frame
 */
static int
p2papi_fsm_proc_gonrsp(p2papi_instance_t* hdl,
	struct ether_addr *src_mac, wifi_p2p_pub_act_frame_t *act_frm,
	uint32 act_frm_len)
{
	int ret = 0;
	uint32 ie_len = act_frm_len - P2P_PUB_AF_FIXED_LEN;
	p2papi_p2p_ie_t p2p_ie;
	p2papi_wps_ie_t wps_ie;
	BCMP2P_STATUS status = BCMP2P_SUCCESS;
	bool our_persist_grp_cap, peer_persist_grp_cap;
	bool strict_persistence_match = FALSE;
	/* status code from rx GONrsp P2P IE status subelt */
	BCMP2P_UINT8 rx_statse;
	/* status code for tx GONconf P2P IE status subelt */
	BCMP2P_UINT8 tx_statse = P2P_STATSE_SUCCESS;

	/* Decode the GO Negotiation action frame's P2P and WPS IEs */
	(void) p2papi_decode_p2pwps_ies(act_frm->elts, ie_len, &p2p_ie, &wps_ie);
	rx_statse = p2p_ie.status_subelt.status;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_fsm_proc_gonrsp:\n"));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"    info_se  : len=%u bm=0x%02x\n",
		p2papi_decode_p2p_ie_length(p2p_ie.capability_subelt.len),
		p2p_ie.capability_subelt.dev));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"    intent_se : len=%u intent=%u\n",
		p2papi_decode_p2p_ie_length(p2p_ie.intent_subelt.len),
		p2p_ie.intent_subelt.intent));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"    listen_chan_se: len=%u chan=%u\n",
		p2papi_decode_p2p_ie_length(p2p_ie.listen_chan_subelt.len),
		p2p_ie.listen_chan_subelt.channel));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"    op_chan_se: len=%u chan=%u\n",
		p2papi_decode_p2p_ie_length(p2p_ie.op_chan_subelt.len),
		p2p_ie.op_chan_subelt.channel));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"    status_se : len=%u status=0x%02x\n",
		p2papi_decode_p2p_ie_length(p2p_ie.status_subelt.len),
		p2p_ie.status_subelt.status));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"    devinfo_se: len=%u mac=%02x:%02x:%02x:%02x:%02x:%02x"
		" name=%s nlen=%u\n",
		p2papi_decode_p2p_ie_length(p2p_ie.devinfo_subelt.len),
		p2p_ie.devinfo_subelt.mac[0], p2p_ie.devinfo_subelt.mac[1],
		p2p_ie.devinfo_subelt.mac[2], p2p_ie.devinfo_subelt.mac[3],
		p2p_ie.devinfo_subelt.mac[4], p2p_ie.devinfo_subelt.mac[5],
		p2p_ie.devinfo_name, p2p_ie.devinfo_name_len));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"    cfg_tmo_se: len=%u go_tmo=%u client_tmo=%u\n",
		p2papi_decode_p2p_ie_length(p2p_ie.cfg_tmo_subelt.len),
		p2p_ie.cfg_tmo_subelt.go_tmo,
		p2p_ie.cfg_tmo_subelt.client_tmo));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"    chanlist_se: len=%u num_entries=%u\n",
		p2papi_decode_p2p_ie_length(p2p_ie.chanlist_subelt.len),
		p2p_ie.chanlist_subelt.chanlist.num_entries));

	/* If the action frame's dialog token does not match our current GO
	 * negotiation dialog token, discard this GONrsp frame.
	 */
	if (act_frm->dialog_token != hdl->gon_dialog_token) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"Discarding GONRSP: dialog token %u, expecting %u\n",
			act_frm->dialog_token, hdl->gon_dialog_token));
		goto gonrsp_end;
	}

	/* Cancel any GONREQ action frame tx in progress, in case the peer acked
	 * our GONREQ but we did not receive it, then the peer sends GONRSP.
	 */
	if (hdl->gon_aftx_hdl != NULL) {
		p2papi_aftx_cancel_send(hdl->gon_aftx_hdl);
		hdl->gon_aftx_hdl = NULL;
	}

	/* Extract necessary information from the decoded IEs. */
	if (p2p_ie.devinfo_name_len > 0) {
		memset(&hdl->peer_ssid, 0, sizeof(hdl->peer_ssid));
		hdl->peer_ssid_len = p2p_ie.devinfo_name_len;
		if (hdl->peer_ssid_len > sizeof(hdl->peer_ssid))
			hdl->peer_ssid_len = sizeof(hdl->peer_ssid);
		memcpy(&hdl->peer_ssid, p2p_ie.devinfo_name, hdl->peer_ssid_len);
	}
	hdl->peer_intent = p2papi_decode_intent(p2p_ie.intent_subelt.intent);
	hdl->peer_go_cfg_tmo_ms = p2p_ie.cfg_tmo_subelt.go_tmo * 10;
	hdl->peer_cl_cfg_tmo_ms = p2p_ie.cfg_tmo_subelt.client_tmo * 10;
	hdl->peer_channel.channel_class = (BCMP2P_CHANNEL_CLASS)p2p_ie.op_chan_subelt.band;
	hdl->peer_channel.channel = p2p_ie.op_chan_subelt.channel;
	memcpy(&hdl->peer_int_addr, &p2p_ie.intintad_subelt.mac,
		sizeof(hdl->peer_int_addr));
	hdl->gon_peer_wants_persist_grp =
		(p2p_ie.capability_subelt.group & P2P_CAPSE_PERSIST_GRP) != 0;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "  Setting peer_wants_persist_grp=%u\n",
		hdl->gon_peer_wants_persist_grp));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"  Setting peer ch=%d:%d intent=%u gotmo=%u gctmo=%u\n",
		hdl->peer_channel.channel_class, hdl->peer_channel.channel,
		hdl->peer_intent, hdl->peer_go_cfg_tmo_ms, hdl->peer_cl_cfg_tmo_ms));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"  Setting peer_int_addr=%02x:%02x:%02x:%02x:%02x:%02x\n",
		hdl->peer_int_addr.octet[0], hdl->peer_int_addr.octet[1],
		hdl->peer_int_addr.octet[2], hdl->peer_int_addr.octet[3],
		hdl->peer_int_addr.octet[4], hdl->peer_int_addr.octet[5]));

	/* If the GONRSP's status indicates the peer accepted our
	 * negotiation request
	 *   Send a negotiation confirm action frame to the peer.
	 * else
	 *   End the GO Negotiation.
	 */
	if (P2P_STATSE_SUCCESS == rx_statse) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"  Peer accepted our negotiate req\n"));

		/* Determine our AP/STA role in the connection */
		status = p2papi_determine_ap_or_sta(hdl, FALSE);
		if (BCMP2P_SUCCESS == status) {
			hdl->conn_state = P2PAPI_ST_NEG_CONFIRMED;
			tx_statse = P2P_STATSE_SUCCESS;

			/* If the peer is acting as the GO, set our Operating Channel
			 * to the channel in the GONRSP's channel subelement.
			 */
			if (!hdl->is_ap) {
				if (hdl->peer_channel.channel != 0) {
					memcpy(&hdl->op_channel, &hdl->peer_channel,
						sizeof(hdl->op_channel));
					BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
						"  Setting our Operating Channel to %d:%d\n",
						hdl->op_channel.channel_class,
						hdl->op_channel.channel));
				} else {
					BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
						"  Not changing our Operating Channel from %d%d\n",
						hdl->op_channel.channel_class,
						hdl->op_channel.channel));
				}

				p2papi_update_chanlist(&hdl->negotiated_channel_list,
					&p2p_ie.chanlist_subelt.chanlist);
			}
			/* Else we are the GO: determine our negotiated channel list by
			 * intersecting our own channel list with the channel list received
			 * in the GONreq.  Then pick our operating channel from the
			 * negotiated channel list.
			 */
			else {
				/* GO - negotiate channel list */
				p2papi_negotiate_chanlist(&hdl->negotiated_channel_list,
					p2papi_get_non_dfs_channel_list(hdl),
					&p2p_ie.chanlist_subelt.chanlist);

				/* check that peers have common channels in channel list */
				if (hdl->negotiated_channel_list.num_entries == 0) {
					BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
						"p2papi_fsm_proc_gonrsp:"
						" no common channel list\n"));
					status = BCMP2P_INVALID_CHANNEL;
					tx_statse = P2P_STATSE_FAIL_NO_COMMON_CHAN;
				}

				/* reset operating channel */
				memcpy(&hdl->op_channel, &hdl->ap_config.operatingChannel,
					sizeof(hdl->op_channel));

				/* check operating channel is in channel list */
				if (!p2papi_find_channel(&hdl->op_channel,
					&hdl->negotiated_channel_list)) {
					/* select operating channel from channel list */
					p2papi_select_channel(&hdl->op_channel,
						&hdl->negotiated_channel_list);
					BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
						"p2papi_fsm_proc_gonrsp: using operating channel"
						" %d:%d from channel list\n",
						hdl->op_channel.channel_class,
						hdl->op_channel.channel));
				}
			}

			if (hdl->is_ap)
				hdl->in_persist_grp = hdl->persistent_grp;
			else
				hdl->in_persist_grp = hdl->gon_peer_wants_persist_grp;

			/* Notify the app of our AP/STA role */
			p2papi_osl_do_notify_cb(hdl,
				BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION,
				hdl->is_ap ? BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_AP_ACK
						   : BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_STA_ACK);

			/* If we have strict persistent group settings matching turned on
			 * and we are not acting as the AP
			 *   If the peer has Persistent Group capability and we don't
			 *     Reject the GO negotiation
			 */
			if (strict_persistence_match && !hdl->is_ap) {
				our_persist_grp_cap = hdl->persistent_grp != 0;
				peer_persist_grp_cap = (p2p_ie.capability_subelt.group &
					P2P_CAPSE_PERSIST_GRP) != 0;
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"fsm_proc_gonrsp: persist grp cap: us=%d peer=%d\n",
					our_persist_grp_cap, peer_persist_grp_cap));
				if (peer_persist_grp_cap && !our_persist_grp_cap) {
					BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
						"fsm_proc_gonrsp: persist grp cap mismatch\n",
						our_persist_grp_cap, peer_persist_grp_cap));
					tx_statse = P2P_STATSE_FAIL_INCOMPAT_PARAMS;
					status = BCMP2P_CONNECT_REJECTED;
				}
			}
		} else {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"  AP/STA determination failed\n"));
			tx_statse = (status == BCMP2P_BOTH_GROUP_OWNER_INTENT)
				? P2P_STATSE_FAIL_INTENT
				: P2P_STATSE_FAIL_UNABLE_TO_ACCOM;
		}

		/* Determine the GO Negotiation result application notification code.
		 * It will be used to generate an application notification after the
		 * GONCONF frame tx is complete.
		 */
		if (status == BCMP2P_SUCCESS && tx_statse == P2P_STATSE_SUCCESS) {
			hdl->gon_notif = BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_COMPLETE;
		} else {
			if (tx_statse == P2P_STATSE_FAIL_INFO_CURR_UNAVAIL) {
				hdl->gon_notif = BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_INFO_UNAVAIL;
			}
			else if (tx_statse == P2P_STATSE_FAIL_INTENT) {
				hdl->gon_notif = BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_FAIL_INTENT;
			}
			else {
				hdl->gon_notif = BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_FAIL;
			}
		}

		/* Send a GONconf action frame to the peer */
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"    Sending GONCONF statse=%d dt=%u ch=%d:%d\n",
			tx_statse, hdl->gon_dialog_token,
			hdl->gon_channel.channel_class, hdl->gon_channel.channel));
		p2plib_send_go_neg_frame(hdl, src_mac, P2P_PAF_GON_CONF, hdl->intent,
			tx_statse, &hdl->op_channel, &hdl->gon_channel,
			hdl->gon_dialog_token, hdl->wps_device_pwd_id,
			p2papi_gonconf_tx_done_cb);
	}
	else {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"    Peer rejected our negotiate req, P2P IE status=%d\n",
			rx_statse));
		status = BCMP2P_ERROR;

		/* Do the GO Negotiation completion actions */
		if (rx_statse == P2P_STATSE_FAIL_INFO_CURR_UNAVAIL) {
			hdl->gon_notif = BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_INFO_UNAVAIL;
		}
		else if (rx_statse == P2P_STATSE_FAIL_INTENT ||
			tx_statse == P2P_STATSE_FAIL_INTENT) {
			hdl->gon_notif = BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_FAIL_INTENT;
		}
		else {
			hdl->gon_notif = BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_FAIL;
		}

		p2papi_gon_end(hdl);
	}

gonrsp_end:
	return ret;
}

/* Group Owner Negotiation FSM: process a received GONCONF.
 * Parameters:
 *   src_mac - src mac addr from the received frame.  Note this cannot be used
 *             as the peer's P2P Device Address.  The peer P2P Device Address
 *             should be obtained from p2p_ie.devinfo_subelt.mac.
 *   act_frm - received wifi action frame
 *   act_frm_len - length of received wifi action frame
 */
static int
p2papi_fsm_proc_gonconf(p2papi_instance_t* hdl,
	struct ether_addr *src_mac, wifi_p2p_pub_act_frame_t *act_frm,
	uint32 act_frm_len)
{
	uint32 ie_len = act_frm_len - P2P_PUB_AF_FIXED_LEN;
	p2papi_p2p_ie_t p2p_ie;
	p2papi_wps_ie_t wps_ie;
	int ret = BCMP2P_SUCCESS;
	uint8 status;
	bool success;

	/* Check if the action frame's dialog token matches our current
	 * GO negotiation's.
	 */
	if (act_frm->dialog_token != hdl->gon_dialog_token) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"Discarding GONCONF: dialog token %u, expecting %u\n",
			act_frm->dialog_token, hdl->gon_dialog_token));
		return ret;
	}

	/* Cancel our GONRSP action frame tx if it is still in progress */
	if (hdl->gon_aftx_hdl != NULL) {
		p2papi_aftx_cancel_send(hdl->gon_aftx_hdl);
		hdl->gon_aftx_hdl = NULL;
	}

	/* Decode the GONCONF action frame and check the status attribute to check
	 * if the GON succeeded or failed.
	 */
	p2papi_decode_p2pwps_ies(act_frm->elts, ie_len, &p2p_ie, &wps_ie);
	status = p2p_ie.status_subelt.status;
	success = (status == P2P_STATSE_SUCCESS ||
		status == P2P_STATSE_FAIL_INFO_CURR_UNAVAIL);

	/* If the GON succeeded
	 *   Change state to GON Confirmed
	 * else
	 *   Change state to Idle
	 */
	if (success) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_proc_gonconf: GO Negotiation succeeded, status=%u\n",
			status));
		hdl->conn_state = P2PAPI_ST_NEG_CONFIRMED;

		/* If the peer is acting as the GO, set our Operating Channel
		 * to the channel in the GONCONF's channel subelement.
		 */
		if (!hdl->is_ap) {
			if (p2p_ie.op_chan_subelt.channel != 0) {
				hdl->peer_channel.channel_class = (BCMP2P_CHANNEL_CLASS)p2p_ie.op_chan_subelt.band;
				hdl->peer_channel.channel = p2p_ie.op_chan_subelt.channel;
				memcpy(&hdl->op_channel, &hdl->peer_channel,
					sizeof(hdl->op_channel));
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"p2papi_proc_gonconf: set our op channel to %d:%d\n",
					hdl->op_channel.channel_class,
					hdl->op_channel.channel));
			} else {
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"p2papi_proc_gonconf: leaving our op channel at %d:%d\n",
					hdl->op_channel.channel_class,
					hdl->op_channel.channel));
			}

			p2papi_update_chanlist(&hdl->negotiated_channel_list,
				&p2p_ie.chanlist_subelt.chanlist);
		}
	} else {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_proc_gonconf: GO Negotiation failed, status=%u.\n",
			status));
		p2papi_fsm_reset(hdl);
	}

	/* Unblock any threads waiting for the GO negotiation to finish */
	ret = p2papi_osl_signal_go_negotiation(hdl, P2PAPI_OSL_GO_STATE_DONE);
	if (BCMP2P_SUCCESS != ret) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_proc_gonconf: signal GON error %d\n", ret));
	}

	/* Notify the app of the GO negotiation success/fail result */
	p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION,
		success ? BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_COMPLETE :
		BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_FAIL);

	return ret;
}

/* Group Owner Negotiation FSM:
 * Process a received Group Owner Negotiation action frame.
 * Parameters:
 *   src_mac - driver event's src mac addr.  Note this is NOT the src mac
 *             addr from the received GON frame.  The peer's src mac (P2P
 *             Device Address) should be obtained from
 *             p2p_ie.devinfo_subelt.mac.
 *   act_frm - received wifi action frame
 *   act_frm_len - length of received wifi action frame
 * Notes:
 * - before calling this function, the caller should ensure the frame is an
 *   action frame by calling p2papi_is_p2p_action_frm().
 */
int
p2papi_fsm_rx_go_neg_frame(p2papi_instance_t* hdl,
	struct ether_addr *src_mac, wifi_p2p_pub_act_frame_t *act_frm,
	uint32 act_frm_len, BCMP2P_CHANNEL *channel)
{
	bool processed = FALSE;
	uint32 ie_len = act_frm_len - P2P_PUB_AF_FIXED_LEN;
	p2papi_p2p_ie_t p2p_ie;
	p2papi_wps_ie_t wps_ie;
	int ret = 0;

	P2PAPI_CHECK_P2PHDL(hdl);
	if (!P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl))
		return -1;
	P2PAPI_GET_WL_HDL(hdl);

	if (!hdl->enable_p2p)
		return 0;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_proc_gonf: state=%u, frame: len=%u subtype=%u token=%u\n",
		hdl->conn_state, act_frm_len, act_frm->subtype, act_frm->dialog_token));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"                : src_mac=%02x:%02x:%02x:%02x:%02x:%02x ch=%d:%d\n",
		src_mac->octet[0], src_mac->octet[1], src_mac->octet[2],
		src_mac->octet[3], src_mac->octet[4], src_mac->octet[5],
		channel->channel_class, channel->channel));

	if (p2papi_is_duplicate_rx_frame(hdl, src_mac, act_frm->subtype,
		act_frm->dialog_token)) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_proc_gonf: discarding duplicate rx frame, token=%u\n",
			act_frm->dialog_token));
		return 0;
	}

	switch (hdl->conn_state) {
	case P2PAPI_ST_IDLE:
	case P2PAPI_ST_START_NEG:
	case P2PAPI_ST_CONNECTED:
		if (act_frm->subtype == P2P_PAF_GON_REQ) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_proc_gonf: conn_state %d rx GONREQ, dt=%u is_sta=%d\n",
				hdl->conn_state, act_frm->dialog_token, p2papi_is_sta(hdl)));
			ret = p2papi_fsm_start_incoming_gon(hdl, act_frm, act_frm_len,
				channel);
			processed = TRUE;
		}
		break;
	case P2PAPI_ST_NEG_REQ_SENT:
		if (act_frm->subtype == P2P_PAF_GON_RSP) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_proc_gonf:"
				"ST_REQ_SENT rx GONRSP, dt=%u is_sta=%d\n",
				act_frm->dialog_token, p2papi_is_sta(hdl)));
			ret = p2papi_fsm_proc_gonrsp(hdl, src_mac, act_frm, act_frm_len);
			processed = TRUE;
		} else if (act_frm->subtype == P2P_PAF_GON_REQ) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_proc_gonf:"
				"ST_REQ_SENT rx GONREQ, dt=%u is_sta=%d\n",
				act_frm->dialog_token, p2papi_is_sta(hdl)));
			(void) p2papi_decode_p2pwps_ies(act_frm->elts, ie_len, &p2p_ie, &wps_ie);
			ret = p2papi_fsm_gonreq_collision(hdl,
				(struct ether_addr *)p2p_ie.devinfo_subelt.mac, act_frm,
				act_frm_len, channel, gon_resp_dev_pwd_id(wps_ie.devpwd_id));
			processed = TRUE;
		}
		break;
	case P2PAPI_ST_NEG_REQ_RECVD:
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_proc_gonf: ST_REQ_RECVD, rx GON frame type %d\n",
			act_frm->subtype));
		if (act_frm->subtype == P2P_PAF_GON_REQ) {
			/* Abandon the previous incomplete GO negotiation and start a new
			 * incoming GO negotiation.
			 */
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_proc_gonf: ST_REQRECVD rx GONREQ, dt=%u sta=%d\n",
				act_frm->dialog_token, p2papi_is_sta(hdl)));
			ret = p2papi_fsm_start_incoming_gon(hdl, act_frm, act_frm_len,
				channel);
			processed = TRUE;
		}
		break;
	case P2PAPI_ST_NEG_RSP_SENT:
		if (act_frm->subtype == P2P_PAF_GON_CONF) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_proc_gonf: ST_ACCEPTED rx GONCONF, dt=%u\n",
				act_frm->dialog_token));
			processed = TRUE;
			ret = p2papi_fsm_proc_gonconf(hdl, src_mac, act_frm, act_frm_len);
		} else if (act_frm->subtype == P2P_PAF_GON_REQ) {
			/* Abandon the previous incomplete GO negotiation and start a new
			 * incoming GO negotiation.
			 */
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_proc_gonf: ST_ACCEPTED rx GONREQ, dt=%u sta=%d\n",
				act_frm->dialog_token, p2papi_is_sta(hdl)));
			ret = p2papi_fsm_start_incoming_gon(hdl, act_frm, act_frm_len,
				channel);
			processed = TRUE;
		}
		break;
	case P2PAPI_ST_NEG_CONFIRMED:
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_proc_gonf: ST_CONFIRMED, ignoring rx frm\n"));
		break;
	default:
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_proc_gonf: unknown state %u!\n", hdl->conn_state));
		break;
	}

	if (!processed) {
		/* If the unprocessed frame is a GO negotiation request with an
		 * unexpected dialog token
		 *   If we have just sent a GON response
		 *     Ignore this GON req.
		 *   else
		 *     Send a GO negotiation reject to the sender
		 */
		if (act_frm->subtype == P2P_PAF_GON_REQ &&
			hdl->gon_dialog_token != act_frm->dialog_token) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
				"p2papi_proc_gonf: GONREQ dialog token %u != %u, state=%u\n",
				act_frm->dialog_token, hdl->gon_dialog_token, hdl->conn_state));
			(void) p2papi_decode_p2pwps_ies(act_frm->elts, ie_len, &p2p_ie, &wps_ie);
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"    intent=%u chan=%u\n",
				p2p_ie.intent_subelt.intent, p2p_ie.op_chan_subelt.channel));
			if (hdl->conn_state != P2PAPI_ST_NEG_RSP_SENT) {
				p2plib_send_go_neg_frame(hdl, src_mac, P2P_PAF_GON_RSP,
					hdl->intent, P2P_STATSE_FAIL_UNABLE_TO_ACCOM,
					&hdl->op_channel, &hdl->gon_channel,
					act_frm->dialog_token, hdl->wps_device_pwd_id,
					p2papi_gonrsp_reject_tx_done_cb);
			}
		}
		/* else if the GON frame is unexpected in our current state
		 *   Log the GON frame.
		 *   Ignore this GON frame.
		 */
		else if (act_frm->subtype == P2P_PAF_GON_REQ ||
			act_frm->subtype == P2P_PAF_GON_RSP ||
			act_frm->subtype == P2P_PAF_GON_CONF) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_proc_gonf: unexpected frame subtype %u in state %u\n",
				act_frm->subtype, hdl->conn_state));
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "  (probably a retransmit)\n"));
		}
		/* else
		 *   The frame subtype is unknown. Ignore this frame.
		 */
		else {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
				"p2papi_proc_gonf: unknown frame subtype %u in state %u\n",
				act_frm->subtype, hdl->conn_state));
		}
	}
	return ret;
}

/* Start a Group Owner Negotiation.
 * Enter a Find phase that alternates between scanning the peer's listen
 * channel and listening on our listen channel until one of these occur:
 * - During our listen state, the peer sends us a probe request on our listen
 *   channel.  We immediately send the peer a GONREQ action frame before it
 *   leaves that channel.
 * - During our search state, we send the peer a probe request on the peer's
 *   listen channel and the peer sends back a GONREQ action frame before we
 *   leave that channel.
 *
 * Why do we need to alternate between scan and listen?  Why not just listen?
 * Because in the case where both peers simultaneously try to start a GON with
 * the other, if both peers only listen then both will end up waiting for a
 * probe request that will never arrive (since neither is actively scanning).
 *
 * Why do we wait for a probe request instead of a probe response? Because
 * a probe response could be sent by the peer near the end of its listen
 * state.  By the time we receive it and respond with a GONREQ, the peer
 * could have exited the listen state and left that channel.
 */
int
p2papi_fsm_start_go_neg(p2papi_instance_t* hdl, struct ether_addr *peer_mac,
	BCMP2P_CHANNEL *peer_listen_channel, bool peer_is_p2p_group)
{
	int err = -1;
	bool sync_channels = FALSE;
	int retries = 3;
	int i;
	int gon_wait_ms;
	BCMP2P_CHANNEL peer_channel;

	memcpy(&peer_channel, peer_listen_channel, sizeof(peer_channel));
	memcpy(&hdl->peer_dev_addr, peer_mac, sizeof(hdl->peer_dev_addr));
	hdl->conn_state = P2PAPI_ST_START_NEG;

	/* Generate a random "DIRECT-xy"-prefixed SSID to be used if we become a
	 * GO.  This SSID is used in encoding the Group ID attribute of our
	 * GONconf frame.
	 */
	p2papi_generate_go_ssid(hdl, &hdl->credentials);

	/* Set our default Operating Channel.
	 * Later this Operating Channel should be overridden by the P2P IE channel
	 * attribute in the GON RSP or GON CONF frame sent by the peer acting as
	 * the Group Owner.
	 */
	if (peer_is_p2p_group) {
		sync_channels = FALSE;

		/* Set our default operating channel to the peer AP's listen channel */
		if (peer_channel.channel == 0) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_fsm_start_go_neg: no peer_listen_channel, using %d:%d\n",
				hdl->listen_channel.channel_class, hdl->listen_channel.channel));
			memcpy(&peer_channel, &hdl->listen_channel, sizeof(peer_channel));
		}
		memcpy(&hdl->op_channel, &peer_channel, sizeof(hdl->op_channel));

		/* Set the GON channel to the peer AP's listen channel */
		memcpy(&hdl->gon_channel, &peer_channel, sizeof(hdl->gon_channel));

	} else { /* peer is not a p2p group */

		if (hdl->enable_multi_social_channels)	/* P2PAPI_ENABLE_MULTI_CHANNEL */
			sync_channels = TRUE;
		else
			sync_channels = FALSE;

		/* Reset our default operating channel to our configured preferred
		 * operating channel.
		 */
		memcpy(&hdl->op_channel, &hdl->ap_config.operatingChannel,
			sizeof(hdl->op_channel));

		/* Set the GON channel to our own listen channel */
		memcpy(&hdl->gon_channel, &hdl->listen_channel,
			sizeof(hdl->gon_channel));
	}

	/* Generate our group owner intent value */
	hdl->intent = p2papi_generate_go_intent(hdl);

	/* Toggle our tx tie breaker bit for the GONreq we are about to send */
	hdl->tx_tie_breaker = !hdl->tx_tie_breaker;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"fsm_start_go_neg: gon_ch=%d:%d op_ch=%d:%d\n",
		hdl->gon_channel.channel_class, hdl->gon_channel.channel,
		hdl->op_channel.channel_class, hdl->op_channel.channel));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"                : pig=%d sync=%d retry=%d intent=%u tb=%u\n",
		peer_is_p2p_group, sync_channels, retries, hdl->intent,
		hdl->tx_tie_breaker));

	/* If P2P Discovery is active
	 *    Suspend P2P Discovery because discovery scans can change the channel.
	 * We want to stay on this channel until the Group Owner Negotiation
	 * completes or times out.
	 */
	if (hdl->is_discovering) {
		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
			"fsm_start_go_neg:call p2papi_discover_enable_search(false)\n"));
		p2papi_discover_enable_search(hdl, FALSE);
	}

	/* Retry the entire GO negotiation until it succeeds or until the peer
	 * rejects the GO negotiation.
	 */
	for (i = 0; i < retries; i++) {
		/* Clear any previous GO negotiation or action frame tx in progress */
		p2papi_cancel_send_at_common_channel(hdl);
		if (hdl->gon_aftx_hdl != NULL) {
			p2papi_aftx_cancel_send(hdl->gon_aftx_hdl);
			hdl->gon_aftx_hdl = NULL;
		}

		hdl->conn_state = P2PAPI_ST_START_NEG;
		(void) p2papi_osl_signal_go_negotiation(hdl, P2PAPI_OSL_GO_STATE_START);


		err = p2papi_fsm_tx_go_neg_req(hdl, &hdl->peer_dev_addr,
			!sync_channels, &peer_channel);
		if (err != 0) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"fsm_start_go_neg: tx_go_neg failed with %d\n", err));
		}
		else {
			/* Wait for the GO Negotiation to complete */
			gon_wait_ms = 2 * hdl->af_tx_max_retries * hdl->af_tx_retry_ms;
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"fsm_start_go_neg: wait for GON to complete(i=%d,wait=%d ms)\n",
				i, gon_wait_ms));
			err = p2papi_osl_wait_for_go_negotiation(hdl, gon_wait_ms);
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"fsm_start_go_neg: GON wait result=%d, st=%u notif=0x%x\n",
				err, hdl->conn_state, hdl->gon_notif));

			/* If the GON succeeded, exit this GON retry loop */
			if (err != BCMP2P_GO_NEGOTIATE_TIMEOUT &&
				hdl->conn_state == P2PAPI_ST_NEG_CONFIRMED) {
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"fsm_start_go_neg: GON completed\n"));
				break;
			}

			/* If the GON was rejected by the peer (not a timeout or the lack
			 * of GONREQ action frame ack), exit this GON retry loop.
			 */
			if (hdl->conn_state == P2PAPI_ST_IDLE) {
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"fsm_start_go_neg: GON rejected, state=%d waitresult=%d\n",
					hdl->conn_state, err));
				break;
			}
		}

		/* Delay before retrying the GON request with a new dialog token */
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"fsm_start_go_neg: sleep %d ms before retry tx GONREQ\n",
			P2PAPI_GONREQ_RETRY_TMO_MS));
		p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_GO_NEGOTIATION_RETRY,
			P2PAPI_GONREQ_RETRY_TMO_MS);

	}
	return err;
}

static bool
p2papi_fsm_is_pending_tx_mac(p2papi_instance_t* hdl, struct ether_addr* addr)
{
	uint8 *src_mac = addr->octet;
	uint8 *peer_mac = hdl->pending_tx_dst_addr.octet;
	return (((src_mac[0] & 0xfd) == (peer_mac[0] & 0xfd)) &&
		0 == memcmp(src_mac + 1, peer_mac + 1, sizeof(struct ether_addr) - 1));
}


/* Send any pending action frame. This should be called on receipt of any probe
 * request or response from the peer, that completed channel synchronization.
 * Does nothing if no pending tx.
 *
 * Modifies instance data:
 *  	hdl->gon_channel
 *  	hdl->pending_tx_act_frm
 * 	hdl->conn_state  P2PAPI_ST_START_NEG ==> P2PAPI_ST_NEG_REQ_SENT
 */
static int
p2papi_fsm_send_pending_tx_act_frm(p2papi_instance_t* hdl, BCMP2P_CHANNEL *channel)
{
	wl_af_params_t	*tx_act_frm;
	p2papi_aftx_instance_t	*aftx_hdl;

	P2PAPI_CHECK_P2PHDL(hdl);
	if (!hdl->enable_p2p)
		return -1;

	P2PAPI_DATA_LOCK_VERB(hdl);
	tx_act_frm = hdl->pending_tx_act_frm;
	hdl->pending_tx_act_frm = NULL;
	P2PAPI_DATA_UNLOCK_VERB(hdl);

	/* If we have a pending tx action frame waiting for the target peer's
	 * probe request to synchronize channels, send it now.
	 */
	if (tx_act_frm != NULL) {

		/* Store for next time (ex. to send GON confirmation) */
		memcpy(&hdl->gon_channel, channel, sizeof(hdl->gon_channel));

		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_fsm_send_pending_tx_act_frm: "
			"state=%d chan=%d:%d wlp2pstate=%d\n",
			hdl->conn_state, channel->channel_class, channel->channel,
			hdl->wl_p2p_state));

		/* Suspend P2P discovery's search-listen to prevent it from
		 * starting a scan or changing the channel.
		 */
		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
			"p2papi_fsm_send_pending_tx_act_frm: "
			"call p2papi_discover_enable_search(false)\n"));
		p2papi_discover_enable_search(hdl, FALSE);

		/* Suspend p2papi_send_at_common_channel()'s search-listen scans to
		 * prevent it from changing the channel or the driver's p2p mode.
		 */

		tx_act_frm->channel = channel->channel;

		/* Send the tx pending action frame */
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"===> sending %s AF, ch=%u dwell_ms=%d\n",
			hdl->pending_tx_dbg_name,
			tx_act_frm->channel, tx_act_frm->dwell_time));

		aftx_hdl = p2papi_aftx_send_frame(hdl, tx_act_frm,
			hdl->bssidx[P2PAPI_BSSCFG_DEVICE], hdl->af_tx_max_retries,
			hdl->af_tx_retry_ms, hdl->pending_tx_complete_cb,
			(void*)hdl, hdl->pending_tx_dbg_name);
		P2PLIB_ASSERT(aftx_hdl != NULL);
		if (hdl->pending_tx_aftx_hdlp)
			*hdl->pending_tx_aftx_hdlp = aftx_hdl;

		/* Disable reception of the probe request WLC event */
		(void) p2papi_enable_driver_events(hdl, FALSE);

	} else {
		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
			"p2papi_fsm_send_pending_tx_act_frm: nothing to send\n"));
	}
	return 0;
}

/* Handle a Probe Response, received as an escan result, during the action
 * frame tx channel synchronization procedure.
 */
static int
p2papi_fsm_handle_chansync_escan_result(p2papi_instance_t* hdl,
	wl_escan_result_t *data)
{
	int status = 0;

	if (hdl->pending_tx_act_frm == NULL) {

		return status;
	}

	/* This event is only useful if the WLC_E_STATUS_PARTIAL escan message
	 * has exactly one bss_info entry.
	 * wl_escan_result_t is in dongle byte order.
	 */
	if (dtoh16(data->bss_count) == 1) {
		wl_bss_info_t *bss_info = &data->bss_info[0];
		struct ether_addr *addr = &bss_info->BSSID;
		bool is_peer = p2papi_fsm_is_pending_tx_mac(hdl, addr);
		BCMP2P_CHANNEL channel;

		p2papi_chspec_to_channel(dtohchanspec(bss_info->chanspec), &channel);

		BCMP2PLOG((is_peer ? BCMP2P_LOG_INFO : BCMP2P_LOG_VERB, TRUE,
			"chansync_escan_result: "
			"from %s %02x:%02x:%02x:%02x:%02x:%02x ch=%d:%d\n",
			is_peer ? "peer" : "non-peer (ignoring)",
			addr->octet[0], addr->octet[1],
			addr->octet[2], addr->octet[3],
			addr->octet[4], addr->octet[5],
			channel.channel_class, channel.channel));

		if (is_peer) {
			status = p2papi_fsm_send_pending_tx_act_frm(hdl, &channel);
		}
	}
	return status;
}

/* Process a received P2P public action frame */
int
p2papi_process_pub_act_frame(p2papi_instance_t *hdl,
	struct ether_addr *src_mac, wifi_p2p_pub_act_frame_t *frame,
	uint32 frame_nbytes, wl_event_rx_frame_data_t *rxframe_data)
{
#ifdef IGNORE_DUPLICATE_ACTION_FRAME
	static bool is_first_frame = true;
	static uint8 last_subtype = ~0;
	static uint8 last_dialog_token = ~0;
#endif /* IGNORE_DUPLICATE_ACTION_FRAME */

	BCMP2P_CHANNEL channel = {BCMP2P_LISTEN_CHANNEL_CLASS, 0};
	(void) hdl;
	(void) frame_nbytes;

#ifdef IGNORE_DUPLICATE_ACTION_FRAME
	/* check for duplicate frame */
	if (!is_first_frame) {
		if (last_subtype == frame->subtype &&
			last_dialog_token == frame->dialog_token &&
			memcmp(src_mac->octet, hdl->af_last_src_mac.octet,
			sizeof(hdl->af_last_src_mac.octet)) == 0) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_proc_pub_act_frm:"
				" ignore duplicate frame type=%d dialog=%d\n",
				frame->subtype, frame->dialog_token));
			return 0;
		}
	}
#endif /* IGNORE_DUPLICATE_ACTION_FRAME */

	if (rxframe_data) {
		p2papi_chspec_to_channel(ntoh16(rxframe_data->channel),	&channel);
	}

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_proc_pub_act_frm: subtype=%u nbytes=%u ch=%d:%d\n",
		frame->subtype, frame_nbytes, channel.channel_class, channel.channel));

	/* If this is a group owner negotiation frame, process it */
	switch (frame->subtype) {
	case P2P_PAF_GON_REQ:
	case P2P_PAF_GON_RSP:
	case P2P_PAF_GON_CONF:
		if (frame->subtype == P2P_PAF_GON_REQ)
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "P2P_PAF_GON_REQ\n"));
		else if (frame->subtype == P2P_PAF_GON_RSP)
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "P2P_PAF_GON_RSP\n"));
		else if (frame->subtype == P2P_PAF_GON_CONF)
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "P2P_PAF_GON_CONF\n"));
		(void) p2papi_fsm_rx_go_neg_frame(hdl, src_mac, frame, frame_nbytes,
			&channel);
		break;
	case P2P_PAF_INVITE_REQ:
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "P2P_PAF_INVITE_REQ\n"));
		(void) p2papi_rx_invite_req_frame(hdl, src_mac, frame, frame_nbytes,
			&channel);
		break;
	case P2P_PAF_INVITE_RSP:
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "P2P_PAF_INVITE_RSP\n"));
		(void) p2papi_rx_invite_rsp_frame(hdl, src_mac, frame, frame_nbytes,
			&channel);
		break;
	case P2P_PAF_DEVDIS_REQ:
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "P2P_PAF_DEVDIS_REQ\n"));
		(void) p2papi_rx_dev_discb_req_frame(hdl, src_mac, frame, frame_nbytes,
			&channel);
		break;
	case P2P_PAF_DEVDIS_RSP:
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "P2P_PAF_DEVDIS_RSP\n"));
		(void) p2papi_rx_discb_rsp_frame(hdl, src_mac, frame, frame_nbytes,
			&channel);
		break;
	case P2P_PAF_PROVDIS_REQ:
	case P2P_PAF_PROVDIS_RSP:
		if (frame->subtype == P2P_PAF_PROVDIS_REQ)
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "P2P_PAF_PROVDIS_REQ\n"));
		else if (frame->subtype == P2P_PAF_PROVDIS_RSP)
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "P2P_PAF_PROVDIS_RSP\n"));
		(void) p2papi_rx_provdis_frame(hdl, src_mac, frame, frame_nbytes,
			&channel);
		break;
	default:
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_proc_pub_act_frm: unknown subtype %u, len=%u\n",
			frame->subtype, frame_nbytes));
		break;
	}

#ifdef IGNORE_DUPLICATE_ACTION_FRAME
	is_first_frame = false;
	last_subtype = frame->subtype;
	last_dialog_token = frame->dialog_token;
	/* Update af_last_src_mac address. We make af_last_src_mac member of p2papi_instance_t
	 * so that it can be reset after GON is finished (either success or failure)
	 */
	memcpy(hdl->af_last_src_mac.octet, src_mac->octet, sizeof(src_mac->octet));
#endif /* IGNORE_DUPLICATE_ACTION_FRAME */

	return 0;
}

/* Process a received P2P action frame */
int
p2papi_process_action_frame(p2papi_instance_t *hdl,
	struct ether_addr *src_mac, wifi_p2p_action_frame_t *frame,
	uint32 frame_nbytes, wl_event_rx_frame_data_t *rxframe_data)
{
#ifdef IGNORE_DUPLICATE_ACTION_FRAME
	static bool is_first_frame = true;
	static uint8 last_subtype = ~0;
	static uint8 last_dialog_token = ~0;
	static struct ether_addr last_src_mac = {{0}};
#endif /* IGNORE_DUPLICATE_ACTION_FRAME */
	BCMP2P_CHANNEL channel = {BCMP2P_LISTEN_CHANNEL_CLASS, 0};
	(void) hdl;
	(void) frame;
	(void) frame_nbytes;

	if (frame == NULL) {
		return -1;
	}

#ifdef IGNORE_DUPLICATE_ACTION_FRAME
	/* check for duplicate frame */
	if (!is_first_frame) {
		if (last_subtype == frame->subtype &&
			last_dialog_token == frame->dialog_token &&
			memcmp(src_mac->octet, last_src_mac.octet,
			sizeof(last_src_mac.octet)) == 0) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_process_action_frame:"
				" ignore duplicate frame type=%d dialog=%d\n",
				frame->subtype, frame->dialog_token));
			return 0;
		}
	}
#endif /* IGNORE_DUPLICATE_ACTION_FRAME */

	if (rxframe_data) {
		p2papi_chspec_to_channel(ntoh16(rxframe_data->channel), &channel);
	}

	/* Process the action frame based on the OUI Subtype */
	switch (frame->subtype) {
	case P2P_AF_NOTICE_OF_ABSENCE:
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "P2P_AF_NOTICE_OF_ABSENCE\n"));
		break;
	case P2P_AF_PRESENCE_REQ:
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "P2P_AF_PRESENCE_REQ\n"));
		p2papi_rx_presence_req_frame(hdl, src_mac, frame, frame_nbytes, &channel);
		break;
	case P2P_AF_PRESENCE_RSP:
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "P2P_AF_PRESENCE_RSP\n"));
		p2papi_rx_presence_rsp_frame(hdl, src_mac, frame, frame_nbytes, &channel);
		break;
	case P2P_AF_GO_DISC_REQ:
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "P2P_AF_GO_DISC_REQ\n"));
		p2papi_rx_go_discb_req_frame(hdl, src_mac, frame, frame_nbytes, &channel);
		break;
	default:
		break;
	}

#ifdef IGNORE_DUPLICATE_ACTION_FRAME
	is_first_frame = false;
	last_subtype = frame->subtype;
	last_dialog_token = frame->dialog_token;
	memcpy(last_src_mac.octet, src_mac->octet, sizeof(last_src_mac.octet));
#endif /* IGNORE_DUPLICATE_ACTION_FRAME */

	return 0;
}
#endif /* SOFTAP_ONLY */

/* Check if a received frame is a P2P Action Frame */
int
p2papi_is_p2p_action_frm(p2papi_instance_t *hdl, void *frame, uint32 frame_len)
{
	wifi_p2p_action_frame_t *act_frm = (wifi_p2p_action_frame_t *)frame;

	(void)hdl;

	if (frame_len < sizeof(wifi_p2p_action_frame_t) - 1)
		return FALSE;

	if (act_frm->category == P2P_AF_CATEGORY &&
		act_frm->type == P2P_VER &&
		0 == memcmp(act_frm->OUI, P2P_OUI, DOT11_OUI_LEN)) {
		return TRUE;
	} else {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"!is_p2p_af: cat=%02x type=%02x OUI=%02x:%02x:%02x\n",
			act_frm->category, act_frm->type,
			act_frm->OUI[0], act_frm->OUI[1], act_frm->OUI[2]));
		return FALSE;
	}
}

/* Check if a received frame is a P2P Public Action Frame */
int
p2papi_is_p2p_pub_act_frm(p2papi_instance_t *hdl, void *frame, uint32 frame_len)
{
	wifi_p2p_pub_act_frame_t *pact_frm = (wifi_p2p_pub_act_frame_t *)frame;

	(void)hdl;

	if (frame_len < sizeof(wifi_p2p_pub_act_frame_t) - 1)
		return FALSE;

	if (pact_frm->category == P2P_PUB_AF_CATEGORY &&
		pact_frm->action == P2P_PUB_AF_ACTION &&
		pact_frm->oui_type == P2P_VER &&
		memcmp(pact_frm->oui, P2P_OUI, sizeof(pact_frm->oui)) == 0) {
		return TRUE;
	} else {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"!is_p2p_pub_af: cat=%02x act=%02x oui=%02x:%02x:%02x typ=%02x\n",
			pact_frm->category, pact_frm->action, pact_frm->oui[0],
			pact_frm->oui[1], pact_frm->oui[2], pact_frm->oui_type));
		return FALSE;
	}
}

#ifndef SOFTAP_ONLY
/*
 * return true if the frame can be processed, otherwise, return false
 */
bool p2papi_process_rx_action_frame(p2papi_instance_t *hdl,
	struct ether_addr *src_mac, uint8 *act_frm,
	uint32 act_frm_len, wl_event_rx_frame_data_t *rxframe)
{
	if (!hdl->enable_p2p) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_process_rx_action_frame: discard, P2P not enabled\n"));
		return false;
	}

	if (p2papi_is_p2p_action_frm(hdl, act_frm, act_frm_len)) {
		p2papi_process_action_frame(hdl, src_mac,
			(wifi_p2p_action_frame_t *)act_frm, act_frm_len, rxframe);
		return true;
	}

	if (p2papi_is_p2p_pub_act_frm(hdl, act_frm, act_frm_len)) {
		p2papi_process_pub_act_frame(hdl, src_mac,
			(wifi_p2p_pub_act_frame_t *)act_frm, act_frm_len, rxframe);
		return true;
	}

	return false;
}

/* Get Group Owner Negotiation peer info */
BCMP2P_STATUS p2papi_get_neg_peer_info(p2papi_instance_t *hdl,
	BCMP2P_DISCOVER_ENTRY *peer_info)
{
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_get_neg_peer_info: mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
		hdl->peer_dev_addr.octet[0], hdl->peer_dev_addr.octet[1],
		hdl->peer_dev_addr.octet[2], hdl->peer_dev_addr.octet[3],
		hdl->peer_dev_addr.octet[4], hdl->peer_dev_addr.octet[5]));

	memcpy(&peer_info->mac_address, &hdl->peer_dev_addr,
		sizeof(peer_info->mac_address));

	memcpy(peer_info->ssid, hdl->peer_ssid, sizeof(peer_info->ssid));
	peer_info->ssidLength = (unsigned int) strlen((char*)peer_info->ssid);

	return BCMP2P_SUCCESS;
}
#endif /* SOFTAP_ONLY */


#if P2PAPI_ENABLE_WPS
/* Process a probe request's WPS IE.
 * Extract a WLC_E_PROBREQ_MSG event's WPS IE and then deliver it to
 * WPSCLI for PBC overlap detection.
 * Assumes the event data fields have already been converted from dongle
 * to host order.
 */
void
p2papi_proc_probe_req_wpsie(p2papi_instance_t *hdl, wl_event_msg_t *event)
{
	int totlen = event->datalen;
	uint8 *ie = (uint8 *)(event + 1) + DOT11_MGMT_HDR_LEN;
	bcm_tlv_t *elt = (bcm_tlv_t *)ie;

	if (hdl->disable_pbc_overlap)
		return;

	/* BCMP2PLOG((BCMP2P_LOG_VERB, TRUE, "p2papi_proc_probe_req_wpsie\n")); */

	while (totlen >= 2) {
		int eltlen = elt->len;

		/* Uncomment this to debug detecting WPS IEs */
		/*
		if (eltlen > 0 && elt->id == 0xdd && totlen >= (eltlen + 2)) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "proc_probreq_wpsie: "
				"eltlen=%d id=%02x data=%02x %02x %02x %02x\n",
				eltlen, elt->id, elt->data[0], elt->data[1], elt->data[2],
				elt->data[3]));
		}
		*/

		/* validate remaining totlen */
		if ((elt->id == 0xdd) && (totlen >= (eltlen + 2))) {
			if ((elt->len >= WPA_IE_OUITYPE_LEN) &&
				(memcmp(elt->data, WPS_OUI, WPS_OUI_LEN) == 0) &&
				(elt->data[WPS_OUI_LEN] == WPS_OUI_TYPE)) {
				BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
					"p2papi_proc_probe_req_wpsie: found WPA_OUI from "
					"%02x:%02x:%02x:%02x:%02x:%02x\n",
					event->addr.octet[0], event->addr.octet[1],
					event->addr.octet[2], event->addr.octet[3],
					event->addr.octet[4], event->addr.octet[5]));
				/*
				BCMP2PLOG((BCMP2P_LOG_INFO, TRUE, "    data="
					"%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
					elt->data[0], elt->data[1], elt->data[2], elt->data[3],
					elt->data[4], elt->data[5], elt->data[6], elt->data[7],
					elt->data[8], elt->data[9], elt->data[10]));
				*/
				brcm_wpscli_softap_on_sta_probreq_wpsie(event->addr.octet,
					&elt->data[4],	elt->len - 4);
				return;
			}
		}
		elt = (bcm_tlv_t*)((uint8*)elt + (eltlen + 2));
		ie = (uint8 *)elt;
		totlen -= (eltlen + 2);
	}
	/*
	BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
		"p2papi_proc_probe_req_wpsie: no WPA_OUI\n"));
	*/
}
#endif /* P2PAPI_ENABLE_WPS */


static void
p2papi_parse_escan_result(p2papi_instance_t *hdl, wl_escan_result_t * escanresult)
{
	int i = 0;
	wl_bss_info_t *new_bss;
	wl_scan_results_t * scanresults;
	scanresults = (wl_scan_results_t *)P2PAPI_SCANRESULT_BUF(hdl);

	new_bss = escanresult->bss_info;
	for (i = 0;
	     i < (int)escanresult->bss_count;
	     i++, new_bss = (wl_bss_info_t*)((int8*)new_bss + dtoh32(new_bss->length))) {

		int j = 0;
		int found = 0;
		wl_bss_info_t *found_bss, *next_bss;

		if (new_bss->flags & WL_BSS_FLAGS_FROM_BEACON) {
			/* Ignore beacon */
/*
			BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
				"  escan res %d: %02x:%02x:%02x:%02x:%02x:%02x:"
				" from beacon, discard\n", i, 
				new_bss->BSSID.octet[0], new_bss->BSSID.octet[1],
				new_bss->BSSID.octet[2], new_bss->BSSID.octet[3],
				new_bss->BSSID.octet[4], new_bss->BSSID.octet[5]));
*/
			continue;
		}
		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
			"  escan res %d: %02x:%02x:%02x:%02x:%02x:%02x len=%u\n", i,
			new_bss->BSSID.octet[0], new_bss->BSSID.octet[1],
			new_bss->BSSID.octet[2], new_bss->BSSID.octet[3],
			new_bss->BSSID.octet[4], new_bss->BSSID.octet[5], new_bss->length));

		found_bss = scanresults->bss_info;
		for (j = 0;
		     j < (int)scanresults->count;
		     j++,
		     found_bss = (wl_bss_info_t*)((int8*)found_bss + dtoh32(found_bss->length))) {
			if (memcmp((void *)new_bss->BSSID.octet,
				(void *)found_bss->BSSID.octet, ETHER_ADDR_LEN) == 0 &&
				dtoh32(new_bss->length) == dtoh32(found_bss->length)) {
				/* duplicate bsscfg found, stop searching */
				found = 1;
				BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
					"       : is duplicate, discard\n"));
				break;
			}
		}

		if (!found) {
			/* Check if buffer is full */
			if (P2PAPI_SCANRESULT_BUF_SIZE <
				(scanresults->buflen +
				dtoh32(new_bss->length))) {
				BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
					"ESCAN: sync_id(%04x) Buffer is full - "
					"stop adding new bss.\n",
					escanresult->sync_id));
				scanresults->buflen = P2PAPI_SCANRESULT_BUF_SIZE;
				p2pwlu_escan_abort(hdl);
				break;
			}

			/* Point to next available slot and copy new found to scanresults buffer */
			next_bss = (wl_bss_info_t*)((int8*)found_bss + dtoh32(found_bss->length));
			P2PAPI_DATA_LOCK_VERB(hdl);
			memcpy((void *)next_bss, (void *)new_bss, dtoh32(new_bss->length));
			scanresults->version = dtoh32(escanresult->version);
			scanresults->buflen += dtoh32(new_bss->length);
			scanresults->count++;
			P2PAPI_DATA_UNLOCK_VERB(hdl);
			BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
				"ESCAN: sync_id(%04x) ch=%d Adding bsscfg "
				"%02x:%02x:%02x:%02x:%02x:%02x to scanresults.\n",
				escanresult->sync_id,
				CHSPEC_CHANNEL(dtohchanspec(new_bss->chanspec)),
				found_bss->BSSID.octet[0],
				found_bss->BSSID.octet[1],
				found_bss->BSSID.octet[2],
				found_bss->BSSID.octet[3],
				found_bss->BSSID.octet[4],
				found_bss->BSSID.octet[5]));
		}
	}
}

/* Process primary interface WL driver event.
 */
static void
p2papi_primary_wl_event(p2papi_instance_t *hdl, wl_event_msg_t *event, void* data,
	uint32 data_len)
{
	uint32 event_type;

	(void) data; /* some builds may not use this parameter */
	/* assert(data) */

	if (!event) {
		return; /* Nothing to do. */
	}

	event_type = event->event_type;

	switch (event_type) {
	case WLC_E_DEAUTH_IND:
	case WLC_E_DISASSOC_IND:
		if (event->datalen >= 2) {
			/* If datalen is 2, event data(2 bytes) is just a
			 * reason code for deauth/disassoc frames
			 */
#ifndef SOFTAP_ONLY
			p2papi_p2p_ie_t p2p_ie;
			p2papi_decode_p2p_ie((uint8*)data + 2, &p2p_ie, BCMP2P_LOG_MED);
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_primary_wl_event: Infrastructure WLAN "
				"disconnected me - minor reason code = %d.\n",
				p2p_ie.minorrc_subelt.minor_rc));
			hdl->minor_rc = p2p_ie.minorrc_subelt.minor_rc;
#endif /* not SOFTAP_ONLY */
			p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_PRIMARY_IF,
				BCMP2P_NOTIF_PRIMARY_IF_DISCONNECTED);
		}
		break;
	case WLC_E_ASSOC:
	case WLC_E_REASSOC:
		/* parse IE looking for P2P Manageability,
		 * Channel Usage, Country, and Power Constraint IEs
		 */
		break;
	case WLC_E_PSK_SUP:
		if (event->status == 6 /* WLC_SUP_KEYED */) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_primary_wl_event: ignore WLC_E_PSK_SUP status=6\n"));
		}
		break;
	default:
		break;
	} /* switch (event_type) */
}

/* Process P2P interface(s) WL driver event.
 */
static void
p2papi_p2p_wl_event(p2papi_instance_t *hdl, wl_event_msg_t *event, void* data,
	uint32 data_len)
{
	uint32 event_type;

	(void) data; /* some builds may not use this parameter */
	/* assert(data) */

	if (!event) {
		return; /* Nothing to do. */
	}

	event_type = event->event_type;

	/* Act on specific events */
	switch (event_type) {
	case WLC_E_ASSOC_IND:
	case WLC_E_REASSOC_IND:
		if (hdl->ap_ready) {
			p2papi_proc_client_assoc(hdl, event, data, data_len);
		}
		break;
	case WLC_E_ASSOC_RESP_IE:
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_p2p_wl_event: hdl->is_wps_enrolling %d, hdl->conn_state %d. \n",
			hdl->is_wps_enrolling, hdl->conn_state));
		/* This event should only apply to STA */
		if (!hdl->is_ap)
			p2papi_proc_ap_assoc_resp_ie(hdl, event, data, data_len);
		break;
	case WLC_E_DEAUTH:
	case WLC_E_DEAUTH_IND:
	case WLC_E_DISASSOC_IND:
		if (hdl->ap_ready) {
			p2papi_proc_client_disassoc(hdl, event, data, data_len);
		}
		if (hdl->is_connected && !hdl->is_ap &&
			hdl->bssidx[P2PAPI_BSSCFG_CONNECTION] == event->bsscfgidx) {
			hdl->disconnect_detected = TRUE;
			p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_CREATE_LINK,
				BCMP2P_NOTIF_LINK_LOSS);
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_p2p_wl_event: %s detected.\n",
				WLC_E_DEAUTH_IND == event_type ? "deauth" : "disassoc"));
		}
		break;
	case WLC_E_LINK:
		/* This event indicates a BSSCFG was brought up (eg. it is sent in
		 * response to "wl bss -C 1 up".
		 */
		if (event->flags == 0 && hdl->is_connected && !hdl->is_ap) {
			hdl->disconnect_detected = TRUE;
			p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_CREATE_LINK,
				BCMP2P_NOTIF_LINK_LOSS);
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_p2p_wl_event: link down\n"));
		}
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"WLC_E_LINK: cbcaw=%u flags=0x%x ifname=%s\n",
			hdl->conn_bsscfg_create_ack_wait, event->flags, event->ifname));
		break;
	case WLC_E_IF:
	{
		void *wl_hdl = P2PAPI_GET_WL_HDL(hdl);
		wl_event_data_if_t *event_data_if = (wl_event_data_if_t *)&event[1];
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"WLC_E_IF: cbcaw=%u flags=0x%x ifname=%s\n",
			hdl->conn_bsscfg_create_ack_wait, event->flags, event->ifname));
		/* If we are waiting for a WLC_E_IF event resulting from setting
		 * the p2p_ifadd iovar to create a BSS
		 */
		if (hdl->conn_bsscfg_create_ack_wait && event_data_if->opcode == WLC_E_IF_ADD &&
		    (event_data_if->role == WLC_E_IF_ROLE_P2P_GO ||
		    event_data_if->role == WLC_E_IF_ROLE_P2P_CLIENT ||
		    event_data_if->role == WLC_E_IF_ROLE_AP)) {

			/* This event indicates the connection BSSCFG has been created.
			 * It is sent in response to "wl p2p_ifadd ..." or
			 * the first "wl ssid -C 1 <name>" on a nonexistent bsscfg.
			 */
			hdl->conn_bsscfg_create_ack_wait = FALSE;

			/* Save the interface name from the event */
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"...saving conn bsscfg ifname\n"));
			strncpy(hdl->conn_ifname, event->ifname,
				sizeof(hdl->conn_ifname) - 1);
			hdl->conn_ifname[sizeof(hdl->conn_ifname) - 1] = '\0';
			p2posl_save_bssname(wl_hdl, P2PAPI_BSSCFG_CONNECTION,
				hdl->conn_ifname);

			/* Do OS-specific actions to complete bringing up the BSSCFG */
			if (hdl->is_ap) {
				(void) p2papi_osl_ap_mode_ifup(hdl, event->ifname);
			} else {
				(void) p2papi_osl_sta_mode_ifup(hdl, event->ifname);
	            p2pwlu_set_wme_apsd_sta(hdl, hdl->maxSPLength, hdl->acBE,
				hdl->acBK, hdl->acVI, hdl->acVO, event_data_if->bssidx);
			}
		}
		break;
	}
	case WLC_E_PSK_SUP:
		if (event->status == 6 /* WLC_SUP_KEYED */) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_p2p_wl_event: wpa2-psk connection secured\n"));
			hdl->is_connection_secured = TRUE;
			p2papi_osl_signal_secure_join(hdl);
		}
		break;
	case WLC_E_PROBREQ_MSG:
		/* Prefer WLC_E_P2P_PROBREQ_MSG instead if needed for channel sync. */
#if P2PAPI_ENABLE_WPS
		/* wps overlap detection */
		p2papi_proc_probe_req_wpsie(hdl, event);
#endif /* P2PAPI_ENABLE_WPS */
		break;

	case WLC_E_ESCAN_RESULT:
		/* Always add to any Discovery results */
		if (event->status == WLC_E_STATUS_PARTIAL) {
			p2papi_parse_escan_result(hdl, (wl_escan_result_t *)data);
#ifndef SOFTAP_ONLY
			/* Always consider whether this completes Channel
			 * Synchronization, allowing a pending action frame tx.
			 */
			p2papi_fsm_handle_chansync_escan_result(hdl,
				(wl_escan_result_t *)data);
#endif /* SOFTAP_ONLY */
		}
		else if (event->status == WLC_E_STATUS_SUCCESS) {
			BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
				"ESCAN: sync_id(%04x) Completed.\n",
				((wl_escan_result_t *)data)->sync_id));
			p2papi_osl_signal_escan_state(hdl, P2PAPI_OSL_ESCAN_STATE_DONE);
		}
		else if (event->status == WLC_E_STATUS_ABORT) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"ESCAN: sync_id(%04x) Aborted.\n",
				((wl_escan_result_t *)data)->sync_id));
			p2papi_osl_signal_escan_state(hdl, P2PAPI_OSL_ESCAN_STATE_ABORT);
		}
		else {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"ESCAN: Aborted by status %d.\n", event->status));
			p2papi_osl_signal_escan_state(hdl, P2PAPI_OSL_ESCAN_STATE_ABORT);
		}
		break;
#ifndef SOFTAP_ONLY
	case WLC_E_ACTION_FRAME_RX:
		{
			/*
			 * Process received action frames
			 */
			wl_event_rx_frame_data_t *rxframe =
				(wl_event_rx_frame_data_t*) data;
			uint8 *act_frm = (uint8 *) (rxframe + 1);
			struct ether_addr* src_mac = &event->addr;
			uint32 act_frm_len = event->datalen - sizeof(wl_event_rx_frame_data_t);

			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"  wl_event_msg.addr=%02x:%02x:%02x:%02x:%02x:%02x\n",
				event->addr.octet[0], event->addr.octet[1],
				event->addr.octet[2], event->addr.octet[3],
				event->addr.octet[4], event->addr.octet[5]));

			p2papi_log_hexdata(BCMP2P_LOG_MED, "RX action frame",
				act_frm, act_frm_len);

			p2papi_process_rx_action_frame(hdl, src_mac, act_frm,
				act_frm_len, rxframe);
		} /* case WLC_E_ACTION_FRAME_RX */
		break;
#endif /* SOFTAP_ONLY */
	default:
		break;
	} /* switch (event_type) */
}

void
p2papi_wl_event_handler_negotiate(p2papi_instance_t *hdl, BCMP2P_BOOL is_primary,
                                  wl_event_msg_t *event, void* data, uint32 data_len)
{
	if (is_primary) {
		p2papi_primary_wl_event(hdl, event, data, data_len);
	}
	else {
		p2papi_p2p_wl_event(hdl, event, data, data_len);
	}
}


#ifndef SOFTAP_ONLY
/* enable/disable extended listen timing */
BCMP2P_STATUS
p2papi_extended_listen_timing(p2papi_instance_t* hdl,
	bool enable, uint32 period, uint32 interval)
{
	P2PAPI_CHECK_P2PHDL(hdl);

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_extended_listen_timing: en=%d per=%d int=%d\n",
		enable, period, interval));
	if (enable && (period > interval))
		return BCMP2P_INVALID_PARAMS;

	hdl->extended_listen.enabled = enable;
	hdl->extended_listen.period = period;
	hdl->extended_listen.interval = interval;
	p2papi_refresh_ies(hdl);

	return 	BCMP2P_SUCCESS;
}
#endif /* not SOFTAP_ONLY */
