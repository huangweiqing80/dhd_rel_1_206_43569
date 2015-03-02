/*
 * P2P Library API - Action Frame Transmitter.  Does retries and channel sync.
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: p2plib_aftx.c,v 1.24 2011-01-25 03:14:17 $
 */

/* ---- Include Files ---------------------------------------------------- */

#include <stdlib.h>
#include <ctype.h>

#include <p2plib_api.h>
#include <p2plib_int.h>
#include <p2plib_aftx.h>
#include <p2pwl.h>

#ifndef SOFTAP_ONLY

/* ---- Public Variables ------------------------------------------------- */
/* ---- Private Constants and Types -------------------------------------- */

/* Uncomment this to test AF tx retries */
/* #define P2PAPI_AFTX_RETRY_TEST 1 */

/* Uncomment this to enable AF tx retries on receiving a tx no-ack indication.
 * When uncommented, retransmits will occur on both a no-ack indication and
 * a timeout.
 * When commented out, retransmits will only occur on a timeout.
 */
/* #define P2PAPI_AFTX_NOACK_RETRANSMIT 1 */

/* ---- Private Variables ------------------------------------------------ */
#ifdef P2PAPI_AFTX_RETRY_TEST
static int aftx_complete_ignore_count = 0; /* For testing tx retries */
static int aftx_complete_force_noack_count = 0; /* For testing tx retries */
#endif /* P2PAPI_AFTX_RETRY_TEST */

/* ---- Private Function Prototypes -------------------------------------- */
static void p2papi_aftx_timeout_cb(void* arg);

/* ---- Functions -------------------------------------------------------- */


/* Allocate and init an instance of the Action Frame Transmitter */
static p2papi_aftx_instance_t*
p2papi_aftx_new(void* p2plib_hdl)
{
	p2papi_instance_t* hdl = (p2papi_instance_t *)p2plib_hdl;
	p2papi_aftx_instance_t* aftx_hdl;

	/* Allocate the AFTX instance */
	aftx_hdl = (p2papi_aftx_instance_t*) P2PAPI_MALLOC(sizeof(*aftx_hdl));
	if (aftx_hdl == NULL) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_aftx_new: alloc failed!\n"));
		goto init_ret;
	}

	memset(aftx_hdl, 0, sizeof(*aftx_hdl));
	aftx_hdl->state = P2PAPI_AFTX_ST_IDLE;
	aftx_hdl->p2plib_hdl = p2plib_hdl;

	/* Create the high level retransmit timer */
	aftx_hdl->retrans_timer = bcmseclib_init_timer_ex(hdl->timer_mgr, p2papi_aftx_timeout_cb,
		                                          aftx_hdl, "aftx_tmr");
	P2PLIB_ASSERT(aftx_hdl->retrans_timer != NULL);
	if (aftx_hdl->retrans_timer == NULL) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_aftx_new: no tmr!\n"));
		P2PAPI_FREE(aftx_hdl);
		aftx_hdl = NULL;
		goto init_ret;
	}
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_aftx_new: aftx_hdl=%p tmr=%p p2phdl=%p\n",
		aftx_hdl, aftx_hdl->retrans_timer, aftx_hdl->p2plib_hdl));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_aftx_new: dbg=0x%x %x %x %x\n",
		aftx_hdl->dbg[0], aftx_hdl->dbg[1], aftx_hdl->dbg[2], aftx_hdl->dbg[3]));

init_ret:
	return aftx_hdl;
}

/* Deinit and free an instance of the Action Frame Transmitter */
static int
p2papi_aftx_delete(p2papi_aftx_instance_t* aftx_hdl)
{
	p2papi_instance_t *p2p_hdl = (p2papi_instance_t*)aftx_hdl->p2plib_hdl;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_aftx_delete: aftx_hdl=%p dbg_name=%s\n",
		aftx_hdl, aftx_hdl ? aftx_hdl->dbg_name : ""));

	/* send signal to re-enable discovery */
	if (p2p_hdl && p2p_hdl->is_discovering)
	{
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
		"p2papi_aftx_delete: p2papi_discover_enable_search(true)\n"));
		p2papi_discover_enable_search(p2p_hdl, TRUE);
	}
	else
	{
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
		"p2papi_aftx_delete: p2p_hdl:%p or not discovering:%d\n", p2p_hdl, p2p_hdl ? p2p_hdl->is_discovering : -1));
	}

	/* Free the AFTX instance */
	if (aftx_hdl) {
		/* Free the high level retransmit timer */
		P2PLIB_ASSERT(aftx_hdl->retrans_timer != NULL);
		bcmseclib_free_timer(aftx_hdl->retrans_timer);

		/* Set this to null to detect repeated frees of the same aftx ptr */
		aftx_hdl->retrans_timer = NULL;

		P2PAPI_FREE(aftx_hdl);
		aftx_hdl = NULL;
	}

	return 0;
}


/* Process a WLC_E_ACTION_FRAME_OFF_CHAN_COMPLETE event */
static void
p2papi_aftx_off_chan_complete(p2papi_aftx_instance_t* aftx_hdl)
{
	P2PLIB_ASSERT(aftx_hdl != NULL);

	if (aftx_hdl) {
		p2papi_instance_t* hdl = (p2papi_instance_t *)aftx_hdl->p2plib_hdl;

		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_aftx_off_chan_complete\n"));

		if (!P2PAPI_CHECK_P2PHDL(hdl)) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "NULL p2plib instance handle\n"));
			return;
		}

		/* If a higher level component suspends p2p discovery search, we will
		 * let it resume it, instead of doing so here.
		 */
		if (!hdl->suspend_disc_search)
			p2papi_chsync_discov_disable((p2papi_instance_t *)aftx_hdl->p2plib_hdl);
	}
}

/* State entry actions for the Idle state */
static int
p2papi_aftx_fsm_enter_st_idle(p2papi_aftx_instance_t* aftx_hdl)
{
	P2PLIB_ASSERT(aftx_hdl != NULL);

	/* Change state to Idle */
	aftx_hdl->state = P2PAPI_AFTX_ST_IDLE;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_aftx_fsm_enter_st_idle\n"));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_aftx_fsm_enter_st_idle: aftx_hdl=%p hdl=%p dbg=0x%x %x %x %x\n",
		aftx_hdl, aftx_hdl->p2plib_hdl, aftx_hdl->dbg[0],
		aftx_hdl->dbg[1], aftx_hdl->dbg[2], aftx_hdl->dbg[3]));

	/* Stop the high level retransmit timer */
	if (false == bcmseclib_del_timer(aftx_hdl->retrans_timer)) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_aftx_fsm_enter_st_idle: tmr already expired at delete\n"));
	}

	/* If we have a pending WLC_E_ACTION_FRAME_OFF_CHAN_COMPLETE event rx
	 * we have not yet processed
	 *   Process it
	 */
	if (aftx_hdl->off_chan_complete) {
		aftx_hdl->off_chan_complete = BCMP2P_FALSE;
		p2papi_aftx_off_chan_complete(aftx_hdl);
	}
	return 0;
}

/* State entry actions for the Wait For Ack state */
static int
p2papi_aftx_fsm_enter_st_wait_for_ack(p2papi_aftx_instance_t* aftx_hdl)
{
	int err;
	chanspec_t chspec;

	P2PLIB_ASSERT(aftx_hdl != NULL);

	/* Change state to Wait For Ack */
	aftx_hdl->state = P2PAPI_AFTX_ST_WAIT_FOR_ACK;

	/* Debug: show the current channel the frame will be sent on */
	p2pwlu_get_chanspec((p2papi_instance_t*) aftx_hdl->p2plib_hdl,
		&chspec, aftx_hdl->bsscfg_index);

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_aftx_fsm_enter_st_wait_for_ack: retries=%u tmo=%u\n",
		aftx_hdl->retries, aftx_hdl->retry_timeout_ms));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"    aftx_hdl=%p hdl=%p idx=%d chspec=0x%x\n",
		aftx_hdl, aftx_hdl->p2plib_hdl, aftx_hdl->bsscfg_index, chspec));

	/* Stop the high level retransmit timer */
	if (false == bcmseclib_del_timer(aftx_hdl->retrans_timer)) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_aftx_fsm_wait_for_ack: tmr already expired at del\n"));
	}

	/* Send the action frame on the device interface */
	err = p2papi_tx_af((p2papi_instance_t*) aftx_hdl->p2plib_hdl,
		aftx_hdl->af_params, aftx_hdl->bsscfg_index);

	/* Start the high level retransmit timer */
	p2papi_add_timer(aftx_hdl->p2plib_hdl, aftx_hdl->retrans_timer,
		aftx_hdl->retry_timeout_ms,	false);

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_aftx_fsm_wait_for_ack: exit\n"));

	return err;
}

/* Invoke action frame complete */
static void
p2papi_aftx_complete(p2papi_aftx_instance_t* aftx_hdl, BCMP2P_BOOL is_success)
{
	P2PLIB_ASSERT(aftx_hdl != NULL);

	/* reset state to allow callback to transmit action frame */
	p2papi_aftx_fsm_enter_st_idle(aftx_hdl);

	/* invoke callback */
	if (aftx_hdl->cb_func != NULL) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_aftx_complete: %s\n", is_success ? "success" : "failed"));
		aftx_hdl->cb_func(aftx_hdl->cb_param, aftx_hdl, is_success,
			aftx_hdl->af_params);
	}
}

/* Retry sending the action frame.
 * Returns 0 if retry sent, non-zero if no more retries.
 */
static int
p2papi_aftx_fsm_do_retry(p2papi_aftx_instance_t* aftx_hdl)
{
	P2PLIB_ASSERT(aftx_hdl != NULL);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_aftx_fsm_do_retry: aftx_hdl=%p hdl=%p dbg=0x%x %x %x %x\n",
		aftx_hdl, aftx_hdl->p2plib_hdl, aftx_hdl->dbg[0],
		aftx_hdl->dbg[1], aftx_hdl->dbg[2], aftx_hdl->dbg[3]));

	if (aftx_hdl->state == P2PAPI_AFTX_ST_IDLE) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_aftx_fsm_do_retry: already in idle state\n"));
		/* Call the AF tx complete callback to indicate tx failure */
		p2papi_aftx_complete(aftx_hdl, BCMP2P_FALSE);
		return 1;
	} else {
		/* If the retry count has not reached the max
		 *   Resend the frame and re-enter Wait For Ack state.
		 * else
		 *   Call the AF tx completion callback fn to indicate failure.
		 *   Enter Idle state.
		 */
		++aftx_hdl->retries;
		if (aftx_hdl->retries < aftx_hdl->max_retries) {
			/* Enter the Wait for Ack state.  The AF will be retransmitted
			 * in the state entry action.
			 */
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_aftx_fsm_do_retry: state %d, retry #%u\n",
				aftx_hdl->state, aftx_hdl->retries));
			(void) p2papi_aftx_fsm_enter_st_wait_for_ack(aftx_hdl);
		}
		else {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_aftx_fsm_do_retry: state %d, max retries failed\n",
				aftx_hdl->state));
			/* p2papi_chsync_discov_disable(hdl); */
			p2papi_aftx_complete(aftx_hdl, BCMP2P_FALSE);
			return 1;
		}
	}
	return 0;
}

/* Timer expiry callback fn - runs in event handler thread */
static void
p2papi_aftx_timeout_cb(void* arg)
{
	p2papi_aftx_instance_t* aftx_hdl = (p2papi_aftx_instance_t*)arg;

	P2PLIB_ASSERT(aftx_hdl != NULL);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_aftx_timeout_cb: aftx_hdl=%p hdl=%p dbg=0x%x %x %x %x\n",
		aftx_hdl, aftx_hdl->p2plib_hdl, aftx_hdl->dbg[0],
		aftx_hdl->dbg[1], aftx_hdl->dbg[2], aftx_hdl->dbg[3]));

	/* assert(aftx_hdl != NULL); */
	if (aftx_hdl == NULL) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_aftx_timeout_cb: bad aftx_hdl\n"));
		return;
	}

	switch (aftx_hdl->state) {
	case P2PAPI_AFTX_ST_IDLE:
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_aftx_timeout_cb: timeout ignored in ST_IDLE\n"));
		break;
	case P2PAPI_AFTX_ST_WAIT_FOR_ACK:
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_aftx_timeout_cb: ST_WAIT_FOR_ACK\n"));
		++aftx_hdl->retries;
		if (aftx_hdl->retries < aftx_hdl->max_retries) {
			/* Enter the Wait for Ack state.  The AF will be retransmitted
			 * in the state entry action.
			 */
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_aftx_timeout_cb: ST_WAIT_FOR_ACK, tx retry %u\n",
				aftx_hdl->retries));
			(void) p2papi_aftx_fsm_enter_st_wait_for_ack(aftx_hdl);
		}
		else {
			/* Call the AF tx complete callback to indicate tx failure. */
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
				"p2papi_aftx_timeout_cb: ST_WAIT_FOR_ACK, tx failed.\n"));
			p2papi_aftx_complete(aftx_hdl, BCMP2P_FALSE);
			(void) p2papi_aftx_delete(aftx_hdl);
			aftx_hdl = NULL;
		}
		break;
	default:
		break;
	}
}

/* Check if we should ignore a receive action frame tx result event.
 * Action frame tx result events are WLC_E_ACTION_FRAME_COMPLETE and
 * WLC_E_TXFAIL.
 */
static BCMP2P_BOOL
p2papi_aftx_chk_tx_result_event(p2papi_aftx_instance_t* aftx_hdl,
	wl_event_msg_t *event, void *event_data, char *dbg_event_name)
{
	BCMP2P_UINT32* pkt_id = (BCMP2P_UINT32*)event_data;

	P2PLIB_ASSERT(aftx_hdl != NULL);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_aftx_chk_tx_result_event: %s\n", dbg_event_name));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"    status=%d pktid=%x, AFTX af=%p cb=%p state=%d\n",
		event->status, (pkt_id ? *pkt_id : 0),
		aftx_hdl->af_params, aftx_hdl->cb_func, aftx_hdl->state));

	if (pkt_id == NULL) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "    Ignore event, no data\n"));
		return BCMP2P_FALSE;
	}

	/* If we have no current tx action frame, ignore event. */
	if (aftx_hdl->af_params == NULL) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "    Ignore event, no af_params\n"));
		return BCMP2P_FALSE;
	}

	/* If event is not for the current tx action frame, ignore event. */
	if (*pkt_id != aftx_hdl->af_params->action_frame.packetId) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"    Ignore event, pktid %u != aftx_pktid %u\n",
			*pkt_id, aftx_hdl->af_params->action_frame.packetId));
		return BCMP2P_FALSE;
	}

	return BCMP2P_TRUE;
}

/* Event Handler for the Action Frame Transmitter FSM.
 */
void
p2papi_wl_event_handler_aftx(p2papi_aftx_instance_t* aftx_hdl,
	BCMP2P_BOOL is_primary, wl_event_msg_t *event, void* data, uint32 data_len)
{
	uint32 event_type;
	uint32 *pkt_id;

	/* If we have no current tx action frame, ignore event. */
	if (aftx_hdl == NULL) {
		return;
	}
	/* If the event is for the primary bsscfg, ignore event. */
	if (is_primary) {
		return;
	}
	/* If there is no event, ignore event */
	if (!event) {
		return;
	}

	/* Act on specific events */
	event_type = event->event_type;
	switch (event_type) {

	/* Action frame tx has received 802.11 ack or failed all 802.11 retries */
	case WLC_E_ACTION_FRAME_COMPLETE:
	{
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_wl_event_handler_aftx: AF_COMP %s aftx_hdl=%p\n",
			aftx_hdl->dbg_name, aftx_hdl));
		/* Check if we should ignore this event or not */
		if (!p2papi_aftx_chk_tx_result_event(aftx_hdl, event, data,
			"WLC_E_ACTION_FRAME_COMPLETE")) {
			break;
		}

#ifdef P2PAPI_AFTX_RETRY_TEST
		/* Test timeout-based tx retries: ignore 1st N tx complete events.
		 * This causes a retransmit after the tx times out.
		 */
		if (aftx_complete_ignore_count > 0) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
				"aftx TEST: ignore WLC_E_ACTION_FRAME_COMPLETE, cnt=%d\n",
				aftx_complete_ignore_count));
			--aftx_complete_ignore_count;
			break;
		}
		/* Test no-ack based tx retries: change tx complete-success event
		 * to tx complete-no-ack.  This causes an immediate retransmit if
		 * retransmit on no-ack is compiled in below.
		 */
		if (aftx_complete_force_noack_count > 0) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
				"aftx TEST: force noack WLC_E_ACTION_FRAME_COMPLETE, cnt=%d\n",
				aftx_complete_force_noack_count));
			--aftx_complete_force_noack_count;
			event->status = WLC_E_STATUS_NO_ACK;
		}
#endif /* P2PAPI_AFTX_RETRY_TEST */

		/* If an 802.11 ack was received for the current tx action frame */
		pkt_id = (BCMP2P_UINT32*)data;
		if (event->status == WLC_E_STATUS_SUCCESS) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"    pktid=%x, 802.11 ack received.\n", *pkt_id));
			p2papi_aftx_complete(aftx_hdl, BCMP2P_TRUE);
			(void) p2papi_aftx_delete(aftx_hdl);
			aftx_hdl = NULL;
		}
		else {
			BCMP2PLOG((BCMP2P_LOG_WARN, TRUE,
				"    pktid=%u, 802.11 ack not received, status=%u\n",
				*pkt_id, event->status));
#ifdef P2PAPI_AFTX_NOACK_RETRANSMIT
			if (p2papi_aftx_fsm_do_retry(aftx_hdl) != 0) {
				(void) p2papi_aftx_delete(aftx_hdl);
				aftx_hdl = NULL;
			}
#endif /* P2PAPI_AFTX_NOACK_RETRANSMIT */
		}
		break;
	}

	/* Off-channel Action frame tx dwell time has completed */
	case WLC_E_ACTION_FRAME_OFF_CHAN_COMPLETE:
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_wl_event_handler_aftx: OFF_CHAN_COMP %s aftx_hdl=%p\n",
			aftx_hdl->dbg_name, aftx_hdl));
		/* This event is sent when:
		 * - The dwell time has completed for a off channel action frame tx
		 *   and the driver has switched back to the home channel, or
		 * - The action frame tx was cancelled by a scan abort (the driver's
		 *   scan engine drives the off channel action frame dwell time.)
		 *   In this case event->status == WLC_E_STATUS_ABORT.
		 */
		/* if this event is not the result of a scan abort cancelling an
		 * off channel action frame tx
		 *   if we are idle (not retransmitting an Action Frame)
		 *     Disable driver P2P discovery if it was turned on for action
		 *     frame tx channel synchronization.
		 *   else
		 *     Remember this event for processing after we finish
		 *     (re)transmitting the action frame.
		 */
		if (event->status != WLC_E_STATUS_ABORT) {
			if (aftx_hdl->state == P2PAPI_AFTX_ST_IDLE) {
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"event_handler_aftx: acting on rx OFF_CHAN_COMPLETE\n"));
				p2papi_aftx_off_chan_complete(aftx_hdl);
			}
			else {
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"event_handler_aftx: saving rx OFF_CHAN_COMPLETE\n",
					aftx_hdl->state));
				aftx_hdl->off_chan_complete = BCMP2P_TRUE;
			}
		}
		else {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"aftx: ignoring WLC_E_AF_OFF_CHAN_COMPLETE from scan abort\n"));
		}
		break;

	/* Action frame tx failed (driver's dot11FailedCount changed) */
	case WLC_E_TXFAIL:
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_wl_event_handler_aftx: TX_FAIL %s aftx_hdl=%p\n",
			aftx_hdl->dbg_name, aftx_hdl));
		/* Check if we should ignore this event or not */
		if (!p2papi_aftx_chk_tx_result_event(aftx_hdl, event, data,
			"WLC_E_TXFAIL")) {
			break;
		}
		pkt_id = (BCMP2P_UINT32*)data;
		if (*pkt_id == aftx_hdl->af_params->action_frame.packetId) {
			if (p2papi_aftx_fsm_do_retry(aftx_hdl) != 0) {
				(void) p2papi_aftx_delete(aftx_hdl);
				aftx_hdl = NULL;
			}
		}
		break;

	default:
		break;
	} /* switch (event_type) */
}

/* AFTX API: Send a P2P public action frame with retries.
 * Returns a handle to an allocated the aftx instance.
 *
 * After the tx has succeeded or all retries have failed, the given callback
 * function is called and then the aftx instance data is freed.  So the
 * callback function should remove any stored references to the aftx instance
 * handle.
 */
p2papi_aftx_instance_t*
p2papi_aftx_send_frame(void* p2plib_hdl,
	wl_af_params_t* af_params, int bsscfg_index,
	BCMP2P_UINT32 max_retries, BCMP2P_UINT32 retry_timeout_ms,
	BCMP2P_AFTX_CALLBACK aftx_result_cb_func, void* cb_context,
	const char *dbg_af_name)
{
	p2papi_aftx_instance_t* aftx_hdl;

	if (af_params == NULL) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_aftx_send_frame: no AF to send!\n"));
		return NULL;
	}

	aftx_hdl = p2papi_aftx_new(p2plib_hdl);
	if (aftx_hdl == NULL) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_aftx_send_frame: init failed!\n"));
		return NULL;
	}

	/* Save the AF tx parameters */
	aftx_hdl->af_params = af_params;
	aftx_hdl->bsscfg_index = bsscfg_index;
	aftx_hdl->max_retries = max_retries;
	aftx_hdl->retry_timeout_ms = retry_timeout_ms;
	aftx_hdl->cb_func = aftx_result_cb_func;
	aftx_hdl->cb_param = cb_context;
	aftx_hdl->dbg_name = dbg_af_name;

	/* Reset state information for this action frame tx */
	aftx_hdl->retries = 0;
	aftx_hdl->off_chan_complete = BCMP2P_FALSE;

#ifdef P2PAPI_AFTX_RETRY_TEST
	/* Change this value to non-zero to test timeout-based tx retries.
	 * A value of N means ignore the 1st N tx complete events, which causes a
	 * retransmit at the tx timeout.
	 */
	aftx_complete_ignore_count = 0;
	/* aftx_complete_ignore_count = 1; */
	/* aftx_complete_ignore_count = max_retries - 1; */
	/* aftx_complete_ignore_count = max_retries + 1; */

	/* Change this value to non-zero to test no_ack-based tx retries.
	 * A value of N means treat the 1st N tx complete-success events as
	 * tx complete-no-ack, which causes an immediate retransmit.
	 */
	aftx_complete_force_noack_count = 0;
	/* aftx_complete_force_noack_count = 1; */
	/* aftx_complete_force_noack_count = max_retries - 1; */
	/* aftx_complete_force_noack_count = max_retries + 1; */
#endif /* P2PAPI_AFTX_RETRY_TEST */

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_aftx_send_frame: aftx_hdl=%p hdl=%p dbg=0x%x %x %x %x\n",
		aftx_hdl, aftx_hdl->p2plib_hdl, aftx_hdl->dbg[0],
		aftx_hdl->dbg[1], aftx_hdl->dbg[2], aftx_hdl->dbg[3]));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"    pktid=0x%x retries=%u tmo=%d state=%d cb=%p name=%s\n",
		af_params->action_frame.packetId, aftx_hdl->max_retries,
		aftx_hdl->retry_timeout_ms, aftx_hdl->state, aftx_hdl->cb_func,
		aftx_hdl->dbg_name));

	/* Enter the Wait for Ack state.  The AF will be transmitted as part of
	 * the state entry action.
	 */
	(void) p2papi_aftx_fsm_enter_st_wait_for_ack(aftx_hdl);

	return aftx_hdl;
}

/* AFTX API: Cancel a send of a P2P public action frame and free the instance */
int
p2papi_aftx_cancel_send(p2papi_aftx_instance_t* aftx_hdl)
{
	if (aftx_hdl == NULL)
		return 0;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_aftx_cancel_send: state=%d af_parms=%p tmr=%p name=%s\n",
		aftx_hdl->state, aftx_hdl->af_params, aftx_hdl->retrans_timer,
		aftx_hdl->dbg_name));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_aftx_cancel_send: aftx_hdl=%p hdl=%p dbg=0x%x %x %x %x\n",
		aftx_hdl, aftx_hdl->p2plib_hdl, aftx_hdl->dbg[0],
		aftx_hdl->dbg[1], aftx_hdl->dbg[2], aftx_hdl->dbg[3]));

	if (aftx_hdl->state != P2PAPI_AFTX_ST_IDLE)
		p2papi_aftx_complete(aftx_hdl, BCMP2P_FALSE);

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_aftx_cancel_send post-cb: aftx_hdl=%p hdl=%p dbg=0x%x %x %x %x\n",
		aftx_hdl, aftx_hdl->p2plib_hdl, aftx_hdl->dbg[0],
		aftx_hdl->dbg[1], aftx_hdl->dbg[2], aftx_hdl->dbg[3]));

	(void) p2papi_aftx_delete(aftx_hdl);
	/* after this point, aftx_hdl cannot be used anymore */

	return 0;
}

/* Core actions for an action frame tx completion callback function.
 * A minimal aftx complete callback function can consist of a call to
 * this function followed by clearing the stored aftx handle.
 */
void
p2papi_aftx_complete_callback_core(void *handle,
	p2papi_aftx_instance_t* aftx_hdl,
	BCMP2P_BOOL acked, wl_af_params_t *af_params)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*)handle;
	P2PLIB_ASSERT(P2PAPI_CHECK_P2PHDL(hdl));

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_aftx_complete_callback: acked=%d af_params=%p\n",
		acked, af_params));
	P2PLIB_ASSERT(aftx_hdl != NULL);

	if (aftx_hdl->af_params != NULL) {
		P2PAPI_FREE(aftx_hdl->af_params);
		aftx_hdl->af_params = NULL;
	}
}

/* AFTX API: Init the action frame transmitter API */
int
p2papi_aftx_api_init(void* p2plib_hdl)
{
	(void) p2plib_hdl;
	return 0;
}

/* AFTX API: Deinit the action frame transmitter API */
int
p2papi_aftx_api_deinit(void* p2plib_hdl)
{
	(void) p2plib_hdl;
	return 0;
}


#else /* SOFTAP_ONLY is defined */


/* Stub out Action Frame Transmitter defns for SOFTAP_ONLY
 */
void
p2papi_wl_event_handler_aftx(p2papi_aftx_instance_t* aftx_hdl,
	BCMP2P_BOOL is_primary, wl_event_msg_t *event, void* data, uint32 data_len)
{
	(void) aftx_hdl;
	(void) is_primary;
	(void) event;
	(void) data;
	(void) data_len;
}
p2papi_aftx_instance_t*
p2papi_aftx_new(void* p2plib_hdl)
{
	(void) p2plib_hdl;
	return NULL;
}
int
p2papi_aftx_delete(p2papi_aftx_instance_t* aftx_hdl)
{
	(void) aftx_hdl;
	return 0;
}
p2papi_aftx_instance_t*
p2papi_aftx_send_frame(void* p2plib_hdl,
	wl_af_params_t* af_params, int bsscfg_index,
	BCMP2P_UINT32 max_retries, BCMP2P_UINT32 retry_timeout_ms,
	BCMP2P_AFTX_CALLBACK aftx_result_cb_func, void* cb_context,
	const char* dbg_af_name)
{
	(void) p2plib_hdl;
	(void) af_params;
	(void) bsscfg_index;
	(void) max_retries;
	(void) retry_timeout_ms;
	(void) aftx_result_cb_func;
	(void) cb_context;
	(void) dbg_af_name;
	return 0;
}
int
p2papi_aftx_cancel_send(p2papi_aftx_instance_t* aftx_hdl)
{
	(void) aftx_hdl;
	return 0;
}

void
p2papi_aftx_complete_callback(void *handle, BCMP2P_BOOL acked,
	wl_af_params_t *af_params)
{
	(void) handle;
	(void) acked;
	(void) af_params;
}

int
p2papi_aftx_api_init(void* p2plib_hdl)
{
	(void) p2plib_hdl;
	return 0;
}

int
p2papi_aftx_api_deinit(void* p2plib_hdl)
{
	(void) p2plib_hdl;
	return 0;
}

#endif /* SOFTAP_ONLY */
