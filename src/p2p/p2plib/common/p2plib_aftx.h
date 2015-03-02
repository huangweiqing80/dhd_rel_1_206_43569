/* P2P Library API - Action Frame Transmitter header file
 *
 * Copyright (C) 2014, Broadcom Corporation. All Rights Reserved.
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * $Id: p2plib_aftx.h,v 1.8 2011-01-07 02:30:16 $
 */

#ifndef _p2plib_aftx_h_
#define _p2plib_aftx_h_

#include <typedefs.h>
#include <p2p.h>
#include <BcmP2PAPI.h>


/* Forward declaration */
struct p2papi_aftx_instance_s;

/* Action frame tx result notification callback function type.
 * Parameters:
 * - cb_context: Context ptr previously provided by the app in
 *               p2papi_aftx_send_frame()'s cb_context parameter.
 * - success:    Indicates whether an 802.11 ack was received from the peer.
 * - af_params:  Pointer to the tx action frame previously provided by the app
 *               in p2papi_aftx_send_frame()'s af_params parameter.
 */
typedef void (*BCMP2P_AFTX_CALLBACK) (void *cb_context,
	struct p2papi_aftx_instance_s* aftx_hdl, BCMP2P_BOOL success, wl_af_params_t* af);

/* Private AFTX FSM state */
typedef enum {
	P2PAPI_AFTX_ST_IDLE,
	P2PAPI_AFTX_ST_WAIT_FOR_ACK
} p2papi_aftx_state_t;

/* Action Frame Transmitter instance data */
typedef struct p2papi_aftx_instance_s {
	/* Action Frame tx Parameters
	 *
	 */
	/* Action frame to send */
	wl_af_params_t*	af_params;

	/* bsscfg index to send on */
	BCMP2P_INT32	bsscfg_index;

	/* Max # of high level (not 802.11 level) retries */
	BCMP2P_UINT32	max_retries;

	/* Retransmit after this timeout if no 802.11 ack */
	BCMP2P_UINT32	retry_timeout_ms;

	/* Tx result success/fail callback function */
	BCMP2P_AFTX_CALLBACK	cb_func;
	void*			cb_param;


	/* Other data
	 *
	 */
	void*			p2plib_hdl; /* p2plib handle */
	p2papi_aftx_state_t	state;	/* FSM state */
	BCMP2P_UINT32		retries; /* high level retransmit count */
	bcmseclib_timer_t*	retrans_timer;
	/* Have a rx WLC_E_ACTION_FRAME_OFF_CHAN_COMPLETE to be processed */
	BCMP2P_BOOL		off_chan_complete;

	/* TEMP - debug */
	BCMP2P_UINT32		dbg[4];
	const char*		dbg_name;
} p2papi_aftx_instance_t;


/* Event Handler for the Action Frame Transmitter FSM */
extern void
p2papi_wl_event_handler_aftx(p2papi_aftx_instance_t* aftx_hdl,
	BCMP2P_BOOL is_primary, wl_event_msg_t *event, void* data, uint32 data_len);


/* AFTX API: Init the action frame transmitter API */
extern int
p2papi_aftx_api_init(void* p2plib_hdl);

/* AFTX API: Deinit the action frame transmitter API */
extern int
p2papi_aftx_api_deinit(void* p2plib_hdl);

/* AFTX API: Send a P2P public action frame with retries */
extern p2papi_aftx_instance_t*
p2papi_aftx_send_frame(void* p2plib_hdl,
	wl_af_params_t* af_params, int bsscfg_index,
	BCMP2P_UINT32 max_retries, BCMP2P_UINT32 retry_timeout_ms,
	BCMP2P_AFTX_CALLBACK aftx_result_cb_func, void* cb_context,
	const char* dbg_af_name);


/* AFTX API: Cancel a send of a P2P public action frame */
extern int
p2papi_aftx_cancel_send(p2papi_aftx_instance_t* aftx_hdl);

/* AFTX API: Core actions for an action frame tx completion callback function.
 * A minimal aftx complete callback function can consist of a call to
 * this function followed by clearing the stored aftx handle.
 */
extern void
p2papi_aftx_complete_callback_core(void *handle,
	p2papi_aftx_instance_t* aftx_hdl,
	BCMP2P_BOOL acked, wl_af_params_t *af_params);

#endif  /* _p2plib_aftx_h_ */
