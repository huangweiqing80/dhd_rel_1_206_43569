/* P2P Service Discovery header file
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
 * $Id: p2plib_sd_sm.h,v 1.3 2010-12-21 23:05:38 $
 */

#ifndef _p2plib_sd_sm_h_
#define _p2plib_sd_sm_h_

#ifndef SOFTAP_ONLY

#include <typedefs.h>
#include <p2p.h>
#include <p2plib_api.h>

#define	MAX_SVC_DATA_PAIRS			256
#define p2plib_sd_DWELL_TIME_MS		200

typedef enum {
	SD_STATUS_SUCCESS = 0,			/* Session ends with success */
	SD_STATUS_CONTINUE,				/* Session continues */
	SD_STATUS_ABORTED,				/* SD session is aborted */
	SD_STATUS_INVALID_PARAM,		/* Invalid parameter passed in */
	SD_STATUS_ENCODE_ERR,			/* Frame encoding error */
	SD_STATUS_DECODE_ERR,			/* Frame decoding error */
	SD_STATUS_RECV_WRONG_FRAG_ID,	/* Wrong fragment id received */
	SD_STATUS_SYSTEM_ERR,			/* Memory allocation or ioctl failure */
	SD_STATUS_GENERIC_ERR,			/* Generic uncatogarized errors */
	SD_STATUS_ERR_TX_MAX_RETRY,		/* SD failure after max tx retries */
	SD_STATUS_ERR_TX
} SD_STATUS;

/* Service Discovery state definition */
typedef enum {
	SD_ST_INIT = 0,
	SD_ST_IDLE,

	/* Request SM states */
	SD_ST_SENDING_INIT_REQ,
	SD_ST_INIT_REQ_SENT,
	SD_ST_SENDING_CB_REQ,
	SD_ST_CB_REQ_SENT,
	SD_ST_INVOKING_GC,

	/* Response SM states */
	SD_ST_SENDING_INIT_RSP,
	SD_ST_INIT_RSP_SENT,
	SD_ST_SENDING_CB_RSP,
	SD_ST_CB_RSP_SENT
} SD_STATE;

/* Service Discovery event definition */
typedef enum {
	SD_E_PEER_FOUND,		/* P2P peer found */
	SD_E_TARGET_DEV_ACTIVATED,
	SD_E_START_REQ,			/* Initl req af plumbed to driver */
	SD_E_TX_SUCCESS,		/* SD_E_TX_AF_FAIL */
	SD_E_TX_FAIL,			/* SD_E_TX_AF_FAIL */
	SD_E_RX_GAS_INIT_REQ,
	SD_E_RX_GAS_INIT_RSP,
	SD_E_RX_GAS_CB_REQ,		/* Comeback req received */
	SD_E_RX_GAS_CB_RSP,		/* Comeback resp received */
	SD_E_GAS_RSP_TIMEOUT,
	SD_E_ABORT_SESSION,		/* Abort current SD session */
} SD_EVENT;

/* Common state machine context */
typedef struct {
	SD_STATE state;
	struct ether_addr peer_mac;
	BCMP2P_CHANNEL channel;		/* Peer device's current listen channel */
	uint8 dialog_token;
	uint16 tsc_id;
	uint16 gas_status;		/* 802.11u GAS status code */
	p2papi_instance_t *hdl;
	uint32 sending_af_pktid;
	bool sending_af;
	bool ch_sync;

	SD_EVENT last_evt;		/* Remember last SM event */
	uint8 *recv_acf_data;	/* Point to currently received af body */
	uint8 total_tx_attempts;	/* Total number of attemps to tx current af */

	wl_af_params_t *pending_tx_af;
	uint8 pending_tx_attempts;
} p2plib_sd_sm_t;

typedef struct p2plib_sd_sm_base {
	struct p2plib_sd_req_sm *next;
	p2plib_sd_sm_t comm_sm;
} p2plib_sd_sm_base_t;

typedef struct p2plib_sd_req_sm {
	struct p2plib_sd_req_sm *next;
	p2plib_sd_sm_t comm_sm;

	BCMP2P_SVC_LIST *req_entry_list;

	uint8 *svc_resp;	/* BCMP2P_SVC_LIST type */

	/* Fragmentation related */
	uint8 *rx_qrsp_buf;			/* Buffer to store all fragments received */	
	uint32 rx_qrsp_buf_size;	/* Buffer size */
	uint32 rx_qrsp_data_len;	/* Total data length of received fragments */
	uint8 fragment_id;			/* Fragment id to expect */
} p2plib_sd_req_sm_t;

typedef struct p2plib_sd_rsp_sm {
	struct p2plib_sd_rsp_sm *next;
	p2plib_sd_sm_t comm_sm;

	uint8 fragment_id;			/* fragment id to expect in the next fragment */
	bool last_frag_sent;		/* Whether last fragment is sent or not */

	/* Fragmentation related */
	uint8 *tx_qrsp_buf;
				/* Buffer holding the encoded query response frame to be
				 * fragmented in wifi_p2psd_qresp_frame_t format
				 */
	uint16 tx_qrsp_frm_size;		/* Size of qrsp_frame data */
	uint8 *tx_qrsp_cur_frag;		/* Point to fragment to send */

} p2plib_sd_rsp_sm_t;

/* Service Data instance saved in Service Data Store */
typedef struct {
	BCMP2PHandle			hsd;			/* Instance handle */
	uint32					svc_id;			/* Transaction ID */
	p2psd_svc_protype_t		pro_type;		/* Service protocol type */
	uint8					*req_data;		/* Service query data */
	uint32					req_data_len;	/* Size of service query data */
	uint8					*resp_data;		/* Service response data */
	uint32					resp_data_len;	/* Size of service response data */
} p2plib_sd_instance_t;

typedef struct {
	uint32					total;
			/* Total number of sd data instances */
	uint32					svc_id_counter;
			/* Service ID counter */
	p2plib_sd_instance_t	instances[MAX_SVC_DATA_PAIRS];
			/* Service data instances */
} p2plib_sd_instance_list_t;


#endif /* not  SOFTAP_ONLY */

#endif  /* _p2plib_sd_sm_h_ */
