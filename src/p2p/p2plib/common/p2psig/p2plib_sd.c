/* P2P Service Discovery implementation
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: p2plib_sd.c,v 1.48 2011-01-10 13:01:32 $
 */
#ifndef SOFTAP_ONLY

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>

#include <p2plib_api.h>
#include <p2pwl.h>
#include <p2plib_int.h>
#include <bcm_llist.h>
#include <p2plib_sd_sm.h>
#include <p2plib_sd.h>

#include <bcmendian.h>
#include <wlioctl.h>
#include <p2p.h>
#include <bcmevent.h>

/* Frame size to trigger comeback/fragmentation.  Must be smaller than ACTION_FRAME_SIZE. */
#define SD_GAS_FRAGMENT_SIZE 	(ACTION_FRAME_SIZE - 400)
#define SD_MAX_TLV_NUMBER		100		/* Max number of svc tlv we can support */
#define LOG_MAC(heading, mac)	p2plib_log_mac(heading, mac)
#define SD_MAX_TX_AF_ATTEMPTS	5

/* Advertisement Protocol Tuple */
#define REQUEST_ADP_TUPLE_QLMT_PAMEBI	P2PSD_ADP_TUPLE_QLMT_PAMEBI
#define RESPONSE_ADP_TUPLE_QLMT_PAMEBI	0x7f

/* External functions */
extern int
p2papi_tx_af(p2papi_instance_t* hdl, wl_af_params_t *af_params, int bssidx);

extern uint8
p2papi_create_dialog_token(uint8 token);

/* Service Data Store (SDS) */
static p2plib_sd_instance_list_t svc_store;
static p2plib_sd_req_sm_t *req_sm_list = NULL;
static p2plib_sd_rsp_sm_t *rsp_sm_list = NULL;

static bool
p2plib_log_mac(const char *heading, struct ether_addr* src_mac)
{
	char mac_str[20] = { 0 };

	if (src_mac != NULL)
		sprintf(mac_str, "%02X:%02X:%02X:%02X:%02X:%02X", src_mac->octet[0],
			src_mac->octet[1], src_mac->octet[2], src_mac->octet[3],
			src_mac->octet[4], src_mac->octet[5]);

	if (heading)
		P2PLOG2("%s %s\n", heading, mac_str);
	else
		P2PLOG1("%s\n", mac_str);

	return true;
}

/* Encode Vendor-specific Content frame for Service Request */
static bool
p2plib_sd_encode_nqp_qreq_vsc(uint8 oui_subtype, uint16 svc_upd_ind,
	BCMP2P_SVC_LIST *svc_entries, uint8 *vsc_data, uint16 *data_len)
{
	wifi_p2psd_nqp_query_vsc_t *nqp_vsc = (wifi_p2psd_nqp_query_vsc_t *)vsc_data;
	wifi_p2psd_qreq_tlv_t *qreq_tlv;
	uint32 i = 0;
	BCMP2P_SVC_ENTRY *svc_entry = 0;

	P2PLOG("p2plib_sd_encode_nqp_qreq_vsc: Entered\n");

	if (svc_entries == NULL || vsc_data == NULL) {
		P2PERR2("p2plib_sd_encode_nqp_qreq_vsc: Exiting. Invalid NULL param. "
			"svc_entries=%d, vsc_data=%d\n", svc_entries, vsc_data);
		return false;
	}

	/* OUI Subtype of NQP Vendor-specific Content */
	nqp_vsc->oui_subtype = oui_subtype;  /* 0x09 */

	/* Service Update Indicator */
	nqp_vsc->svc_updi = svc_upd_ind;

	/* Fill Service Requets TLVs */
	*data_len = sizeof(nqp_vsc->oui_subtype) + sizeof(nqp_vsc->svc_updi);
	qreq_tlv = (wifi_p2psd_qreq_tlv_t *)nqp_vsc->svc_tlvs;
	svc_entry = (BCMP2P_SVC_ENTRY *)svc_entries->svcEntries;
	for (i = 0; i < svc_entries->svcNum; i++) {

		/* Service Protocol Type */
		qreq_tlv->svc_prot = svc_entry->svcProtol;

		/* Service Transaction ID */
		qreq_tlv->svc_tscid = svc_entry->tsc_id;

		/* Query Request Data */
		if (svc_entry->dataSize > 0)
		memcpy(qreq_tlv->query_data, svc_entry->svcData, svc_entry->dataSize);

		/* TLV Length */
		qreq_tlv->len = 2 + svc_entry->dataSize;

		/* Update total VSC length */
		*data_len += sizeof(qreq_tlv->len) + qreq_tlv->len;

		/* Move to the beginning of the next service TLV */
		qreq_tlv = (wifi_p2psd_qreq_tlv_t *)((uint8 *)qreq_tlv + sizeof(qreq_tlv->len) +
			qreq_tlv->len);

		/* Move to the beginning of the next Service Data entry */
		svc_entry = (BCMP2P_SVC_ENTRY *)((uint8 *)svc_entry + sizeof(BCMP2P_SVC_ENTRY) +
			svc_entry->dataSize - 1);
	}

	P2PLOG("p2plib_sd_encode_nqp_qreq_vsc: Exiting\n");
	return true;
}

/* Encode Vendor-specific Content frame for Service Response */
static bool
p2plib_sd_encode_nqp_qresp_vsc(uint8 oui_subtype, uint16 svc_upd_ind,
	uint32 num_entries, const BCMP2P_SVC_ENTRY *svc_entries, p2psd_resp_status_t status,
	uint8 *vsc_data, uint16 *data_len)
{
	wifi_p2psd_nqp_query_vsc_t *nqp_vsc = (wifi_p2psd_nqp_query_vsc_t *)vsc_data;
	wifi_p2psd_qresp_tlv_t *qresp_tlv;
	uint32 i = 0;
	const BCMP2P_SVC_ENTRY *svc_entry = 0;

	P2PLOG("p2plib_sd_encode_nqp_qresp_vsc: Entered\n");

	/* OUI Subtype of NQP Vendor-specific Content */
	nqp_vsc->oui_subtype = oui_subtype;  /* 0x09 */

	/* Service Update Indicator */
	nqp_vsc->svc_updi = svc_upd_ind;

	/* Fill Service Requets TLVs */
	*data_len = sizeof(nqp_vsc->oui_subtype) + sizeof(nqp_vsc->svc_updi);
	qresp_tlv = (wifi_p2psd_qresp_tlv_t *)nqp_vsc->svc_tlvs;
	svc_entry = svc_entries;
	for (i = 0; i < num_entries; i++) {
		/* Service Protocol Type */
		qresp_tlv->svc_prot = svc_entry->svcProtol;

		/* Service Transaction ID */
		qresp_tlv->svc_tscid = svc_entry->tsc_id;

		/* Query Response Data */
		if (svc_entry->svcData)
		memcpy(qresp_tlv->query_data, svc_entry->svcData, svc_entry->dataSize);

		/* TLV Length */
		qresp_tlv->len = 3 + svc_entry->dataSize;

		/* Status Code */
		qresp_tlv->status = svc_entry->status;

		/* Update total VSC length */
		*data_len += sizeof(qresp_tlv->len) + qresp_tlv->len;

		/* Move to the beginning of the next tlv */
		qresp_tlv = (wifi_p2psd_qresp_tlv_t *)((uint8 *)qresp_tlv + sizeof(qresp_tlv->len) +
			qresp_tlv->len);

		/* Pointing to next entry */
		svc_entry = (BCMP2P_SVC_ENTRY *)((uint8 *)svc_entry + sizeof(BCMP2P_SVC_ENTRY) +
			svc_entry->dataSize - 1);
	}

	P2PLOG("p2plib_sd_encode_nqp_qresp_vsc: Exiting\n");
	return true;
}

/* Encode NQP Query Request frame */
static bool
p2plib_sd_encode_nqp_qreq_frame(uint16 svc_updi, BCMP2P_SVC_LIST *svc_entries,
	uint8 *data_buf, uint16 *data_len)
{
	wifi_p2psd_qreq_frame_t *qreq_frm = (wifi_p2psd_qreq_frame_t *)data_buf;

	P2PLOG("p2plib_sd_encode_nqp_qreq_frame: Entered\n");

	/* Info ID of NQP Query Request Frame */
	qreq_frm->info_id = P2PSD_GAS_NQP_INFOID;  /* 0xDDDD */

	/* OI of NQP Query Request Frame */
	memcpy(qreq_frm->oui, P2PSD_GAS_OUI, sizeof(qreq_frm->oui));  /* 0x0050F2 */

	/* Encode NQP Vendor-specific Content and set its size to data_len */
	p2plib_sd_encode_nqp_qreq_vsc(P2PSD_GAS_OUI_SUBTYPE, svc_updi, svc_entries,
		qreq_frm->qreq_vsc, data_len);

	/* Length of NQP Query Request Frame */
	qreq_frm->len = 3 + *data_len;

	/* Set total length of NQP Query Reqest Frame */
	*data_len = sizeof(qreq_frm->info_id) + sizeof(qreq_frm->len) + qreq_frm->len;

	P2PLOG("p2plib_sd_encode_nqp_qreq_frame: Exiting\n");
	return true;
}

/* Encode NQP Query Response frame */
static bool
p2plib_sd_encode_nqp_qresp_frame(uint16 svc_updi,
	uint32 num_entries, const BCMP2P_SVC_ENTRY *svc_entries,
	p2psd_resp_status_t sd_status, uint8 *data_buf, uint16 *data_len)
{
	wifi_p2psd_qresp_frame_t *qresp_frm = (wifi_p2psd_qresp_frame_t *)data_buf;

	P2PLOG("p2plib_sd_encode_nqp_qresp_frame: Entered\n");

	/* Info ID of NQP Query Response Frame */
	qresp_frm->info_id = P2PSD_GAS_NQP_INFOID;  /* 0xDDDD */

	/* OI of NQP Query Response Frame */
	memcpy(qresp_frm->oui, P2PSD_GAS_OUI, sizeof(qresp_frm->oui));  /* 0x0050F2 */

	/* Encode Query Response NQP Vendor-specific Content */
	p2plib_sd_encode_nqp_qresp_vsc(P2PSD_GAS_OUI_SUBTYPE, svc_updi,
		num_entries, svc_entries, sd_status, qresp_frm->qresp_vsc, data_len);

	/* Length of NQP Query Response Frame */
	qresp_frm->len = *data_len + 3;

	/* Set total length of NQP Query Response Frame */
	*data_len += sizeof(wifi_p2psd_qresp_frame_t) - 1;

	P2PLOG("p2plib_sd_encode_nqp_qresp_frame: Exiting\n");
	return true;
}

/* Encode Advertisement Protocol IE */
static void
p2plib_sd_encode_adp_ie(wifi_p2psd_adp_ie_t *adp_ie, uint8 llm_pamebi)
{
	P2PLOG("p2plib_sd_encode_adp_ie: Entered\n");

	adp_ie->id = P2PSD_AD_EID;  /* 0x12 for P2P SD */
	adp_ie->len = sizeof(adp_ie->adp_tpl);
	adp_ie->adp_tpl.adp_id = P2PSD_ADP_PROTO_ID;
	adp_ie->adp_tpl.llm_pamebi = llm_pamebi;

	P2PLOG("p2plib_sd_encode_adp_ie: Exiting\n");
}

/* Encode GAS Initial Request action frame data */
static bool
p2plib_sd_encode_gas_ireq_af_data(uint16 svc_updi, BCMP2P_SVC_LIST *svc_entries,
	uint8 *data_buf, uint16 *data_len)
{
	wifi_p2psd_gas_ireq_frame_t *gas_ireq_frm = (wifi_p2psd_gas_ireq_frame_t *)data_buf;
	uint16 qreq_frm_len = 0;

	P2PLOG("p2plib_sd_encode_gas_ireq_af_data: Entered\n");

	/* Fill Advertisement Protocol IE */
	p2plib_sd_encode_adp_ie(&gas_ireq_frm->adp_ie, REQUEST_ADP_TUPLE_QLMT_PAMEBI);

	/* Encode the NQP Query Request Frame */
	p2plib_sd_encode_nqp_qreq_frame(svc_updi, svc_entries, (uint8 *)&gas_ireq_frm->qreq_frm,
		&qreq_frm_len);

	/* Query Request Length */
	gas_ireq_frm->qreq_len = qreq_frm_len;

	/* Return length of GAS AF data (the part after "Dialog Token" field") */
	*data_len = sizeof(wifi_p2psd_gas_ireq_frame_t) + qreq_frm_len - 1;

	P2PLOG("p2plib_sd_encode_gas_ireq_af_data: Exiting\n");
	return true;
}

/* Lookup SDS and create response data list */
static BCMP2P_SVC_LIST *
p2plib_sd_build_rsp_entry_list(BCMP2P_SVC_LIST *req_list)
{
	uint8 *resp_buf;
	uint16 req_buf_len = ACTION_FRAME_SIZE;
	uint16 resp_buf_len = ACTION_FRAME_SIZE;
	BCMP2P_SVC_LIST	*resp_list;
	BCMP2P_SVC_ENTRY *req_entry_beg, *resp_entry_beg;
	uint32 i,j;
	BCMP2P_SD_STATUS resp_tlv_status = BCMP2P_SD_STATUS_SUCCESS;
	uint32 resp_data_size = 0;

	P2PLOG("p2plib_sd_build_rsp_entry_list: Entered\n");

	/* Allocate buffer to hold the response entry list */
	resp_buf = (uint8 *)P2PAPI_MALLOC(resp_buf_len);
	if (resp_buf == NULL) {
		P2PERR("p2plib_sd_build_rsp_entry_list: Exiting. "
			"Failed to allocate memory for resp_buf\n");
		return NULL;
	}

	memset(resp_buf, 0, resp_buf_len);

	/* Remove the service instance from Service Data Store */
	resp_list = (BCMP2P_SVC_LIST *)resp_buf;
	req_entry_beg = (BCMP2P_SVC_ENTRY *)req_list->svcEntries;
	resp_entry_beg = (BCMP2P_SVC_ENTRY *)resp_list->svcEntries;
	resp_list->dataSize = 0;
	for (i = 0; i < req_list->svcNum; i++) {
		/* Pointing to the service request entry */
		bool found = false;

		/* check request buffer size */
		if ((uint8 *)req_entry_beg >= (uint8 *)req_list + req_buf_len) {
			P2PLOG("p2plib_sd_build_rsp_entry_list: truncating req buf\n");
			goto END;
		}

		for (j = 0; j < svc_store.total; j++) {
			/* TBD: Generate "status code" if response is not found */

			/* Match protocol type first */
			switch ((BCMP2P_SVC_PROTYPE)req_entry_beg->svcProtol) {
			case BCMP2P_SVC_PROTYPE_ALL:
				  /* All service types are requested */
				found = true;
				break;
			case BCMP2P_SVC_PROTYPE_BONJOUR:
			case BCMP2P_SVC_PROTYPE_UPNP:
			case BCMP2P_SVC_PROTYPE_WSD:
				found = (req_entry_beg->svcProtol ==
					svc_store.instances[j].pro_type);
				break;
			case BCMP2P_SVC_PROTYPE_VENDOR:
				/* Vendor specific protocol type */
				/* TBD: May eed to verify vendor OUI too per spec */
				found = (req_entry_beg->svcProtol ==
					svc_store.instances[j].pro_type);
				break;
			default:
				/* Unrecoganized protocol type */
				resp_tlv_status = BCMP2P_SD_STATUS_BAD_REQUEST;
			}

			if (!found) {
				/* Protocol does not match, continue to try
				 * next instance in SDS
				 */
				continue;
			}

			/* If service request data is attached, need to match it with the Q
			 * of the QR instance in SDS too, otherwise protocol match is enough.
			 */
			if (req_entry_beg->dataSize > 0) {
				if (memcmp(req_entry_beg->svcData, svc_store.instances[j].req_data,
					req_entry_beg->dataSize) == 0) {
					found = true;
				}
				else {
					resp_tlv_status = BCMP2P_SD_STATUS_INFO_NA;
					found = false;
				}
			}

			/* If service response data is found matching the request (with or w/0)
			 * reqest data, generate response tlv for the request
			 */
			if (found) {
				uint16 entry_size;

				/* Entry is found for the incoming request data entry
				 * Set fields of service response entry
				 */

				/* check response buffer size */
				if ((uint8 *)resp_entry_beg + sizeof(BCMP2P_SVC_ENTRY) +
					svc_store.instances[j].resp_data_len >= resp_buf +
					resp_buf_len) {
					uint32 buf_offset =
						(char *)resp_entry_beg - (char *)resp_buf;

					P2PLOG("p2plib_sd_build_rsp_entry_list: "
						"realloc resp buf\n");
					resp_buf_len += ACTION_FRAME_SIZE;
					resp_buf = (uint8 *)P2PAPI_REALLOC(resp_buf, resp_buf_len);
					if (resp_buf == NULL) {
						P2PERR1("p2plib_sd_build_rsp_entry_list: "
							"Failed to realloc memory for resp_buf."
							" resp_buf_len=%d", resp_buf_len);
						resp_list = NULL;
						goto END;
					}
					resp_list = (BCMP2P_SVC_LIST *)resp_buf;
					resp_entry_beg =
						(BCMP2P_SVC_ENTRY *)(resp_buf + buf_offset);
				}

				/* Length */
				resp_entry_beg->dataSize = svc_store.instances[j].resp_data_len;
				resp_data_size += resp_entry_beg->dataSize;

				/* Response Data */
				memcpy(resp_entry_beg->svcData, svc_store.instances[j].resp_data,
					svc_store.instances[j].resp_data_len);

				/* Service Protocol Type */
				resp_entry_beg->svcProtol =
					(BCMP2P_SVC_PROTYPE)svc_store.instances[j].pro_type;

				/* Service Transaction ID */
				resp_entry_beg->tsc_id = req_entry_beg->tsc_id;

				/* Status Code */
				resp_entry_beg->status = BCMP2P_SD_STATUS_SUCCESS;

				/* Calculate the total size of current rsp entry */
				entry_size = sizeof(BCMP2P_SVC_ENTRY) +
					resp_entry_beg->dataSize - 1;

				/* Update the data size and entry number of rsp entry list */
				resp_list->svcNum++;
				resp_list->dataSize += entry_size;

				/* Move to beginning of the next response entry in the list */
				resp_entry_beg = (BCMP2P_SVC_ENTRY *)
					((uint8 *)resp_entry_beg + entry_size);
			}
		}

		/* No service data, still need to create entry to tell status */
		if (!found) {
			/* Length */
			resp_entry_beg->dataSize = 0;

			/* Service Protocol Type */
			resp_entry_beg->svcProtol =	req_entry_beg->svcProtol;

			/* Service Transaction ID */
			resp_entry_beg->tsc_id = req_entry_beg->tsc_id;

			/* Status Code */
			resp_entry_beg->status = resp_tlv_status;

			/* Move to next entry of the response entry in the list */
			resp_entry_beg = (BCMP2P_SVC_ENTRY *)((uint8 *)resp_entry_beg +
				sizeof(BCMP2P_SVC_ENTRY) + resp_entry_beg->dataSize - 1);

			/* Update the number and data size of response entry list */
			resp_list->svcNum++;
			resp_list->dataSize += sizeof(BCMP2P_SVC_ENTRY) +
				resp_entry_beg->dataSize - 1;

		}

		/* Move to next entry of the request data in the list */
		req_entry_beg = (BCMP2P_SVC_ENTRY *)((uint8 *)req_entry_beg +
			sizeof(BCMP2P_SVC_ENTRY) + req_entry_beg->dataSize - 1);
	}

END:
	P2PLOG1("p2plib_sd_build_rsp_entry_list: Exiting. resp_list=%d\n", resp_list);
	return resp_list;
}


/* Build public action frame iovar parameter */
wl_af_params_t *
p2plib_build_pub_act_frm_param(p2papi_instance_t* hdl,
	struct ether_addr *dst_ea, struct ether_addr *bssid, uint8 action,
	uint8 dialog_token, uint8 *frm_data, uint16 data_len,
	BCMP2P_CHANNEL *channel, int32 dwell_time_ms)
{
	wl_action_frame_t *wl_af;
	wl_af_params_t *af_params;

	/* p2p actiion frame shared the same stucture as that of readio measurement */
	dot11_rm_action_t *rm_action;

	P2PLOG("p2plib_build_pub_act_frm_param: Entered\n");

	P2PAPI_CHECK_P2PHDL(hdl);
	P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl);

	/* Verify parameters passed in */
	if (dst_ea == NULL || frm_data == NULL) {
		P2PERR2("p2plib_build_pub_act_frm: Exiting. Invalid NULL parameter."
			" dst_ea %d, frm_data %d\n", dst_ea, frm_data);
		return NULL;
	}

	af_params = (wl_af_params_t*)P2PAPI_MALLOC(sizeof(*af_params));
	if (af_params == NULL) {
		P2PERR("p2plib_build_pub_act_frm: Exiting. malloc of af_params failed\n");
		return NULL;
	}
	memset(af_params, 0, sizeof(*af_params));

	if (data_len > ACTION_FRAME_SIZE) {
		P2PERR("p2plib_build_pub_act_frm: Exiting. Af size over limit.\n");
		return NULL;
	}

	wl_af = &af_params->action_frame;

	/* Add the packet Id */
	wl_af->packetId = (uint32)(uintptr)wl_af;

	/* Fill in the destination MAC addr */
	memcpy(&wl_af->da.octet, dst_ea->octet, ETHER_ADDR_LEN);

	/* Fill in the action frame data */
	rm_action = (dot11_rm_action_t *)wl_af->data;

	rm_action->category = 4;  /* public action frame */
	rm_action->action = action;
	rm_action->token = dialog_token;
	memcpy(rm_action->data, frm_data, data_len);

	/* variable lenght of the action frame */
	wl_af->len = DOT11_RM_ACTION_LEN + data_len;

	/* Fill in other af_params info. */
	af_params->channel = channel->channel;
	af_params->dwell_time = dwell_time_ms;

	/* Fill in BSSID info. of the action frame */
	memcpy(af_params->BSSID.octet, bssid, sizeof(af_params->BSSID));

	P2PLOG("p2plib_build_pub_act_frm_param: Exiting\n");
	return af_params;
}

static wl_af_params_t *
p2plib_sd_build_gas_creq_act_frm_param(p2papi_instance_t* hdl, struct ether_addr *dst_ea,
	uint8 dialog_token, BCMP2P_CHANNEL *channel,	int32 dwell_time_ms)
{
	wl_af_params_t *af_params;
	uint8 *frm_data;
	uint16 data_len = 0;

	P2PLOG("p2plib_sd_build_gas_creq_act_frm_param: Entered\n");

	frm_data = (uint8 *)P2PAPI_MALLOC(ACTION_FRAME_SIZE);

	if (frm_data == NULL) {
		P2PLOG("p2plib_sd_build_gas_creq_act_frm_param: Exiting. "
			"Invalid NULL frm_data\n");
		return NULL;
	}

	af_params = p2plib_build_pub_act_frm_param(hdl, dst_ea, dst_ea, P2PSD_ACTION_ID_GAS_CREQ,
		dialog_token, frm_data, data_len, channel, dwell_time_ms);

	P2PLOG("p2plib_sd_build_gas_creq_act_frm_param: Exiting\n");
	return af_params;
}

/* Build parameter of AF iovar for GAS Initial Request AF. Caller is responsible for
 * freeing the the returned pointer.
 */
static wl_af_params_t *
p2plib_sd_build_gas_ireq_act_frm_param(p2papi_instance_t* hdl, struct ether_addr *dst_ea,
	uint8 dialog_token, BCMP2P_SVC_LIST *svc_entries, uint16 svc_updi,
	BCMP2P_CHANNEL *channel,	int32 dwell_time_ms)
{
	wl_af_params_t *af_params;
	uint8 *frm_data;
	uint16 data_len;

	P2PLOG("p2plib_sd_build_gas_ireq_act_frm_param: Entered\n");

	frm_data = (uint8 *)P2PAPI_MALLOC(ACTION_FRAME_SIZE);

	if (frm_data == NULL)
		return NULL;

	data_len = ACTION_FRAME_SIZE;

	/* Encode the action frame payload */
	p2plib_sd_encode_gas_ireq_af_data(svc_updi, svc_entries, frm_data, &data_len);

	af_params = p2plib_build_pub_act_frm_param(hdl, dst_ea, dst_ea, P2PSD_ACTION_ID_GAS_IREQ,
		dialog_token, frm_data, data_len, channel, dwell_time_ms);

	P2PAPI_FREE(frm_data);

	P2PLOG("p2plib_sd_build_gas_ireq_act_frm_param: Exiting\n");
	return af_params;
}

/* Build parameter of AF iovar for GAS Initial Response AF */
static wl_af_params_t *
p2plib_sd_build_gas_iresp_act_frm_param(p2plib_sd_rsp_sm_t *rsp_sm,
	uint8 mfrm_status, int32 dwell_time_ms)
{
	wl_af_params_t *af_params;
	uint8 *frm_data;
	uint16 frm_data_len = 0;
	wifi_p2psd_gas_iresp_frame_t *gas_iresp_frm;
	uint8 *buf;

	P2PLOG("p2plib_sd_build_gas_iresp_act_frm_param: Entered\n");

	frm_data = (uint8 *)P2PAPI_MALLOC(ACTION_FRAME_SIZE);

	if (frm_data == NULL) {
		P2PERR("p2plib_sd_build_gas_iresp_act_frm_param: Exiting. "
			"malloc of frm_data failed.\n");
		return NULL;
	}

	gas_iresp_frm = (wifi_p2psd_gas_iresp_frame_t *)frm_data;
	memset(gas_iresp_frm, 0, ACTION_FRAME_SIZE);

	/* 802.11 management frame status code, little endian */
	buf = (uint8*)&gas_iresp_frm->status;
	buf[0] = mfrm_status;
	buf[1] = 0;

	/* Fill Advertisement Protocol IE */
	p2plib_sd_encode_adp_ie(&gas_iresp_frm->adp_ie, RESPONSE_ADP_TUPLE_QLMT_PAMEBI);

	/* Fragment GAS Response and send them via multiple frames if the total size
	 * is larger than SD_GAS_FRAGMENT_SIZE
	 */
	if (rsp_sm->tx_qrsp_frm_size > SD_GAS_FRAGMENT_SIZE) {
		/* Fragmentation is required */
		gas_iresp_frm->cb_delay = 1;
		gas_iresp_frm->qresp_len = 0;
		rsp_sm->tx_qrsp_cur_frag = rsp_sm->tx_qrsp_buf;
	}
	else {
		/* Fragmentation is not required */
		gas_iresp_frm->cb_delay = 0;
		gas_iresp_frm->qresp_len = rsp_sm->tx_qrsp_frm_size;
		memcpy(gas_iresp_frm->qresp_frm, rsp_sm->tx_qrsp_buf, rsp_sm->tx_qrsp_frm_size);
		rsp_sm->tx_qrsp_cur_frag = NULL;
	}

	frm_data_len = sizeof(wifi_p2psd_gas_iresp_frame_t) +
		gas_iresp_frm->qresp_len - 1;

	af_params = p2plib_build_pub_act_frm_param(rsp_sm->comm_sm.hdl,
		&rsp_sm->comm_sm.peer_mac, &rsp_sm->comm_sm.hdl->p2p_dev_addr,
		P2PSD_ACTION_ID_GAS_IRESP, rsp_sm->comm_sm.dialog_token,
		frm_data, frm_data_len, &rsp_sm->comm_sm.channel, dwell_time_ms);

	P2PAPI_FREE(frm_data);

	P2PLOG("p2plib_sd_build_gas_iresp_act_frm_param: Exiting\n");
	return af_params;
}

/* Build parameter of AF iovar for GAS Comeback Response AF */
static wl_af_params_t *
p2plib_sd_build_gas_cresp_act_frm_param(p2plib_sd_rsp_sm_t *rsp_sm,
	uint8 gas_resp_status, int32 dwell_time_ms)
{
	wl_af_params_t *af_params = NULL;
	uint8 *frm_data;
	uint16 frm_data_len;
	uint16 qrsp_left_len;  /* Length of left fragments of query response */
	wifi_p2psd_gas_cresp_frame_t *gas_cresp_frame;
	uint8 *buf;
	uint8 frag_id_no, frag_id_more;
	size_t max_qresp_size = ACTION_FRAME_SIZE -
		OFFSETOF(wifi_p2psd_gas_cresp_frame_t, qresp_frm);

	P2PLOG("p2plib_sd_build_gas_cresp_act_frm_param: Entered\n");

	frm_data_len = ACTION_FRAME_SIZE;
	frm_data = (uint8 *)P2PAPI_MALLOC(ACTION_FRAME_SIZE);

	if (frm_data == NULL) {
		P2PLOG("p2plib_sd_build_gas_cresp_act_frm_param: Exiting."
			" Failed to allocate memory.\n");
		return NULL;
	}

	gas_cresp_frame = (wifi_p2psd_gas_cresp_frame_t *)frm_data;
	memset(gas_cresp_frame, 0, ACTION_FRAME_SIZE);

	/* Start fragmentation */
	qrsp_left_len = rsp_sm->tx_qrsp_frm_size -
		(rsp_sm->tx_qrsp_cur_frag - rsp_sm->tx_qrsp_buf);
	gas_cresp_frame->fragment_id = rsp_sm->fragment_id++;  /* Fragment ID */

	/* comeback delay zero for comeback response */
	gas_cresp_frame->cb_delay = 0;

	if (qrsp_left_len > SD_GAS_FRAGMENT_SIZE) {
		/* Not last fragment */
		gas_cresp_frame->qresp_len = SD_GAS_FRAGMENT_SIZE;

		/* Set the "More GAS Fragments" bit B7 to 1 */
		gas_cresp_frame->fragment_id |= 0x80;
	}
	else {
		/* Last fragment to send */
		P2PLOG("p2plib_sd_build_gas_cresp_act_frm_param: Last fragment\n");

		gas_cresp_frame->qresp_len = qrsp_left_len; /* Less than SD_GAS_FRAGMENT_SIZE */

		/* Set the "More GAS Fragments" bit B7 to 0 */
		gas_cresp_frame->fragment_id &= ~0x80;
		rsp_sm->last_frag_sent = true;
	}

	/* Set GAS Query Response data */
	if (rsp_sm->tx_qrsp_cur_frag != NULL) {
		if (gas_cresp_frame->qresp_len > max_qresp_size) {
			P2PERR2("p2plib_sd_build_gas_cresp_act_frm_param: qresp_len %u > %u!\n",
				gas_cresp_frame->qresp_len, max_qresp_size);
			goto cresp_exit;
		}
		memcpy(gas_cresp_frame->qresp_frm, rsp_sm->tx_qrsp_cur_frag,
			gas_cresp_frame->qresp_len);
	}

	/* Update the tx_qrsp_cur_frag pointer */
	if (qrsp_left_len > SD_GAS_FRAGMENT_SIZE)
		rsp_sm->tx_qrsp_cur_frag += SD_GAS_FRAGMENT_SIZE;
	else
		rsp_sm->tx_qrsp_cur_frag = NULL;

	frag_id_no = gas_cresp_frame->fragment_id & 0x7f;
	frag_id_more = gas_cresp_frame->fragment_id & 0x80? 1 : 0;

	P2PLOG4("p2plib_sd_build_gas_cresp_act_frm_param: GAS comeback frame. "
	"tx frag_id_no=%d, frag_id_more=%d, cb_delay=%d, qresp_len=%d\n", frag_id_no,
	frag_id_more, gas_cresp_frame->cb_delay, gas_cresp_frame->qresp_len);

	/* 802.11 management frame status code, little endian */
	buf = (uint8*)&gas_cresp_frame->status;
	buf[0] = gas_resp_status;
	buf[1] = 0;

	/* Advertisement Protocol IE */
	p2plib_sd_encode_adp_ie(&gas_cresp_frame->adp_ie, RESPONSE_ADP_TUPLE_QLMT_PAMEBI);

	frm_data_len = sizeof(wifi_p2psd_gas_cresp_frame_t) + gas_cresp_frame->qresp_len - 1;

	af_params = p2plib_build_pub_act_frm_param(rsp_sm->comm_sm.hdl,
		&rsp_sm->comm_sm.peer_mac, &rsp_sm->comm_sm.hdl->p2p_dev_addr,
		P2PSD_ACTION_ID_GAS_CRESP, rsp_sm->comm_sm.dialog_token, frm_data,
		frm_data_len, &rsp_sm->comm_sm.channel, dwell_time_ms);

cresp_exit:
	P2PLOG1("p2plib_sd_build_gas_cresp_act_frm_param: Exiting. af_params=%p\n", af_params);

	P2PAPI_FREE(frm_data);
	return af_params;
}

void
p2plib_sd_backup_tx_af(p2plib_sd_sm_t *sm, wl_af_params_t *af_params)
{
	P2PLOG("p2plib_sd_backup_tx_af: Entered\n");

	if (sm == NULL || af_params == NULL) {
		P2PERR2("p2plib_sd_backup_tx_af: NULL parameter. sm=%d, af_params=%d",
			sm, af_params);
		return;
	}

	if (sm->pending_tx_af)
		P2PAPI_FREE(sm->pending_tx_af);

	sm->pending_tx_af = (wl_af_params_t *)P2PAPI_MALLOC(sizeof(wl_af_params_t));
	if (sm->pending_tx_af)
		memcpy(sm->pending_tx_af, af_params, sizeof(wl_af_params_t));
	else
		P2PERR("p2plib_sd_backup_tx_af: Malloc of pending_tx_af failed\n");

	P2PLOG("p2plib_sd_backup_tx_af: Exiting\n");
}

/* Callback function called when a Service Discovery P2P action frame tx completes. */
static void
p2papi_sd_tx_done_cb(void *handle, p2papi_aftx_instance_t *aftx_hdl,
	BCMP2P_BOOL acked, wl_af_params_t *af_params)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*)handle;

	P2PLIB_ASSERT(P2PAPI_CHECK_P2PHDL(hdl));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_sd_tx_done_cb: acked=%d aftx_hdl=%p,%p\n",
		acked, aftx_hdl, hdl->invite_aftx_hdl));

	/* Do the generic AF tx complete actions */
	p2papi_aftx_complete_callback_core(handle, aftx_hdl, acked, af_params);
	hdl->sd_aftx_hdl = NULL;
}

/* Send action frame */
static int
p2plib_sd_send_af(p2papi_instance_t* hdl, bool ch_sync, wl_af_params_t *af_params)
{
	int err = 0;
	wl_af_params_t *pending_af_local;

	P2PLOG2("p2plib_sd_send_af: Entered. ch_sync=%d, channel=%d\n",
		ch_sync, af_params->channel);

	if (af_params == NULL) {
		P2PERR("p2plib_sd_send_af: Exiting. Null af_params pointer\n");
		return BCME_ERROR;
	}

	P2PLOG1("p2plib_sd_send_af: Sending action frame. pktid=%u\n",
		af_params->action_frame.packetId);

	/* Send it out */
	if (ch_sync) {
		/* Send after channel synchronization. The malloc'ed action
		 * frame will be freed after it is sent (by the event handler).
		 */
		pending_af_local = (wl_af_params_t *)P2PAPI_MALLOC(sizeof(wl_af_params_t));
		if (pending_af_local) {
			BCMP2P_CHANNEL ch;
			memcpy(pending_af_local, af_params, sizeof(wl_af_params_t));
			memcpy(&hdl->peer_dev_addr, &pending_af_local->action_frame.da,
				sizeof(hdl->peer_dev_addr));
			ch.channel_class = BCMP2P_LISTEN_CHANNEL_CLASS;
			ch.channel = pending_af_local->channel;
			err = p2papi_send_at_common_channel(hdl, &ch,
				pending_af_local, p2papi_sd_tx_done_cb, FALSE,
				&hdl->sd_aftx_hdl, "sd");
		}
		else {
			P2PERR("p2plib_sd_send_af: malloc of pending_af_local failed\n");
			err = -1;
		}
	}
	else {
		/* Set the flag only for tx af in piggy back mode. When tx af in channel
		 * sync mode, we use the tx af mechanism defined in p2plib_aftx.c
		 */
		hdl->sd.sending_sd_af_piggyback = true;
		err = p2papi_tx_af(hdl, af_params, hdl->bssidx[P2PAPI_BSSCFG_DEVICE]);
	}

	P2PLOG1("p2plib_sd_send_af: Exiting. err=%d\n", err);
	return err;
}

/* Send Comeback Request */
static bool
p2plib_sd_send_comeback_request(p2plib_sd_req_sm_t *req_sm, int32 dwell_time_ms, bool ch_sync)
{
	bool ret = true;
	wl_af_params_t *af_params;

	P2PLOG("p2plib_sd_send_comeback_request: Entered\n");

	/* Build response action frame */
	af_params = p2plib_sd_build_gas_creq_act_frm_param(req_sm->comm_sm.hdl,
		&req_sm->comm_sm.peer_mac, req_sm->comm_sm.dialog_token,
		&req_sm->comm_sm.channel, dwell_time_ms);
	if (af_params == NULL) {
		P2PERR("p2plib_sd_send_comeback_request: Exiting. Failed to build comeback"
			" request af param\n");
		return false;
	}

	if (req_sm->comm_sm.pending_tx_af)
		P2PAPI_FREE(req_sm->comm_sm.pending_tx_af);

	req_sm->comm_sm.pending_tx_af = af_params;
	if (p2plib_sd_send_af(req_sm->comm_sm.hdl, ch_sync, af_params) != 0) {
		P2PERR("p2plib_sd_send_comeback_request: p2plib_sd_send_af failed\n");
		ret = false;
	}

	P2PLOG("p2plib_sd_send_comeback_request: Exiting\n");
	return ret;
}

/* Verify the Advertisement Protocol IE for SD */
static bool
p2plib_sd_verify_adp_ie(wifi_p2psd_adp_ie_t *adp_ie, uint8 llm_pamebi)
{
	return (adp_ie->id == P2PSD_AD_EID &&
		adp_ie->adp_tpl.adp_id == P2PSD_ADP_PROTO_ID &&
		adp_ie->adp_tpl.llm_pamebi == llm_pamebi);
}

/* Decode request data and save to service data entry list data_buf */
static bool
p2plib_sd_decode_qreq_svc_data(wifi_p2psd_gas_ireq_frame_t *ireq_frm,
	uint8 *entry_data_buf, uint16 entry_data_len)
{
	wifi_p2psd_qreq_frame_t *qreq_frm;
	wifi_p2psd_nqp_query_vsc_t *vsc_frm;
	BCMP2P_SVC_LIST *entry_list = (BCMP2P_SVC_LIST *)entry_data_buf;
	wifi_p2psd_qreq_tlv_t *tlv_beg;
	BCMP2P_SVC_ENTRY *entry_beg;
	uint16 total_tlv_len;
	int total_len = 0;

	P2PLOG("p2plib_sd_decode_qreq_svc_data: Entered\n");

	/* TBA: generate entry_list->status code */

	if (!ireq_frm) {
		P2PLOG("p2plib_sd_decode_qreq_svc_data: Exiting. Invalid NULL ireq_frm\n");
		return false;
	}

	qreq_frm = (wifi_p2psd_qreq_frame_t *)&ireq_frm->qreq_frm;

	/* Verify data buffer and size passed in */
	if (!entry_data_buf || entry_data_len < qreq_frm->len) {
		P2PERR2("p2plib_sd_decode_qreq_svc_data: Exiting. Not enough buffer buf."
			"entry_data_buf=%d, entry_data_len=%d\n", entry_data_buf, entry_data_len);
		return false;  /* Not enough buffer size passed in */
	}

	/* Verify Advertisement Protocol IE for SD */
	if (!p2plib_sd_verify_adp_ie(&ireq_frm->adp_ie, REQUEST_ADP_TUPLE_QLMT_PAMEBI)) {
		P2PERR("p2plib_sd_decode_qreq_svc_data: Exiting. Wrong ADP IE\n");
		return false;
	}

	/* Verify NQP EID */
	if (qreq_frm->info_id != P2PSD_GAS_NQP_INFOID) {
		P2PERR("p2plib_sd_decode_qreq_svc_data: Exiting. Wrong info id\n");
		return false;
	}

	/* Verify OI Type */
	if (memcmp(qreq_frm->oui, P2PSD_GAS_OUI, 3) != 0)  {
		P2PERR("p2plib_sd_decode_qreq_svc_data: Exiting. Wrong oui\n");
		return false;
	}

	vsc_frm = (wifi_p2psd_nqp_query_vsc_t *)qreq_frm->qreq_vsc;

	/* Verify OUI Subtype of Query Request NQP VSC */
	if (vsc_frm->oui_subtype != P2PSD_GAS_OUI_SUBTYPE) {
		P2PERR("p2plib_sd_decode_qreq_svc_data: Exiting. Wrong oui subtype\n");
		return false;
	}

	/* Parse Service Request TLVs */
	tlv_beg = (wifi_p2psd_qreq_tlv_t *)vsc_frm->svc_tlvs;
	entry_beg = (BCMP2P_SVC_ENTRY *)entry_list->svcEntries;
	entry_list->svcNum = 0;
	total_len = 0;
	total_tlv_len = qreq_frm->len - sizeof(qreq_frm->oui)
		- 3;  /* Get the total length of all tlvs */
	while (total_len < total_tlv_len) {
		entry_beg->svcProtol = (BCMP2P_SVC_PROTYPE)tlv_beg->svc_prot;
		entry_beg->tsc_id = tlv_beg->svc_tscid;
		entry_beg->dataSize = tlv_beg->len - 2;

		if (tlv_beg->query_data && entry_beg->dataSize > 0)
			memcpy(entry_beg->svcData, tlv_beg->query_data, entry_beg->dataSize);

		/* Update the currently calculated total tlv size */
		total_len += sizeof(tlv_beg->len) + tlv_beg->len;

		/* Pointing to the next tlv */
		tlv_beg = (wifi_p2psd_qreq_tlv_t *)((uint8 *)tlv_beg + tlv_beg->len +
			sizeof(tlv_beg->len));

		p2papi_log_hexdata(BCMP2P_LOG_MED,
			"p2plib_sd_decode_qreq_svc_data: Service request data",
			entry_beg->svcData, entry_beg->dataSize);

		entry_beg = (BCMP2P_SVC_ENTRY *)((uint8 *)entry_beg + sizeof(BCMP2P_SVC_ENTRY) +
			entry_beg->dataSize - 1);

		entry_list->svcNum++;  /* Increment entry total number */
	}

	if (entry_list->svcNum > 0)
		entry_list->status = BCMP2P_SD_STATUS_SUCCESS;

	P2PLOG("p2plib_sd_decode_qreq_svc_data: Exiting\n");
	return true;
}

/* Decode response data and save to service data entry list */
static bool
p2plib_sd_decode_qresp_svc_data(wifi_p2psd_qresp_frame_t *qresp_frm,
	uint8 *entry_data_buf, uint16 entry_data_buf_len)
{
	wifi_p2psd_nqp_query_vsc_t *vsc_frm;
	BCMP2P_SVC_LIST *entry_list = (BCMP2P_SVC_LIST *)entry_data_buf;
	wifi_p2psd_qresp_tlv_t *tlv_beg;
	BCMP2P_SVC_ENTRY *entry_beg;
	uint16 total_len, total_tlv_len;
	bool ret = true;

	P2PLOG("p2plib_sd_decode_qresp_svc_data: Entered\n");

	if (!qresp_frm) {
		P2PERR("p2plib_sd_decode_qresp_svc_data: Exiting. Invalid NULL param\n");
		return false;
	}

	memset(entry_data_buf, 0, entry_data_buf_len);

	/* Verify data buffer and size passed in */
	if (!entry_data_buf || entry_data_buf_len < qresp_frm->len) {
		P2PERR2("p2plib_sd_decode_qresp_svc_data: Exiting. Not enough buffer buf."
			"entry_data_buf=%d, entry_data_buf_len=%d\n",
			entry_data_buf, entry_data_buf_len);
		return false;  /* Not enough buffer size passed in */
	}

	/* Verify NQP EID */
	if (qresp_frm->info_id != P2PSD_GAS_NQP_INFOID) {
		P2PERR("p2plib_sd_decode_qresp_svc_data: Exiting. Wrong info id\n");
		return false;
	}

	/* Verify OI Type */
	if (memcmp(qresp_frm->oui, P2PSD_GAS_OUI, 3) != 0) {
		P2PERR("p2plib_sd_decode_qresp_svc_data: Exiting. Wrong oui\n");
		return false;
	}

	vsc_frm = (wifi_p2psd_nqp_query_vsc_t *)qresp_frm->qresp_vsc;

	/* Verify OUI Subtype of Query Response NQP VSC */
	if (vsc_frm->oui_subtype != P2PSD_GAS_OUI_SUBTYPE) {
		P2PERR("p2plib_sd_decode_qresp_svc_data: Exiting. Wrong oui subtype\n");
		return false;
	}

	/* Parse Service Response TLVs */
	tlv_beg = (wifi_p2psd_qresp_tlv_t *)vsc_frm->svc_tlvs;
	entry_beg = (BCMP2P_SVC_ENTRY *)entry_list->svcEntries;
	entry_list->svcNum = 0;
	total_len = 0;
	entry_list->dataSize = 0;  /* Initialize entry list data size to 0 */

	/* 3 is the total length of "VSC OUI Subtype" + "Service Update Indicator" */
	total_tlv_len = qresp_frm->len - sizeof(qresp_frm->oui) - 3;
	while (total_len < total_tlv_len) {
		/* Validate buffer size first */
		if (entry_list->dataSize > entry_data_buf_len) {
			/* Size of the buffer passed in is not big enough */
			P2PERR2("p2plib_sd_decode_qresp_svc_data: Not enough buffer size"
				"entry_list->dataSize=%d, entry_data_buf_len=%d\n",
				entry_list->dataSize, entry_data_buf_len);
			ret = false;
			break;
		}

		entry_beg->svcProtol = (BCMP2P_SVC_PROTYPE)tlv_beg->svc_prot;
		entry_beg->tsc_id = tlv_beg->svc_tscid;
		entry_beg->dataSize = tlv_beg->len - 3;
		entry_beg->status = tlv_beg->status;

		if (tlv_beg->query_data)
			memcpy(entry_beg->svcData, tlv_beg->query_data, entry_beg->dataSize);

		/* Update the currently calculated total tlv size */
		total_len += sizeof(tlv_beg->len) + tlv_beg->len;

		/* Pointing to the beginning of the next tlv */
		tlv_beg = (wifi_p2psd_qresp_tlv_t *)((uint8 *)tlv_beg + tlv_beg->len +
			sizeof(tlv_beg->len));

		p2papi_log_hexdata(BCMP2P_LOG_MED,
		                   "p2plib_sd_decode_qresp_svc_data: Service response data",
		                   entry_beg->svcData,
		                   entry_beg->dataSize);

		/* Update the BCMP2P_SVC_LIST list data size */
		entry_list->dataSize += sizeof(BCMP2P_SVC_ENTRY) + entry_beg->dataSize - 1;

		/* Pointing to the next entry in the entry list */
		entry_beg = (BCMP2P_SVC_ENTRY *)((uint8 *)entry_beg + sizeof(BCMP2P_SVC_ENTRY) +
			entry_beg->dataSize - 1);

		entry_list->svcNum++;  /* Increment entry total number */
	}

	P2PLOG("p2plib_sd_decode_qresp_svc_data: Exiting with success\n");
	return ret;
}

static SD_STATUS
p2plib_sd_send_pending_af(p2plib_sd_sm_t *sm)
{
	SD_STATUS status = SD_STATUS_CONTINUE;
	int err;

	P2PLOG("p2plib_sd_send_pending_af: Entered.\n");

	if (sm->pending_tx_attempts > SD_MAX_TX_AF_ATTEMPTS) {
		P2PERR("p2plib_sd_send_pending_af: Exiting. Already tried maximum times\n");
		return SD_STATUS_ERR_TX_MAX_RETRY;
	}

	err = p2plib_sd_send_af(sm->hdl, sm->ch_sync, sm->pending_tx_af);
	sm->pending_tx_attempts++;
	if (err != 0)
		status = SD_STATUS_SYSTEM_ERR;

	P2PLOG2("p2plib_sd_send_pending_af: Exiting. Attempts=%d"
		"status=%d\n", sm->pending_tx_attempts, status);
	return status;
}

static p2plib_sd_req_sm_t *
p2plib_sd_create_req_sm(p2papi_instance_t *hdl, BCMP2P_CHANNEL *peer_channel,
	struct ether_addr *peer_mac, uint8 dialog_token, SD_STATE init_state,
	BCMP2P_SVC_LIST *svc_req_list)
{
	p2plib_sd_req_sm_t *req_sm;

	P2PLOG("p2plib_sd_create_req_sm: Entered\n");

	if (peer_mac == NULL || hdl == NULL || svc_req_list == NULL) {
		P2PERR3("p2plib_sd_create_req_sm: Invalid NULL parameter passed in. "
			"hdl=%d, peer_mac=%d, svc_req_list=%d\n", hdl, peer_mac, svc_req_list);
		return NULL;
	}

	req_sm = (p2plib_sd_req_sm_t *)P2PAPI_MALLOC(sizeof(p2plib_sd_req_sm_t));
	if (req_sm == NULL) {
		/* malloc error */
		P2PERR("p2plib_sd_create_req_sm: Exiting. req_sm alloc failed\n");
		return NULL;
	}

	memset(req_sm, 0, sizeof(p2plib_sd_req_sm_t));

	/* Initialize SM members */
	req_sm->comm_sm.state = init_state;

	/* Create dialog token for this SM */
	memcpy(&req_sm->comm_sm.peer_mac, peer_mac, ETHER_ADDR_LEN);
	memcpy(&req_sm->comm_sm.channel, peer_channel,
		sizeof(req_sm->comm_sm.channel));
	req_sm->comm_sm.dialog_token = dialog_token;
	req_sm->comm_sm.hdl = hdl;

	req_sm->req_entry_list = svc_req_list;

	/* Allocate buffer for received service data */
	req_sm->rx_qrsp_buf_size = ACTION_FRAME_SIZE * 2;  /* Initial buff size */
	req_sm->rx_qrsp_buf = (uint8 *)P2PAPI_MALLOC(req_sm->rx_qrsp_buf_size);
	if (req_sm->rx_qrsp_buf) {
		memset(req_sm->rx_qrsp_buf, 0, req_sm->rx_qrsp_buf_size);
	}
	else {
		P2PERR("p2plib_sd_create_req_sm: MALLOC of req_sm->rx_qrsp_buf failed\n");
		P2PAPI_FREE(req_sm);
		req_sm = NULL;
	}

	P2PLOG("p2plib_sd_create_req_sm: Exiting\n");
	return req_sm;
}

static p2plib_sd_req_sm_t *
p2plib_sd_find_req_sm(struct ether_addr *peer_mac)
{
	p2plib_sd_req_sm_t *cur = NULL;

	P2PLOG("p2plib_sd_find_req_sm: Entered\n");

	if (peer_mac == NULL) {
		P2PERR("p2plib_sd_find_req_sm: Exiting. peer_mac is NULL!\n");
		return NULL;
	}

	if (req_sm_list == NULL) {
		return NULL;
	}

	cur = req_sm_list;
	while (cur != NULL) {
		if (memcmp(&cur->comm_sm.peer_mac, peer_mac, ETHER_ADDR_LEN) == 0)
			break;

		cur = cur->next;
	}

	P2PLOG1("p2plib_sd_find_req_sm: Exiting. req_sm=%d\n", cur);
	return cur;
}

static p2plib_sd_rsp_sm_t *
p2plib_sd_create_rsp_sm(p2papi_instance_t *hdl, struct ether_addr *peer_mac,
	uint8 dialog_token, SD_STATE init_state)
{
	p2plib_sd_rsp_sm_t *rsp_sm;

	P2PLOG("p2plib_sd_create_rsp_sm: Entered\n");

	if (peer_mac == NULL || hdl == NULL) {
		P2PERR2("p2plib_sd_create_rsp_sm: Invalid NULL parameter passed in. "
			"hdl=%d, peer_mac=%d", hdl, peer_mac);
		return NULL;
	}

	rsp_sm = (p2plib_sd_rsp_sm_t *)P2PAPI_MALLOC(sizeof(p2plib_sd_rsp_sm_t));
	if (rsp_sm == NULL) {
		/* malloc error */
		P2PERR("p2plib_sd_create_rsp_sm: Exiting. rsp_sm malloc failed\n");
		return NULL;
	}

	memset(rsp_sm, 0, sizeof(p2plib_sd_rsp_sm_t));

	memcpy(&rsp_sm->comm_sm.peer_mac, peer_mac, ETHER_ADDR_LEN);
	rsp_sm->comm_sm.state = init_state;
	rsp_sm->comm_sm.dialog_token = dialog_token;
	rsp_sm->comm_sm.hdl = hdl;
	rsp_sm->last_frag_sent = false;

	P2PLOG("p2plib_sd_create_rsp_sm: Exiting\n");
	return rsp_sm;
}

static p2plib_sd_rsp_sm_t *
p2plib_sd_find_rsp_sm(struct ether_addr *peer_mac)
{
	p2plib_sd_rsp_sm_t *cur = NULL;

	P2PLOG("p2plib_sd_find_rsp_sm: Entered\n");

	if (peer_mac == NULL) {
		P2PERR("p2plib_sd_find_rsp_sm: Exiting. peer_mac is NULL!\n");
		return NULL;
	}

	if (rsp_sm_list == NULL) {
		P2PERR("p2plib_sd_find_rsp_sm: Exiting. rsp_sm_list is NULL!\n");
		return NULL;
	}

	cur = rsp_sm_list;
	while (cur != NULL) {
		if (memcmp(&cur->comm_sm.peer_mac, peer_mac, ETHER_ADDR_LEN) == 0)
			break;

		cur = cur->next;
	}

	P2PLOG1("p2plib_sd_find_rsp_sm: Exiting. rsp_sm=%d\n", cur);
	return cur;
}

static void
p2plib_sd_del_req_sm(p2plib_sd_req_sm_t *req_sm)
{
	P2PLOG("p2plib_sd_del_req_sm: Entered\n");

	if (req_sm == NULL) {
		P2PERR("p2plib_sd_del_req_sm: Invalid NULL param\n");
		return;
	}

	bcm_llist_del_member(&req_sm_list, req_sm);

	if (req_sm->rx_qrsp_buf) {
		P2PAPI_FREE(req_sm->rx_qrsp_buf);
		req_sm->rx_qrsp_buf = NULL;
	}

	if (req_sm->svc_resp) {
		P2PAPI_FREE(req_sm->svc_resp);
		req_sm->svc_resp = NULL;
	}

	req_sm->comm_sm.recv_acf_data = NULL;
	req_sm->req_entry_list = NULL;

	P2PAPI_FREE(req_sm);
	req_sm = NULL;

	P2PLOG("p2plib_sd_del_req_sm: Exiting\n");
}

static void
p2plib_sd_del_rsp_sm(p2plib_sd_rsp_sm_t *rsp_sm)
{
	P2PLOG("p2plib_sd_del_rsp_sm: Entered\n");

	if (rsp_sm == NULL) {
		P2PERR("p2plib_sd_del_rsp_sm: Invalid NULL param\n");
		return;
	}

	bcm_llist_del_member(&rsp_sm_list, rsp_sm);

	if (rsp_sm->tx_qrsp_buf)
		P2PAPI_FREE(rsp_sm->tx_qrsp_buf);

	P2PAPI_FREE(rsp_sm);
	rsp_sm = NULL;

	P2PLOG("p2plib_sd_del_rsp_sm: Exiting\n");
}

static void
p2plib_sd_del_req_sm_list(p2plib_sd_req_sm_t *req_sm_list)
{
	p2plib_sd_req_sm_t *cur, *tmp;

	P2PLOG("p2plib_sd_del_req_sm_list: Entered\n");

	if (req_sm_list == NULL) {
		P2PLOG("p2plib_sd_del_req_sm_list: Exiting. NULL req_sm_list\n");
		return;
	}

	cur = req_sm_list;
	tmp = cur;
	while (cur != NULL) {
		tmp = cur->next;
		p2plib_sd_del_req_sm(cur);
		cur = tmp;
	}

	req_sm_list = NULL;

	P2PLOG("p2plib_sd_del_req_sm_list: Exiting\n");
}

static void
p2plib_sd_del_rsp_sm_list(p2plib_sd_rsp_sm_t *rsp_sm_list)
{
	p2plib_sd_rsp_sm_t *cur, *tmp;

	P2PLOG("p2plib_sd_del_rsp_sm_list: Entered\n");

	if (rsp_sm_list == NULL) {
		P2PLOG("p2plib_sd_del_rsp_sm_list: Exiting. NULL rsp_sm_list\n");
		return;
	}

	cur = rsp_sm_list;
	tmp = cur;
	while (cur != NULL) {
		tmp = cur->next;
		p2plib_sd_del_rsp_sm(cur);
		cur = tmp;
	}

	rsp_sm_list = NULL;

	P2PLOG("p2plib_sd_del_rsp_sm_list: Exiting\n");
}

/* Store the received rsp fragment in req SM */
static SD_STATUS
p2plib_sd_sm_attach_resp_frag(p2plib_sd_req_sm_t *req_sm, uint8 *frag_data,
	uint16 frag_data_len)
{
	P2PLOG1("p2plib_sd_sm_attach_resp_frag: Entered. frag_data_len=%d\n", frag_data_len);

	if (req_sm == NULL || frag_data == NULL) {
		P2PERR2("p2plib_sd_sm_attach_resp_frag: Exiting. Invalid NULL parameter "
			"req_sm=%d, frag_data=%d\n", req_sm, frag_data);
		return SD_STATUS_INVALID_PARAM;
	}

	/* Check whether rx buffer is big enough */
	if (req_sm->rx_qrsp_buf_size - req_sm->rx_qrsp_data_len <
		frag_data_len) {
		/* Not enough buffer to store resp data */
		req_sm->rx_qrsp_buf_size += ACTION_FRAME_SIZE * 5;
		req_sm->rx_qrsp_buf = (uint8 *)P2PAPI_REALLOC(req_sm->rx_qrsp_buf,
			req_sm->rx_qrsp_buf_size);
		if (req_sm->rx_qrsp_buf == NULL) {
			P2PERR("p2plib_sd_sm_attach_resp_frag: Exiting."
				"malloc of rx_qrsp_buf failed.\n");
			return SD_STATUS_SYSTEM_ERR;
		}
	}

	/* Attach the received fragment */
	memcpy(req_sm->rx_qrsp_buf + req_sm->rx_qrsp_data_len, frag_data, frag_data_len);
	req_sm->rx_qrsp_data_len += frag_data_len;  /* Update data length */

	P2PLOG("p2plib_sd_sm_attach_resp_frag: Exiting with success\n");
	return SD_STATUS_SUCCESS;
}

/* Process GAS Initial Service Response frame */
static SD_STATUS
p2plib_sd_sm_proc_iresp_actfrm(p2plib_sd_req_sm_t *req_sm)
{
	SD_STATUS status;
	wifi_p2psd_gas_iresp_frame_t *iresp_frame;
	uint32 svc_resp_buf_len;

	P2PLOG("p2plib_sd_sm_proc_iresp_actfrm: Entered\n");

	iresp_frame = (wifi_p2psd_gas_iresp_frame_t *)req_sm->comm_sm.recv_acf_data;

	/* Attach the resp fragment */
	status = p2plib_sd_sm_attach_resp_frag(req_sm, iresp_frame->qresp_frm,
		iresp_frame->qresp_len);
	if (status != SD_STATUS_SUCCESS)
		goto END;

	if (iresp_frame->cb_delay == 0) {
		/* No fragmentation */
		if (req_sm->svc_resp) {
			P2PAPI_FREE(req_sm->svc_resp);
			req_sm->svc_resp = NULL;
		}

		svc_resp_buf_len = req_sm->rx_qrsp_data_len + sizeof(PBCMP2P_SVC_LIST)
			+ sizeof(PBCMP2P_SVC_ENTRY) * SD_MAX_TLV_NUMBER;
		req_sm->svc_resp = (uint8 *)P2PAPI_MALLOC(svc_resp_buf_len);
		if (req_sm->svc_resp != NULL) {
			/* Decode service reponse and set it to peer entry */
			memset(req_sm->svc_resp, 0, svc_resp_buf_len);
			if (!p2plib_sd_decode_qresp_svc_data(
				(wifi_p2psd_qresp_frame_t *)req_sm->rx_qrsp_buf,
				req_sm->svc_resp, svc_resp_buf_len)) {
				P2PERR("p2plib_sd_sm_proc_iresp_actfrm: Failed to decode"
					"query rsp frame\n");
				P2PAPI_FREE(req_sm->svc_resp);
				req_sm->svc_resp = NULL;
				status = SD_STATUS_DECODE_ERR;
			}
			else {
				status = SD_STATUS_SUCCESS;
			}
		}
		else {
			/* malloc failed */
			P2PERR1("p2plib_sd_sm_proc_iresp_actfrm: malloc of peer->svc_resp failed"
				"req_sm->rx_qrsp_data_len=%d", req_sm->rx_qrsp_data_len);
			status = SD_STATUS_SYSTEM_ERR;
		}
	}
	else {
		/* Fragmentation is expected. Send out comeback request */
		req_sm->comm_sm.ch_sync = false;
		if (!p2plib_sd_send_comeback_request(req_sm, P2PAPI_AF_DWELL_TIME, false)) {
			P2PERR("p2plib_sd_sm_proc_iresp_actfrm: Failed to send"
				"comeback request frame\n");
			status = SD_STATUS_SYSTEM_ERR;
		}
		else {
			status = SD_STATUS_CONTINUE;
		}
	}

END:
	P2PLOG1("p2plib_sd_sm_proc_iresp_actfrm: Exiting. status=%d\n", status);
	return status;
}

/* Process GAS Comeback Service Response frame via SM */
static SD_STATUS
p2plib_sd_sm_proc_cresp_actfrm(p2plib_sd_req_sm_t *req_sm)
{
	SD_STATUS status;
	uint8 status_code, fragment_id;
	bool more;
	uint16 cb_delay;
	uint8 *buf;
	wifi_p2psd_gas_cresp_frame_t *cresp_frame;

	P2PLOG("p2plib_sd_sm_proc_cresp_actfrm: Entered\n");

	if (req_sm == NULL) {
		P2PERR("p2plib_sd_sm_proc_cresp_actfrm: Exiting. Invalid NULL req_sm\n");
		return SD_STATUS_INVALID_PARAM;
	}

	cresp_frame = (wifi_p2psd_gas_cresp_frame_t *)req_sm->comm_sm.recv_acf_data;

	/* GAS response status code */
	buf = (uint8*)&cresp_frame->status;
	status_code = buf[0];

	/* Comeback delay */
	cb_delay = cresp_frame->cb_delay;

	/* Get fragment_id and store it as current fragment id */
	fragment_id = cresp_frame->fragment_id & 0x7f;

	/* Get "More Frame" flag */
	more = cresp_frame->fragment_id & 0x80 ? true : false;

	P2PLOG4("p2plib_sd_sm_proc_cresp_actfrm: Service resp data:"
		"status code %d, cb_delay %d, fragment_id %d, more %d\n",
		status_code, cb_delay, fragment_id, more);

	/* Validate fragment id */
	if (req_sm->fragment_id == fragment_id)
		req_sm->fragment_id++;
	else {
		/* It could be a retry of a fragment already received */
		P2PERR2("p2plib_sd_sm_proc_cresp_actfrm: Exiting. mismatched fragment id "
			"req_sm->fragment_id=%d, incoming fragment_id=%d\n",
			req_sm->fragment_id, fragment_id);
		return SD_STATUS_CONTINUE;
	}

	/* Attach the query response fragment */
	p2plib_sd_sm_attach_resp_frag(req_sm, cresp_frame->qresp_frm, cresp_frame->qresp_len);

	if (more) {
		/* Send out "Comeback Request" for next response frame */
		if (!p2plib_sd_send_comeback_request(req_sm, P2PAPI_AF_DWELL_TIME, false)) {
			P2PERR("p2plib_sd_sm_proc_cresp_actfrm: Failed to send"
				"comeback request frame\n");
			status = SD_STATUS_SYSTEM_ERR;
		}
		else
			status = SD_STATUS_CONTINUE;
	}
	else {
		/* Last fragment received */
		uint32 svc_resp_buf_len;
		P2PLOG("p2plib_sd_sm_proc_cresp_actfrm: Last fragment is received\n");

		svc_resp_buf_len = req_sm->rx_qrsp_data_len + sizeof(PBCMP2P_SVC_LIST)
			+ sizeof(PBCMP2P_SVC_ENTRY) * SD_MAX_TLV_NUMBER;
		req_sm->svc_resp = (uint8 *)P2PAPI_MALLOC(svc_resp_buf_len);
		if (req_sm->svc_resp != NULL) {
			memset(req_sm->svc_resp, 0, svc_resp_buf_len);
			if (!p2plib_sd_decode_qresp_svc_data(
				(wifi_p2psd_qresp_frame_t *)req_sm->rx_qrsp_buf,
				req_sm->svc_resp, svc_resp_buf_len)) {
				P2PERR("p2plib_sd_sm_proc_cresp_actfrm: Failed to decode"
					"query rsp frame\n");
				status = SD_STATUS_DECODE_ERR;
			}
			else {
				status = SD_STATUS_SUCCESS;
			}
		}
		else {
			P2PERR("p2plib_sd_sm_proc_cresp_actfrm: malloc of peer->svc_resp failed\n");
			status = SD_STATUS_SYSTEM_ERR;
		}
	}

	P2PLOG1("p2plib_sd_sm_proc_cresp_actfrm: Exiting. status=%d\n", status);
	return status;
}

static SD_STATUS
p2plib_sd_sm_proc_ireq_actfrm(p2plib_sd_rsp_sm_t *rsp_sm)
{
	SD_STATUS status;
	uint8 *req_buf;
	uint16 req_buf_len = ACTION_FRAME_SIZE;
	BCMP2P_SVC_LIST	*resp_list;
	wl_af_params_t *af_params;

	P2PLOG("p2plib_sd_sm_proc_ireq_actfrm: Entered\n");

	if (rsp_sm->last_frag_sent) {
		/* Retry of last fragment is handled elsewhere, but no need to build
		 * last fragment as it is already cached in pending_tx_af.
		 */
		P2PLOG("p2plib_sd_sm_proc_ireq_actfrm: Exiting. Last fragment was sent\n");
		status = SD_STATUS_CONTINUE;
	}

	/* free any previous response data buffer */
	if (rsp_sm->tx_qrsp_buf) {
		P2PAPI_FREE(rsp_sm->tx_qrsp_buf);
		rsp_sm->tx_qrsp_buf = NULL;
	}
	rsp_sm->tx_qrsp_cur_frag = NULL;
	rsp_sm->tx_qrsp_frm_size = 0;

	/* Allocate buffer to hold the request entry list */
	req_buf = (uint8 *)P2PAPI_MALLOC(req_buf_len);
	if (req_buf == NULL) {
		P2PERR("p2plib_sd_sm_proc_ireq_actfrm: malloc of req_buf failed\n");
		status = SD_STATUS_SYSTEM_ERR;
		goto END;
	}

	/* Decode service request data */
	memset(req_buf, 0, req_buf_len);
	if (!p2plib_sd_decode_qreq_svc_data(
			(wifi_p2psd_gas_ireq_frame_t *)rsp_sm->comm_sm.recv_acf_data,
			req_buf, req_buf_len)) {
		P2PERR("p2plib_sd_sm_proc_ireq_actfrm: Failed to decode req frame\n");
		status = SD_STATUS_DECODE_ERR;
		goto END;
	}

	/* Get the response entry list based on the request entries */
	resp_list = p2plib_sd_build_rsp_entry_list((BCMP2P_SVC_LIST *)req_buf);
	if (resp_list == NULL) {
		P2PERR("p2plib_sd_sm_proc_ireq_actfrm: Failed to build rsp entry list\n");
		status = SD_STATUS_GENERIC_ERR;
		goto END;
	}

	/* Calculate the exact GAS query response data/frame size including
	 * headers and all service response data in each TLV
	 */
	rsp_sm->tx_qrsp_frm_size = (sizeof(wifi_p2psd_qresp_frame_t) - 1) +
		(sizeof(wifi_p2psd_nqp_query_vsc_t) - 1) +
		((sizeof(wifi_p2psd_qresp_tlv_t) - 1) * resp_list->svcNum) +
		resp_list->dataSize;

	/* Allocate memory for GAS query response frame */
	rsp_sm->tx_qrsp_buf = (uint8 *)P2PAPI_MALLOC(rsp_sm->tx_qrsp_frm_size);
	if (rsp_sm->tx_qrsp_buf == NULL) {
		P2PERR("p2plib_sd_sm_proc_ireq_actfrm: malloc of qrsp_frame failed\n");
		status = SD_STATUS_SYSTEM_ERR;
		goto END;
	}

	memset(rsp_sm->tx_qrsp_buf, 0, rsp_sm->tx_qrsp_frm_size);

	/* Encode the full original GAS query resposne frame */
	/* TBD: Determine Svc Update Indicator value */
	if (!p2plib_sd_encode_nqp_qresp_frame(0, resp_list->svcNum,
		(BCMP2P_SVC_ENTRY *)resp_list->svcEntries, P2PSD_RESP_STATUS_SUCCESS,
		rsp_sm->tx_qrsp_buf, &rsp_sm->tx_qrsp_frm_size)) {
		P2PERR("p2plib_sd_sm_proc_ireq_actfrm: Failed to decode query rsp frame\n");
		status = SD_STATUS_DECODE_ERR;
		goto END;
	}

	/* If the full orignal GAS query response frame is larger than MMPDU, we nned to
	 * fragment it and send fragments one by one. Different format of GAS action frame
	 * will be built if fragmentation is required.
	 */
	af_params = p2plib_sd_build_gas_iresp_act_frm_param(rsp_sm,
		P2PSD_RESP_STATUS_SUCCESS, 200);

	/* TBD: It seems without this on service response side, one-to-one SD is still OK */
/*	if (rsp_sm->tx_qrsp_cur_frag != NULL)
		rsp_sm->comm_sm.hdl->suspend_disc_search = true;
*/
	if (af_params) {
		rsp_sm->comm_sm.pending_tx_af = af_params;
		status = (p2plib_sd_send_af(rsp_sm->comm_sm.hdl, false, af_params) == 0)?
			SD_STATUS_CONTINUE : SD_STATUS_SYSTEM_ERR;
	}
	else
		status = SD_STATUS_ENCODE_ERR;

END:
	if (req_buf)
		P2PAPI_FREE(req_buf);

	P2PLOG1("p2plib_sd_sm_proc_ireq_actfrm: Exiting. status=%d\n", status);
	return status;
}

static SD_STATUS
p2plib_sd_sm_proc_creq_actfrm(p2plib_sd_rsp_sm_t *rsp_sm)
{
	SD_STATUS status;
	wl_af_params_t *af_params;
	int tx_qrsp_frm_size;
	wifi_p2psd_qresp_frame_t *qrsp_frm;

	P2PLOG("p2plib_sd_sm_proc_creq_actfrm: Entered\n");

	if (rsp_sm->last_frag_sent) {
		/* Retry of last fragment is handled elsewhere, but no need to build
		 * last fragment as it is already cached in pending_tx_af.
		 */
		P2PLOG("p2plib_sd_sm_proc_creq_actfrm: Exiting. Last fragment was sent\n");
		status = SD_STATUS_CONTINUE;
	}

	qrsp_frm = (wifi_p2psd_qresp_frame_t *)rsp_sm->tx_qrsp_buf;
	tx_qrsp_frm_size = sizeof(wifi_p2psd_qresp_frame_t) - 1 + qrsp_frm->len;

	if (tx_qrsp_frm_size <= SD_GAS_FRAGMENT_SIZE) {
		P2PERR1("p2plib_sd_process_gas_creq_actfrm: Exiting. Unexpected comeback "
			"request. tx_qrsp_frm_size=%d\n", tx_qrsp_frm_size);
		return SD_STATUS_INVALID_PARAM;
	}

	/* Build response action frame */
	af_params = p2plib_sd_build_gas_cresp_act_frm_param(rsp_sm, 0, p2plib_sd_DWELL_TIME_MS);
	if (af_params) {
		rsp_sm->comm_sm.pending_tx_af = af_params;
		status = (p2plib_sd_send_af(rsp_sm->comm_sm.hdl, false, af_params) == 0)?
			SD_STATUS_CONTINUE : SD_STATUS_SYSTEM_ERR;
	}
	else {
		P2PERR("p2plib_sd_process_gas_creq_actfrm: Failed to build GAS comeback "
			"resp action frame\n");
		status = SD_STATUS_SYSTEM_ERR;
	}

	P2PLOG1("p2plib_sd_sm_proc_creq_actfrm: Exiting. status=%d\n", status);
	return status;
}

static SD_STATUS
p2plib_sd_req_sm_on_af_tx(p2plib_sd_req_sm_t *req_sm, bool tx_success)
{
	SD_STATUS status = SD_STATUS_CONTINUE;

	P2PLOG1("p2plib_sd_req_sm_on_af_tx: Entered. tx_success=%d\n", tx_success);

	/* One more tx attempt */
	req_sm->comm_sm.pending_tx_attempts++;

	if (tx_success) {
		/* Tx of service action frame succeeded */
		if (req_sm->comm_sm.pending_tx_af != NULL) {
			if (!req_sm->comm_sm.ch_sync) {
				P2PLOG("p2plib_sd_req_sm_on_af_tx: Not using channel sync. "
					"Free pending af\n");
				P2PAPI_FREE(req_sm->comm_sm.pending_tx_af);
			}
			else {
				/* When channel sync is used to tx action frame,
				 * p2papi_send_at_common_channel will free the af.
				 */
				P2PLOG("p2plib_sd_req_sm_on_af_tx: Channel sync is used. "
					"tx af will be freed already at this time.\n");
			}
			req_sm->comm_sm.pending_tx_af = NULL;
			req_sm->comm_sm.pending_tx_attempts = 0;
		}
	}
	else {
		/* Tx of service request failed */
		if (req_sm->comm_sm.pending_tx_attempts <= SD_MAX_TX_AF_ATTEMPTS)
			status = SD_STATUS_CONTINUE;
		else
			status = SD_STATUS_ERR_TX_MAX_RETRY;
	}

	P2PLOG2("p2plib_sd_req_sm_on_af_tx: Exiting. status=%d. total tx attempts %d\n",
		status, req_sm->comm_sm.pending_tx_attempts);
	return status;
}

static SD_STATUS
p2plib_sd_rsp_sm_on_af_tx(p2plib_sd_rsp_sm_t *rsp_sm, bool tx_success)
{
	SD_STATUS status = SD_STATUS_CONTINUE;

	P2PLOG1("p2plib_sd_rsp_sm_on_af_tx: Entered. tx_success=%d\n", tx_success);

	/* One more tx attempt */
	rsp_sm->comm_sm.pending_tx_attempts++;

	if (tx_success) {
		/* Tx of service action frame succeeded */
		if (rsp_sm->tx_qrsp_cur_frag == NULL) {
			/* Last fragment was sent successfully */
			status = SD_STATUS_SUCCESS;  /* SD is successful */
		}
		else {
			if (rsp_sm->comm_sm.pending_tx_af != NULL) {
				P2PLOG("p2plib_sd_rsp_sm_on_af_tx: Free pending af\n");
				P2PAPI_FREE(rsp_sm->comm_sm.pending_tx_af);
				rsp_sm->comm_sm.pending_tx_af = NULL;
			}
		}
	}
	else {
		/* Tx of service action frame failed */
		if (rsp_sm->comm_sm.pending_tx_attempts <= 3)
			status = SD_STATUS_CONTINUE;
		else
			status = SD_STATUS_ERR_TX_MAX_RETRY;
	}

	P2PLOG2("p2plib_sd_rsp_sm_on_af_tx: Exiting. status=%d. total tx attempts %d\n",
		status, rsp_sm->comm_sm.pending_tx_attempts);
	return status;
}


/* Start requesting service */
static SD_STATUS
p2plib_sd_sm_on_start_req(p2plib_sd_req_sm_t *req_sm)
{
	SD_STATUS status = SD_STATUS_CONTINUE;
	wl_af_params_t *af_params;

	P2PLOG("p2plib_sd_sm_on_start_req: Entered\n");

	/* Build reqest action frame */
	af_params = p2plib_sd_build_gas_ireq_act_frm_param(req_sm->comm_sm.hdl,
		&req_sm->comm_sm.peer_mac, req_sm->comm_sm.dialog_token,
		req_sm->req_entry_list, 0, &req_sm->comm_sm.channel,
		p2plib_sd_DWELL_TIME_MS);
	if (af_params) {
		int err;

		/* Suspend discovery search */
		if (req_sm->comm_sm.ch_sync)
			req_sm->comm_sm.hdl->suspend_disc_search = true;

		req_sm->comm_sm.pending_tx_af = af_params;
		err = p2plib_sd_send_af(req_sm->comm_sm.hdl, req_sm->comm_sm.ch_sync, af_params);
		if (err != 0)
			status = SD_STATUS_SYSTEM_ERR;
	}
	else {
		status = SD_STATUS_ENCODE_ERR;
	}

	P2PLOG1("p2plib_sd_sm_on_start_req: Exiting. status=%d\n", status);
	return status;
}

static void
p2plib_sd_req_session_end(p2plib_sd_req_sm_t *req_sm, SD_STATUS status)
{
	P2PLOG1("p2plib_sd_req_session_end: Entered. status=%d\n", status);

	req_sm->comm_sm.hdl->suspend_disc_search = false;

	if (req_sm->comm_sm.hdl->is_discovering)
		p2papi_discover_enable_search(req_sm->comm_sm.hdl, TRUE);

	/* Notify session end */
	p2papi_osl_do_notify_cb(req_sm->comm_sm.hdl, BCMP2P_NOTIF_SERVICE_DISCOVERY,
		BCMP2P_NOTIF_SVC_REQ_COMPLETED);

	/* If service is required, we will trigger BCMP2P_NOTIF_DISCOVER_FOUND_PEERS
	 * only after the peer's service data is discovered
	 */
	if (req_sm->comm_sm.hdl->svc_req_entries != NULL) {
		if (p2plib_sd_is_svc_discovered(&req_sm->comm_sm.peer_mac)) {
			p2papi_osl_do_notify_cb(req_sm->comm_sm.hdl, BCMP2P_NOTIF_DISCOVER,
				BCMP2P_NOTIF_DISCOVER_FOUND_PEERS);
		}
	}

	P2PLOG("p2plib_sd_req_session_end: Exiting\n");
}

static void
p2plib_sd_rsp_session_end(p2plib_sd_rsp_sm_t *rsp_sm, SD_STATUS status)
{
	P2PLOG1("p2plib_sd_rsp_session_end: Entered. status=%d\n", status);

	rsp_sm->comm_sm.hdl->suspend_disc_search = false;

	if (rsp_sm->comm_sm.hdl->is_discovering)
		p2papi_discover_enable_search(rsp_sm->comm_sm.hdl, TRUE);

	p2plib_sd_del_rsp_sm(rsp_sm);

	P2PLOG("p2plib_sd_rsp_session_end: Exiting\n");
}

static SD_STATUS
p2plib_sd_update_rsp_sm(p2papi_instance_t* hdl, p2plib_sd_rsp_sm_t *rsp_sm, SD_EVENT sd_evt)
{
	SD_STATUS status = SD_STATUS_CONTINUE;

	if (rsp_sm == NULL) {
		P2PERR("p2plib_sd_update_rsp_sm: Exiting. Null rsp_sm\n");
		return SD_STATUS_INVALID_PARAM;
	}

	P2PLOG2("p2plib_sd_update_rsp_sm: Entered. rsp_sm->comm_sm.state=%d, evt=%d\n",
		rsp_sm->comm_sm.state, sd_evt);

/*	P2PAPI_DATA_LOCK(hdl); */

	switch (sd_evt) {
	case SD_E_RX_GAS_INIT_REQ:
		if (rsp_sm->comm_sm.state == SD_ST_INIT) {
			/* Process GAS Init Resp and send comeback request if needed */
			status = p2plib_sd_sm_proc_ireq_actfrm(rsp_sm);
			if (status == SD_STATUS_CONTINUE)
				/* SD session not completed after initial req/rsp */
				rsp_sm->comm_sm.state = SD_ST_SENDING_INIT_RSP;
		}
		break;
	case SD_E_RX_GAS_CB_REQ:
		if (rsp_sm->comm_sm.state == SD_ST_INIT_RSP_SENT ||
			rsp_sm->comm_sm.state == SD_ST_CB_RSP_SENT) {
			/* Process GAS Init Resp and send comeback request if needed */
			status = p2plib_sd_sm_proc_creq_actfrm(rsp_sm);
			if (status == SD_STATUS_CONTINUE)
				/* SD session not completed after initial req/rsp */
				rsp_sm->comm_sm.state = SD_ST_SENDING_CB_RSP;
		}
		break;
	case SD_E_ABORT_SESSION:
		status = SD_STATUS_ABORTED;
		break;
	case SD_E_PEER_FOUND:
		/* Peer channel is in sync so trigger retry on pending af */
		if (rsp_sm->comm_sm.pending_tx_af != NULL) {
			P2PLOG("p2plib_sd_update_rsp_sm: Re-send pending af\n");
			status = p2plib_sd_send_pending_af(&rsp_sm->comm_sm);
		}
		break;
	case SD_E_TX_SUCCESS:
		if (rsp_sm->comm_sm.state == SD_ST_SENDING_INIT_RSP) {
			rsp_sm->comm_sm.state = SD_ST_INIT_RSP_SENT;
			status = p2plib_sd_rsp_sm_on_af_tx(rsp_sm, true);
		}
		else if (rsp_sm->comm_sm.state == SD_ST_SENDING_CB_RSP) {
			rsp_sm->comm_sm.state = SD_ST_CB_RSP_SENT;
			status = p2plib_sd_rsp_sm_on_af_tx(rsp_sm, true);
		}
		break;
	case SD_E_TX_FAIL:
		status = p2plib_sd_rsp_sm_on_af_tx(rsp_sm, false);
		break;
	default:
		;
	}

/*	P2PAPI_DATA_UNLOCK(hdl); */

	if (status != SD_STATUS_CONTINUE) {
		/* Rsp SM will be deleted once session is end */
		p2plib_sd_rsp_session_end(rsp_sm, status);
	}

	P2PLOG2("p2plib_sd_update_rsp_sm: Exiting. status=%d, state=%d\n",
		status, rsp_sm->comm_sm.state);
	return status;
}

/* Request SM when local machine is requesting service */
static SD_STATUS
p2plib_sd_update_req_sm(p2papi_instance_t* hdl, p2plib_sd_req_sm_t *req_sm, SD_EVENT sd_evt)
{
	SD_STATUS status = SD_STATUS_CONTINUE;

	if (req_sm == NULL) {
		P2PERR("p2plib_sd_update_req_sm: Exiting. Null req_sm\n");
		return SD_STATUS_INVALID_PARAM;
	}

	P2PLOG2("p2plib_sd_update_req_sm: Entered. req_sm->comm_sm.state=%d, evt=%d\n",
		req_sm->comm_sm.state, sd_evt);

/*	P2PAPI_DATA_LOCK(hdl); */

	if (req_sm->comm_sm.state == SD_ST_IDLE)
		goto END;

	switch (sd_evt) {
	case SD_E_START_REQ:
		if (req_sm->comm_sm.state == SD_ST_INIT) {
			req_sm->comm_sm.state = SD_ST_SENDING_INIT_REQ;
			status = p2plib_sd_sm_on_start_req(req_sm);
		}
		break;
	case SD_E_RX_GAS_INIT_RSP:
		if (req_sm->comm_sm.state == SD_ST_SENDING_INIT_REQ ||
			req_sm->comm_sm.state == SD_ST_INIT_REQ_SENT) {
			/* Process GAS Init Resp and send comeback request if needed */
			req_sm->comm_sm.state = SD_ST_SENDING_CB_REQ;
			status = p2plib_sd_sm_proc_iresp_actfrm(req_sm);
		}
		break;
	case SD_E_RX_GAS_CB_RSP:
		if (req_sm->comm_sm.state == SD_ST_SENDING_CB_REQ ||
			req_sm->comm_sm.state == SD_ST_CB_REQ_SENT) {
			/* Process GAS Init Resp and send comeback request if needed */
			req_sm->comm_sm.state = SD_ST_SENDING_CB_REQ;
			status = p2plib_sd_sm_proc_cresp_actfrm(req_sm);
		}
		break;
	case SD_E_ABORT_SESSION:
		status = SD_STATUS_ABORTED;
		break;
	case SD_E_PEER_FOUND:
		/* Peer channel is in sync so trigger retry on pending af */
		if (req_sm->comm_sm.pending_tx_af != NULL) {
			P2PLOG("p2plib_sd_update_req_sm: Re-send pending af\n");
			status = p2plib_sd_send_pending_af(&req_sm->comm_sm);
		}
		break;
	case SD_E_TX_SUCCESS:
		if (req_sm->comm_sm.state == SD_ST_SENDING_INIT_REQ) {
			req_sm->comm_sm.state = SD_ST_INIT_REQ_SENT;
			status = p2plib_sd_req_sm_on_af_tx(req_sm, true);
		}
		else if (req_sm->comm_sm.state == SD_ST_SENDING_CB_REQ) {
			req_sm->comm_sm.state = SD_ST_CB_REQ_SENT;
			status = p2plib_sd_req_sm_on_af_tx(req_sm, true);
		}
		break;
	case SD_E_TX_FAIL:
		status = p2plib_sd_req_sm_on_af_tx(req_sm, false);
		break;
	default:
		;
	}

/*	P2PAPI_DATA_UNLOCK(hdl); */
END:
	if (status != SD_STATUS_CONTINUE) {
		p2plib_sd_req_session_end(req_sm, status);
		req_sm->comm_sm.state = SD_ST_IDLE;
	}

	P2PLOG2("p2plib_sd_update_req_sm: Exiting. status=%d, state=%d\n",
		status, req_sm->comm_sm.state);
	return status;
}

/* Process Service Request action frame */
static SD_STATUS
p2plib_sd_process_gas_ireq_actfrm(p2papi_instance_t *hdl, struct ether_addr *src_mac,
	BCMP2P_CHANNEL *channel, uint8 dialog_token, wifi_p2psd_gas_ireq_frame_t *ireq_frame)
{
	SD_STATUS status;
	p2plib_sd_rsp_sm_t *rsp_sm;

	P2PLOG6("p2plib_sd_process_gas_ireq_actfrm: Entered. "
		"Peer addr: %02x:%02x:%02x:%02x:%02x:%02x\n",
		src_mac->octet[0], src_mac->octet[1], src_mac->octet[2],
		src_mac->octet[3], src_mac->octet[4], src_mac->octet[5]);

	if (!hdl->sd.is_service_discovery)
	{
		P2PLOG("p2plib_sd_process_gas_ireq_actfrm: is_service_discovery == 0!\n");
		status = SD_STATUS_ABORTED;
		goto END;
	}

	/* Validate Advertisement Protocol IE for SD */
	if (!p2plib_sd_verify_adp_ie(&ireq_frame->adp_ie, REQUEST_ADP_TUPLE_QLMT_PAMEBI)) {
		P2PERR("p2plib_sd_process_gas_ireq_actfrm: Exiting. Invalid ADP IE\n");
		status = SD_STATUS_DECODE_ERR;
		goto END;
	}

	/* We only allow one sm for each peer */
	rsp_sm = p2plib_sd_find_rsp_sm(src_mac);
	if (rsp_sm != NULL)
		p2plib_sd_del_rsp_sm(rsp_sm);

	rsp_sm = p2plib_sd_create_rsp_sm(hdl, src_mac, dialog_token, SD_ST_INIT);
	if (rsp_sm == NULL) {
		P2PERR("p2plib_sd_process_gas_ireq_actfrm: Exiting. Failed to create SM\n");
		status = SD_STATUS_SYSTEM_ERR;
		goto END;
	}
	else {
		/* Add the req sm to the rsp sm list */
		bcm_llist_add_member(&rsp_sm_list, rsp_sm);
	}

	/* Update rsp SM */
	rsp_sm->comm_sm.dialog_token = dialog_token;
	rsp_sm->comm_sm.recv_acf_data = (uint8 *)ireq_frame;
	memcpy(&rsp_sm->comm_sm.channel, channel, sizeof(rsp_sm->comm_sm.channel));
	status = p2plib_sd_update_rsp_sm(hdl, rsp_sm, SD_E_RX_GAS_INIT_REQ);
	
	/* send notification */
	p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_SERVICE_DISCOVERY, BCMP2P_NOTIF_SVC_REQ_RECEIVED);
	

END:
	P2PLOG1("p2plib_sd_process_gas_iresp_actfrm: Exiting. status=%d\n", status);
	return status;
}

/* Process Comeback Request action frame */
static SD_STATUS
p2plib_sd_process_gas_creq_actfrm(p2papi_instance_t *hdl, struct ether_addr *src_mac,
	BCMP2P_CHANNEL *channel, uint8 dialog_token)
{
	SD_STATUS status;
	p2plib_sd_rsp_sm_t *rsp_sm;

	P2PLOG6("p2plib_sd_process_gas_creq_actfrm: Entered. "
		"Peer addr: %02x:%02x:%02x:%02x:%02x:%02x\n",
		src_mac->octet[0], src_mac->octet[1], src_mac->octet[2],
		src_mac->octet[3], src_mac->octet[4], src_mac->octet[5]);

	hdl->sd.notify_params.comebackDelay = 0;
	hdl->sd.notify_params.fragmentId = 0;
	hdl->sd.notify_params.length = 0;
	p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_SERVICE_DISCOVERY,
		BCMP2P_NOTIF_SVC_COMEBACK_REQ_RECEIVED);

	rsp_sm = p2plib_sd_find_rsp_sm(src_mac);
	if (rsp_sm == NULL) {
		P2PERR("p2plib_sd_process_gas_creq_actfrm: Exiting. Rsp SM not existed\n");
		return SD_STATUS_GENERIC_ERR;
	}

	/* Validate dialog token */
	if (rsp_sm->comm_sm.dialog_token != dialog_token) {
		P2PERR2("p2plib_sd_process_gas_creq_actfrm: Dialog token not matched."
			" rsp_sm->comm_sm.dialog_token=%d, dialog_token=%d\n",
			rsp_sm->comm_sm.dialog_token, dialog_token);
		status = SD_STATUS_DECODE_ERR;
		goto END;
	}

	memcpy(&rsp_sm->comm_sm.channel, channel,
		sizeof(rsp_sm->comm_sm.channel));  /* Update peer channel */
	status = p2plib_sd_update_rsp_sm(hdl, rsp_sm, SD_E_RX_GAS_CB_REQ);

END:
	P2PLOG1("p2plib_sd_process_gas_creq_actfrm: Exiting. status=%d\n", status);
	return status;
}

static SD_STATUS
p2plib_sd_process_gas_cresp_actfrm(p2papi_instance_t *hdl,
	struct ether_addr *src_mac,	BCMP2P_CHANNEL *channel,
	uint8 dialog_token, wifi_p2psd_gas_cresp_frame_t *cresp_frame)
{
	SD_STATUS status;
	p2plib_sd_req_sm_t *req_sm;

	P2PLOG("p2plib_sd_process_gas_cresp_actfrm: Entered\n");

	LOG_MAC("Received comeback response from peer ", src_mac);

	hdl->sd.notify_params.comebackDelay = cresp_frame->cb_delay;
	hdl->sd.notify_params.fragmentId = cresp_frame->fragment_id;
	hdl->sd.notify_params.length = cresp_frame->qresp_len;
	p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_SERVICE_DISCOVERY,
		BCMP2P_NOTIF_SVC_COMEBACK_RESP_RECEIVED);

	/* Validate Advertisement Protocol IE for SD */
	if (!p2plib_sd_verify_adp_ie(&cresp_frame->adp_ie, RESPONSE_ADP_TUPLE_QLMT_PAMEBI)) {
		P2PERR("p2plib_sd_process_gas_cresp_actfrm: Exiting. Invalid ADP IE\n");
		return SD_STATUS_DECODE_ERR;
	}

	req_sm = p2plib_sd_find_req_sm(src_mac);
	if (req_sm) {
		/* Validate dialog token */
		if (req_sm->comm_sm.dialog_token != dialog_token) {
			P2PERR2("p2plib_sd_process_gas_iresp_actfrm: Dialog token not matched."
				" req_sm->comm_sm.dialog_token=%d, dialog_token=%d\n",
				req_sm->comm_sm.dialog_token, dialog_token);
			status = SD_STATUS_DECODE_ERR;
			goto END;
		}

		/* Update SD SM */
		req_sm->comm_sm.recv_acf_data = (uint8 *)cresp_frame;
		req_sm->comm_sm.dialog_token = dialog_token;
		status = p2plib_sd_update_req_sm(hdl, req_sm, SD_E_RX_GAS_CB_RSP);
	}
	else {
		P2PERR("p2plib_sd_process_gas_cresp_actfrm: Req SM for this Peer not found\n");
		status = SD_STATUS_GENERIC_ERR;
	}

END:
	P2PLOG1("p2plib_sd_process_gas_cresp_actfrm: Exiting. status=%d\n", status);
	return status;
}

/* Process Service Response action frame */
static SD_STATUS
p2plib_sd_process_gas_iresp_actfrm(p2papi_instance_t *hdl, struct ether_addr *src_mac,
	BCMP2P_CHANNEL *channel, uint8 dialog_token, wifi_p2psd_gas_iresp_frame_t *iresp_frame)
{
	SD_STATUS status = SD_STATUS_CONTINUE;
	p2plib_sd_req_sm_t *req_sm;

	LOG_MAC("p2plib_sd_process_gas_iresp_actfrm: Received service resp af from peer ",
		src_mac);

	hdl->sd.notify_params.comebackDelay = iresp_frame->cb_delay;
	hdl->sd.notify_params.length = iresp_frame->qresp_len;
	p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_SERVICE_DISCOVERY,
		BCMP2P_NOTIF_SVC_RESP_RECEIVED);

	/* Validate Advertisement Protocol IE for SD */
	if (!p2plib_sd_verify_adp_ie(&iresp_frame->adp_ie, RESPONSE_ADP_TUPLE_QLMT_PAMEBI)) {
		P2PERR("p2plib_sd_process_gas_iresp_actfrm: Exiting. Invalid ADP IE\n");
		return SD_STATUS_DECODE_ERR;
	}

	req_sm = p2plib_sd_find_req_sm(src_mac);
	if (req_sm) {
		P2PLOG1("p2plib_sd_process_gas_iresp_actfrm: comeback delay %d\n",
			iresp_frame->cb_delay);

		/* Validate dialog token */
		if (req_sm->comm_sm.dialog_token != dialog_token) {
			P2PERR2("p2plib_sd_process_gas_iresp_actfrm: Dialog token not matched."
			" req_sm->comm_sm.dialog_token=%d, dialog_token=%d\n",
			req_sm->comm_sm.dialog_token, dialog_token);
			status = SD_STATUS_DECODE_ERR;
			goto END;
		}

		/* Update SD SM */
		req_sm->comm_sm.recv_acf_data = (uint8 *)iresp_frame;
		status = p2plib_sd_update_req_sm(hdl, req_sm, SD_E_RX_GAS_INIT_RSP);
	}
	else {
		P2PLOG("p2plib_sd_process_gas_iresp_actfrm: Peer req SM not found\n");
	}

END:
	P2PLOG1("p2plib_sd_process_gas_iresp_actfrm: Exiting. status=%d\n", status);
	return status;
}

/* Check if it is GAS Initial Request or Response frame */
static int
p2plib_sd_is_gas_actfrm(p2papi_instance_t *hdl, void *frame, uint32 frame_len)
{
	wifi_p2psd_gas_pub_act_frame_t *act_frm = (wifi_p2psd_gas_pub_act_frame_t *)frame;

	if (frame_len < sizeof(wifi_p2psd_gas_pub_act_frame_t) - 1)
		return FALSE;

	if (act_frm->category != P2PSD_ACTION_CATEGORY)
		return FALSE;

	if (act_frm->action == P2PSD_ACTION_ID_GAS_IREQ ||
		act_frm->action == P2PSD_ACTION_ID_GAS_IRESP ||
		act_frm->action == P2PSD_ACTION_ID_GAS_CREQ ||
		act_frm->action == P2PSD_ACTION_ID_GAS_CRESP)
		return TRUE;
	else
		return FALSE;
}

/* Process GAS Initial Request or Response frame for SD */
static SD_STATUS
p2plib_sd_process_rx_gas_actfrm(p2papi_instance_t *hdl, struct ether_addr *src_mac,
	wifi_p2psd_gas_pub_act_frame_t *gas_frm, uint32 gas_frm_len,
	wl_event_rx_frame_data_t *rxframe_data)
{
	SD_STATUS status;
	BCMP2P_CHANNEL channel;
	uint8 mac[6];

	/* TBA: matching sd response to sd request, and timing consideration */

	/* Get peer device's channel and mac address */
	p2papi_chspec_to_channel(ntoh16(rxframe_data->channel), &channel);
	memcpy(mac, src_mac->octet, 6);

	P2PLOG8("p2plib_sd_process_rx_gas_actfrm: Entered. Recv GAS frame. "
		"peer %02x:%02x:%02x:%02x:%02x:%02x, channel %d:%d\n",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
		channel.channel_class, channel.channel);

	/* initialize notification params */
	memset(&hdl->sd.notify_params, 0, sizeof(hdl->sd.notify_params));
	memcpy(&hdl->sd.notify_params.peerAddress, src_mac,
		sizeof(hdl->sd.notify_params.peerAddress));
	hdl->sd.notify_params.dialogToken = gas_frm->dialog_token;

	switch (gas_frm->action) {
	case P2PSD_ACTION_ID_GAS_IREQ:
		status = p2plib_sd_process_gas_ireq_actfrm(hdl, src_mac, &channel,
		gas_frm->dialog_token, (wifi_p2psd_gas_ireq_frame_t *)(gas_frm->query_data));
		break;
	case P2PSD_ACTION_ID_GAS_IRESP:
		status = p2plib_sd_process_gas_iresp_actfrm(hdl, src_mac, &channel,
		gas_frm->dialog_token, (wifi_p2psd_gas_iresp_frame_t *)(gas_frm->query_data));
		break;
	case P2PSD_ACTION_ID_GAS_CREQ:
		status = p2plib_sd_process_gas_creq_actfrm(hdl, src_mac, &channel,
		gas_frm->dialog_token);
		break;
	case P2PSD_ACTION_ID_GAS_CRESP:
		status = p2plib_sd_process_gas_cresp_actfrm(hdl, src_mac, &channel,
		gas_frm->dialog_token, (wifi_p2psd_gas_cresp_frame_t *)(gas_frm->query_data));
		break;
	default:
		status = SD_STATUS_ENCODE_ERR;
	}

	P2PLOG1("p2plib_sd_process_rx_gas_actfrm: Exiting. status=%d\n", status);
	return status;
}

BCMP2P_STATUS
p2plib_sd_start_req_to_peer(p2papi_instance_t* hdl, struct ether_addr *peer_mac,
	BCMP2P_CHANNEL *channel, BCMP2P_SVC_LIST *svc_req_list, bool ch_sync)
{
	BCMP2P_STATUS status;
	p2plib_sd_req_sm_t *req_sm;

	P2PLOG3("p2plib_sd_start_req_to_peer: Entered. channel=%d:%d, ch_sync=%d\n",
		channel->channel_class, channel->channel, ch_sync);

	LOG_MAC("Sending service request to peer ", peer_mac);

	if (!P2PAPI_CHECK_P2PHDL(hdl)) {
		P2PERR("p2plib_sd_start_req_to_peer: Exiting. Invalid hdl\n");
		return BCMP2P_INVALID_HANDLE;
	}

	if (peer_mac == NULL || svc_req_list == NULL) {
		P2PERR2("p2plib_sd_start_req_to_peer: Exiting. peer_mac=%d, svc_req_list=%d\n",
			peer_mac, svc_req_list);
		return BCMP2P_INVALID_PARAMS;
	}

	/* We only allow one sm for each peer */
	req_sm = p2plib_sd_find_req_sm(peer_mac);
	if (req_sm != NULL)
		p2plib_sd_del_req_sm(req_sm);

	/* Create req SM and start service request */
	hdl->sd_dialog_token = p2papi_create_dialog_token(hdl->sd_dialog_token);
	req_sm = p2plib_sd_create_req_sm(hdl, channel, peer_mac,
		hdl->sd_dialog_token, SD_ST_INIT, svc_req_list);

	if (req_sm == NULL) {
		LOG_MAC("p2plib_sd_on_peer_found: Failed to create req "
			"SM for peer: ", peer_mac);
		status = BCMP2P_ERROR;
		goto END;
	}
	else {
		/* Add the req sm to the req sm list */
		bcm_llist_add_member(&req_sm_list, req_sm);
	}

	/* Kick off the request sm */
	req_sm->comm_sm.ch_sync = ch_sync;
	p2plib_sd_update_req_sm(hdl, req_sm, SD_E_START_REQ);
	status = BCMP2P_SUCCESS;

END:
	P2PLOG1("p2plib_sd_start_req_to_peer: Exiting. status=%d\n", status);
	return status;
}

BCMP2P_API BCMP2P_STATUS
p2plib_sd_cancel_req_svc(p2papi_instance_t* hdl, struct ether_addr* peer_mac)
{
	p2plib_sd_req_sm_t *req_sm;

	P2PLOG("p2plib_sd_cancel_req_svc: Entered\n");

	/* TBA: This is just temporary code. Need to use SM to handle this */
	p2papi_cancel_send_at_common_channel(hdl);

	req_sm = p2plib_sd_find_req_sm(peer_mac);
	if (req_sm != NULL) {
	/*	p2plib_sd_del_req_sm(req_sm); */
		p2plib_sd_update_req_sm(hdl, req_sm, SD_E_ABORT_SESSION);
	}

	P2PLOG("p2plib_sd_cancel_req_svc: Exiting\n");
	return BCMP2P_SUCCESS;
}

void
p2plib_sd_disable_auto_req_svc(p2papi_instance_t* hdl)
{
	int i;

	P2PLOG("p2plib_sd_disable_auto_req_svc: Entered\n");

	for (i = 0; i < hdl->peer_count; i++) {
		p2papi_peer_info_t *peer = &hdl->peers[i];
		p2plib_sd_req_sm_t *req_sm;

		req_sm = p2plib_sd_find_req_sm(&peer->mac);
		if (req_sm != NULL) {
			LOG_MAC("p2plib_sd_disable_auto_req_svc: Abort SD session with peer ",
				&req_sm->comm_sm.peer_mac);
			p2plib_sd_update_req_sm(hdl, req_sm, SD_E_ABORT_SESSION);
		}

		peer->requesting_svc = false;
	}

	P2PLOG("p2plib_sd_disable_auto_req_svc: Exiting\n");
}

/* Response SM when local machine is responding to service request */
int
p2plib_sd_on_peer_found(int old_peer_count, p2papi_instance_t* hdl)
{
	int i;

	P2PLOG1("p2plib_sd_on_peer_found: Entered. hdl->peer_count=%d\n", hdl->peer_count);

	/* Create SM for each newly found peer device */
	for (i = 0; i < hdl->peer_count; i++) {
		p2papi_peer_info_t *peer = &hdl->peers[i];
		p2plib_sd_req_sm_t *req_sm;
		p2plib_sd_rsp_sm_t *rsp_sm;

		req_sm = p2plib_sd_find_req_sm(&peer->mac);
		rsp_sm = p2plib_sd_find_rsp_sm(&peer->mac);

		if (!peer->requesting_svc) {
			/* Create req SM winthin the function */
			peer->requesting_svc = true;
			p2plib_sd_start_req_to_peer(hdl, &peer->mac, &peer->listen_channel,
				(BCMP2P_SVC_LIST *)hdl->svc_req_entries, false);
		}
		else {
			if (req_sm == NULL) {
				P2PERR("p2plib_sd_on_peer_found: NULL req_sm!\n");
				goto END;
			}

			/* TBA: More efficient or right way is to trigger SD_E_PEER_FOUND upon
			 * WLC_E_ESCAN_RESULT/WLC_E_STATUS_PARTIAL. Based on the found peer mac,
			 * identify its req SM and update it with the SD_E_PEER_FOUND event
			 */
			/* Peer channel in sync. Update request SM */
			if (req_sm->svc_resp == NULL) {
				p2plib_sd_update_req_sm(hdl, req_sm, SD_E_PEER_FOUND);
			}
			else {
				/* Ignore SD_E_PEER_FOUND if SD is done already */
				P2PLOG("p2plib_sd_on_peer_found: Service req done already\n");
			}
		}

		if (rsp_sm != NULL)
			p2plib_sd_update_rsp_sm(hdl, rsp_sm, SD_E_PEER_FOUND);
	}

END:
	P2PLOG("p2plib_sd_on_peer_found: Exiting\n");
	return 0;
}


/* Service discovery event handler. */
void
p2plib_sd_wl_event_handler(p2papi_instance_t *hdl, BCMP2P_BOOL is_primary,
	wl_event_msg_t *wl_event, void* data, uint32 data_len)
{
	uint32 event_type;
	uint32 *pkt_id;

	if (is_primary) {
		/* Not interested in events from the primary interface. */
		return;
	}

	if (!wl_event) {
		P2PLOG("p2plib_sd_wl_event_handler: Exiting. event param is NULL\n");
		return;
	}

	event_type = wl_event->event_type;

	switch (event_type) {
	case WLC_E_ACTION_FRAME_RX:
		{
		/* Process received action frames */
		wl_event_rx_frame_data_t *rxframe = (wl_event_rx_frame_data_t*)data;
		uint8 *act_frm = (uint8 *) (rxframe + 1);
		struct ether_addr* src_mac = &wl_event->addr;
		uint32 act_frm_len = wl_event->datalen - sizeof(wl_event_rx_frame_data_t);

		if (!hdl->enable_p2p) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"%s: discard, P2P not enabled\n", __FUNCTION__));
			return;
		}

		if (p2plib_sd_is_gas_actfrm(hdl, act_frm, act_frm_len)) {

			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2plib_sd_wl_event_handler: wl_event_msg.addr="
				"%02x:%02x:%02x:%02x:%02x:%02x\n",
				wl_event->addr.octet[0], wl_event->addr.octet[1],
				wl_event->addr.octet[2], wl_event->addr.octet[3],
				wl_event->addr.octet[4], wl_event->addr.octet[5]));

			p2papi_log_hexdata(BCMP2P_LOG_MED,
				"p2plib_sd_wl_event_handler: RX action frame",
				act_frm, act_frm_len);

			p2plib_sd_process_rx_gas_actfrm(hdl, src_mac,
				(wifi_p2psd_gas_pub_act_frame_t *)act_frm,
				act_frm_len, rxframe);
		}
		}
		break;
	case WLC_E_ACTION_FRAME_COMPLETE:
		{
		SD_EVENT tx_evt;
		pkt_id = (uint32 *)(data);
		p2plib_sd_req_sm_t *cur_req_sm = req_sm_list;
		p2plib_sd_rsp_sm_t *cur_rsp_sm = rsp_sm_list;

		P2PLOG2("p2plib_sd_wl_event_handler: WLC_E_ACTION_FRAME_COMPLETE evt. "
			"*pkt_id=%u, status=%d\n", *pkt_id, wl_event->status);

		if (wl_event->status == WLC_E_STATUS_SUCCESS)
			tx_evt = SD_E_TX_SUCCESS;
		else
			tx_evt = SD_E_TX_FAIL;

		/* Search req SM list to find matching SM */
		while (cur_req_sm != NULL) {
			if (cur_req_sm->comm_sm.pending_tx_af) {
				if (cur_req_sm->comm_sm.pending_tx_af->action_frame.packetId
					== *pkt_id) {
					p2plib_sd_update_req_sm(hdl, cur_req_sm, tx_evt);
					return;
				}
			}
			cur_req_sm = cur_req_sm->next;
		}

		/* Search rsp SM list to find matching SM */
		while (cur_rsp_sm != NULL) {
			if (cur_rsp_sm->comm_sm.pending_tx_af) {
				if (cur_rsp_sm->comm_sm.pending_tx_af->action_frame.packetId
					== *pkt_id) {
					p2plib_sd_update_rsp_sm(hdl, cur_rsp_sm, tx_evt);
					return;
				}
			}
			cur_rsp_sm = cur_rsp_sm->next;
		}
		}
		break;
	case WLC_E_ACTION_FRAME_OFF_CHAN_COMPLETE:
		/* WLC_E_ACTION_FRAME_OFF_CHAN_COMPLETE does not come with valid event data */

		/* It seems that WLC_E_ACTION_FRAME_OFF_CHAN_COMPLETE always follows 
		 * WLC_E_ACTION_FRAME_COMPLETE regardless of whether the af is sent
		 * off-channel or not.
		 */
		P2PLOG1("p2plib_sd_wl_event_handler: WLC_E_ACTION_FRAME_OFF_CHAN_COMPLETE "
			"received. sending_sd_af_piggyback=%d\n", hdl->sd.sending_sd_af_piggyback);

		/* Only react to events due to tx of sd action frames */
		if (hdl->sd.sending_sd_af_piggyback) {
			if (!hdl->suspend_disc_search) {
				if (hdl->is_discovering)
					p2papi_discover_enable_search(hdl, BCMP2P_TRUE);
			}
		}
		/* WLC_E_ACTION_FRAME_OFF_CHAN_COMPLETE is always received whether tx af
		 * is complete (preceded by WLC_E_ACTION_FRAME_COMPLETE) or aborted
		 */
		hdl->sd.sending_sd_af_piggyback = false;
		break;
	default:
		;  /* Ignore other events */
	}
}

/* Get the BCMP2P_SVC_LIST list of requested services from peer device */
BCMP2P_SVC_LIST *
p2plib_sd_get_peer_svc(struct ether_addr *peer_mac)
{
	p2plib_sd_req_sm_t * req_sm;

	P2PLOG("p2plib_sd_get_svc_rsp: Entered\n");

	if (peer_mac == NULL) {
		P2PLOG("p2plib_sd_get_svc_rsp: Exiting. Null peer_mac!\n");
		return NULL;
	}

	LOG_MAC("p2plib_sd_get_svc_rsp: peer mac ", peer_mac);

	req_sm = p2plib_sd_find_req_sm(peer_mac);
	if (req_sm == NULL) {
		P2PLOG("p2plib_sd_get_svc_rsp: Exiting. Can't find peer req SM!\n");
		return NULL;
	}

	P2PLOG("p2plib_sd_get_svc_rsp: Exiting\n");
	return (BCMP2P_SVC_LIST *)req_sm->svc_resp;
}

/* Check each service response entry to see if a valid service is discovered */
extern bool
p2plib_sd_is_svc_discovered(struct ether_addr *peer_mac)
{
	BCMP2P_SVC_LIST *entry_list;
	BCMP2P_SVC_ENTRY *entry_beg;
	int i;
	bool bRet = false;

	P2PLOG("p2plib_sd_is_svc_discovered: Entering\n");

	if (peer_mac == NULL) {
		P2PLOG("p2plib_sd_is_svc_discovered: Null peer_mac passed in!\n");
		goto END;
	}

	entry_list = p2plib_sd_get_peer_svc(peer_mac);
	if (entry_list == NULL) {
		P2PLOG("p2plib_sd_is_svc_discovered: No service response received.\n");
		goto END;
	}

	entry_beg = (BCMP2P_SVC_ENTRY *)entry_list->svcEntries;
	for (i = 0; i < entry_list->svcNum; i++) {
		if (entry_beg->status == BCMP2P_SD_STATUS_SUCCESS &&
			entry_beg->dataSize > 0) {
			bRet = true;
			break;
		}

		entry_beg = (BCMP2P_SVC_ENTRY *)((uint8 *)entry_beg +
			sizeof(BCMP2P_SVC_ENTRY) + entry_beg->dataSize - 1);
	}

END:
	P2PLOG1("p2plib_sd_is_svc_discovered: Exiting. bRet=%d\n", bRet);
	return bRet;
}

void
p2plib_sd_cleanup(p2papi_instance_t *hdl)
{
	P2PLOG("p2plib_sd_cleanup: Entered\n");

	if (!P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl)) {
		P2PERR("p2plib_sd_cleanup: Exiting. NULL hdl\n");
		return;
	}

	p2plib_sd_del_req_sm_list(req_sm_list);
	p2plib_sd_del_rsp_sm_list(rsp_sm_list);

	P2PLOG("p2plib_sd_unit: Exiting\n");
}

static int
p2plib_sd_find_svc(p2psd_svc_protype_t svcProtocol, const uint8 *queryData,
	uint32 queryDataLen)
{
	int i, ret_index = -1;

	for (i = 0; i < MAX_SVC_DATA_PAIRS; i++) {
		if (svc_store.instances[i].hsd == NULL)
			continue;  /* Empty spot */

		if (svcProtocol == svc_store.instances[i].pro_type &&
			memcmp(queryData, svc_store.instances[i].req_data, queryDataLen) == 0) {
			ret_index = i;  /* QR is found */
			break;
		}
	}

	return ret_index;
}

static BCMP2P_STATUS
p2plib_sd_add_svc(uint32 svc_id, p2psd_svc_protype_t pro_type,
	const uint8 *req_data, uint32 req_data_len, const uint8 * resp_data,
	uint32 resp_data_len, p2plib_sd_instance_t **hsd)
{
	int i, spot_index = -1;
	p2plib_sd_instance_t *sd_instance = 0;

	if (req_data == NULL || req_data_len == 0) {
		P2PERR("p2plib_sd_add_svc: Service request can't be NULL.\n");
		return BCMP2P_INVALID_PARAMS;
	}

	/* Find an empty spot */
	for (i = 0; i < MAX_SVC_DATA_PAIRS; i++) {
		if (svc_store.instances[i].hsd == NULL) {
			spot_index = i;
			break;
		}
	}

	if (spot_index < 0) {
		P2PERR("p2plib_sd_add_svc: SDS has no room for new QR.\n");
		return BCMP2P_ERROR;  /* No room for new QR */
	}

	sd_instance = &svc_store.instances[spot_index];

	sd_instance->hsd = sd_instance;
	sd_instance->svc_id = svc_id;
	sd_instance->pro_type = pro_type;

	/* Service Request data */
	sd_instance->req_data_len = req_data_len;
	if (req_data_len > 0) {
		sd_instance->req_data = (uint8 *)P2PAPI_MALLOC(req_data_len);
		memcpy(sd_instance->req_data, req_data, req_data_len);
	}

	/* Service Response data */
	sd_instance->resp_data_len = resp_data_len;
	if (resp_data_len > 0) {
		sd_instance->resp_data = (uint8 *)P2PAPI_MALLOC(resp_data_len);
		memcpy(sd_instance->resp_data, resp_data, resp_data_len);
	}

	/* Return service data handle */
	*hsd = sd_instance;
	svc_store.total++;

	return BCMP2P_SUCCESS;
}

/* Register service request-response pair to Service Data Store */
BCMP2P_STATUS
p2plib_sd_register_svc_data(uint32 svc_id, p2psd_svc_protype_t pro_type,
	const uint8 *req_data, uint32 req_data_len, const uint8 * resp_data,
	uint32 resp_data_len, void **hsd)
{
	int found;
	BCMP2P_STATUS status;

	if (req_data == NULL || req_data_len == 0) {
		P2PERR("p2plib_sd_register_svc_data: Service request can't be NULL.\n");
		return BCMP2P_INVALID_PARAMS;
	}

	if (resp_data == NULL || resp_data_len == 0) {
		P2PERR("p2plib_sd_register_svc_data: Service response can't be NULL.\n");
		return BCMP2P_INVALID_PARAMS;
	}

	found = p2plib_sd_find_svc(pro_type, req_data, req_data_len);
	if (found < 0) {
		/* Invalid index. Service not existed */
		if (svc_id != 0)
			status = BCMP2P_ERROR;  /* Invalid transaction */
		else
			svc_id = ++svc_store.svc_id_counter;
	}
	else {
		/* Service found existed already, remove it first */
		p2plib_sd_deregister_svc_data((p2plib_sd_instance_t *)
			svc_store.instances[found].hsd);
	}

	/* Add service QR to SDS */
	status = p2plib_sd_add_svc(svc_id, pro_type, req_data, req_data_len,
		resp_data, resp_data_len, (p2plib_sd_instance_t **)hsd);

	return status;
}

/* Deregister a service from P2P library */
BCMP2P_STATUS
p2plib_sd_deregister_svc_data(void *hsd)
{
	BCMP2P_STATUS status = BCMP2P_INVALID_HANDLE;
	int i;
	p2plib_sd_instance_t *hsd_dereg = (p2plib_sd_instance_t *)hsd;

	if (hsd == NULL) {
		P2PVERB("p2plib_sd_deregister_svc_data: Service request can't be NULL.\n");
		return BCMP2P_INVALID_PARAMS;
	}

	/* Remove the service instance from Service Data Store */
	for (i = 0; i < MAX_SVC_DATA_PAIRS; i++) {
		if (hsd_dereg == svc_store.instances[i].hsd) {
			svc_store.total--;  /* Decrease service store size */

			/* Free memory allocated for the service instance to remove */
			if (hsd_dereg->req_data)
				P2PAPI_FREE(hsd_dereg->req_data);

			if (hsd_dereg->resp_data)
				P2PAPI_FREE(hsd_dereg->resp_data);

			/* Mark the spotted as vacant */
			memset(&svc_store.instances[i], 0, sizeof(p2plib_sd_instance_t));

			status = BCMP2P_SUCCESS;
			break;
		}
	}

	return status;
}

BCMP2P_STATUS
p2plib_sd_get_registered_service(BCMP2P_SVC_PROTYPE svcProtocol, uint8 *queryData,
	uint32 queryDataLen, uint8 *respDataBuf, uint32 *respDataLen, uint32 *svc_id)
{
	BCMP2P_STATUS status = BCMP2P_SUCCESS;
	int found;

	/* Validate query data */
	if (queryData == NULL || queryDataLen == 0) {
		P2PERR("p2plib_sd_get_registered_service: Service request can't be NULL.\n");
		return BCMP2P_INVALID_PARAMS;
	}

	/* Look up the SDS to find the QR pair */
	found = p2plib_sd_find_svc((p2psd_svc_protype_t)svcProtocol,
		queryData, queryDataLen);

	if (found < 0) {
		/* Assign a spot and a service id for the service request */
		p2plib_sd_instance_t *hsd_cur = NULL;

		/* Assign a service id for the service request */
		*svc_id = ++svc_store.svc_id_counter;

		/* Add it to the SDS */
		status = p2plib_sd_add_svc(*svc_id, (p2psd_svc_protype_t)svcProtocol,
			queryData, queryDataLen, NULL, 0, &hsd_cur);

		/* Service QR is not existed, set response data
		 * length to 0 to indicate that
		 */
		*respDataLen = 0;

		return status;
	}

	/* Check whether response buffer is provided */
	if (respDataBuf == NULL) {
		/* No buffer is provided, return total size required */
		*respDataLen = svc_store.instances[found].resp_data_len;
	}
	else {
		/* Return the response data of the QR pair in SDS */
		if (*respDataLen >= svc_store.instances[found].resp_data_len) {
			memcpy(respDataBuf, svc_store.instances[found].resp_data,
				svc_store.instances[found].resp_data_len);
			*respDataLen = svc_store.instances[found].resp_data_len;
			*svc_id = svc_store.instances[found].svc_id;
		}
		else {
			/* Not enough buffer size */
			status = BCMP2P_NOT_ENOUGH_SPACE;
		}
	}

	return status;
}

/* Release Service Data Store memory */
int
p2plib_sd_free_sds()
{
	return 0;
}

#endif /* not SOFTAP_ONLY */
