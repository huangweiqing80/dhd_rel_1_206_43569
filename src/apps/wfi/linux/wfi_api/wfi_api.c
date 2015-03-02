/* 
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wfi_api.c,v 1.16 2010-10-25 23:39:26 $
 */


#include "wfi_api.h"
#include "wlioctl.h"
#include "wpscli_api.h"
#include "wpscli_osl.h"
#include "wfi_utils.h"
#include <stdio.h>
#include "bcmendian.h"
#include <stdlib.h>
#include <wpserror.h>

#include <pthread.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include <packed_section_start.h>

/*
 *  WFI Vendor Extension format in WPS IE:
 */
typedef BWL_PRE_PACKED_STRUCT struct {
	uint8 type;
	uint8 len;
	uint8 OUI[4];
	uint8 data[1];
} BWL_POST_PACKED_STRUCT wps_ie_t;
#define WPS_OUI		"\x00\x50\xF2\x04"
/*   WFI Vendor Extension Data */
#define BRCM_SMI_CODE	"\x00\x11\x3D"
#define SMI_CODE_LEN	3
#define BRCM_VENDOR_EXTN_TYPE_WFI	0x1

typedef BWL_PRE_PACKED_STRUCT struct {
	uint8 type;    /* type of this IE = WFI_IE_TYPE. Will be defined in wlioctl.h */
	uint8 version; /* WFI version = 1 */ 
	uint8 cap;     /* WFI capabilities. HOTSPOT = 0x1. Secure PIN= 0x02, Bits 2-7 : Reserved */
	uint8 pin[4];  /* Nonce used for key generation */
	uint8 mac_addr[6]; /* MAC address of the STA requesting WFI (ProbeReq) or MAC address 
					      of the STA for which the WFI is destined (ProbeRsp) 
						*/
	uint8 fname_len; /* Length of the BDD friendly name 
					    (of STA in case of ProbeReq, of AP in case of ProbeRsp) 
					  */
	uint8 fname[1];  /* BDD Friendly name, non-null-terminated */
}	BWL_POST_PACKED_STRUCT brcm_wfi_vndr_extn_data_t;

/* Defines for easier access of WFI IE */
#define	WFI_IE_OFFSET_TYPE		0
#define	WFI_IE_OFFSET_VER		1
#define	WFI_IE_OFFSET_CAP		2
#define WFI_IE_OFFSET_NONCE		3
#define WFI_IE_OFFSET_MAC_ADDR	5
#define WFI_IE_OFFSET_FRAME_LEN	11
#define	WFI_IE_OFFSET_FNAME		12

/* Defines for WFI capabilities */
#define WFI_CAP_HOTSPOT 0x1
#define WFI_CAP_SECURE_PIN 0x2

#include <packed_section_end.h>


#define WPS_LEN_BYTE 	1
#define WPS_LEN_SHORT 	2
#define WPS_LEN_WORD 	4

#define WPS_TYPE_VERSION			0x104A
#define WPS_TYPE_REQUEST_TYPE		0x103A
#define WPS_TYPE_CONFIG_METHOD		0x1008
#define WPS_TYPE_UUID				0x1047
#define WPS_TYPE_PRIMARY_DEVICE_TYPE	0x1054
#define WPS_TYPE_RF_BANDS_TYPE		0x103C
#define WPS_TYPE_ASSOC_STATE 		0x1002
#define WPS_TYPE_CONFIG_ERROR		0x1009
#define WPS_TYPE_DEVICE_PASSWD_ID 	0x1012
#define WPS_TYPE_VENDOR_EXTENSION	0x1049

#define ARRAYSIZE(a)  (sizeof(a)/sizeof(a[0]))

#if defined(DEBUG)
#define DBGPRINT(x) printf x
#else
#define DBGPRINT(x) do {} while (0)
#endif

static WFI_STATUS g_uiStatus;

static pthread_t g_evt_thread_hndlr;
static pthread_cond_t g_evt_thread_completed;
static pthread_mutex_t g_evt_thread_completed_mutex;

/* g_evt_thread_done : Whether g_evt_thread should stop. */
static int g_evt_thread_done = FALSE;

/* g_active : Indicates whether periodic WFI scan should be skipped. 
 * Eg: Skip scan when WPS is started.
 */
static int g_active = TRUE;

/* g_interval : Interval between WFI Scans */
static int g_interval = 15000;


/* --------------------Internal functions ------------------------- */

static brcm_wpscli_status eiWFIWPSStatus; /* WPS Status reported by callback function */

static struct _sWPS_STATUS
{	brcm_wpscli_status eiWPSStatus;
	char *pcString;
}	asWPSCLIStatusString[] =
/*	Broadcom WPS Protocol Stack specific statuses */
{	{	WPS_STATUS_PROTOCOL_SUCCESS, "Suceessful" },
	{	WPS_STATUS_PROTOCOL_INIT_FAIL, "Initialization Failed" },
	{	WPS_STATUS_PROTOCOL_INIT_SUCCESS, "Initialized" },
	{	WPS_STATUS_PROTOCOL_START_EXCHANGE, "Start message exchange" },
	{	WPS_STATUS_PROTOCOL_CONTINUE, "Exchanging" },
	{	WPS_STATUS_PROTOCOL_SEND_MEG, "Sending message" },
	{	WPS_STATUS_PROTOCOL_WAIT_MSG, "Waiting for message" },
	{	WPS_STATUS_PROTOCOL_RECV_MSG, "Received message" },
	/* timeout and fails in M1-M8 negotiation */
	{	WPS_STATUS_PROTOCOL_FAIL_TIMEOUT, "Timeout" },
	/* don't retry any more because of EAP timeout as AP gives up already */
	{	WPS_STATUS_PROTOCOL_FAIL_MAX_EAP_RETRY,	"Failed after retries"  },
	/* PBC session overlap */
	{	WPS_STATUS_PROTOCOL_FAIL_OVERLAP, "PBC session overlap" },
	/* fails in protocol processing stage because of unmatched pin number */
	{	WPS_STATUS_PROTOCOL_FAIL_WRONG_PIN,	"PIN mismatches" },
	/* fails because of EAP failure */
	{	WPS_STATUS_PROTOCOL_FAIL_EAP, "EAP failure" },
	/* after wps negotiation, unexpected network credentials are received */
	{	WPS_STATUS_PROTOCOL_FAIL_UNEXPECTED_NW_CRED, "Unexpected Credential" },
	/* after wps negotiation, unexpected network credentials are received */
	{	WPS_STATUS_PROTOCOL_FAIL_PROCESSING_MSG, "Message error" },
	{	WPS_STATUS_WLAN_CONNECTION_START, "Connecting..." },
	{	WPS_STATUS_WLAN_CONNECTION_ATTEMPT_FAIL, "Connecting to AP failed" }
};

static char *wfi_wps_get_status_message(void)
/* Return the Null-terminate string for status display. */
{	int i;
	for (i = 0; i < sizeof(asWPSCLIStatusString)/sizeof(asWPSCLIStatusString[0]); i++)
	{	if (asWPSCLIStatusString[i].eiWPSStatus == eiWFIWPSStatus)
			return asWPSCLIStatusString[i].pcString;
	}

	return "Unknown Status";
}

static brcm_wpscli_status wfi_wps_process_callback(void *context,
	brcm_wpscli_status eiFromWPS,
	void *data)
{	eiWFIWPSStatus = eiFromWPS;
	DBGPRINT(("wfi_wps_process_callback: S=%d [%s]\n",
		eiWFIWPSStatus,
		wfi_wps_get_status_message()));
	switch (eiWFIWPSStatus)
	{	case WPS_STATUS_SUCCESS:
		case WPS_STATUS_PROTOCOL_SUCCESS:
			DBGPRINT(("WPS_STATUS_PROTOCOL_SUCCESS received\n"));
			break;
		default:
			break;
	}
	if (g_uiStatus == WFI_STATUS_SUCCESS ||
		g_uiStatus == WFI_STATUS_ERROR ||
		g_uiStatus == WFI_STATUS_CANCELED)
		g_active = TRUE; /* WPS done. Start the WFI periodic scan. */

	return WPS_STATUS_SUCCESS;
}


static WFI_RET
wfi_wps_generate_pin(char *pcPin, int siSize)
/* Generate a Null-terminated WPS PIN string.
*
*  pin: output, contains the generated pin string.
*  siSize: input, shall be larger than 8.
*/
{	if (siSize <= 8)
		return WFI_RET_WPS_ERROR;
	return (brcm_wpscli_generate_pin(pcPin, siSize)? WFI_RET_SUCCESS: WFI_RET_WPS_ERROR);
}

static WFI_RET
wfi_wps_start_enrollee(wfi_context_t *context, brcm_wpscli_nw_settings *wcred)
/* Start the WPS Enrollee protocol */
{	brcm_wpscli_status eiRet;
	uint8 ucWSEC = 2;
	char acPin[12];

	if (context->stBSS.capability & DOT11_CAP_ESS)
		ucWSEC |= DOT11_CAP_ESS;
	if (context->stBSS.capability & DOT11_CAP_PRIVACY)
		ucWSEC |= DOT11_CAP_PRIVACY;
	sprintf(acPin, "%08x", wpscli_ntohl(*(uint32 *)context->stWFI.pin));

	/* Prepare configuration */
	eiRet = wpscli_sta_construct_def_devinfo();
	if(eiRet != WPS_STATUS_SUCCESS) {
		printf("Failed to construct device informations. status=%s\n", eiRet);
		return WFI_RET_WPS_ERROR;
	}

	eiRet = brcm_wpscli_sta_start_wps((char *)context->stBSS.ssid.SSID,
		ucWSEC,
		context->stBSS.bssid.octet,
		1,
		&(context->stWFI.channel),
		BRCM_WPS_MODE_STA_ENR_JOIN_NW,
		BRCM_WPS_PWD_TYPE_PIN,
		acPin,
		120,
		wcred);
	if (eiRet == WPS_STATUS_SUCCESS)
	{
		DBGPRINT(("Enrollee success\n"));
		return WFI_RET_SUCCESS;
	}
	DBGPRINT(("AP SSID=%s", context->stBSS.ssid.SSID));
	DBGPRINT(("Enrollee fail %d\n", eiRet));
	return WFI_RET_WPS_ERROR;
}

/* Following code is for rejecting invite only. Would be moved to WPSCLI library later */
extern int wpscli_osl_init(char *bssid);
extern brcm_wpscli_status wpscli_sta_eap_send_data_down(char *dataBuffer, uint32 dataLen);


#define WPS_EAP_DATA_MAX_LENGTH         2048
#define WPS_EAP_READ_DATA_TIMEOUT       3

typedef struct eapol_hdr {
	uint8 version;
	uint8 type;
	uint16 len;
} EAPOL_HDR;

#define EAP_MSG_OFFSET 4

typedef struct eap_header {
	uint8 code;
	uint8 id;
	uint16 length;
	uint8 type;
} EAP_HDR;

char eapol_start_msg[] = {0x1, 0x1, 0x0, 0x0};
char eapol_nak_msg[]	= {0x1, 0x0, 0x0, 0x6, 0x2, 0x0, 0x0, 0x2, 0x3, 0x0};

#define EAP_ID_OFFSET	5

static int
is_eapol_identity_req(uint8 *buf, uint len)
{
	EAPOL_HDR *eapol_hdr = (EAPOL_HDR*)buf;
	EAP_HDR *eap_hdr = (EAP_HDR*)(buf + EAP_MSG_OFFSET);
	int i = 0;
	for (i = 0; i < len; i++)
	{
			DBGPRINT(("%08x ", buf[i]));
	}
	DBGPRINT(("len=%d \n", len));
	if (eapol_hdr->type != 0) {
		DBGPRINT(("hdr type=%d\n", eapol_hdr->type));
	}
	if (eap_hdr->code != 1) {
		DBGPRINT(("eap_hdr->code=%d\n", eap_hdr->code));
	}
	if (eap_hdr->type != 1) {
		DBGPRINT(("eap_hdr type=%d\n", eap_hdr->type));
	}
	return ((eapol_hdr->type == 0) && /* EAP Packet */
			(eap_hdr->code == 1) && /* EAP request */
			(eap_hdr->type == 1)); /* EAP Identity */
}


static WFI_RET
wfi_wps_reject_enrollee(wfi_context_t *context)
/* Reject the WFI Invite */
{
	int retry = 5;
	uint32 ret_val = WFI_RET_ERR_UNKNOWN;
	int len;
	uint8 buf[WPS_EAP_DATA_MAX_LENGTH];

	wpscli_wlan_disconnect();
	if (wpscli_wlan_connect((char *)context->stBSS.ssid.SSID,
		2,
		(char *)context->stBSS.bssid.octet,
		1,
		&(context->stWFI.channel)) != WPS_STATUS_SUCCESS)
	{
		DBGPRINT(("Join failed.\n"));
		ret_val = WFI_RET_ERR_UNKNOWN;
		goto done;
	}
	wpscli_osl_init(NULL);
	if (WPS_STATUS_SUCCESS != wpscli_pktdisp_open(context->stBSS.bssid.octet))
	{
		DBGPRINT(("Exiting as init failed\n"));
		wfi_wps_process_callback(NULL, WFI_STATUS_ERROR, NULL);
		ret_val = WFI_RET_ERR_UNKNOWN;
		goto done;
	}
		while (retry--)
		{
			len = WPS_EAP_DATA_MAX_LENGTH;
/*					
 *	Cindy: Since wpscli_pktdisp_open open RAW socket, we have to call 
 *		   wpscli_sta_eap_send_data_down instead of wpscli_pktdisp_send_packet 
 *		   to add eth header in.
 */
			ret_val = wpscli_sta_eap_send_data_down(eapol_start_msg,
				sizeof(eapol_start_msg));
			if (ret_val != WPS_STATUS_SUCCESS)
			{
				DBGPRINT(("wpscli_pktdisp_send_packet failed\n"));
			}
/*  
*  Cindy: thoe timeout option in new APIs is msec not sec.  
*/
			ret_val = wpscli_pktdisp_wait_for_packet((char *)buf,
				(uint32 *) &len,
				WPS_EAP_READ_DATA_TIMEOUT * 1000,
				FALSE);
			if (ret_val != WPS_STATUS_SUCCESS)
			{
				DBGPRINT(("wait for packet timeout\n"));
				continue;
			}
			if (is_eapol_identity_req(buf, len))
			{
					eapol_nak_msg[EAP_ID_OFFSET] = buf[EAP_ID_OFFSET];
					ret_val = wpscli_sta_eap_send_data_down(eapol_nak_msg,
						sizeof(eapol_nak_msg));
					if (ret_val == WPS_STATUS_SUCCESS)
					{
						ret_val =  WFI_RET_SUCCESS;
						DBGPRINT(("wpscli_pktdisp_send_packet done\n"));
						break;
					}
					else
					{
						DBGPRINT(("wpscli_pktdisp_send_packet failed\n"));
						continue;
					}

			}
			 else
			{
				DBGPRINT(("is_eapol_identity_req is not ture\n"));
				ret_val = WFI_RET_ERR_UNKNOWN;
				continue;
			}
		}
done:
/* This sleep prevents getting disassociated a bit too quickly */
usleep(300 * 1000);
wpscli_pktdisp_close();
wpscli_wlan_disconnect();
return ret_val;
}

/*  End WPS WFI reject functions  */

/* Creates the data portion of the WFI specific WPS vendor extension data
 * TLV and returns the length 
 */
static int
wfi_vendor_ext_data(wfi_param_t *wfi_handle, uint8 *data, char *pin)
{

	brcm_wfi_vndr_extn_data_t *wfi_data;
	int i;

	memcpy(data, BRCM_SMI_CODE, SMI_CODE_LEN);
	data += SMI_CODE_LEN;

	wfi_data = (brcm_wfi_vndr_extn_data_t *)(data);

	wfi_data->type = BRCM_VENDOR_EXTN_TYPE_WFI;
	wfi_data->version = WFI_VERSION;
	wfi_data->cap = 0;

	if (NULL == pin) {
		wfi_data->cap = WFI_CAP_SECURE_PIN;
	} else {
		for (i = 0; i < 4; i++) {
			wfi_data->pin[i] = (pin[2*i] - '0') << 4 | (pin[(2*i) + 1] - '0');
		}
	}

	memcpy(&wfi_data->mac_addr, wfi_handle->sta_mac_addr, ETHER_ADDR_LEN);

	if (wfi_handle->fname.name != NULL) {
		wfi_data->fname_len = wfi_handle->fname.len;
		strncpy((char *)wfi_data->fname,
			wfi_handle->fname.name,
			WFI_FNAME_LEN);
	}
	else
	{
		wfi_ether_ntoa((const struct ether_addr *)&wfi_data->mac_addr,
			(char *)wfi_data->fname);
		wfi_data->fname_len = strlen((char *)wfi_data->fname);
	}

	/* Return the length of the total Vendor Extension data */
	return (SMI_CODE_LEN + (sizeof(brcm_wfi_vndr_extn_data_t) - 1)
		+ wfi_data->fname_len); /* -1 to exclude data field */ 

}

/* Create WPS TLVs and return the next position in the IE buffer */
static uint8*
wfi_tlv_serialize(int type, int len, void* content, uint8* wfi_ie_curr_pos)
{
	wfi_htons_ptr((uint8 *)&type, wfi_ie_curr_pos);
	wfi_ie_curr_pos += 2;
	wfi_htons_ptr((uint8 *)&len, wfi_ie_curr_pos);
	wfi_ie_curr_pos += 2;

	switch (len)
	{
		case WPS_LEN_SHORT:
			wfi_htons_ptr(content, wfi_ie_curr_pos);
			break;
		case WPS_LEN_WORD:
			wfi_htonl_ptr(content, wfi_ie_curr_pos);
			break;
		default:
			memcpy(wfi_ie_curr_pos, content, len);
			break;
	}
	return (wfi_ie_curr_pos += len);
}

/* Creates WPS IE for the Probe Requests.
 * Ref : Section 7.2.4 of Wi-Fi Protected Setup Sepcification 1.0h. 
 *
 * When 'pin' is NULL, Secure PIN bit of the Capability field of 
 * WFI IE will be set. 
 */
static WFI_RET
wfi_create_wps_probereq_ie(wfi_param_t *wfi_handle)
{
	char *pin = (wfi_handle->pin_mode == WFI_PIN_PROMPT_USER) ? NULL : wfi_handle->pin;
	uint8 *cur_pos = wfi_handle->wfi_ie;
	uint8 wps_version = WPS_VERSION;
	uint8 wps_req_type = 0x0;
	uint16 wps_config_methods = 0x008C;
	uint8 wps_uuid[16] =
		{0x22, 0x21, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0xa, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	uint16 wps_primary_device_type_category = 1;
	uint32 wps_primary_device_type_oui = 0x0050F204;
	uint8 wps_primary_device_type_subcategory = 1;
	uint8 wps_rf_band = 1;	/* Hardcoded to 2.4 GHz. Need to be changed. */
	uint16 wps_assoc_state = 0x0;
	uint16 wps_config_error = 0x0;
	uint16 wps_device_passwd_id = 0x00;	/* default */
	uint16 temp;
	int wfi_vendor_extn_len;
	uint8* vendor_extn_len_field;

	/* Create the WPS Information Element Header */
	wps_ie_t * wps_ie = (wps_ie_t *)wfi_handle->wfi_ie;
	wps_ie->type = DOT11_MNG_PROPR_ID;
	/* wps_ie->len = Will be filled later */
	memcpy(wps_ie->OUI, WPS_OUI, 4);

	/* Now generate the data section of the WPS IEs  for probe request */
	cur_pos = wps_ie->data;

	cur_pos = wfi_tlv_serialize(WPS_TYPE_VERSION, WPS_LEN_BYTE, &wps_version, cur_pos);
	cur_pos = wfi_tlv_serialize(WPS_TYPE_REQUEST_TYPE, WPS_LEN_BYTE, &wps_req_type, cur_pos);
	cur_pos = wfi_tlv_serialize(WPS_TYPE_CONFIG_METHOD, WPS_LEN_SHORT,
		&wps_config_methods, cur_pos);
	cur_pos = wfi_tlv_serialize(WPS_TYPE_UUID, 16, wps_uuid, cur_pos);

	temp = WPS_TYPE_PRIMARY_DEVICE_TYPE; /* Type of Primary Device */
	wfi_htons_ptr((uint8 *)&temp, cur_pos);
	cur_pos += 2;
	temp = 8; /* Length of Primary Device Type */
	wfi_htons_ptr((uint8 *)&temp, cur_pos);
	cur_pos += 2;
	wfi_htons_ptr((uint8 *)&wps_primary_device_type_category, cur_pos);
	cur_pos += 2;
	wfi_htonl_ptr((uint8 *)&wps_primary_device_type_oui, cur_pos);
	cur_pos += 4;
	wfi_htons_ptr((uint8 *)&wps_primary_device_type_subcategory, cur_pos);
	cur_pos += 2;

	cur_pos = wfi_tlv_serialize(WPS_TYPE_RF_BANDS_TYPE,
		WPS_LEN_BYTE,
		&wps_rf_band,
		cur_pos);
	cur_pos = wfi_tlv_serialize(WPS_TYPE_ASSOC_STATE,
		WPS_LEN_SHORT,
		&wps_assoc_state,
		cur_pos);
	cur_pos = wfi_tlv_serialize(WPS_TYPE_CONFIG_ERROR,
		WPS_LEN_SHORT,
		&wps_config_error,
		cur_pos);
	cur_pos = wfi_tlv_serialize(WPS_TYPE_DEVICE_PASSWD_ID,
		WPS_LEN_SHORT,
		&wps_device_passwd_id,
		cur_pos);

	/* BEGIN : setting Vendor Extension */

	temp = WPS_TYPE_VENDOR_EXTENSION;
	wfi_htons_ptr((uint8 *)&temp, cur_pos);	cur_pos += 2;

	/* Note down the 'length' field, but do not set 'length' now */
	vendor_extn_len_field = cur_pos;
	cur_pos += 2;

	/* Data = Vendor Extn Code (3bytes) + Vendor Data (...) */
	wfi_vendor_extn_len = wfi_vendor_ext_data(wfi_handle, cur_pos, pin);
	/* Addtional fname */
	cur_pos += wfi_vendor_extn_len;
	/* Set the length of the vendor extn, now */
	wfi_htons_ptr((uint8 *)&wfi_vendor_extn_len, vendor_extn_len_field);
	/* END : setting Vendor Extension */

	/* Calculate the length of the IE and incorporate it */
	wps_ie->len = cur_pos - ((uint8 *)&wps_ie->OUI);

	return WFI_RET_SUCCESS;
}


/* Adds or Deletes an IE */
static WFI_RET
wfi_feature_ie(uint8 *ie, int len, int flag, int add)
{
	vndr_ie_setbuf_t *ie_setbuf;
	int buflen, iecount;
	int32 pktflag;
	WFI_RET ret = WFI_RET_SUCCESS;

	int i = 0;
	for (i = 0; i < len; i++)
	{
		DBGPRINT(("%02x ", *(ie+i)));
	}
	DBGPRINT(("\n"));

	if (len > VNDR_IE_MAX_LEN || len < VNDR_IE_MIN_LEN) {
		DBGPRINT(("wfi_feature_ie : Vendor IE len is incorrect.\n"));
		return WFI_RET_ERR_UNKNOWN;
	}

	buflen = sizeof(vndr_ie_setbuf_t) - sizeof(vndr_ie_t) + len;
	ie_setbuf = (vndr_ie_setbuf_t *) malloc(buflen);
	if (!ie_setbuf) {
		DBGPRINT(("wfi_feature_ie : malloc failed.\n"));
		return WFI_RET_ERR_UNKNOWN;
	}

	if (add)
		strcpy(ie_setbuf->cmd, "add");
	else
		strcpy(ie_setbuf->cmd, "del");

	iecount = htod32(1);
	memcpy(&ie_setbuf->vndr_ie_buffer.iecount, &iecount, sizeof(int));

	pktflag = htod32(flag);
	memcpy(&ie_setbuf->vndr_ie_buffer.vndr_ie_list[0].pktflag, &flag, sizeof(uint32));

	memcpy(&ie_setbuf->vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data, ie, len);
	ret = wfi_iovar_setbuf("vndr_ie", ie_setbuf, buflen);
	if (ret != 0)
		DBGPRINT(("vndr_ie not set properly\n"));
	else
		DBGPRINT(("vndr_ie set properly\n"));
	free(ie_setbuf);
	return ret;
}

/* Given a series of TLV, find the TLV that matches the 'key'
 * Note : 'type_len' argument specifies the length of 'T' and 'L' fields of the TLV.
 */
static uint8 *
wfi_parse_tlvs(uint8 *tlv_buf, int buflen, uint key, int type_len)
{
	uint8 *cp = tlv_buf;
	int remaining_len = buflen;

	/* find tagged parameter */
	while (remaining_len >= 2 * type_len) {
		uint tag;
		int len;

		if (type_len == WPS_LEN_SHORT) {
			tag = wfi_ntohs(cp);
			len = wfi_ntohs(cp + type_len);
		} else {
			tag = *cp;
			len = *(cp + type_len);
		}

		/* validate remaining totlen */
		if (tag == key)
		{
			if (remaining_len >= (len + 2 * type_len))
				return (cp);
			else
				return NULL;
		}

		cp += (len + 2 * type_len);
		remaining_len -= (len + 2 * type_len);
	}

	return NULL;
}

/* Find if the IE is a WPS IE, else move the input 
 * pointers to point to the next IE 
 */
static bool
is_wps_ie(uint8 **wpsie, uint8 **tlvs, int *tlvs_len)
{
	uint8 *ie = *wpsie;

	/* If the contents match the WPS_OUI and type=1 */
	if ((ie[1] >= 4) && !memcmp(&ie[2], WPS_OUI, 4)) {
		return TRUE;
	}

	/* point to the next ie */
	ie += ie[1] + 2;
	/* calculate the length of the rest of the buffer */
	*tlvs_len -= (int)(ie - *tlvs);
	/* update the pointer to the start of the buffer */
	*tlvs = ie;

	return FALSE;
}

/* Given a WPS TLV, finds out if the TLV is a valid WFI vendor extension */
static bool
is_wfi_vendor_extension(uint8 **wfi_vndr_extn, uint8 **tlvs, uint *tlvs_len)
{
	uint8 *ie = *wfi_vndr_extn;
	brcm_wfi_vndr_extn_data_t *wfi_data;
	int len = wfi_ntohs(*wfi_vndr_extn + 2);
	if (WPS_TYPE_VENDOR_EXTENSION == wfi_ntohs(*wfi_vndr_extn)) {
		/* Type(2) + Len(2) + SMI Code(3) + Vendor Data */
		if (len > (2 + 2 + 3 + sizeof(brcm_wfi_vndr_extn_data_t))) {
			if (!memcmp((*wfi_vndr_extn + 4), BRCM_SMI_CODE, 3)) {
				wfi_data = (brcm_wfi_vndr_extn_data_t *)(*wfi_vndr_extn + 7);
				if (wfi_data->type == BRCM_VENDOR_EXTN_TYPE_WFI)
					return TRUE;
			}
		}
	}

	/* point to the next ie */
	ie += len + 4;
	/* calculate the length of the rest of the buffer */
	*tlvs_len -= (int)(ie - *tlvs);
	/* update the pointer to the start of the buffer */
	*tlvs = ie;

	return FALSE;
}

/* Given a list of IEs, looks for WPS IE, and then 
 * for WFI Vendor Extension data 
 */
static uint8 *
find_wfi_vndr_extn_in_ies(uint8 *iebuf, int len)
{
	uint8 *wfi_ie = NULL;
	uint8 *wfi_ie2 = NULL;
	int len2 = 0;
	uint8 *ie_buf = iebuf;
	int* ie_len = &len;
	uint8 *cur_wps_ie;


	/* 1. Find WPS IE */
	while ((*ie_len > 0) &&
		(wfi_ie = wfi_parse_tlvs(ie_buf, *ie_len, DOT11_MNG_PROPR_ID, WPS_LEN_BYTE)))
	{

		/* 1a. Check WPS OUI to confirm */
		if (!is_wps_ie(&wfi_ie, &ie_buf, ie_len))
			continue;

		cur_wps_ie = wfi_ie;

		/* 2. Parse WPS TLVs for Vendor Extension */
		/* Skip the Type, Len, WPS OUI fields before data section */

		/* Point to the beginning of data element section */
		wfi_ie2 = wfi_ie + 6;

		/* The wfi_ie[1] already excludes T and L fields. 
		 * So subtract length of WPS OUI to point to vendor data 
		 */
		len2 = wfi_ie[1] - 4;
		while ((wfi_ie = wfi_parse_tlvs(wfi_ie2,
			len2,
			WPS_TYPE_VENDOR_EXTENSION,
			WPS_LEN_SHORT)))
		{
			if (!is_wfi_vendor_extension(&wfi_ie, &wfi_ie2, (uint *)&len2))
				continue;
			else
				return wfi_ie;
		}

		/* Remaining IE len = Last reported remaining IE length - 
		 *	(Distance of current WPS IE from last reported IE) - 
		 *	Length of WPS IE 
		 */

		*ie_len = *ie_len - (cur_wps_ie - ie_buf) - (cur_wps_ie[1] + 2);
		ie_buf = cur_wps_ie + (cur_wps_ie[1]+2); /* Point to the next IE */
	}
	return NULL;	/* will be NULL, if not found */
}

/* Convert the WFI vendor data extension WPS TLV to wfi_contenxt_t */
static WFI_RET
wfi_ie_to_context(
	wl_bss_info_t *bss_info,
	brcm_wfi_vndr_extn_data_t* wfi_data,
	wfi_context_t *wfi_ctxt,
	uint8 *sta_mac_addr)
{
	WFI_RET ret = WFI_RET_ERR_UNKNOWN;


	if (wfi_data->type != BRCM_VENDOR_EXTN_TYPE_WFI || wfi_data->version != WFI_VERSION)
		return ret;

	/* Check if the mac addr matches our own */
	if (memcmp(wfi_data->mac_addr, sta_mac_addr, ETHER_ADDR_LEN))
		return ret;

	/* Now populate the WFI context	*/
	wfi_ctxt->stBSS.ssid.SSID_len  = (bss_info->SSID_len > 32 ? 32 : bss_info->SSID_len);
	memcpy(wfi_ctxt->stBSS.ssid.SSID, bss_info->SSID, wfi_ctxt->stBSS.ssid.SSID_len);
	memcpy(wfi_ctxt->stBSS.bssid.octet, bss_info->BSSID.octet, ETHER_ADDR_LEN);

	wfi_ctxt->stWFI.fname.len = wfi_data->fname_len;
	memcpy(wfi_ctxt->stWFI.fname.name, wfi_data->fname, wfi_data->fname_len);
	wfi_ctxt->stWFI.wfi_cap = wfi_data->cap;
	memcpy(wfi_ctxt->stWFI.pin, wfi_data->pin, 4);

	ret = WFI_RET_SUCCESS;

	return ret;
}

static int
is_sta_associated()
{
	uint8 bssid[ETHER_ADDR_LEN];
	if (0 == wfi_get(WLC_GET_BSSID, &bssid, ETHER_ADDR_LEN))
		return TRUE;
	else
		return FALSE;
}


static WFI_RET
wfi_custom_scan()
{
	wl_scan_params_t *params;
	WFI_RET ret;
	/* int i = 0; */
	int params_size = WL_SCAN_PARAMS_FIXED_SIZE + WL_NUMCHANNELS * sizeof(uint16);

	params = (wl_scan_params_t*)malloc(params_size);
	if (params == NULL)
		return	WFI_RET_ERR_UNKNOWN;

	memset(params, 0, params_size);
	params->bss_type = DOT11_BSSTYPE_ANY;
	memcpy(&params->bssid, &ether_bcast, ETHER_ADDR_LEN);
	params->scan_type = DOT11_SCANTYPE_ACTIVE;
	params->nprobes = htod32(-1);
	params->active_time = htod32(-1);
	params->passive_time = htod32(-1);
	params->home_time = htod32(-1);
	params->channel_num = 0;

	ret = wfi_set(WLC_SCAN, params, params_size);

	free(params);
	return ret;
}

static  wl_scan_results_t *
wfi_scan_results()
{
	wl_scan_results_t *scan_res = (wl_scan_results_t *)malloc(BUFFER_MAXLEN);
	if (!scan_res) {
		DBGPRINT(("wfi_scan_results : malloc failed."));
		return NULL;
	}
	scan_res->buflen = htod32(BUFFER_MAXLEN);
	if (WFI_RET_SUCCESS == wfi_get(WLC_SCAN_RESULTS, scan_res, BUFFER_MAXLEN))
		return scan_res;
	else {
		free(scan_res);
		return NULL;
	}
}

/* SCAN_DELAY : Delay between scan request and fetching scan results */ 
#define SCAN_DELAY 5000
/* Refresh WFI IE in driver once in a while, so that even if the driver
 * is re-downloadeded after a sleep/wake cycle our WFI IE is re-added 
 */
#define WFI_IE_REFRESH_INTERVAL	4

/* wfi_evt_sleep : 
 * Sleeps for duration of msec
 * Checks for g_evt_thread_done at every one sec interval, if it is set 
 * the function returns.
 * Returns the difference between intended and actual interval elapsed.
 * (i.e zero if msec are elapse without g_evt_thread_done getting set)
 */
static unsigned int wfi_evt_thread_sleep(wfi_param_t *wfi_handle, unsigned int interval)
{
	WFI_EVENT evt = WFI_EVENT_NONE;
	const unsigned int sec_num = 1000;

	while (interval >= sec_num && !g_evt_thread_done)
	{
		if (wfi_handle->wfi_invite_evt_hndlr != NULL)
		{
			wfi_handle->wfi_invite_evt_hndlr(&evt, NULL);
			switch (evt)
			{
			case WFI_EVENT_STOP:
				g_active = FALSE;
				break;
			case WFI_EVENT_START:
				g_active = TRUE;
				break;
			case WFI_EVENT_QUIT:
				g_evt_thread_done = TRUE;
				return 1;
			default:
				break;
			}
		}
		usleep(sec_num * 1000);
		interval -= sec_num;
	}
	if (interval > 0 && !g_evt_thread_done) {
		usleep(interval * 1000);
		interval = 0;
	}

	return interval;
}

/* ------------ WFI PERIODIC SCAN THREAD -------------------- */
/* g_evt_thread_hndlr : Handle to the thread that does
 * periodic WFI scan for WFI IEs.
 */

static void* wfi_evt_thread(void* param)
{
	wfi_param_t *wfi_handle = (wfi_param_t*)param;
	WFI_RET ret;

	DBGPRINT(("g_evt_thread_done=%d\n", g_evt_thread_done));
	while (!g_evt_thread_done) {
		if (wfi_evt_thread_sleep(wfi_handle, g_interval - SCAN_DELAY) > 0)
			break;

		if (!g_active) {
			DBGPRINT(("wfi_evt_thread : Inactive.\n"));
			continue;	/* Most probably a WPS is underway, so skip scan */
		}

		ret = wfi_scan(wfi_handle);
		if (ret == WFI_RET_ABORT)
			break;
		else if (ret != WFI_RET_SUCCESS)
			continue;
		DBGPRINT(("wfi_evt_thread : Active. Scanning.\n"));

		/* Give 5 seconds for the scan to complete */
		if (wfi_evt_thread_sleep(wfi_handle, SCAN_DELAY) > 0)
			break;

		if (wfi_parse_scan_results(wfi_handle) != WFI_RET_SUCCESS)
			continue;
	}

	pthread_mutex_lock(&g_evt_thread_completed_mutex);
	pthread_cond_signal(&g_evt_thread_completed);
	pthread_mutex_unlock(&g_evt_thread_completed_mutex);
	return NULL;
}


static WFI_RET
wfi_event_monitor_start(wfi_param_t *wfi_handle)
{

	if (wfi_handle->sync_mode == FALSE)
	{
		g_evt_thread_done = FALSE;
		g_active = TRUE;
		pthread_mutex_init(&g_evt_thread_completed_mutex, NULL);
		pthread_cond_init(&g_evt_thread_completed, NULL);

		if (0 == pthread_create(&g_evt_thread_hndlr, NULL, wfi_evt_thread, wfi_handle))
			return WFI_RET_SUCCESS;
		else
			return WFI_RET_ERR_UNKNOWN;
	}
	else
		return WFI_RET_SUCCESS;
}

static WFI_RET
wfi_event_monitor_stop()
{
	g_evt_thread_done = TRUE;
	g_active = FALSE;

	struct timespec ts;
	int ret_val;

	if (pthread_equal(pthread_self(), g_evt_thread_hndlr))
		/* The caller's thread context itself is the monitor thread.
		 * Hence we should not wait for thread termination.
		 * The end of current thread execution itself leads to stopping
		 * event_monitor thread.
		 */
		return WFI_RET_SUCCESS;
	else {
		pthread_mutex_lock(&g_evt_thread_completed_mutex);
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += 10;
		ret_val = pthread_cond_timedwait(&g_evt_thread_completed,
			&g_evt_thread_completed_mutex,
			&ts);
		pthread_mutex_unlock(&g_evt_thread_completed_mutex);
		if (ret_val == 0)
			return WFI_RET_SUCCESS;
		else
		{
			DBGPRINT(("wfi_event_monitor_stop :\n"));
			DBGPRINT(("wfi_wps_process_callback waiting thread"));
			DBGPRINT(("did not stop within 10 seconds.\n"));
			DBGPRINT(("Terminating the thread."));
			pthread_kill(g_evt_thread_hndlr, SIGTERM);
			return WFI_RET_ERR_UNKNOWN;
		}
	}
}


/* --------- End of WFI PERIODIC SCAN THREAD implemenation ------------ */

/* ------------------- WFI APIs -------------------------------------- */

wfi_param_t * wfi_init(char * name, unsigned int pin_mode, uint8 sync_mode)
{
	wfi_param_t *wfi_handle;
	wfi_handle = (wfi_param_t*)malloc(sizeof(wfi_param_t));
	if (wfi_handle == NULL)
	{
		DBGPRINT(("Create WFI handle failes \n"));
		return NULL;
	}

	memset(wfi_handle, 0, sizeof(wfi_param_t));
	wfi_handle->pin_mode = pin_mode;
	wfi_handle->sync_mode = sync_mode;
	strncpy((char *)wfi_handle->fname.name, name, WFI_FNAME_LEN);
	wfi_handle->fname.len = strlen(name);

	if (WFI_PIN_AUTO_GENERATE == pin_mode) {
		wfi_wps_generate_pin(wfi_handle->pin, sizeof(wfi_handle->pin));
		DBGPRINT(("%s, len=%d\n", wfi_handle->pin, sizeof(wfi_handle->pin)));
	}

	if (wfi_iovar_getbuf("cur_etheraddr", &(wfi_handle->sta_mac_addr), ETHER_ADDR_LEN) != 0)
	{
		DBGPRINT(("wfi_init : cur_etheraddr failed. Wi-Fi may be off.\n"));
		free(wfi_handle);
		wfi_handle = NULL;
		return wfi_handle;
	}
	wfi_create_wps_probereq_ie(wfi_handle);

	if (sync_mode == FALSE)
	{
		if (wfi_event_monitor_start(wfi_handle) != WFI_RET_SUCCESS)
		{
			free(wfi_handle);
			wfi_handle = NULL;
		}
	}
	return wfi_handle;

}

WFI_RET
wfi_deinit(wfi_param_t *wfi_handle)
{
	if (wfi_handle->scan_stop == 0)
	{
		if (wfi_stop_scan(wfi_handle) != WFI_RET_SUCCESS)
		{
			free(wfi_handle);
			return WFI_RET_ERROR;
		}
	}

	if (wfi_handle->sync_mode == FALSE)
	{
		if (WFI_RET_SUCCESS != wfi_event_monitor_stop())
		{
			DBGPRINT(("wfi_deinit : failed to stop wfi_event_monitor.\n"));
		}
	}

	free(wfi_handle);
	return WFI_RET_SUCCESS;
}

WFI_RET
wfi_accept(wfi_param_t *wfi_handle, wfi_context_t *wfi_context)
{
	/* by default, assume wep is ON */
	char ssid[MAX_SSID_LEN + 1];
	bool ret;
	uint8 if_name[WPS_EAP_DATA_MAX_LENGTH];

	g_active = FALSE; /* Stop the WFI periodic scan. We will be starting WPS shortly */

	if (wfi_context->stWFI.wfi_cap & WFI_CAP_HOTSPOT)
	{
		strcpy(wfi_handle->wps_cred.ssid, "");
		strcpy(wfi_handle->wps_cred.nwKey, "NONE");
		wfi_handle->wps_cred.authType = BRCM_WPS_AUTHTYPE_OPEN;
		wfi_handle->wps_cred.encrType = BRCM_WPS_ENCRTYPE_NONE;
		wfi_handle->wps_cred.wepIndex = 0;
		memcpy(wfi_handle->wps_cred.ssid,
			wfi_context->stBSS.ssid.SSID,
			wfi_context->stBSS.ssid.SSID_len);
		DBGPRINT(("Cindy: Hotspot mode\n"));
		g_active = TRUE; /* Start the WFI periodic scan. */
		return WFI_RET_SUCCESS;
	}

	DBGPRINT(("Get ifname and calling wps_open\n"));

	if (WFI_RET_SUCCESS != wfi_get_interface_name((char *)if_name))
	{
			DBGPRINT(("Failed to discover Wi-Fi interface.\n"));
			return WFI_RET_WPS_ERROR;
	}

//	status = brcm_wpscli_open(WL_ADAPTER_IF_NAME, BRCM_WPSCLI_ROLE_STA, NULL, NULL);
	if (brcm_wpscli_open((const char*)if_name,
		BRCM_WPSCLI_ROLE_STA,
		NULL,
		wfi_wps_process_callback) != WPS_STATUS_SUCCESS)
	{
		DBGPRINT(("Cindy: wpscli Open Failed \n"));
		g_active = TRUE; /* Start the WFI periodic scan. */
		return WFI_RET_WPS_ERROR;
	}

	strncpy(ssid, (char *)wfi_context->stBSS.ssid.SSID,
		wfi_context->stBSS.ssid.SSID_len);
	ssid[wfi_context->stBSS.ssid.SSID_len] = '\0';

	DBGPRINT(("Starting WPS\n"));
	DBGPRINT(("Pin = %s \n", wfi_context->stWFI.pin));
	DBGPRINT(("SSID = %s, SSID_LEN=%d\n", ssid, strlen(ssid)));
	DBGPRINT(("BSSID = %02x:%02x:%02x:%02x:%02x:%02x\n",
		wfi_context->stBSS.bssid.octet[0],
		wfi_context->stBSS.bssid.octet[1],
		wfi_context->stBSS.bssid.octet[2],
		wfi_context->stBSS.bssid.octet[3],
		wfi_context->stBSS.bssid.octet[4],
		wfi_context->stBSS.bssid.octet[5]));

	DBGPRINT(("SSID = %s, SSID_LEN=%d\n",
		wfi_context->stBSS.ssid.SSID,
		strlen(ssid)));
	DBGPRINT(("BSSID = %02x:%02x:%02x:%02x:%02x:%02x\n",
		wfi_context->stBSS.bssid.octet[0],
		wfi_context->stBSS.bssid.octet[1],
		wfi_context->stBSS.bssid.octet[2],
		wfi_context->stBSS.bssid.octet[3],
		wfi_context->stBSS.bssid.octet[4],
		wfi_context->stBSS.bssid.octet[5]));

	memset(&(wfi_handle->wps_cred), 0, sizeof(brcm_wpscli_nw_settings));

	ret = wfi_wps_start_enrollee(wfi_context, &(wfi_handle->wps_cred));
	DBGPRINT(("wps_cred.ssid=%s\n", wfi_handle->wps_cred.ssid));
	DBGPRINT(("wps_cred.nwKey=%s\n", wfi_handle->wps_cred.nwKey));
	DBGPRINT(("wps_cred.encrType=%d\n", wfi_handle->wps_cred.encrType));
	DBGPRINT(("wps_cred.wepIndex=%d\n", wfi_handle->wps_cred.wepIndex));

	if (ret == WPS_STATUS_SUCCESS)
	{
		DBGPRINT(("Calling wps_get_AP_infoEx... Succeeded\n"));
		brcm_wpscli_sta_rem_wps_ie();
		brcm_wpscli_close(); /* WPS failed. Close the library */

		g_active = TRUE; /* Start the WFI periodic scan. */
		return WFI_RET_SUCCESS;
	}
	else
	{
		DBGPRINT(("Calling wps_get_AP_infoEx.... Failed\n"));
		brcm_wpscli_abort();
		g_active = TRUE; /* Start the WFI periodic scan. */
		return WFI_RET_WPS_ERROR;
	}

	DBGPRINT(("WFI accept succes\n"));
}


WFI_RET
wfi_reject(wfi_param_t *wfi_handle, wfi_context_t *context)
{
	uint32 ret_val = WFI_RET_ERR_UNKNOWN;
	uint8 buf[WPS_EAP_DATA_MAX_LENGTH];

	g_active = FALSE; /* Stop WFI periodic scan. */

	if (context->stWFI.wfi_cap & WFI_CAP_HOTSPOT)
	{
		if (wfi_set (WLC_SCB_DEAUTHENTICATE,
			context->stBSS.bssid.octet,
			sizeof(ETHER_ADDR_LEN))
			!= WFI_RET_SUCCESS)
		{
			DBGPRINT(("Failed to send deauth."));
			ret_val = WFI_RET_WPS_ERROR;
		}
	}
	else
	{
		if (WFI_RET_SUCCESS != wfi_get_interface_name((char *)buf))
		{
			DBGPRINT(("Failed to retrieve interface name\n"));
			ret_val = WFI_RET_ERR_UNKNOWN;
		}

		if (brcm_wpscli_open((const char *)buf,
			BRCM_WPSCLI_ROLE_STA,
			NULL,
			wfi_wps_process_callback)
			!= WPS_STATUS_SUCCESS)
		{
			DBGPRINT(("Cindy: wpscli Open Failed \n"));
			g_active = TRUE; /* Start the WFI periodic scan. */
			ret_val = WFI_RET_WPS_ERROR;
		}
		ret_val = wfi_wps_reject_enrollee(context);
	}
	brcm_wpscli_close(); /* Close the library */
	g_active = TRUE; /* Restart WFI periodic scan. */
	return ret_val;
}

WFI_RET
wfi_scan(wfi_param_t *wfi_handle)
{

	wfi_feature_ie(wfi_handle->wfi_ie, wfi_handle->wfi_ie[1] + 2, VNDR_IE_PRBREQ_FLAG, FALSE);
	wfi_handle->scan_stop = 1;
	if (is_sta_associated())
	{
		DBGPRINT(("sta has been associated\n"));
		return WFI_RET_EXIST;
	}
	else
	{
		wfi_feature_ie(wfi_handle->wfi_ie,
			wfi_handle->wfi_ie[1] + 2,
			VNDR_IE_PRBREQ_FLAG, TRUE);
		wfi_handle->scan_stop = 0;
	}


	if (WFI_RET_SUCCESS != wfi_custom_scan()) {
		DBGPRINT(("wfi_evt_thread : Active, but scan failed.\n"));
		return WFI_RET_ERROR;
	}
	DBGPRINT(("wfi_scan: Active. Scanning.\n"));
	return WFI_RET_SUCCESS;
}

WFI_RET wfi_parse_scan_results(wfi_param_t *wfi_handle)
{
	wl_scan_results_t * scan_list;
	int i;
	uint8 *vendor_extn;
	brcm_wfi_vndr_extn_data_t *wfi_ie_data;

	if ((scan_list = wfi_scan_results()) != NULL) {
		wl_bss_info_t *bi = scan_list->bss_info;
		for (i = 0; i < (int) scan_list->count; i++,
			bi = (wl_bss_info_t*)((int8*)bi + dtoh32(bi->length)))
		{
			uint8 *parse;
			uint parse_len;
			wfi_context_t wfi_context;

			memset(&wfi_context, 0, sizeof(wfi_context_t));

			if (dtoh32(bi->version) == LEGACY_WL_BSS_INFO_VERSION) {
				parse_len = ((wl_bss_info_t *)bi)->ie_length;
				parse = (uint8 *)((uint8 *)bi + sizeof(wl_bss_info_t));
			} else {
				parse_len = bi->ie_length;
				parse = (uint8 *)((uint8 *)bi + dtoh16(bi->ie_offset));
			}
			if (bi->n_cap)
				wfi_context.stWFI.channel = bi->ctl_ch;
			else
				wfi_context.stWFI.channel =
				CHSPEC_CHANNEL(dtohchanspec(bi->chanspec));
			vendor_extn = find_wfi_vndr_extn_in_ies(parse, parse_len);
			if (NULL != vendor_extn)
			{
			   /* 7 = Vendor data offset from beginning of data element. 
			      Make this a macro 
				*/
				wfi_ie_data = (brcm_wfi_vndr_extn_data_t *)(vendor_extn + 7);
				if (WFI_RET_SUCCESS == wfi_ie_to_context(bi,
					wfi_ie_data,
					&wfi_context,
					wfi_handle->sta_mac_addr))
				{
					if (wfi_handle->wfi_invite_rcvd_hndlr)
						wfi_handle->wfi_invite_rcvd_hndlr(&wfi_context, wfi_handle->param);
				}
			}

		}
		free(scan_list);
	}
        
	return WFI_RET_SUCCESS;
}

WFI_RET
wfi_stop_scan(wfi_param_t *wfi_handle)
{
	WFI_RET ret = WFI_RET_SUCCESS;

	if (wfi_handle->scan_stop == 0)
	{
		ret = wfi_feature_ie(wfi_handle->wfi_ie,
			wfi_handle->wfi_ie[1] + 2,
			VNDR_IE_PRBREQ_FLAG, FALSE);
		if (ret == WFI_RET_SUCCESS)
			wfi_handle->scan_stop = 1;
	}
	return ret;
}


/* ---------------------- End of WFI APIs ---------------------------------------- */
