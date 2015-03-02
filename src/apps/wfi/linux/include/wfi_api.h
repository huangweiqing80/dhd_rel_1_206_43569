/* 
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wfi_api.h,v 1.12 2011-01-07 05:46:14 $
 */


#ifndef _WFI_API_H_
#define _WFI_API_H_

#ifdef __cplusplus
extern "C" {
#endif


/* Broadcom WPSCLI API */
#include "wpscli_api.h"


#if !defined(ETHER_ADDR_LEN)
#define ETHER_ADDR_LEN		6
#endif

/*
 *  WFI/WPS Supported Versions:
 */
#define WFI_VERSION		0x1
#define WPS_VERSION 	0x10

#define MAX_SSID_LEN 32
#define MAX_IE_LEN 256

#define BUFFER_MAXLEN	(127 * 1024 )


typedef struct bssid_s
{	uint8 octet[ETHER_ADDR_LEN];
} bssid_t;

typedef struct ssid_s
{	uint8		SSID_len;
	uint8		SSID[MAX_SSID_LEN+1];
} ssid_t;

#define WFI_FNAME_LEN				32
typedef struct wfi_fname_s {
	uint8 len;	/* length of friendly name */
	uint8 name[WFI_FNAME_LEN+1];	/* friendly name */
} wfi_fname_t;

/* Basic Service Set info */
typedef struct wfi_bss_info_s
{	ssid_t ssid;
	bssid_t bssid;
	uint16 capability;
}	WFI_BSS_INFO;

/* WFI info */
typedef struct wfi_info_s
{	wfi_fname_t fname;
	uint8 channel;
	uint8 wfi_cap;
	uint8 pin[4];
}	WFI_VE_INFO;

typedef struct wfi_context_s
{
	WFI_BSS_INFO stBSS;
	WFI_VE_INFO stWFI;
}	wfi_context_t;

typedef enum {
	WFI_PIN_AUTO_GENERATE = 0,
	WFI_PIN_PRECONFIGURED,
	WFI_PIN_PROMPT_USER
}	WFI_PIN_MODE;


/*
 *  WFI API Definitions and Functions.
 *  The following functions are used together with Vendor Specific DRV
 *  and WPS modules to build up wfi_api.lib, which will be called by
 *  WFI client Applications.
 */
typedef enum eWFI_RET	/* Return codes for API, DRV and WPS calls */
{
	WFI_RET_SUCCESS = 0,
	WFI_RET_EXIST,
	WFI_RET_ERROR,
	WFI_RET_WPS_ERROR,	/* Error returned by wps functions */
	WFI_RET_ERR_UNKNOWN,
	WFI_RET_OPERATION_NOT_SUPPORTED,
	WFI_RET_NO_INTERFACE,
	WFI_RET_ABORT
}	WFI_RET;

typedef enum {
	/* WFI Event */
	WFI_EVENT_NONE = 0,
	WFI_EVENT_START,
	WFI_EVENT_STOP,
	WFI_EVENT_QUIT,
	WFI_EVENT_TIMER,
	WFI_EVENT_PRIORITY
} WFI_EVENT;


typedef enum {
	/* WFI APP status */
	WFI_STATUS_SUCCESS = 0,
	WFI_STATUS_ERROR,
	WFI_STATUS_CANCELED,
	WFI_STATUS_WARNING_TIMEOUT,
	WFI_STATUS_WARNING_WPS_PROTOCOL_FAILED,
	WFI_STATUS_WARNING_NOT_INITIALIZED,
	WFI_STATUS_DISABLING_WIFI_MANAGEMENT,
	WFI_STATUS_INIT,
	WFI_STATUS_SCANNING,
	WFI_STATUS_SCANNING_OVER,
	WFI_STATUS_ASSOCIATING,
	WFI_STATUS_ASSOCIATED,
	WFI_STATUS_STARTING_WPS_EXCHANGE,
	WFI_STATUS_SENDING_WPS_MESSAGE,
	WFI_STATUS_WAITING_WPS_RESPONSE,
	WFI_STATUS_GOT_WPS_RESPONSE,
	WFI_STATUS_DISCONNECTING,
	WFI_STATUS_ENABLING_WIFI_MANAGEMENT,
	WFI_STATUS_CREATING_PROFILE,
	/* WFI specific status */
	WFI_STATUS_INTIALIZED,
	WFI_STATUS_ACTIVATED,
	WFI_STATUS_WFI_DEACTIVATED,
	WFI_STATUS_IDLE = 0xffff
} WFI_STATUS;


typedef struct {
	void (*wfi_invite_rcvd_hndlr)(wfi_context_t *, void *);
	/* Callback to be called when WFI invite is received */

	void *param; 
	/* reserved for APP passing data */

	WFI_PIN_MODE pin_mode;
	/* If you want to use a fixed pin, set to WFI_PIN_PRECONFIGURED 
	 *  The pin will be sent over the air so WFI_PIN_AUTO_GENERATE is recommended.
	 */
	char pin[9];
	/* 8 digit PIN string. Only digits are allowed. 
	 * Used when pin_mode is set to WFI_PIN_PRECONFIGURED
	 */			

	wfi_fname_t fname;

	brcm_wpscli_nw_settings wps_cred;
	/*
	 *  The structure of WPS credentials retrieved by WPS.
	 */
	uint8 sta_mac_addr[ETHER_ADDR_LEN];
	/*
	 *   Indicate the mac address of STA
	 */
	uint8 wfi_ie[MAX_IE_LEN];
	/*
	 *   WFI IE for WFI probe request.
	 */
	unsigned int scan_stop;
	/*
	 *  Flag to determine scan process depending on wfi ie created or cleared.
	 */

	uint8 sync_mode;
	/*
	 *	API mode: 
	 *	TURE: the API will be called synchronous. Provide functionality APIs to application.
	 *	FALSE: the wfi_evt_thread is on and application takes interaction 
	 *         with APIs by callback functions.
	 */

	/* Following items would not be used if sync_mode == TRUE */
	void (*wfi_status_callback)(WFI_STATUS, void *);
	/* Handler that receives regular status updates from the API library */
	void (*wfi_rcv_wps_credentials)(brcm_wpscli_nw_settings *);
	/* Callback to be called when WPS credentials are successfully received */
	void (*wfi_invite_evt_hndlr)(unsigned int *, void *);
	/* Callback to be called when application wants to interaction with WFI thread */

	} wfi_param_t, *p_wfi_param_t;


/* ---------------- WFI APIS ------------------ */
/*
 * Function : wfi_init
 * Parameters :
	    fname: friend name of STA. e.g.: pass device name.
	           Set to NULL to select default friendly name.
		pin_mode: PIN MODE.  Default: WFI_PIN_AUTO_GENERATE
		sync_mode: API mode. 
				Refer : wfi_param_t
 * Return values :  
		On success, the WFI handler is returned point to data between APP and API.
		On Failure, NULL is returned.
 * Description :
		This should be the first call to the library. This sets up wfi 
		library and initilizes all other dependecies such as WPS.
 */
wfi_param_t * wfi_init(char * fname, unsigned int pin_mode, uint8 sync_mode);

/*
 * Function : wfi_accept

 * Parameters : 
		handle: WFI API handle.
 * Return values :
		On success, WFI_RET_SUCCESS is returned. On Failure appropriate
		return value from WFI_RET enumeration is returned.
 * Description :
		This initiates the interactions with the specified AP to retrieve
		the credentials using WPS protocol.
		Immediately after sending this frame, the AP is expected to be in 
		PBC mode of operation, so that the STA can join and retrieve credentials 
		using WPS protocol.
 */
WFI_RET wfi_accept(wfi_param_t *handle, wfi_context_t *wfi_context);

/*
 * Function : wfi_reject
 * Parameters : 
		handle: WFI API handle. 
 * Return values :
		On success, WFI_RET_SUCCESS is returned. On Failure appropriate
		return value from WFI_RET enumeration is returned.
 * Description :
		This causes the STA to join to the AP, send an EAPOL START. When 
		the AP sends back an EAPOL IDENTITY, the STA will respond with a
		NACK EAP. This indicates to the AP that the client has rejected the
		Wi-Fi Invite.
 */
WFI_RET wfi_reject(wfi_param_t *handle, wfi_context_t *wfi_context);


/*
 * Function : wfi_stop_scan
 * Parameters :
		handle: WFI API handle. 
 * Return values :
		On success, WFI_RET
_SUCCESS is returned. On Failure appropriate
		return value from WFI_RET enumeration is returned.
 * Description :
		This API should be used to stop an on-going WPS exchange. This
		call is asynchronous and returns immediately. When the WPS
		handshake is completely stopped, wfi_status_callback() will 
		be called with WFI_STATUS_WPS_STOPPED.
 */

WFI_RET wfi_stop_scan(wfi_param_t *handle);


/*
 * Function : wfi_deinit
 * Parameters :
		handle: WFI API handle. 
 * Return values :
		On success, WFI_RET_SUCCESS is returned. On Failure appropriate
		return value from WFI_RET enumeration is returned.
 * Description :
		Use this API to de-initilize the WFI library.
 */
WFI_RET wfi_deinit(wfi_param_t *handle);

/*
 * Function : wfi_scan
 * Parameters :
		handle: WFI API handle. 
 * Return values :
		On success, WFI_RET
_SUCCESS is returned. On Failure appropriate
		return value from WFI_RET enumeration is returned.
 * Description :
		This API is used to start a scan process by sending a WFI IE probe request.
 */
WFI_RET wfi_scan(wfi_param_t *handle);

/*
 * Function : wfi_parse_scan_results
 * Parameters :
		handle: WFI API handle. 
 * Return values :
		On success, WFI_RET
_SUCCESS is returned. On Failure appropriate
		return value from WFI_RET enumeration is returned.
 * Description :
	This API is used to parse scan results and get WFI invite info.
	The WIFI invite AP information is passed to APP by callback function wfi_invite_rcvd_hndlr.
	This API should be called after wfi_scan()
 */
WFI_RET wfi_parse_scan_results(wfi_param_t *handle);

#ifdef TARGETENV_android
WFI_RET EnableSupplicantEvents(int bEnable);
int    WFIIsActive();
void   WFISetActive(int active);
#endif

#ifdef __cplusplus
}
#endif

#endif /* _WFI_API_H_ */
