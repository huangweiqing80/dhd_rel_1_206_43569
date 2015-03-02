/* 
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wps_sdk.h 343243 2012-07-06 03:55:48Z $
 */

#ifndef _WPS_SDK_H_
#define _WPS_SDK_H_

#ifdef __cplusplus
extern "C" {
#endif

/* Definition of Wi-Fi security encryption mask type */
#define WPS_ENCRYPT_NONE	0x0001
#define WPS_ENCRYPT_WEP		0x0002
#define WPS_ENCRYPT_TKIP	0x0004
#define WPS_ENCRYPT_AES		0x0008

#undef SIZE_20_BYTES
#undef SIZE_32_BYTES
#undef SIZE_64_BYTES
#define SIZE_20_BYTES	20
#define SIZE_32_BYTES	32
#define SIZE_64_BYTES	64

#define ENCRYPT_NONE	1
#define ENCRYPT_WEP		2
#define ENCRYPT_TKIP	4
#define ENCRYPT_AES		8

#undef WPS_SCSTATE_UNKNOWN
#undef WPS_SCSTATE_UNCONFIGURED
#undef WPS_SCSTATE_CONFIGURED

/* Simple Config state */
enum eWPS_CONIG_STATE {
	WPS_SCSTATE_UNKNOWN	= 0,
	WPS_SCSTATE_UNCONFIGURED,
	WPS_SCSTATE_CONFIGURED
};

/* STA_ENR_JOIN_NW_PIN and STA_REG_CONFIG_NW require PIN as well */
enum eWPS_MODE {
	STA_ENR_JOIN_NW_PBC = 0,
	STA_ENR_JOIN_NW_PIN,
	STA_REG_JOIN_NW,
	STA_REG_CONFIG_NW
};

typedef struct _wps_credentials
{
	char	ssid[SIZE_32_BYTES+1];
	char	keyMgmt[SIZE_20_BYTES+1];
	char	nwKey[SIZE_64_BYTES+1];
	uint32	encrType;
	uint16	wepIndex;
	bool	nwKeyShareable;	
} wps_credentials;

/*
 WPS status values provided to the callback wps_join_callback (see below)
*/
enum {
	WPS_STATUS_SUCCESS = 0,
	WPS_STATUS_ERROR,
	WPS_STATUS_CANCELED,
	WPS_STATUS_WARNING_TIMEOUT,
	WPS_STATUS_WARNING_WPS_PROTOCOL_FAILED,
	WPS_STATUS_WARNING_NOT_INITIALIZED,
	WPS_STATUS_DISABLING_WIFI_MANAGEMENT,
	WPS_STATUS_INIT,
	WPS_STATUS_SCANNING,
	WPS_STATUS_SCANNING_OVER,
	WPS_STATUS_ASSOCIATING,
	WPS_STATUS_ASSOCIATED,
	WPS_STATUS_STARTING_WPS_EXCHANGE,
	WPS_STATUS_SENDING_WPS_MESSAGE,
	WPS_STATUS_WAITING_WPS_RESPONSE,
	WPS_STATUS_GOT_WPS_RESPONSE,
	WPS_STATUS_DISCONNECTING,
	WPS_STATUS_ENABLING_WIFI_MANAGEMENT,
	WPS_STATUS_CREATING_PROFILE,
	WPS_STATUS_OVERALL_PROCESS_TIMOUT,
	WPS_STATUS_CONFIGURING_ACCESS_POINT,
	WPS_STATUS_IDLE=0xffff, // Ignore this status notification
};

/*
 WPS callback function definition
 if it returns FALSE, the WPS protocol will be canceled
*/
typedef bool (*fnWpsProcessCB)(void *context, unsigned int uiStatus, void *data);


/**************************************************************
 * Function : wps_open
 * Parameters :
		context  - Optional. If provided, the WPS status callback
				   will be called with this context.
		callback - WPS status callback.
		if_name  - Optional. Name of the interface to be used.
				   When not used, this should be NULL.
		version2 - BOOL WPS version2 support
 * Return values :  
		TRUE on success, FALSE on failure.

 * Description :
		This must be the first function made to this library.
 **************************************************************/
extern bool wps_open(void *context, fnWpsProcessCB callback, char if_name[], bool version2);

/**************************************************************
 * Function : wps_close
 * Parameters :
		None.
 * Return values :  
		TRUE on success, FALSE on failure.
 * Description :
		This must be the last call made to this library.
 **************************************************************/
extern bool wps_close(void);

//extern bool wps_configure_wzcsvc(bool enable);
/**************************************************************
 * Function : wps_findAP
 * Parameters :
		nAP  - [out] Number of APs found
		mode - [in] STA_ENR_JOIN_NW_PBC for PBC mode. 
			   STA_ENR_JOIN_NW_PBC for PIN mode of operation.
		timeout - Time to scan for the APs.
 * Return values :  
		TRUE on success, FALSE on failure.
 * Description :
		After the successful execution of this API, nAP contains
		the number APs found. In case of PBC mode of operation
		this should be 1. When more than one PBC APs found, the
		application should warn the user appropriately.
		Use wps_getAP with an index to get more details about
		the AP.
 **************************************************************/
extern bool wps_findAP(int *nAP, int mode, int timeout);

/**************************************************************
 * Function : wps_getAP
 * Parameters :
		nAP   - [in] Index of the AP whose details are being sought.
		bssid - [out] BSSID of the AP
		ssid  - [out] SSID of the AP
		wep   - [out] Whether AP uses encryption
		band  - [out] Band in which AP is operating.
 * Return values :  
		TRUE on success, FALSE on failure.
 * Description :
		Note : wps_findAP API should be called before invoking
		this API.
 **************************************************************/
extern bool wps_getAP(int nAP, unsigned char * bssid, char *ssid, uint8 *wep, uint16 *band,
	uint8 *channel, uint8 *version2, uint8 *authorizedMACs);

/**************************************************************
 * Function : wps_join
 * Parameters :
		bssid - [in] BSSID of the AP
		ssid  - [in] SSID of the AP
		wep   - [in] Whether AP uses encryption
 * Return values :  
		TRUE on success, FALSE on failure.
 * Description :
		Use this API to join to an WPS AP.
 **************************************************************/
extern bool wps_join(uint8 * bssid, char *ssid, uint8 wep);

/**************************************************************
 * Function : wps_get_AP_info
 * Parameters :
		wps_mode - [in] Mode of operation (STA_ENR_JOIN_NW_PBC or 
						STA_ENR_JOIN_NW_PIN)
		bssid	 - [in] BSSID of the AP
		ssid	 - [in] SSID of the AP
		pin		 - [in] PIN to be used (Applicable only in PIN mode)
		credentials - [out] Credentials obtained using WPS
 * Return values :  
		TRUE on success, FALSE on failure.
 * Description :
		This function starts the WPS exchange protocol and gathers
		the credentials of the AP. Call this function once wps_join
		is successful. 
		The calling process provides a callback function in wps_open()
		that will be called periodically by the WPS API. When called,
		this callback function will be provided with the current 
		status. If the calling process wants to cancel the WPS protocol,
		it should return FALSE (upon the user pressing a Cancel button,
		for example).
		GUI applications should use the asynchronous version of this 
		function (wps_get_AP_infoEx) so as not to block or slow down
		a UI's message loop.
 **************************************************************/
extern bool wps_get_AP_info(int wps_mode, uint8 *bssid, char *ssid, char *pin, wps_credentials *credentials);

/**************************************************************
 * Function : wps_get_AP_infoEx
 * Parameters :
		wps_mode - [in] Mode of operation (STA_ENR_JOIN_NW_PBC or 
						STA_ENR_JOIN_NW_PIN)
		bssid	 - [in] BSSID of the AP
		ssid	 - [in] SSID of the AP
		pin		 - [in] PIN to be used (Applicable only in PIN mode)
		retries  - [in] Number of retries in case of WPS failure.
		credentials - [out] Credentials obtained using WPS
 * Return values :  
		TRUE on success, FALSE on failure.
 * Description :
		This function is the asynchronous version of wps_get_AP_info().
		This function returns immediately and starts the WPS protocol
		in a separate thread. The calling process uses the status 
		callback to determine the state of the WPS protocol.
		
		The calling process will get a WPS_STATUS_SUCCESS once the
		WPS protocol completed successfully.
		The calling process will get a WPS_STATUS_ERROR if the WPS 
		protocol completed unsuccessfully. 
		The calling process will get a WPS_STATUS_CANCELED if the 
		WPS protocol was canceled by the calling thread.
		
		The calling process must wait for any one of these 3 status
		notifications or any error notification before calling 
		wps_close() or terminating.
		
		Unlike the synchronous version of this API call, the callback
		parameter in wps_open()CANNOT be NULL. A callback is required
		for this function to work correctly.
		
		Before this function returns, it will call the calling process'
		callback with a status of WPS_STATUS_START_WPS_EXCHANGE
 **************************************************************/
extern bool wps_get_AP_infoEx(int wps_mode, uint8 * bssid, char *ssid, char *pin, int retries, wps_credentials *credentials);

/**************************************************************
 * Function : wps_create_profile
 * Parameters :
		credentials - [out] Credentials retried using WPS.
 * Return values :  
		TRUE on success, FALSE on failure.
 * Description :
 **************************************************************/
extern bool wps_create_profile(const wps_credentials *credentials);

/*-------------------------------------------------------------*/

/**************************************************************
 * Function : wps_configureAP
 * Parameters :
		bssid - [in] BSSID of the AP to be configured
		pin - [in] PIN to be used for configuration
		credentials - [in] Credentials to be used.
 * Return values :  
		TRUE on success, FALSE on failure.
 * Description :
		Use this API to configure an AP with the given
		networking credentials as an ER (External Registrar).
 **************************************************************/
extern bool wps_configureAP(uint8 *bssid, const char *pin, const wps_credentials *credentials);

/**************************************************************
 * Function : wps_generate_pin
 * Parameters :
		pin - [out] Generated 8-digit numeric PIN
		buf_len -[in] Pin buffer length. Should not be less than 9.
 * Return values :  
		TRUE on success, FALSE on failure.
 * Description :
		Randomly generates an 8-digit numeric PIN with valid 
		checksum 8th digit.
 **************************************************************/
extern bool wps_generate_pin(char *pin, int buf_len);

/**************************************************************
 * Function : wps_generate_cred
 * Parameters :
		credentials - [out] Credentials retried using WPS.
 * Return values :  
		TRUE on success, FALSE on failure.
 * Description :
 		This API generates secure "Personal" network settings.
		The following details are generated:
		SSID - derived from STA Wi-fi adapter MAC address
		Network Key - well-formated network key derived from
		random bytes
		Authentication Method - WPA2-PSK (Fixed)
		Encryption Method - AES (Fixed)
 **************************************************************/
extern bool wps_generate_cred(wps_credentials *credentials);

/**************************************************************
 * Function : wps_is_reg_activated
 * Parameters :
		bssid - [in] BSSID of the AP.
 * Return values :  
		TRUE on success, FALSE on failure.
 * Description :
		Returns whether the Registrar associated with the given
		AP is activated or not.
 **************************************************************/
extern bool wps_is_reg_activated(const uint8 *bssid);

/**************************************************************
 * Function : wps_validate_checksum
 * Parameters :
		pin - [in] Credentials retried using WPS.
 * Return values :  
		TRUE on success, FALSE on failure.
 * Description :
		Return whether the given PIN code passes the WPS PIN 
		checksum validation or not. 8th digit of valid PIN
		is computerd by the other 7 PIN digits according to
		WPS specification.
 **************************************************************/
extern bool wps_validate_checksum(const unsigned long pin);

/**************************************************************
 * Function : wps_get_AP_scstate
 * Parameters :
		credentials - [out] Credentials retried using WPS.
 * Return values :  
		TRUE on success, FALSE on failure.
 * Description :
		Return the eWPS_CONIG_STATE state of whether the network
		security is configured or not.
 **************************************************************/
extern uint8 wps_get_AP_scstate(const uint8 *bssid);

#ifdef __cplusplus 
}
#endif
#endif  // __BRCM_WPSAPI_Hs_
