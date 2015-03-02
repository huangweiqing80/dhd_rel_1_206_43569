/* 
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wps_sdk.h 470127 2014-04-14 04:14:51Z $
 */

#ifndef _WPS_SDK_H_
#define _WPS_SDK_H_

#ifdef WIN32

#ifdef BCM_WPSAPI_EXPORT
#define BCM_WPSAPI __declspec(dllexport)
#else
#define BCM_WPSAPI __declspec(dllimport)
#endif

#else
/* Linux */
#define BCM_WPSAPI extern

#endif /* WIN32 */

#ifdef __cplusplus
extern "C" {
#endif

/* Opaque types declaration */
struct wps_ap_list_info;

/* Definition of Wi-Fi security encryption mask type */
#define WPS_ENCRYPT_NONE	0x0001
#define WPS_ENCRYPT_WEP		0x0002
#define WPS_ENCRYPT_TKIP	0x0004
#define WPS_ENCRYPT_AES		0x0008

/* Definition of Wi-Fi bands */
#define WPSAPI_BAND_2G		1
#define WPSAPI_BAND_5G		2

/* Define WPS PIN size */
#define WPS_PIN_TOTAL_DIGIT		8

#ifdef __cplusplus
typedef unsigned int	uint32;
typedef unsigned char	uint8;
typedef unsigned short	uint16;
#endif /* __cplusplus */

#undef SIZE_20_BYTES
#undef SIZE_32_BYTES
#undef SIZE_64_BYTES
#undef SIZE_128_BYTES
#undef SIZE_16_BYTES
#define SIZE_16_BYTES   16
#define SIZE_20_BYTES	20
#define SIZE_32_BYTES	32
#define SIZE_64_BYTES	64
#define SIZE_128_BYTES	128


#define ENCRYPT_NONE	1
#define ENCRYPT_WEP	2
#define ENCRYPT_TKIP	4
#define ENCRYPT_AES	8

/* Device Type categories for Primary device types */
#define DEV_CAT_COMPUTER  1	/* (COMP) Computer */
#define DEV_CAT_INPUT     2	/* (INP) Input Device */
#define DEV_CAT_PRINTER   3	/* (PRTR) Printers, Scanners, Faxes and Copiers */
#define DEV_CAT_CAMERA    4	/* (CAM) Camera */
#define DEV_CAT_STORAGE   5	/* (STOR) Storage */
#define DEV_CAT_NW        6	/* (NW) Network Infrastructure */
#define DEV_CAT_DISPLAYS  7	/* (DISP) Display */
#define DEV_CAT_MM        8	/* (MM) Multimedia Devices */
#define DEV_CAT_GAME      9	/* (GAM) Gaming Devices */
#define DEV_CAT_TELEPHONE 10	/* (PHONE) Telephone */
#define DEV_CAT_AUDIO     11	/* (AUDIO) Audio Device, WSC 2.0 */

/* Device Type sub categories for Secondary device types */
#define DEV_SUB_CAT_COMP_PC         1	/* PC */
#define DEV_SUB_CAT_COMP_SERVER     2	/* Servce */
#define DEV_SUB_CAT_COMP_MEDIA_CTR  3	/* Media Center */
#define DEV_SUB_CAT_COMP_UM_PC      4	/* Ultra-mobile PC, WSC 2.0 */
#define DEV_SUB_CAT_COMP_NOTEBOOK   5	/* Notebook, WSC 2.0 */
#define DEV_SUB_CAT_COMP_DESKTOP    6	/* Desktop, WSC 2.0 */
#define DEV_SUB_CAT_COMP_MID        7	/* MID (Mobile Internet Device, WSC 2.0 */
#define DEV_SUB_CAT_COMP_NETBOOK    8	/* (Netbook), WSC 2.0 */
#define DEV_SUB_CAT_INP_Keyboard    1	/* Keyboard, WSC 2.0 */
#define DEV_SUB_CAT_INP_MOUSE       2	/* Mouse, WSC 2.0 */
#define DEV_SUB_CAT_INP_JOYSTICK    3	/* Joystick, WSC 2.0 */
#define DEV_SUB_CAT_INP_TRACKBALL   4	/* Trackball, WSC 2.0 */
#define DEV_SUB_CAT_INP_GAM_CTRL    5	/* Gaming controller, WSC 2.0 */
#define DEV_SUB_CAT_INP_REMOTE      6	/* Remote, WSC 2.0 */
#define DEV_SUB_CAT_INP_TOUCHSCREEN 7	/* Touchscreen, WSC 2.0 */
#define DEV_SUB_CAT_INP_BIO_READER  8	/* Biometric reader 8, WSC 2.0 */
#define DEV_SUB_CAT_INP_BAR_READER  9	/* Barcode reader, WSC 2.0 */
#define DEV_SUB_CAT_PRTR_PRINTER    1	/* Printer or Print Server */
#define DEV_SUB_CAT_PRTR_SCANNER    2	/* Scanner */
#define DEV_SUB_CAT_PRTR_FAX        3	/* Fax, WSC 2.0 */
#define DEV_SUB_CAT_PRTR_COPIER     4	/* Copier, WSC 2.0 */
#define DEV_SUB_CAT_PRTR_ALLINONE   5	/* All-in-one (Printer, Scanner, Fax, Copier), WSC 2.0 */
#define DEV_SUB_CAT_CAM_DGTL_STILL  1	/* Digital Still Camera */
#define DEV_SUB_CAT_CAM_VIDEO_CAM   2	/* Video Camera, WSC 2.0 */
#define DEV_SUB_CAT_CAM_WEB_CAM     3	/* Web Camera, WSC 2.0 */
#define DEV_SUB_CAT_CAM_SECU_CAM    4	/* Security Camera, WSC 2.0 */
#define DEV_SUB_CAT_STOR_NAS        1	/* NAS */
#define DEV_SUB_CAT_NW_AP           1	/* AP */
#define DEV_SUB_CAT_NW_ROUTER       2	/* Router */
#define DEV_SUB_CAT_NW_SWITCH       3	/* Switch */
#define DEV_SUB_CAT_NW_Gateway      4	/* Gateway, WSC 2.0 */
#define DEV_SUB_CAT_NW_BRIDGE       5	/* Bridge, WSC 2.0 */
#define DEV_SUB_CAT_DISP_TV         1	/* Television */
#define DEV_SUB_CAT_DISP_PIC_FRAME  2	/* Electronic Picture Frame */
#define DEV_SUB_CAT_DISP_PROJECTOR  3	/* Projector */
#define DEV_SUB_CAT_DISP_MONITOR    4	/* Monitor, WSC 2.0 */
#define DEV_SUB_CAT_MM_DAR          1	/* DAR */
#define DEV_SUB_CAT_MM_PVR          2	/* PVR */
#define DEV_SUB_CAT_MM_MCX          3	/* MCX */
#define DEV_SUB_CAT_MM_STB          4	/* Set-top box, WSC 2.0 */
#define DEV_SUB_CAT_MM_MS_ME        5	/* Media Server/Media Adapter/Media Extender, WSC 2.0 */
#define DEV_SUB_CAT_MM_PVP          6	/* Portable Video Player, WSC 2.0 */
#define DEV_SUB_CAT_GAM_XBOX        1	/* Xbox */
#define DEV_SUB_CAT_GAM_XBOX_360    2	/* Xbox360 */
#define DEV_SUB_CAT_GAM_PS          3	/* Playstation */
#define DEV_SUB_CAT_GAM_GC          4	/* Game Console/Game Console Adapter, WSC 2.0 */
#define DEV_SUB_CAT_GAM_PGD         5	/* Portable Gaming Device, WSC 2.0 */
#define DEV_SUB_CAT_PHONE_WM        1	/* Windows Mobile */
#define DEV_SUB_CAT_PHONE_PSM       2	/* Phone - single mode, WSC 2.0 */
#define DEV_SUB_CAT_PHONE_PDM       3	/* Phone - dual mode, WSC 2.0 */
#define DEV_SUB_CAT_PHONE_SSM       4	/* Smartphone - single mode, WSC 2.0 */
#define DEV_SUB_CAT_PHONE_SDM       5	/* Smartphone - dual mode, WSC 2.0 */
#define DEV_SUB_CAT_AUDIO_TUNER     1	/* Audio tuner/receiver, WSC 2.0 */
#define DEV_SUB_CAT_AUDIO_SPEAKERS  2	/* Speakers, WSC 2.0 */
#define DEV_SUB_CAT_AUDIO_PMP       3	/* Portable Music Player (PMP), WSC 2.0 */
#define DEV_SUB_CAT_AUDIO_HEADSET   4	/* Headset (headphones + microphone), WSC 2.0 */
#define DEV_SUB_CAT_AUDIO_HPHONE    5	/* Headphones, WSC 2.0 */
#define DEV_SUB_CAT_AUDIO_MPHONE    6	/* Microphone, WSC 2.0 */
#define DEV_SUB_CAT_AUDIO_HTS       7	/* Home Theater Systems, WSC 2.0 */

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

typedef struct _wps_devinf {
	char    deviceName[SIZE_32_BYTES+1];
	uint16  primDeviceCategory;
	uint16  primDeviceSubCategory;
	char    manufacturer[SIZE_64_BYTES+1];
	char    modelName[SIZE_32_BYTES+1];
	char    modelNumber[SIZE_32_BYTES+1];
	char    serialNumber[SIZE_32_BYTES+1];
	char    transport_uuid[SIZE_16_BYTES];  /* Transport protocol UUID, not to be confused with
						 * the WPS UUID that is automatically generated
						 */
} wps_devinf;

#ifdef WFA_WPS_20_TESTBED
typedef struct _wps20_testbed_inf {
	uint8	v2_num;
	char    dummy_ssid[SIZE_32_BYTES+1];
	bool    b_zpadding;
	bool    b_zlength;
	bool    b_mca;		/* Multiple Credential Attributes for Registrar */
	int     nattr_len;
	char    nattr_tlv[SIZE_128_BYTES];
} wps20_testbed_inf;
#endif /* WFA_WPS_20_TESTBED */

typedef struct _wps_apinf {
	uint8  bssid[6];
	char   ssid[SIZE_32_BYTES+1];
	uint8  wep;
	uint16 band;
	bool   configured;
	uint8  channel;
	uint8  version2;
	uint8  authorizedMACs[6 * 5];
} wps_apinf;


/* WPS status values provided to the callback wps_join_callback (see below) */
enum {
	WPS_STATUS_SUCCESS = 0,
	WPS_STATUS_ERROR = 1,
	WPS_STATUS_CANCELED = 2,
	/* WPS_STATUS_WARNING_TIMEOUT, //Only have one 2-minis overall time */
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
	WPS_STATUS_OVERALL_PROCESS_TIMEOUT,
	WPS_STATUS_WRONG_PIN,
	WPS_STATUS_SCANNING_OVER_SUCCESS,
	WPS_STATUS_SCANNING_OVER_SESSION_OVERLAP,
	WPS_STATUS_SCANNING_OVER_NO_AP_FOUND,
	WPS_STATUS_REJOIN,
	WPS_STATUS_IDLE = 0xffff
};

/* Useful Macros */
#define DEVICE_PASSWORD_ID(appin, pin, new_cred) \
	(((appin) && (new_cred)) ? STA_REG_CONFIG_NW : \
	(appin) ? STA_REG_JOIN_NW : \
	(pin) == NULL ? STA_ENR_JOIN_NW_PBC : \
	strlen((pin)) ? STA_ENR_JOIN_NW_PIN : STA_ENR_JOIN_NW_PBC)

#define PIN_MODE(emode)	(((emode) == STA_REG_JOIN_NW) || \
	((emode) == STA_REG_CONFIG_NW) || \
	((emode) == STA_ENR_JOIN_NW_PIN))
#define PBC_MODE(emode)	((emode) == STA_ENR_JOIN_NW_PBC)


/* WPS callback function definition */
typedef void (*fnWpsProcessCB)(void *context, unsigned int uiStatus, void *data);


/*
 * Function : wps_api_status_cb
 * Parameters :
 *		cb - WPS status callback
 *		cb_ctx  - Optional. If provided, the WPS status callback
 *			will be called with this context.
 *		uiStatus - WPS status.
 *		data  - Optional. additional infornation for uiStatus.
 * Return values :  
 *
 * Description :
 */
BCM_WPSAPI void wps_api_status_cb(fnWpsProcessCB *cb, void *cb_ctx, unsigned int uiStatus,
	void *data);


/*
 * Function : wps_api_open
 * Parameters :
 *		adapter_id - Adapter identifier
 *		cb_ctx  - Optional. If provided, the WPS status callback
 *			will be called with this context.
 *		callback - WPS status callback.
 *		if_name  - Optional. Name of the interface to be used.
 *				   When not used, this should be NULL.
 *		devinf - Option. WPS device information
 *		wps20_tbinf - For WPS 2.0 testbed utility only.
 *		ap_pin - Use AP's PIN (registrar method) or STA device PIN (enrollee method)
 *		version2 - Option. WPS version2 support
 * Return values :  
 *		TRUE on success, FALSE on failure.
 *
 * Description :
 *		This must be called first, before any other wps api call.
 *		If adapter_id is NULL, SDK will enumerate and select a
 * 		wlan adapter automatically.
 *		If devinf is NULL, SDK will use default device inof as below
 *			Primary Device Category = DEV_CAT_COMPUTER
 *			primary Device SubCategory = DEV_SUB_CAT_COMP_PC
 *			device Name = "Broadcom Registrar"
 *			manufacturer = "Broadcom"
 *			model Name = "WPS Wireless Registrar"
 *			model Number = "1234"
 *			serial Number = "5678"
 */
#ifdef WFA_WPS_20_TESTBED
BCM_WPSAPI bool wps_api_open(const char *adapter_id, void *cb_ctx, fnWpsProcessCB callback,
	wps_devinf *devinf, wps20_testbed_inf *wps20_tbinf, bool ap_pin, bool version2);
#else
BCM_WPSAPI bool wps_api_open(const char *adapter_id, void *cb_ctx, fnWpsProcessCB callback,
	wps_devinf *devinf, bool ap_pin, bool version2);
#endif


/*
 * Function : wps_api_close
 * Parameters :
 *		None.
 * Return values :  
 *		TRUE on success, FALSE on failure.
 * Description :
 *		This must be called once you are done using the wps api
 */
BCM_WPSAPI bool wps_api_close(void);


/*
 * Function : wps_api_abort
 * Parameters :
 *		None.
 * Return values :  
 *		None.
 * Description :
 *		For async mode to abort WPS thread.
 */
BCM_WPSAPI void wps_api_abort(void);


/*
 * Function : wps_api_find_ap
 * Parameters :
 *		wpsaplist  - [in] all APs list got from wps_api_surveying
 *		nAP  - [out] Number of APs found
 *		b_pbc - [in] PBC mode enabled/disabled. 
 *		mac - [in] find AP which announce this mac in AP's Authorized MAC
 *		b_wc - [in] find AP which announce wildcard mac in AP's Authorized MAC
 *			when argument mac not matched in AP's Authorized MAC. 
 *		b_pbcap - [out] is found AP running PBC. 
 *		b_auto - [in] find all APs which are running PIN now.
 * Return values :  
 *		TRUE on success, FALSE on failure.
 * Description :
 *		After the successful execution of this API, nAP contains
 *		the number APs found. In case of PBC mode of operation
 *		this should be 1. When more than one PBC APs found, the
 *		application should warn the user appropriately.
 *		Use wps_api_get_ap with an index to get more details about
 *		the AP.
 */
BCM_WPSAPI bool wps_api_find_ap(struct wps_ap_list_info *wpsaplist, int *nAP, bool b_pbc,
	uint8 *mac, bool b_wc, bool *b_pbcap, bool b_auto);


/*
 * Function : wps_api_get_ap
 * Parameters :
 *		nAP   - [in] Index of the AP whose details are being sought.
 *		apinf - [out] information of the AP
 * Return values :  
 *		TRUE on success, FALSE on failure.
 * Description :
 *		Note : wps_api_find_ap API should be called before invoking
 *		this API.
 */
BCM_WPSAPI bool wps_api_get_ap(int nAP, wps_apinf *apinf);


/*
 * Function : wps_api_get_credentials
 * Parameters :
 *		credentials - [out] buffer pointer to retrieve credentials from WPS.
 * Return values :  
 *		credentials or NULL
 * Description :
 */
BCM_WPSAPI wps_credentials *wps_api_get_credentials(wps_credentials *credentials);


/*
 * Function : wps_api_generate_cred
 * Parameters :
 *		credentials - [out] random credential
 * Return values :  
 *		TRUE on success, FALSE on failure.
 * Description :
 * 		This API generates secure "Personal" network settings.
 *		The following details are generated:
 *		SSID - derived from STA Wi-Fi adapter MAC address
 *		Network Key - well-formated network key derived from random bytes
 *		Authentication Method - WPA2-PSK (Fixed)
 *		Encryption Method - AES (Fixed)
 */
BCM_WPSAPI bool wps_api_generate_cred(wps_credentials *credentials);


/*
 * Function : wps_api_generate_pin
 * Parameters :
 *		pin - [out] Generated 8-digit numeric PIN
 *		buf_len -[in] Pin buffer length. Should not be less than 9.
 * Return values :  
 *		TRUE on success, FALSE on failure.
 * Description :
 *		Randomly generates an 8-digit numeric PIN with valid 
 *		checksum 8th digit.
 */
BCM_WPSAPI bool wps_api_generate_pin(char *pin, int buf_len);


/*
 * Function : wps_api_hwbutton_supported
 * Parameters :
 *		guid - [in] hardware GPIO PIN guid
 * Return value :
 *		TRUE on supported, FALSE on not supported.
 * Description :
 *		Return whether the WPS hardware GPIO PIN button is supported or not
 *		This function must need OSL API supported.
 */
BCM_WPSAPI bool wps_api_hwbutton_supported(const char *guid);


/*
 * Function : wps_api_hwbutton_open
 * Parameters :
 *		guid - [in] hardware GPIO PIN guid
 * Return value :
 *		TRUE on success, FALSE on failure.
 * Description :
 *		Initialize Wi-Fi adapter for GPIO process, for example, pulling WPS GPIO PIN state.
 *		It should be called before calling wps_api_hwbutton_state
 *		This function must need OSL API supported.
 */
BCM_WPSAPI bool wps_api_hwbutton_open(const char *guid);


/*
 * Function : wps_api_hwbutton_close
 * Parameters :
 *		None.
 * Return value :
 *		None.
 * Description :
 *		Uninitialize Wi-Fi adapter after GPIO process is completed.
 *		This function must need OSL API supported.
 */
BCM_WPSAPI void wps_api_hwbutton_close();


/*
 * Function : wps_api_hwbutton_state
 * Parameters :
 *		None.
 * Return value :
 *		1 - button is pressed, 0 - button is not pressed.
 * Description :
 *		Return whether the WPS hardware GPIO PIN button state.
 *		The polling interval should be more than 200ms	in order not to disturb driver much
 *		This function must need OSL API supported.
 */
BCM_WPSAPI bool wps_api_hwbutton_state();


/*
 * Function : wps_api_wps_is_reg_activated
 * Parameters :
 *		bssid - [in] BSSID of the AP.
 * Return values :  
 *		TRUE on success, FALSE on failure.
 * Description :
 *		Returns whether the Registrar associated with the given
 *		AP is activated or not.
 */
BCM_WPSAPI bool wps_api_wps_is_reg_activated(const uint8 *bssid);


/*
 * Function : wps_api_validate_checksum
 * Parameters :
 *		pinStr - [in] PIN number.
 * Return values :  
 *		TRUE on success, FALSE on failure.
 * Description :
 *		Return whether the given PIN code passes the WPS PIN 
 *		checksum validation or not. 8th digit of valid PIN
 *		is computerd by the other 7 PIN digits according to
 *		WPS specification.
 */
BCM_WPSAPI bool wps_api_validate_checksum(char *pinStr);


/*
 * Function : wps_api_run
 * Parameters :
 *		mode - [in] join network or config network.
 *		bssid - [in] BSSID of the AP
 *		ssid - [in] SSID of the AP
 *		wep - [in] security enabled/disabled
 *		pin -[in] PIN to be used (Applicable only in PIN mode)
 *		new_cred - [in] new credentials to configure AP
 *		b_async - [in] running as async mode (create thread to run WPS) or not
 * Return values :  
 *		TRUE on success, FALSE on failure.
 * Description :
 *		This functino called after AP has connected (for example, wps_api_join successful).
 */
BCM_WPSAPI bool wps_api_run(enum eWPS_MODE mode, uint8 *bssid, char *ssid, uint8 wep, char *pin,
	wps_credentials *new_cred, bool b_async);


/*
 * Function : wps_api_process_data
 * Parameters :
 *		buf - [in] WPS data buffer got from wps_api_poll_eapol_packet.
 *		len - [in] WPS data buffer len. 
 * Return values :  
 *		WPS_STATUS_SUCCESS
 *		WPS_STATUS_ERROR
 *		WPS_STATUS_REJOIN
 *		WPS_STATUS_IDLE
 * Description :
 */
BCM_WPSAPI uint32 wps_api_process_data(char *buf, uint32 len);


/*
 *   Function : wps_api_process_timeout
 *   Parameters :
 *		None
 *   Return values :  
 *		WPS_STATUS_ERROR
 *		WPS_STATUS_REJOIN
 *		WPS_STATUS_IDLE
 *   Description :
 *		This function must be called periodically
 */
BCM_WPSAPI uint32 wps_api_process_timeout(void);


/*
 *   Function : wps_api_set_linkup
 *   Parameters :
 *		None
 *   Return values :  
 *		None
 *   Description :
 *		Notify wps api that the interface link is up after join/rejoin successful.
 */
BCM_WPSAPI void wps_api_set_linkup(void);


/*
 *   Function : wps_api_create_profile
 *   Parameters :
 *		credentials - [in] credentials retrieved from wps_api_get_credentials.
 *   Return values :  
 *		TRUE on success, FALSE on failure.
 *   Description :
 *		This function must need OSL API supported
 */
BCM_WPSAPI bool wps_api_create_profile(const wps_credentials *credentials);


/*
 *  Function : wps_api_poll_eapol_packet
 *  Parameters :
 *		buf - [in] EAPOL packet data buffer got from OSL API supported..
 *		len - [in/out] in - length of passed buf.  out - length of received eapol packet
 *  Return values :  
 *		WPS_STATUS_SUCCESS
 *		WPS_STATUS_ERROR
 *		WPS_STATUS_IDLE;
 *  Description :
 *		This function must need OSL API supported.
 */ 
BCM_WPSAPI uint32 wps_api_poll_eapol_packet(char *buf, uint32 *len);


/*
 * Function : wps_api_surveying
 * Parameters :
 *		b_pbc   - [in] PBC mode enabled/disabled. 
 *		b_v2 - [in] WPS Version2 enabled/disabled.
 *		b_add_wpsie - [in] Add WPS IE or not.
 * Return values :  
 *		All APs list or NULL
 * Description :
 *		When first time you call this function, you should set b_add_wpsie to TRUE
 *		to add wps ie in probe request and associate request.
 *		When you need to call it again (for example: re-scan) you don't need to add
 *		wps ie again, you just keep the previous one.
 *		If you set b_add_wpsie TRUE again, the WPS IE will remove and add again.
 *		(WL API), Use this API to scan WPS APs.
 */
BCM_WPSAPI struct wps_ap_list_info *wps_api_surveying(bool b_pbc, bool b_v2, bool b_add_wpsie);


/*
 * Function : wps_api_join
 * Parameters :
 *		bssid - [in] BSSID of the AP
 *		ssid  - [in] SSID of the AP
 *		wep   - [in] Whether AP uses encryption
 * Return values :  
 *		TRUE on success, FALSE on failure.
 * Description :
 *		(WL API), Use this API to join to an WPS AP.
 */
BCM_WPSAPI bool wps_api_join(uint8 * bssid, char *ssid, uint8 wep);


/*
 * Function : wps_api_auto_pin_reset
 * Parameters :
 *		cb_ctx  - Optional. If provided, the WPS status callback
 *			will be called with this context.
 *		callback - WPS status callback.
 * Return values :  
 *		TRUE on success, FALSE on failure.
 * Description :
 *		This fuinction is used for Auto PIN mode.
 *		Auto PIN mode: Device WPS with all WPS enabled APs sequentially
 *			until successful or all failed. 
 */
BCM_WPSAPI bool wps_api_auto_pin_reset(void *cb_ctx, fnWpsProcessCB callback);


/*
 * Function : wps_api_is_wep_incompatible
 * Parameters :
 * Return values :  
 *		TRUE on incompatible happend, FALSE on else.
 * Description :
 *		This fuinction is used for WEP incompatible situation.
 */
BCM_WPSAPI bool wps_api_is_wep_incompatible(void);


/*
 * Function : wps_api_force_v1_reset
 * Parameters :
 *		cb_ctx  - Optional. If provided, the WPS status callback
 *			will be called with this context.
 *		callback - WPS status callback.
 * Return values :  
 *		TRUE on success, FALSE on failure.
 * Description :
 *		This fuinction is used for WEP incompatible situation.
 *		Force V1 mode: Start WPS in V1 mode again.
 */
BCM_WPSAPI bool wps_api_force_v1_reset(void *cb_ctx, fnWpsProcessCB callback);


BCM_WPSAPI bool wps_api_get_dev_mac(uint8 *buf, uint8 len);

#ifdef WFA_WPS_20_TESTBED
/*
 * Function : wps_api_set_wps_ie_frag_threshold
 * Parameters :
 *		threshold  - WPS IE fragment threshold (72 ~ 230)
 * Return values :  
 *		TRUE on success, FALSE on failure.
 * Description :
 *		Set WPS IE fragment threshold
 */
BCM_WPSAPI bool wps_api_set_wps_ie_frag_threshold(int threshold);


/*
 * Function : wps_api_set_sta_eap_frag_threshold
 * Parameters :
 *		threshold  - EAP fragment threshold (100 ~ 1398)
 * Return values :  
 *		TRUE on success, FALSE on failure.
 * Description :
 *		Set EAP fragment threshold
 */
BCM_WPSAPI bool wps_api_set_sta_eap_frag_threshold(int threshold);


/*
 * Function : wps_api_update_prbreq_ie
 * Parameters :
 *		updie_str  - Update IE string
 * Return values :  
 *		TRUE on success, FALSE on failure.
 * Description :
 *		Update partial embedded WPS probe request IE
 *		For example: updie_str = "104a000111" means replace version value with 0x11
 */
BCM_WPSAPI bool wps_api_update_prbreq_ie(uint8 *updie_str);


/*
 * Function : wps_api_update_assocreq_ie
 * Parameters :
 *		updie_str  - Update IE string
 * Return values :  
 *		TRUE on success, FALSE on failure.
 * Description :
 *		Update partial embedded WPS associate request IE
 *		For example: updie_str = "104a000111" means replace version value with 0x11
 */
BCM_WPSAPI bool wps_api_update_assocreq_ie(uint8 *updie_str);
#endif /* WFA_WPS_20_TESTBED */


#ifdef __cplusplus
}
#endif

#endif /* _WPS_SDK_H_ */
