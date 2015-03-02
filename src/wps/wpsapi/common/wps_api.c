/*
 * Broadcom WPS Enrollee
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wps_api.c 470127 2014-04-14 04:14:51Z $
 */

#include <wpsheaders.h>
#include <wps_enrapi.h>
#include <wps_sta.h>
#include <tutrace.h>

#include "wps_api_priv.h"
#include <wpscommon.h>
#include "wlioctl.h"


#define STATE_LINKDOWN		0
#define STATE_LINKUP		1
#define STATE_WAIT_LINKUP	2

extern void RAND_bytes(unsigned char *buf, int num);

typedef struct WPS_API_S
{
	wps_devinf *devinf;		/* wps sdk device info passed by client application */
#ifdef WFA_WPS_20_TESTBED
	wps20_testbed_inf *wps20_tbinf;	/* WPS 2.0 testbed extra info */
#endif
	int mode;
	uint8 bssid[SIZE_6_BYTES];
	char ssid[SIZE_SSID_LENGTH];
	uint8 wep;
	char *pin;
	bool b_ap_pin;			/* for registrar method */
	bool b_new_cred;		/* for registrar method */
	bool b_secure_nw;

	int state;			/* for re-join */
	bool b_linkup;

#ifdef ASYNC_MODE
	void *async_thread;
	char buf[4096];
	uint32 buf_len;
	bool b_abort;
#endif

	bool b_v2_saved;		/* WPS V2 support flag, saved */
	bool b_v2;			/* WPS V2 support flag */

	void *cb_ctx;			/* Client call back context */
	fnWpsProcessCB cb;		/* Client call back function for status update */

	unsigned long start_time;
} WPS_API_T;

static WPS_API_T *wps_api_wksp = NULL;	/* wps api working space context */

static void
_wps_api_reg_config_init(WpsEnrCred *credential, char *bssid)
{
	DevInfo info;
	char uuid[16] = {0x22, 0x21, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0xa, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	char nwKey[SIZE_64_BYTES+1], *Key = NULL;
	uint8 mac[6];


	/* Fill in device default info */
	memset((char *)(&info), 0, sizeof(info));
	info.version = WPS_VERSION;

	/* MAC addr */
	wps_hook_get_mac(mac);
	memcpy(info.macAddr, mac, 6); /* Fill mac address */

	memcpy(uuid + 10, mac, 6);
	memcpy(info.uuid, uuid, sizeof(info.uuid));

	wps_strncpy(info.deviceName, wps_api_wksp->devinf->deviceName, sizeof(info.deviceName));
	info.primDeviceCategory = wps_api_wksp->devinf->primDeviceCategory;
	info.primDeviceOui = 0x0050F204; /* Fixed OUI value */
	info.primDeviceSubCategory = wps_api_wksp->devinf->primDeviceSubCategory;
	wps_strncpy(info.manufacturer, wps_api_wksp->devinf->manufacturer,
		sizeof(info.manufacturer));
	wps_strncpy(info.modelName, wps_api_wksp->devinf->modelName, sizeof(info.modelName));
	wps_strncpy(info.modelNumber, wps_api_wksp->devinf->modelNumber, sizeof(info.modelNumber));
	wps_strncpy(info.serialNumber, wps_api_wksp->devinf->serialNumber,
		sizeof(info.serialNumber));

	/* Set Transport and WPS UUID to either default (if not already set)
	 * or saved wps_api_wksp->devinf values
	 */
	memcpy(info.transport_uuid,
		(memcmp(info.transport_uuid, wps_api_wksp->devinf->transport_uuid,
		sizeof(info.transport_uuid)) == 0) ?
		uuid : wps_api_wksp->devinf->transport_uuid, sizeof(info.transport_uuid));

	/*
	 * WSC 2.0, Default standalone STA.
	 * 0x0004 Label | 0x0280 Virtual Push Button |
	 * 0x2008 Virtual Display PIN
	 */
	if (wps_api_wksp->b_v2) {
		info.configMethods = (WPS_CONFMET_LABEL | WPS_CONFMET_VIRT_PBC |
			WPS_CONFMET_VIRT_DISPLAY);
	} else {
		info.configMethods = WPS_CONFMET_LABEL | WPS_CONFMET_DISPLAY | WPS_CONFMET_PBC;
	}

	/*
	 * WSC 2.0, WPS-PSK and SHARED are deprecated.
	 * When both the Registrar and the Enrollee are using protocol version 2.0
	 * or newer, this variable can use the value 0x0022 to indicate mixed mode
	 * operation (both WPA-Personal and WPA2-Personal enabled)
	 */
	if (wps_api_wksp->b_v2) {
		info.authTypeFlags = (uint16)(WPS_AUTHTYPE_OPEN | WPS_AUTHTYPE_WPAPSK |
			WPS_AUTHTYPE_WPA | WPS_AUTHTYPE_WPA2 | WPS_AUTHTYPE_WPA2PSK);
	} else {
		info.authTypeFlags = (uint16)(WPS_AUTHTYPE_OPEN | WPS_AUTHTYPE_WPAPSK |
			WPS_AUTHTYPE_SHARED | WPS_AUTHTYPE_WPA | WPS_AUTHTYPE_WPA2 |
			WPS_AUTHTYPE_WPA2PSK);
	}

	/* ENCR_TYPE_FLAGS */
	/*
	 * WSC 2.0, deprecated WEP. TKIP can only be advertised on the AP when
	 * Mixed Mode is enabled (Encryption Type is 0x000c)
	 */
	if (wps_api_wksp->b_v2) {
		info.encrTypeFlags = (uint16)(WPS_ENCRTYPE_NONE | WPS_ENCRTYPE_TKIP |
			WPS_ENCRTYPE_AES);
	} else {
		info.encrTypeFlags = (uint16)(WPS_ENCRTYPE_NONE | WPS_ENCRTYPE_WEP |
			WPS_ENCRTYPE_TKIP | WPS_ENCRTYPE_AES);
	}

	info.connTypeFlags = WPS_CONNTYPE_ESS;

	/* rfBand will update again later */
	info.rfBand = WPS_RFBAND_24GHZ;

	info.osVersion = 0x80000000;
	info.featureId = 0x80000000;

	/* WSC 2.0 */
	if (wps_api_wksp->b_v2) {
		info.version2 = WPS_VERSION2;
		info.settingsDelayTime = WPS_SETTING_DELAY_TIME_LINUX;
		info.b_reqToEnroll = FALSE;
		info.b_nwKeyShareable = FALSE;
	}

	/* Replease if need */
	if (credential) {
		/* SSID */
		memcpy(info.ssid, credential->ssid, SIZE_SSID_LENGTH);

		/* keyMgmt */
		memcpy(info.keyMgmt, credential->keyMgmt, SIZE_20_BYTES);
		/* crypto */
		info.crypto = credential->encrType;
		if (credential->encrType & WPS_ENCRTYPE_WEP)
			info.wep = 1;
		else
			info.wep = 0;

		/* nwKey */
		wps_strncpy(nwKey, credential->nwKey, sizeof(nwKey));
		Key = nwKey;
	}

#ifdef WFA_WPS_20_TESTBED
	if (wps_api_wksp->wps20_tbinf->v2_num != 0)
		info.version2 = wps_api_wksp->wps20_tbinf->v2_num;

	/* For internal testing purpose, do zero padding */
	info.b_zpadding = wps_api_wksp->wps20_tbinf->b_zpadding;
	info.b_zlength = wps_api_wksp->wps20_tbinf->b_zlength;
	info.b_mca = wps_api_wksp->wps20_tbinf->b_mca;
	strcpy(info.dummy_ssid, "DUMMY SSID");
	memcpy(info.nattr_tlv, wps_api_wksp->wps20_tbinf->nattr_tlv,
		wps_api_wksp->wps20_tbinf->nattr_len);
	info.nattr_len = wps_api_wksp->wps20_tbinf->nattr_len;
#endif /* WFA_WPS_20_TESTBED */

	wpssta_reg_init(&info, Key, bssid);
}

static bool
_wps_api_do_registration(char *pin)
{
	bool bRet = true;
	int len;
	char *sendBuf;
	unsigned long now;


	TUTRACE((TUTRACE_INFO, "Starting WPS registration.\n"));

	now = wps_hook_get_current_time();
	if (wpssta_start_registration(pin, now) != WPS_SUCCESS) {
		TUTRACE((TUTRACE_ERR, "Start registration failed.\n"));
		bRet = false;
		goto err;
	}

	/*
	 * Start the process by sending the eapol start . Created from the
	 * Enrollee SM Initialize.
	 */
	len = wps_get_msg_to_send(&sendBuf, (uint32)now);
	if (sendBuf) {
		int msg_type = WPS_PRIVATE_ID_EAPOL_START;

		/* Update status */
		wps_api_status_cb(&wps_api_wksp->cb, wps_api_wksp->cb_ctx,
			WPS_STATUS_STARTING_WPS_EXCHANGE, NULL);

		wps_hook_send_eapol_packet(sendBuf, len);

		/* Update status */
		wps_api_status_cb(&wps_api_wksp->cb, wps_api_wksp->cb_ctx,
			WPS_STATUS_SENDING_WPS_MESSAGE, &msg_type);

		TUTRACE((TUTRACE_INFO, "Send EAPOL-Start\n"));
	}
	else {
		/* This means the system is not initialized */
		/* Update status */
		wps_api_status_cb(&wps_api_wksp->cb, wps_api_wksp->cb_ctx,
			WPS_STATUS_WARNING_NOT_INITIALIZED, NULL);

		TUTRACE((TUTRACE_ERR, "WPS library not initialized.\n"));
		bRet = false;
		goto err;
	}

err:
	return bRet;
}

/*
 * Fill up the device info and pass it to WPS.
 * This will need to be tailored to specific platforms (read from a file,
 * nvram ...)
 */
static void
_wps_api_config_init(void)
{
	DevInfo info;
	unsigned char mac[6];
	char uuid[16] = {0x22, 0x21, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0xa, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};


	/* Fill in device specific info. The way this information is stored is app specific */
	/* Would be good to document all of these ...  */
	memset((char *)(&info), 0, sizeof(info));
	info.version = WPS_VERSION;

	/* MAC addr */
	wps_hook_get_mac(mac);
	memcpy(info.macAddr, mac, 6);

	/* Generate UUID base on the MAC addr */
	memcpy(uuid + 10, mac, 6);
	memcpy(info.uuid, uuid, sizeof(info.uuid));

	wps_strncpy(info.deviceName, wps_api_wksp->devinf->deviceName, sizeof(info.deviceName));

	info.primDeviceCategory = wps_api_wksp->devinf->primDeviceCategory;
	info.primDeviceOui = 0x0050F204; /* Fixed OUI value */
	info.primDeviceSubCategory = wps_api_wksp->devinf->primDeviceSubCategory;
	wps_strncpy(info.manufacturer, wps_api_wksp->devinf->manufacturer,
		sizeof(info.manufacturer));
	wps_strncpy(info.modelName, wps_api_wksp->devinf->modelName, sizeof(info.modelName));
	wps_strncpy(info.modelNumber, wps_api_wksp->devinf->modelNumber, sizeof(info.modelNumber));
	wps_strncpy(info.serialNumber, wps_api_wksp->devinf->serialNumber,
		sizeof(info.serialNumber));

	/* Set Transport and WPS UUID to either default (if not already set)
	 * or saved wps_api_wksp->devinf values
	 */
	memcpy(info.transport_uuid,
		(memcmp(info.transport_uuid, wps_api_wksp->devinf->transport_uuid,
		sizeof(info.transport_uuid)) == 0) ?
		uuid : wps_api_wksp->devinf->transport_uuid, sizeof(info.transport_uuid));

	/*
	 * WSC 2.0, Default standalone STA.
	 * 0x0004 Label | 0x0280 Virtual Push Button |
	 * 0x2008 Virtual Display PIN
	 */
	if (wps_api_wksp->b_v2) {
		info.configMethods = (WPS_CONFMET_LABEL | WPS_CONFMET_VIRT_PBC |
			WPS_CONFMET_VIRT_DISPLAY);
	} else {
		info.configMethods = WPS_CONFMET_LABEL | WPS_CONFMET_DISPLAY | WPS_CONFMET_PBC;
	}

	/*
	 * WSC 2.0, WPS-PSK and SHARED are deprecated.
	 * When both the Registrar and the Enrollee are using protocol version 2.0
	 * or newer, this variable can use the value 0x0022 to indicate mixed mode
	 * operation (both WPA-Personal and WPA2-Personal enabled)
	 */
	if (wps_api_wksp->b_v2) {
		info.authTypeFlags = (uint16)(WPS_AUTHTYPE_OPEN | WPS_AUTHTYPE_WPAPSK |
			WPS_AUTHTYPE_WPA | WPS_AUTHTYPE_WPA2 | WPS_AUTHTYPE_WPA2PSK);
	} else {
		info.authTypeFlags = (uint16)(WPS_AUTHTYPE_OPEN | WPS_AUTHTYPE_WPAPSK |
			WPS_AUTHTYPE_SHARED | WPS_AUTHTYPE_WPA | WPS_AUTHTYPE_WPA2 |
			WPS_AUTHTYPE_WPA2PSK);
	}

	/* ENCR_TYPE_FLAGS */
	/*
	 * WSC 2.0, deprecated WEP. TKIP can only be advertised on the AP when
	 * Mixed Mode is enabled (Encryption Type is 0x000c)
	 */
	if (wps_api_wksp->b_v2) {
		info.encrTypeFlags = (uint16)(WPS_ENCRTYPE_NONE | WPS_ENCRTYPE_TKIP |
			WPS_ENCRTYPE_AES);
	} else {
		info.encrTypeFlags = (uint16)(WPS_ENCRTYPE_NONE | WPS_ENCRTYPE_WEP |
			WPS_ENCRTYPE_TKIP | WPS_ENCRTYPE_AES);
	}

	info.connTypeFlags = WPS_CONNTYPE_ESS;

	/* rfBand will update again later */
	info.rfBand = WPS_RFBAND_24GHZ | WPS_RFBAND_50GHZ;

	info.osVersion = 0x80000000;
	info.featureId = 0x80000000;

	/* WSC 2.0 */
	if (wps_api_wksp->b_v2) {
		info.version2 = WPS_VERSION2;
		info.settingsDelayTime = WPS_SETTING_DELAY_TIME_LINUX;
		info.b_reqToEnroll = TRUE;
		info.b_nwKeyShareable = FALSE;
	}

#ifdef WFA_WPS_20_TESTBED
	if (wps_api_wksp->wps20_tbinf->v2_num != 0)
		info.version2 = wps_api_wksp->wps20_tbinf->v2_num;

	/* For internal testing purpose, do zero padding */
	info.b_zpadding = wps_api_wksp->wps20_tbinf->b_zpadding;
	info.b_zlength = wps_api_wksp->wps20_tbinf->b_zlength;
	info.b_mca = false;
	memcpy(info.nattr_tlv, wps_api_wksp->wps20_tbinf->nattr_tlv,
		wps_api_wksp->wps20_tbinf->nattr_len);
	info.nattr_len = wps_api_wksp->wps20_tbinf->nattr_len;
#endif /* WFA_WPS_20_TESTBED */

	wpssta_enr_init(&info);
}

static bool
_wps_api_do_enrollment(char *pin)
{
	bool bRet = true;
	int len;
	char *sendBuf;
	unsigned long now;


	TUTRACE((TUTRACE_INFO, "Starting WPS enrollment.\n"));

	now = wps_hook_get_current_time();
	if (wpssta_start_enrollment(pin, now) != WPS_SUCCESS) {
		TUTRACE((TUTRACE_ERR, "Start enrollment failed.\n"));
		bRet = false;
		goto err;
	}

	/*
	 * Start the process by sending the eapol start . Created from the
	 * Enrollee SM Initialize.
	 */
	len = wps_get_msg_to_send(&sendBuf, (uint32)now);
	if (sendBuf) {
		int msg_type = WPS_PRIVATE_ID_EAPOL_START;

		/* Update status */
		wps_api_status_cb(&wps_api_wksp->cb, wps_api_wksp->cb_ctx,
			WPS_STATUS_STARTING_WPS_EXCHANGE, NULL);

		wps_hook_send_eapol_packet(sendBuf, len);

		/* Update status */
		wps_api_status_cb(&wps_api_wksp->cb, wps_api_wksp->cb_ctx,
			WPS_STATUS_SENDING_WPS_MESSAGE, &msg_type);

		TUTRACE((TUTRACE_INFO, "Send EAPOL-Start\n"));
	}
	else {
		/* This means the system is not initialized */
		/* Update status */
		wps_api_status_cb(&wps_api_wksp->cb, wps_api_wksp->cb_ctx,
			WPS_STATUS_WARNING_NOT_INITIALIZED, NULL);

		TUTRACE((TUTRACE_ERR, "WPS library not initialized.\n"));
		bRet = false;
		goto err;
	}

err:
	return bRet;
}

static void
_wps_api_get_random_credential(WpsEnrCred *credential)
{
	uint8 mac[6];
	char macString[18];

	memset(credential, 0, sizeof(WpsEnrCred));

	/* mac */
	wps_hook_get_mac(mac);
	sprintf(macString, "%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	/* ssid */
	wps_gen_ssid(credential->ssid, sizeof(credential->ssid), NULL, macString);

	/* network key */
	wps_gen_key(credential->nwKey, sizeof(credential->nwKey));
	credential->nwKeyLen = (uint32)strlen(credential->nwKey);

	/* keyMgmt, WPA2-PSK/AES is compatible in V1 and V2 */
	strcpy(credential->keyMgmt, "WPA2-PSK");

	/* Crypto */
	credential->encrType = ENCRYPT_AES;
}


/* Given a list of wps aps, find the pbc ap and set it to the first one in the given ap list */
static int
_wps_api_get_pbc_ap(wps_ap_list_info_t *list_inout, int count, int *nAP)
{
	char bssid[6]; /* bssid is a 48-bit identifier */
	char ssid[33] = { 0 };
	uint8 wep = 1;
	int nRet = PBC_NOT_FOUND;
	int i = 0;


	*nAP = 0;
	nRet = wps_get_pbc_ap(&list_inout[0], bssid, ssid, &wep,
		wps_hook_get_current_time(), (char)1);
	if (nRet == PBC_FOUND_OK) {
		/*
		 * Search the wps ap list and set the pbc ap (only one is allowed currently)
		 * to the first one in this given ap list
		 */
		while (i < count) {
			if (memcmp(list_inout[i].BSSID, bssid, sizeof(bssid)) == 0) {
				/* if i=0, the list one in the ap list is pbc ap, no need to copy */
				if (i > 0)
					memcpy(&list_inout[0], &list_inout[i],
						sizeof(wps_ap_list_info_t));
				*nAP = 1;
				break;
			}
			i++;
		}
	}

	return nRet;
}

/* Given a list of wps aps, find the pbc ap and set it to the first one in the given ap list */
static int
_wps_api_get_amac_ap(wps_ap_list_info_t *list_inout, int count, int *nAP,
	uint8 *mac, bool b_wc, bool *b_pbcap)
{
	char bssid[6]; /* bssid is a 48-bit identifier */
	char ssid[33] = { 0 };
	uint8 wep = 1;
	int nRet = AUTHO_MAC_NOT_FOUND;
	int i = 0;


	*nAP = 0;
	nRet = wps_get_amac_ap(&list_inout[0], mac, b_wc ? 1 : 0, bssid, ssid, &wep,
		wps_hook_get_current_time(), (char)1);
	if (nRet == AUTHO_MAC_PBC_FOUND || nRet == AUTHO_MAC_WC_PBC_FOUND ||
	    nRet == AUTHO_MAC_PIN_FOUND || nRet == AUTHO_MAC_WC_PIN_FOUND) {
		/*
		 * Search the wps ap list and set the found ap
		 * to the first one in this given ap list
		 */
		while (i < count) {
			if (memcmp(list_inout[i].BSSID, bssid, sizeof(bssid)) == 0) {
				/*
				 * if i=0, the list one in the ap list is found ap,
				 * no need to copy
				 */
				if (i > 0)
					memcpy(&list_inout[0], &list_inout[i],
						sizeof(wps_ap_list_info_t));
				*nAP = 1;
				if (b_pbcap != NULL && (nRet == AUTHO_MAC_PBC_FOUND ||
				    nRet == AUTHO_MAC_WC_PBC_FOUND))
					*b_pbcap = true;
				break;
			}
			i++;
		}
	}

	return nRet;
}

static bool
_wps_api_compare_mac(const uint8 *mac1, const uint8 *mac2)
{
	int i;

	if (mac1 == NULL || mac2 == NULL)
		return false;

	for (i = 0; i < 6; i++)
		if (mac1[i] != mac2[i])
			return false;

	return true;
}

#ifdef ASYNC_MODE
static int
_wps_api_process_event(void)
{
	int retVal;

	wps_api_wksp->buf_len = sizeof(wps_api_wksp->buf);

	retVal = wps_api_poll_eapol_packet(wps_api_wksp->buf, &wps_api_wksp->buf_len);
	if (retVal != WPS_STATUS_SUCCESS)
		return retVal;

	/* Now we only process WPS event */
	retVal = wps_api_process_data(wps_api_wksp->buf, wps_api_wksp->buf_len);
	if (retVal == WPS_STATUS_SUCCESS) {
		return WPS_STATUS_SUCCESS;
	}
	else if (retVal == WPS_STATUS_REJOIN) {
		if (wps_api_join(wps_api_wksp->bssid, wps_api_wksp->ssid, wps_api_wksp->wep)
			== FALSE) {
			/* Connecting Failed */
			TUTRACE((TUTRACE_ERR, "\nConnecting %s failed\n", wps_api_wksp->ssid));
			return WPS_STATUS_ERROR;
		}
		/* Tell wps_api link up */
		wps_api_set_linkup();

		return WPS_STATUS_REJOIN;
	}
	else if (retVal == WPS_STATUS_ERROR)
		return WPS_STATUS_ERROR;

	return WPS_STATUS_IDLE;
}

/*
 * This function starts the WPS exchange protocol and gathers the credentials
 * of the AP. Call this function once wps_api_join is successful.
 *
 * This function will return only once the WPS exchange is finished or an
 * error occurred.
 *
 * The calling process provides a callback function in wps_api_open() that will be called
 * periodically by the WPS API. When called, this callback function will be provided with
 * the current status. If the calling process wants to cancel the WPS protocol, it should
 * return FALSE (upon the user pressing a Cancel button, for example).
 *
 * If the calling process does not want to be called back, it should send NULL as a function
 * pointer.
 *
 * GUI applications should use the asynchronous version of this function so as not to block or
 * slow down a UI's message loop.
*/
static bool
_wps_api_get_ap_info(void)
{
	int retVal;

	TUTRACE((TUTRACE_INFO, "Entered : wps_get_AP_info\n"));

	while (1) {
		/* Event process */
		retVal = _wps_api_process_event();
		switch (retVal) {
		case WPS_STATUS_SUCCESS:
		case WPS_STATUS_CANCELED:
		case WPS_STATUS_ERROR:
			goto done;

		default:
			break;
		}

		/* Now we only process WPS timeout */
		retVal = wps_api_process_timeout();
		if (retVal == WPS_STATUS_ERROR || retVal == WPS_STATUS_SUCCESS)
			goto done;

		if (retVal == WPS_STATUS_REJOIN) {
			if (wps_api_join(wps_api_wksp->bssid, wps_api_wksp->ssid,
				wps_api_wksp->wep) == FALSE) {
				/* Connecting Failed */
				TUTRACE((TUTRACE_ERR, "\nConnecting %s failed\n",
					wps_api_wksp->ssid));
				retVal = WPS_STATUS_ERROR;
				goto done;
			}
			/* Tell wps_api link up */
			wps_api_set_linkup();
		}

		/* User canceled */
		if (wps_api_wksp->b_abort) {
			TUTRACE((TUTRACE_INFO, "\nUser canceled\n"));
			retVal = WPS_STATUS_CANCELED;
			goto done;
		}

		/* Sleep is needed so the async thread does not hog the CPU */
		WpsSleepMs(10);
	}

done:
	wps_api_status_cb(&wps_api_wksp->cb, wps_api_wksp->cb_ctx, retVal, NULL);
	if (retVal == WPS_STATUS_SUCCESS)
		return true;
	return false;
}

static void *
_wps_api_main_thread(void *lpParam)
{
	_wps_api_get_ap_info();

	return NULL;
}

/*
 * Asynchronous version of wps_get_AP_info(). This function returns immediately and starts
 * the WPS protocol in a separate thread.  The calling process uses the status callback to
 * determine the state of the WPS protocol.
 *
 * The calling process will get a WPS_STATUS_SUCCESS once the WPS protocol completed successfully
 * The calling process will get a WPS_STATUS_ERROR if the WPS protocol completed unsuccessfully
 * The calling process will get a WPS_STATUS_CANCELED if the WPS protocol was canceled by the
 * calling thread
 *
 * The calling process must wait for any one of these 3 status notifications or any error
 * notification before calling wps_api_close() or terminating.
 *
 * Unlike the synchronous version of this API call, the callback parameter in wps_api_open() CANNOT
 * be NULL.
 * A callback is required for this function to work correctly.
 *
 * Before this function returns, it will call the calling process' callback with a status of
 * WPS_STATUS_START_WPS_EXCHANGE
*/
static bool
_wps_api_get_ap_infoEx(void)
{
	TUTRACE((TUTRACE_INFO, "Entered : wps_get_AP_infoEx\n"));

	if (wps_api_wksp == NULL)
		return FALSE;

	if (wps_api_wksp->cb == NULL)
		return FALSE;

	if (wps_api_wksp->async_thread)
		return FALSE;

	wps_api_wksp->async_thread = wps_hook_thread_create(_wps_api_main_thread, NULL);

	if (wps_api_wksp->async_thread == NULL)
		return FALSE;

	return TRUE;
}
#endif /* ASYNC_MODE */

/* WPS API private functions for sub-files */
void
wps_api_status_cb(fnWpsProcessCB *cb, void *cb_ctx, unsigned int uiStatus, void *data)
{
	wps_credentials credentials;

	if (uiStatus == WPS_STATUS_SUCCESS) {
		/* Call get credentials to update the b_secure_nw */
		wps_api_get_credentials(&credentials);
	}

	wps_hook_update_led(uiStatus, wps_api_wksp ? wps_api_wksp->b_secure_nw : FALSE);

	if ((*cb) == NULL)
		return; /* no status_cb provided */

	/* Call back to update status */
	(*cb)(cb_ctx, uiStatus, data);

	if (uiStatus == WPS_STATUS_SUCCESS || uiStatus == WPS_STATUS_ERROR) {
		/* Disable any more notification to the client at this point */
		*cb = NULL;
	}
}


/* *************************************************** */
/* WPS SDK APIs                                                                                  */
/* *************************************************** */
/* wps_api_open function must be called first, before any other wps api call */
BCM_WPSAPI bool
#ifdef WFA_WPS_20_TESTBED
wps_api_open(const char *adapter_id, void *cb_ctx, fnWpsProcessCB callback, wps_devinf *devinf,
	wps20_testbed_inf *wps20_tbinf, bool ap_pin, bool b_v2)
#else
wps_api_open(const char *adapter_id, void *cb_ctx, fnWpsProcessCB callback, wps_devinf *devinf,
	bool ap_pin, bool b_v2)
#endif /* WFA_WPS_20_TESTBED */
{
	TUTRACE((TUTRACE_INFO, "Entered : wps_api_open\n"));

	/* Duplicate wps_api_open detection */
	if (wps_api_wksp)
		return false;

	/* Allocate wps_api_wksp */
	wps_api_wksp = (WPS_API_T *)malloc(sizeof(WPS_API_T));
	if (wps_api_wksp == NULL)
		return false;

	memset(wps_api_wksp, 0, sizeof(WPS_API_T));

	/* Allocate wps_devinf */
	wps_api_wksp->devinf = (wps_devinf *)malloc(sizeof(wps_devinf));
	if (wps_api_wksp->devinf == NULL)
		return false;

#ifdef WFA_WPS_20_TESTBED
	/* Allocate wps20_testbed_inf */
	wps_api_wksp->wps20_tbinf = (wps20_testbed_inf *)malloc(sizeof(wps20_testbed_inf));
	if (wps_api_wksp->wps20_tbinf == NULL)
		return false;
#endif /* WFA_WPS_20_TESTBED */

	wps_api_wksp->state = STATE_LINKDOWN;
	wps_api_wksp->b_ap_pin = ap_pin;
	wps_api_wksp->cb_ctx = cb_ctx;
	wps_api_wksp->cb = callback;
	wps_api_wksp->b_v2 = b_v2;
	wps_api_wksp->b_secure_nw = false;

	if (devinf)
		*wps_api_wksp->devinf = *devinf;
	else {
		/* Copy default */
		wps_api_wksp->devinf->primDeviceCategory = 1;
		wps_api_wksp->devinf->primDeviceSubCategory = 1;
		strcpy(wps_api_wksp->devinf->deviceName, "Broadcom Registrar");
		strcpy(wps_api_wksp->devinf->manufacturer, "Broadcom");
		strcpy(wps_api_wksp->devinf->modelName, "WPS Wireless Registrar");
		strcpy(wps_api_wksp->devinf->modelNumber, "1234");
		strcpy(wps_api_wksp->devinf->serialNumber, "5678");
	}

#ifdef WFA_WPS_20_TESTBED
	if (wps20_tbinf)
		*wps_api_wksp->wps20_tbinf = *wps20_tbinf;
	else
		memset(wps_api_wksp->wps20_tbinf, 0, sizeof(wps20_testbed_inf));
#endif /* WFA_WPS_20_TESTBED */

	wps_api_status_cb(&wps_api_wksp->cb, wps_api_wksp->cb_ctx, WPS_STATUS_INIT, NULL);

	/* WPS hook init for adapter and led (HW) */
	if (wps_hook_init(cb_ctx, callback, adapter_id) == false) {
		TUTRACE((TUTRACE_ERR, "wps_api_open : Failed to initial wireless adapter.\n"));
		return false;
	}

	/* WPS wl init for (SW) */
	if (wps_wl_init(cb_ctx, callback) == false) {
		TUTRACE((TUTRACE_ERR, "wps_api_open : Open WL failed.\n"));
		return false;
	}

	if (wps_api_wksp->b_ap_pin) {
		/* WSC 2.0, preliminary _wps_api_reg_config_init for adding WPS IE in probe req */
		_wps_api_reg_config_init(NULL, NULL);
	}
	else {
		/*
		* Setup device configuration for WPS needs to be done before eventual
		* scan for PBC.
		*/
		_wps_api_config_init();
	}

	TUTRACE((TUTRACE_INFO, "Exit : wps_api_open\n"));
	return true;
}

/* wps_api_close function must be called once you are done using the wps api */
BCM_WPSAPI bool
wps_api_close(void)
{
	TUTRACE((TUTRACE_INFO, "Entered : wps_api_close\n"));

	if (wps_api_wksp == NULL)
		return false;

	if (wps_api_wksp->devinf)
		free(wps_api_wksp->devinf);

#ifdef WFA_WPS_20_TESTBED
	if (wps_api_wksp->wps20_tbinf)
		free(wps_api_wksp->wps20_tbinf);
#endif /* WFA_WPS_20_TESTBED */

	if (wps_api_wksp->pin)
		free(wps_api_wksp->pin);

	/* Clean up engine */
	wps_cleanup();

	/* Remove WPS IE */
	rem_wps_ie(NULL, 0, VNDR_IE_PRBREQ_FLAG);
	if (wps_api_wksp->b_v2)
		rem_wps_ie(NULL, 0, VNDR_IE_ASSOCREQ_FLAG);

	wps_wl_deinit();
	wps_hook_deinit();

	/* No move status call back */
	wps_api_wksp->cb_ctx = NULL;
	wps_api_wksp->cb = NULL;

	/* Free wps_api_wksp */
	free(wps_api_wksp);
	wps_api_wksp = NULL;

	TUTRACE((TUTRACE_INFO, "Exit : wps_api_close\n"));
	return true;
}

BCM_WPSAPI void
wps_api_abort(void)
{
	TUTRACE((TUTRACE_INFO, "Entered : wps_api_abort\n"));

	/* Hook osl abort */
	wps_hook_abort();

#ifdef ASYNC_MODE
	if (wps_api_wksp && wps_api_wksp->async_thread) {
		wps_api_wksp->b_abort = true;
		/* Wait for thread terminated */
		wps_hook_thread_join(wps_api_wksp->async_thread, NULL);
	}
#else
	TUTRACE((TUTRACE_ERR, "Async mode not supported\n"));
#endif /* ASYNC_MODE */
}

BCM_WPSAPI bool
wps_api_run(enum eWPS_MODE mode, uint8 *bssid, char *ssid, uint8 wep, char *pin,
	wps_credentials *new_cred, bool b_async)
{
	bool bRet = true;
	uint band_num, active_band;
	uint8 *bssid_ptr = bssid;
	uint8 cur_bssid[6];
	uint32 pin_len = pin ? (uint32)strlen(pin) : 0;
	WpsEnrCred wps_enr_cred, *enr_cred = NULL;


	if (wps_api_wksp == NULL) {
		TUTRACE((TUTRACE_ERR, "WPS not opened, Quit....\n"));
		bRet = false;
		goto err;
	}

	/* Construct WpsEnrCred if we have new_cred */
	if (new_cred) {
		wps_api_wksp->b_new_cred = true;

		enr_cred = &wps_enr_cred;
		memset(enr_cred, 0, sizeof(WpsEnrCred));
		strcpy(enr_cred->ssid, new_cred->ssid);
		enr_cred->ssidLen = (uint32)strlen(new_cred->ssid);
		enr_cred->encrType = new_cred->encrType;
		strcpy(enr_cred->keyMgmt, new_cred->keyMgmt);
		strcpy(enr_cred->nwKey, new_cred->nwKey);
		enr_cred->nwKeyLen = (uint32)strlen(new_cred->nwKey);
	}

	/* Update specific RF band */
	wps_get_bands(&band_num, &active_band);
	if (active_band == WLC_BAND_5G)
		active_band = WPS_RFBAND_50GHZ;
	else if (active_band == WLC_BAND_2G)
		active_band = WPS_RFBAND_24GHZ;
	else
		active_band = WPS_RFBAND_24GHZ;
	wps_update_RFBand((uint8)active_band);

	/* If user_bssid not defined, use associated AP's */
	if (!bssid_ptr) {
		if (wps_get_bssid((char *)cur_bssid)) {
			TUTRACE((TUTRACE_ERR, "Can not get [%s] BSSID, Quit....\n", ssid));
			bRet = false;
			goto err;
		}
		bssid_ptr = cur_bssid;
	}

	/* Setup raw 802.1X socket with "bssid" destination  */
	if (wps_hook_setup_802_1x((char *)bssid_ptr) != WPS_SUCCESS) {
		TUTRACE((TUTRACE_ERR, "Initializing 802.1x raw socket failed.\n"
			"Check PF PACKET support in kernel.\n"));
		bRet = false;
		goto err;
	}

	/* Start registration or enrollment */
	wps_api_wksp->mode = mode;
	memcpy(wps_api_wksp->bssid, bssid_ptr, sizeof(wps_api_wksp->bssid));
	memcpy(wps_api_wksp->ssid, ssid, sizeof(wps_api_wksp->ssid));
	wps_api_wksp->ssid[sizeof(wps_api_wksp->ssid)-1] = '\0';
	wps_api_wksp->wep = wep;
	if (pin_len) {
		if ((wps_api_wksp->pin = malloc(pin_len + 1)) == NULL) {
			TUTRACE((TUTRACE_ERR, "Memory allocate for PIN failed.\n"));
			bRet = false;
			goto err;
		}
		strncpy(wps_api_wksp->pin, pin, pin_len);
		wps_api_wksp->pin[pin_len] = '\0';
	}
	else {
		if (wps_api_wksp->pin)
			free(wps_api_wksp->pin);
		wps_api_wksp->pin = NULL;
	}

	wps_api_wksp->start_time = wps_hook_get_current_time();

	if (wps_api_wksp->b_ap_pin) {
		/* Clean up for preliminary _wps_api_reg_config_init */
		wps_cleanup();

		/* Setup device configuration for WPS */
		_wps_api_reg_config_init(enr_cred, (char *)bssid_ptr);

		/* Launch registration */
		if (_wps_api_do_registration(wps_api_wksp->pin) == false) {
			TUTRACE((TUTRACE_ERR, "Start registration failed.\n"));
			bRet = false;
			goto err;
		}
	}
	else {
		/* Launch first enrollment try */
		if (_wps_api_do_enrollment(wps_api_wksp->pin) == false) {
			TUTRACE((TUTRACE_ERR, "Start enrollment failed.\n"));
			bRet = false;
			goto err;
		}
	}

	/* Loop for Async mode */
	if (b_async) {
#ifdef ASYNC_MODE
		/* Create a thread and execute process loop */
		bRet = _wps_api_get_ap_infoEx();
		if (bRet == false) {
			TUTRACE((TUTRACE_ERR, "Async mode execution failed.\n"));
		}
#else
		bRet = false;
		TUTRACE((TUTRACE_ERR, "Async mode not support.\n"));
#endif
	}

err:
	if (bRet == false) {
		/* Update status */
		wps_api_status_cb(&wps_api_wksp->cb, wps_api_wksp->cb_ctx, WPS_STATUS_ERROR, NULL);
	}

	return bRet;
}

BCM_WPSAPI uint32
wps_api_process_data(char *buf, uint32 buf_len)
{
	uint32 retVal;
	char *sendBuf;
	int len;
	int last_recv_msg;
	int state;
	int msg_type = 0;
	char *msg_str;
	unsigned long now = wps_hook_get_current_time();


	/* Show receive message */
	msg_type = (int)wps_get_msg_type(buf, buf_len);
	msg_str = wps_get_msg_string(msg_type);

	TUTRACE((TUTRACE_INFO, "Receive EAP-Request%s\n", msg_str));
	/* Update status */
	wps_api_status_cb(&wps_api_wksp->cb, wps_api_wksp->cb_ctx,
		WPS_STATUS_GOT_WPS_RESPONSE, &msg_type);

	/* Process ap message */
	retVal = wps_process_ap_msg(buf, buf_len);

	/* Check return code to do more things */
	if (retVal == WPS_SEND_MSG_CONT ||
	    retVal == WPS_SEND_MSG_SUCCESS ||
	    retVal == WPS_SEND_MSG_ERROR ||
	    retVal == WPS_ERR_ENROLLMENT_PINFAIL ||
	    retVal == WPS_ERR_REGISTRATION_PINFAIL) {
		len = wps_get_eapol_msg_to_send(&sendBuf, now);
		if (sendBuf) {
			msg_type = (int)wps_get_msg_type(sendBuf, len);
			msg_str = wps_get_msg_string(msg_type);

			wps_hook_send_eapol_packet(sendBuf, len);

			wps_api_status_cb(&wps_api_wksp->cb, wps_api_wksp->cb_ctx,
				WPS_STATUS_SENDING_WPS_MESSAGE, &msg_type);

			TUTRACE((TUTRACE_INFO, "Send EAP-Response%s\n", msg_str));
		}

		if (retVal == WPS_ERR_ENROLLMENT_PINFAIL ||
		    retVal == WPS_ERR_REGISTRATION_PINFAIL) {
			/* Update status */
			wps_api_status_cb(&wps_api_wksp->cb, wps_api_wksp->cb_ctx,
				WPS_STATUS_WRONG_PIN, wps_api_wksp->pin ? wps_api_wksp->pin : "");

			retVal = WPS_SEND_MSG_ERROR;
		}

		/*
		 * Sleep a short time for driver to send last WPS DONE message,
		 * otherwise doing leave_network before do_wpa_psk in
		 * enroll_device() may cause driver to drop the last WPS DONE
		 * message if it not transmit.
		 */
		if (retVal == WPS_SEND_MSG_SUCCESS ||
		    retVal == WPS_SEND_MSG_ERROR)
			WpsSleepMs(2);

		/* Over-write retVal */
		if (retVal == WPS_SEND_MSG_SUCCESS)
			return WPS_STATUS_SUCCESS;
		else if (retVal == WPS_SEND_MSG_ERROR)
			return WPS_STATUS_ERROR;
	}
	else if (retVal == EAP_FAILURE) {
		/* We received an eap failure from registrar */
		/*
		 * Check if this is coming AFTER the protocol passed the M2
		 * mark or is the end of the discovery after M2D.
		 */
		last_recv_msg = wps_get_recv_msg_id();
		TUTRACE((TUTRACE_INFO, "Received eap failure, last recv msg EAP-Request%s\n",
			wps_get_msg_string(last_recv_msg)));
		if (last_recv_msg > WPS_ID_MESSAGE_M2D) {
			/* Update status */
			wps_api_status_cb(&wps_api_wksp->cb, wps_api_wksp->cb_ctx,
				WPS_STATUS_WARNING_WPS_PROTOCOL_FAILED, NULL);

			return WPS_STATUS_ERROR;
		}

		/* Set link down, notify caller to re-join */
		wps_api_wksp->b_linkup = false;
		wps_api_wksp->state = STATE_WAIT_LINKUP;
		return WPS_STATUS_REJOIN;
	}
	/* Special case, without doing wps_eap_create_pkt */
	else if (retVal == WPS_SEND_MSG_IDRESP) {
		len = wps_get_msg_to_send(&sendBuf, now);
		if (sendBuf) {
			msg_type = WPS_PRIVATE_ID_IDENTITY;
			wps_hook_send_eapol_packet(sendBuf, len);

			wps_api_status_cb(&wps_api_wksp->cb, wps_api_wksp->cb_ctx,
				WPS_STATUS_SENDING_WPS_MESSAGE, &msg_type);

			TUTRACE((TUTRACE_INFO, "Send EAP-Response / Identity\n"));
		}
	}
	/* Re-transmit last sent message, because we receive a re-transmit packet */
	else if (retVal == WPS_SEND_RET_MSG_CONT) {
		len = wps_get_retrans_msg_to_send(&sendBuf, now, (char *)&msg_type);
		if (sendBuf) {
			state = wps_get_eap_state();

			if (state == EAPOL_START_SENT) {
				msg_type = WPS_PRIVATE_ID_EAPOL_START;
				TUTRACE((TUTRACE_INFO, "Re-Send EAPOL-Start\n"));
			}
			else if (state == EAP_IDENTITY_SENT) {
				msg_type = WPS_PRIVATE_ID_IDENTITY;
				TUTRACE((TUTRACE_INFO, "Re-Send EAP-Response / Identity\n"));
			}
			else {
				TUTRACE((TUTRACE_INFO, "Re-Send EAP-Response%s\n",
					wps_get_msg_string(msg_type)));
			}

			wps_hook_send_eapol_packet(sendBuf, len);

			wps_api_status_cb(&wps_api_wksp->cb, wps_api_wksp->cb_ctx,
				WPS_STATUS_SENDING_WPS_MESSAGE, &msg_type);
		}
	}
	else if (retVal == WPS_SEND_FRAG_CONT ||
		retVal == WPS_SEND_FRAG_ACK_CONT) {
		len = wps_get_frag_msg_to_send(&sendBuf, now);
		if (sendBuf) {
			if (retVal == WPS_SEND_FRAG_CONT) {
				msg_type = WPS_PRIVATE_ID_FRAG;
				msg_str = "FRAG";
			} else {
				msg_type = WPS_PRIVATE_ID_FRAG_ACK;
				msg_str = "FRAG_ACK";
			}

			wps_hook_send_eapol_packet(sendBuf, len);

			wps_api_status_cb(&wps_api_wksp->cb, wps_api_wksp->cb_ctx,
				WPS_STATUS_SENDING_WPS_MESSAGE, &msg_type);

			TUTRACE((TUTRACE_INFO, "Send EAP-Response(%s)\n", msg_str));
		}
	}
	else if (retVal == WPS_SUCCESS)
		return WPS_STATUS_SUCCESS;

	return WPS_STATUS_IDLE;
}

BCM_WPSAPI uint32
wps_api_process_timeout(void)
{
	int retVal, state;
	int last_recv_msg, last_sent_msg;
	int msg_type = 0;
	char *sendBuf, *msg_str;
	int len;
	unsigned long now = wps_hook_get_current_time();


	/* Overall 2 minutes checking */
	if (now > wps_api_wksp->start_time + PBC_WALK_TIME) {
		TUTRACE((TUTRACE_INFO, "Overall WPS negotiation timeout \n"));
		wps_api_status_cb(&wps_api_wksp->cb, wps_api_wksp->cb_ctx,
			WPS_STATUS_OVERALL_PROCESS_TIMEOUT, NULL);
		return WPS_STATUS_ERROR;
	}

	/* Link state handle */
	if (wps_api_wksp->state == STATE_LINKDOWN && wps_api_wksp->b_linkup)
		wps_api_wksp->state = STATE_LINKUP;

	if (wps_api_wksp->state == STATE_WAIT_LINKUP && wps_api_wksp->b_linkup) {
		wps_api_wksp->state = STATE_LINKUP;
		if (_wps_api_do_enrollment(wps_api_wksp->pin) == false) {
			TUTRACE((TUTRACE_ERR, "Start enrollment failed.\n"));
			wps_api_status_cb(&wps_api_wksp->cb, wps_api_wksp->cb_ctx,
				WPS_STATUS_ERROR, NULL);
			return WPS_STATUS_ERROR;
		}
	}

	/* Periodically check eap receive timer.  It might be time to re-transmit */
	if ((retVal = wps_eap_check_timer(now)) == WPS_SEND_RET_MSG_CONT) {
		len = wps_get_retrans_msg_to_send(&sendBuf, now, (char *)&msg_type);
		if (sendBuf) {
			state = wps_get_eap_state();

			if (state == EAPOL_START_SENT) {
				msg_type = WPS_PRIVATE_ID_EAPOL_START;
				TUTRACE((TUTRACE_INFO, "Re-Send EAPOL-Start\n"));
			}
			else if (state == EAP_IDENTITY_SENT) {
				msg_type = WPS_PRIVATE_ID_IDENTITY;
				TUTRACE((TUTRACE_INFO, "Re-Send EAP-Response / Identity\n"));
			}
			else {
				msg_str = wps_get_msg_string(msg_type);
				TUTRACE((TUTRACE_INFO, "Re-Send EAP-Response%s\n", msg_str));
			}

			wps_hook_send_eapol_packet(sendBuf, len);

			wps_api_status_cb(&wps_api_wksp->cb, wps_api_wksp->cb_ctx,
				WPS_STATUS_SENDING_WPS_MESSAGE, &msg_type);
		}
	}
	/* Re-transmission count exceeded, start other launch */
	else if (retVal == EAP_TIMEOUT) {
		last_recv_msg = wps_get_recv_msg_id();

		if (last_recv_msg == WPS_ID_MESSAGE_M2D) {
			TUTRACE((TUTRACE_INFO, "M2D Wait timeout, again.\n"));
		}
		else if (last_recv_msg > WPS_ID_MESSAGE_M2D) {
			last_sent_msg = wps_get_sent_msg_id();
			TUTRACE((TUTRACE_INFO, "Timeout, last recv/sent msg "
				"[EAP-Response%s/EAP-Request%s], again.\n",
				wps_get_msg_string(last_recv_msg),
				wps_get_msg_string(last_sent_msg)));
			if (last_recv_msg == WPS_ID_MESSAGE_M8 &&
			    last_sent_msg == WPS_ID_MESSAGE_NACK) {
			    /* Assume the AP didn't well handle NACK after sent M8 */
				return WPS_STATUS_ERROR;
			}
		}
		else {
			TUTRACE((TUTRACE_INFO, "Re-transmission count exceeded, again\n"));
		}

		/* Set link down, notify caller to re-join */
		wps_api_wksp->b_linkup = false;
		wps_api_wksp->state = STATE_WAIT_LINKUP;
		return WPS_STATUS_REJOIN;
	}
	else if (retVal == WPS_ERR_ADAPTER_NONEXISTED) {
		/* This is probably due to adapter being removed during wps */
		return WPS_STATUS_ERROR;
	}
	else if (retVal == WPS_SUCCESS)
		return WPS_STATUS_SUCCESS;

	return WPS_STATUS_IDLE;
}

/*
 * wps_api_find_ap scans for WPS PBC APs and returns the one with the strongest RSSI
 * Returns true if it finds an AP within the specified time. This function is designed to
 * be called repeatidly with small timeouts in seconds (say 4 or 5 secs) to allow for UI
 * updates and user cancelation. If multiple PBC APs are found, this is an error condition
 * and FALSE is returned. nAP will contain the number of PBC APs found (will be greater than 1).
 *
 * The value of *nAP is updated with the number of APs found. For PBC APs,
 * it will be always 1 on success (or if more than 1 is returned, the UI should warn
 * the user to try again later).
 * For PIN APs, it will varie from 0 to the max numbers of the list.

 * Call wps_api_get_ap to get the APs found
 */
/*
 * NOTE: Need to think about the original wps_findAP design purpose of timeout argument
 * Caller has to handle the timeout execption case.
*/
BCM_WPSAPI bool
wps_api_find_ap(struct wps_ap_list_info *wpsaplist, int *nAP, bool b_pbc,
	uint8 *mac, bool b_wc, bool *b_pbcap, bool b_auto)
{
	int wps_ap_total = 0;


	TUTRACE((TUTRACE_INFO, "Entered : wps_api_find_ap\n"));

	*nAP = 0;

	if (wps_api_wksp == NULL || wpsaplist == NULL)
		return false;

	if ((wps_ap_total = wps_get_aplist(wpsaplist, wpsaplist)) == 0)
		return false;

	/* AMAC check */
	if (mac) {
		_wps_api_get_amac_ap(wpsaplist, wps_ap_total, nAP, mac, b_wc, b_pbcap);
	} else if (b_auto) {
		/* Automatically WPS in PIN mode */
		*nAP = wps_get_pin_aplist(wpsaplist, wpsaplist);
	}
	else {
		if (b_pbc) {
			if (_wps_api_get_pbc_ap(wpsaplist, wps_ap_total, nAP) == PBC_OVERLAP) {
				wps_api_status_cb(&wps_api_wksp->cb, wps_api_wksp->cb_ctx,
					WPS_STATUS_SCANNING_OVER_SESSION_OVERLAP, NULL);
				*nAP = 2;
			}
		}
		else {
			*nAP = wps_ap_total;
		}
	}

	return (*nAP > 0);
}

/*
 * wps_api_get_ap returns the AP #nAP from the list of WPS APs found
 * by wps_api_find_apwps_api_find_ap.
 */
BCM_WPSAPI bool
wps_api_get_ap(int nAP, wps_apinf *apinf)
{
	int i = 0;
	wps_ap_list_info_t *ap;


	TUTRACE((TUTRACE_INFO, "Entered : wps_api_get_ap\n"));
	if (wps_api_wksp == NULL || apinf == NULL)
		return false;

	memset(apinf, 0, sizeof(wps_apinf));

	ap = wps_get_ap_list();
	if (nAP >= WPS_MAX_AP_SCAN_LIST_LEN || ap[nAP].used == FALSE)
		return false;

	for (i = 0; i < 6; i++)
		apinf->bssid[i] = ap[nAP].BSSID[i];

	memcpy(apinf->ssid, ap[nAP].ssid, ap[nAP].ssidLen);
	apinf->ssid[ap[nAP].ssidLen] = '\0';
	apinf->wep = ap[nAP].wep;
	apinf->band = ap[nAP].band;
	apinf->configured = (ap[nAP].scstate == WPS_SCSTATE_CONFIGURED);
	apinf->channel = ap[nAP].channel;

	if (wps_api_wksp->b_v2 && ap[nAP].version2 >= WPS_VERSION2) {
		apinf->version2 = ap[nAP].version2;
		memcpy(apinf->authorizedMACs, ap[nAP].authorizedMACs,
			sizeof(ap[nAP].authorizedMACs));
	}
	else
		apinf->version2 = 0;
	return true;
}

BCM_WPSAPI bool
wps_api_wps_is_reg_activated(const uint8 *bssid)
{
	wps_ap_list_info_t *ap_list = wps_get_ap_list();
	int i = 0;

	for (i = 0; i < WPS_MAX_AP_SCAN_LIST_LEN; i++) {
		/* Find the ap according by comparing the mac address */
		if (_wps_api_compare_mac(bssid, ap_list[i].BSSID))
			return wps_get_select_reg(&ap_list[i]);
	}

	return false;
}

BCM_WPSAPI bool
wps_api_validate_checksum(char *pinStr)
{
	return wps_validate_pin(pinStr);
}

/* Cleanup and re-config */
BCM_WPSAPI bool
wps_api_auto_pin_reset(void *cb_ctx, fnWpsProcessCB callback)
{
	TUTRACE((TUTRACE_INFO, "Entered : wps_api_auto_pin_reset\n"));

	if (wps_api_wksp == NULL)
		return false;

	/* Clean up engine */
	wps_cleanup();

	wps_api_wksp->cb_ctx = cb_ctx;
	wps_api_wksp->cb = callback;
	wps_api_wksp->b_v2 = wps_api_wksp->b_v2_saved;

	wps_api_status_cb(&wps_api_wksp->cb, wps_api_wksp->cb_ctx, WPS_STATUS_INIT, NULL);

	/* Re config */
	_wps_api_config_init();

	return true;
}

/* Cleanup and re-config, force in WPS V1 */
BCM_WPSAPI bool
wps_api_force_v1_reset(void *cb_ctx, fnWpsProcessCB callback)
{
	TUTRACE((TUTRACE_INFO, "Entered : wps_api_auto_pin_reset\n"));

	if (wps_api_wksp == NULL)
		return false;

	/* Clean up engine */
	wps_cleanup();

	wps_api_wksp->cb_ctx = cb_ctx;
	wps_api_wksp->cb = callback;
	wps_api_wksp->b_v2_saved = wps_api_wksp->b_v2;
	wps_api_wksp->b_v2 = FALSE;

	wps_api_status_cb(&wps_api_wksp->cb, wps_api_wksp->cb_ctx, WPS_STATUS_INIT, NULL);

	/* Re config */
	_wps_api_config_init();

	return true;
}

BCM_WPSAPI bool
wps_api_get_dev_mac(uint8 *buf, uint8 len)
{
	int retVal;

	if (len < 6)
		return false;

	/* Get local device mac address */
	retVal = wps_osl_get_mac(buf);

	return ((retVal == WPS_OSL_SUCCESS) ? true : false);
}

/* HW Button */
BCM_WPSAPI bool
wps_api_hwbutton_supported(const char *guid)
{
	return wps_hook_hwbutton_supported(guid);
}

BCM_WPSAPI bool
wps_api_hwbutton_open(const char *guid)
{
	return wps_hook_hwbutton_open(guid);
}

BCM_WPSAPI void
wps_api_hwbutton_close()
{
	wps_hook_hwbutton_close();
}

BCM_WPSAPI bool
wps_api_hwbutton_state()
{
	return wps_hook_hwbutton_state();
}

BCM_WPSAPI bool
wps_api_generate_pin(char *pin, int buf_len)
{
	uint32 retVal;

	retVal = wps_gen_pin(pin, buf_len);

	if (retVal == WPS_SUCCESS)
		return true;

	return false;
}

BCM_WPSAPI bool
wps_api_generate_cred(wps_credentials *credentials)
{
	bool bRet = false;
	WpsEnrCred credNew;

	if (!credentials)
		return bRet;

	_wps_api_get_random_credential(&credNew);
	credentials->encrType = credNew.encrType;
	wps_strncpy(credentials->keyMgmt, credNew.keyMgmt, sizeof(credentials->keyMgmt));
	wps_strncpy(credentials->nwKey, credNew.nwKey, sizeof(credentials->nwKey));
	wps_strncpy(credentials->ssid, credNew.ssid, sizeof(credentials->ssid));
	credentials->wepIndex = 1;
	credentials->nwKeyShareable = credNew.nwKeyShareable;

	return true;
}

BCM_WPSAPI wps_credentials *
wps_api_get_credentials(wps_credentials *credentials)
{
	WpsEnrCred cred;

	if (wps_api_wksp == NULL)
		return NULL;

	memset(&cred, 0, sizeof(cred));

	if (wps_api_wksp->b_ap_pin) {
		if (wps_api_wksp->b_new_cred)
			wpssta_get_reg_M8credentials(&cred);
		else
			wpssta_get_reg_M7credentials(&cred);
	}
	else {
		wpssta_get_credentials(&cred, wps_api_wksp->ssid, (int)strlen(wps_api_wksp->ssid));
	}


	/* Output Wi-Fi credential */
	memset(credentials, 0, sizeof(wps_credentials));
	wps_strncpy(credentials->ssid, cred.ssid, sizeof(credentials->ssid));
	wps_strncpy(credentials->nwKey, cred.nwKey, sizeof(credentials->nwKey));
	wps_strncpy(credentials->keyMgmt, cred.keyMgmt, sizeof(credentials->keyMgmt));
	credentials->encrType = cred.encrType;
	if (credentials->encrType == WPS_ENCRTYPE_NONE)
		wps_api_wksp->b_secure_nw = FALSE;
	else
		wps_api_wksp->b_secure_nw = TRUE;

	credentials->wepIndex = 1;
	if (wps_api_wksp->b_v2)
		credentials->nwKeyShareable = cred.nwKeyShareable;

	return credentials;
}

BCM_WPSAPI void
wps_api_set_linkup(void)
{
	if (wps_api_wksp == NULL)
		return;

	wps_api_wksp->b_linkup = true;
}


/* ###### */
/*  OSL APIs */
/* ###### */
BCM_WPSAPI bool
wps_api_create_profile(const struct _wps_credentials *credentials)
{
	return wps_hook_create_profile(credentials);
}

BCM_WPSAPI uint32
wps_api_poll_eapol_packet(char *buf, uint32 *len)
{
	uint32 retVal = wps_hook_poll_eapol_packet(buf, len);

	if (retVal == WPS_SUCCESS)
		return WPS_STATUS_SUCCESS;
	if (retVal == WPS_ERR_ADAPTER_NONEXISTED)
		return WPS_STATUS_ERROR;

	return WPS_STATUS_IDLE;
}

/* ###### */
/*  WL APIs  */
/* ###### */
#ifdef WFA_WPS_20_TESTBED
BCM_WPSAPI bool
wps_api_set_wps_ie_frag_threshold(int threshold)
{
	if (set_wps_ie_frag_threshold(threshold) == 0)
		return TRUE;
	return FALSE;
}
BCM_WPSAPI bool
wps_api_set_sta_eap_frag_threshold(int threshold)
{
	if (sta_eap_sm_set_eap_frag_threshold(threshold) == 0)
		return TRUE;
	return FALSE;
}

BCM_WPSAPI bool
wps_api_update_prbreq_ie(uint8 *updie_str)
{
	if (set_update_partial_ie(updie_str, VNDR_IE_PRBREQ_FLAG) == 0)
		return TRUE;
	return FALSE;
}

BCM_WPSAPI bool
wps_api_update_assocreq_ie(uint8 *updie_str)
{
	if (set_update_partial_ie(updie_str, VNDR_IE_ASSOCREQ_FLAG) == 0)
		return TRUE;
	return FALSE;
}
#endif /* WFA_WPS_20_TESTBED */

BCM_WPSAPI wps_ap_list_info_t *
wps_api_surveying(bool b_pbc, bool b_v2, bool b_add_wpsie)
{
	return wps_wl_surveying(b_pbc, b_v2, b_add_wpsie);
}

BCM_WPSAPI bool
wps_api_join(uint8 *bssid, char *ssid, uint8 wep)
{
	uint band_num, active_band;
	bool retVal;

	retVal = wps_wl_join(bssid, ssid, wep);
	if (retVal == true) {
		/* Update specific RF band */
		wps_get_bands(&band_num, &active_band);
		if (active_band == WLC_BAND_5G)
			active_band = WPS_RFBAND_50GHZ;
		else if (active_band == WLC_BAND_2G)
			active_band = WPS_RFBAND_24GHZ;
		else
			active_band = WPS_RFBAND_24GHZ;
		wps_update_RFBand((uint8)active_band);
	}

	return retVal;
}

BCM_WPSAPI bool
wps_api_is_wep_incompatible(void)
{
	return (wps_is_wep_incompatible(wps_api_wksp->b_ap_pin));
}

/* **************************************************** */
/* End WPS SDK APIs                                                                             */
/* **************************************************** */
