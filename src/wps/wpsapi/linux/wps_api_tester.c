/*
 * WPS API tester
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wps_api_tester.c 287159 2011-09-30 07:19:20Z $
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <typedefs.h>

#include <wps_sdk.h>
#include <wps_version.h>
#include <wps_api_osl.h>
#include "wps_api_tester.h"
#include <wpscommon.h>


typedef struct event_s
{
	int type;
	char buf[4096];
	uint32 buf_len;
} EVENT_T;

#define GET_EVENT_SUCCESS	1
#define GET_EVENT_ERROR		2
#define GET_EVENT_IDLE		3

#define EVENT_TYPE_WPS		1

#define PROCESS_RESULT_SUCCESS		1
#define PROCESS_RESULT_ERROR		2
#define PROCESS_RESULT_REJOIN		3
#define PROCESS_RESULT_CANCELED		4
#define PROCESS_RESULT_IDLE		5

/* Tester context structure */
typedef struct TESTER_S {
	bool b_async;
	TESTER_WPS_T *wps;
} TESTER_T;

TESTER_WPS_T g_wps;
TESTER_T g_tester;

int g_result = PROCESS_RESULT_IDLE;
unsigned int g_uiStatus = 0;


#ifdef TARGETENV_android
int
EnableSupplicantEvents(bool bEnable)
{
	FILE* ftp = NULL;
	char* filename = (char*)"/data/local/wlapps.lock";
	int iRet = 0;
	if (!bEnable) {
		if (access(filename, F_OK) != 0) {
			if ((ftp = fopen(filename, "w")) != NULL) {
				iRet = 1;
				fclose(ftp);
				WPS_PRINT(("Created %s\n", filename));
			}
		} else {
			iRet = 1;
		}
	} else {
		if (access(filename, F_OK) == 0) {
			WPS_PRINT(("File found %s\n", filename));
			char cmd[80];
			snprintf(cmd, sizeof(cmd), "/system/bin/rm %s\n", filename);
			iRet = system(cmd);
			if (iRet == -1) {
				iRet = 0;
			} else {
				WPS_PRINT(("Deleted %s\n", filename));
				iRet = 1;
			}
		}
	}
	return iRet;
}
#endif /* TARGETENV_android */

/* ######## */
/* WPS STUFF   */
/* ######## */
/* Application main layer can define their own string */
static char* MY_WPS_MSG_STRS[] = {
	" NONE",
	"(BEACON)",
	"(PROBE_REQ)",
	"(PROBE_RESP)",
	"(M1)",
	"(M2)",
	"(M2D)",
	"(M3)",
	"(M4)",
	"(M5)",
	"(M6)",
	"(M7)",
	"(M8)",
	"(ACK)",
	"(NACK)",
	"(DONE)",
	" / Identity",
	"(Start)",
	"(FAILURE)",
	"(FRAG)",
	"(FRAG_ACK)",
	"(EAPOL-Start)"
};

static char *
_wps_print_my_msg_string(int mtype)
{
	if (mtype >= 0 && mtype <= (ARRAYSIZE(MY_WPS_MSG_STRS)-1))
		return MY_WPS_MSG_STRS[mtype];

	return MY_WPS_MSG_STRS[0];
}

static void
_wps_join_callback(void *context, unsigned int uiStatus, void *data)
{
	g_uiStatus = uiStatus;

	switch (uiStatus) {
	case WPS_STATUS_INIT:
		WPS_PRINT(("STATUS: INIT\n"));
		break;
	case WPS_STATUS_DISABLING_WIFI_MANAGEMENT:
		WPS_PRINT(("STATUS: DISABLING_WIFI_MANAGEMENT\n"));
		break;
	case WPS_STATUS_SCANNING:
		WPS_PRINT(("STATUS: SCANNING\n"));
		break;
	case WPS_STATUS_SCANNING_OVER:
		WPS_PRINT(("STATUS: SCANNING OVER\n"));
		break;
	case WPS_STATUS_ASSOCIATING:
		WPS_PRINT(("STATUS: ASSOCIATING TO %s\n", (char*) data));
		break;
	case WPS_STATUS_ASSOCIATED:
		WPS_PRINT(("STATUS: ASSOCIATED TO %s\n", (char*) data));
		break;
	case WPS_STATUS_STARTING_WPS_EXCHANGE:
		WPS_PRINT(("STATUS: STARTING_WPS_EXCHANGE\n"));
		break;
	case WPS_STATUS_SENDING_WPS_MESSAGE:
		WPS_PRINT(("STATUS: SENDING_WPS_MESSAGE %s\n",
			_wps_print_my_msg_string(*((int *)data))));
		break;
	case WPS_STATUS_WAITING_WPS_RESPONSE:
		WPS_PRINT(("STATUS: WAITING_WPS_RESPONSE\n"));
		break;
	case WPS_STATUS_GOT_WPS_RESPONSE:
		WPS_PRINT(("STATUS: GOT_WPS_RESPONSE %s\n",
			_wps_print_my_msg_string(*((int *)data))));
		break;
	case WPS_STATUS_DISCONNECTING:
		WPS_PRINT(("STATUS: DISCONNECTING\n"));
		break;
	case WPS_STATUS_ENABLING_WIFI_MANAGEMENT:
		WPS_PRINT(("STATUS: ENABLING_WIFI_MANAGEMENT\n"));
		break;
	case WPS_STATUS_SUCCESS:
		WPS_PRINT(("STATUS: SUCCESS\n"));
		break;
	case WPS_STATUS_CANCELED:
		WPS_PRINT(("STATUS: CANCELED\n"));
		break;
	case WPS_STATUS_WARNING_WPS_PROTOCOL_FAILED:
		WPS_PRINT(("STATUS: ERROR_WPS_PROTOCOL\n"));
		break;
	case WPS_STATUS_WRONG_PIN:
		WPS_PRINT(("STATUS: WPS_STATUS_WRONG_PIN %s\n", (char*) data));
		break;
	case WPS_STATUS_WARNING_NOT_INITIALIZED:
		WPS_PRINT(("STATUS: WARNING_NOT_INITIALIZED\n"));
		break;
	case WPS_STATUS_ERROR:
		WPS_PRINT(("STATUS: ERROR\n"));
		break;
	case WPS_STATUS_CREATING_PROFILE:
		WPS_PRINT(("STATUS: WPS_STATUS_CREATING_PROFILE\n"));
		break;
	case WPS_STATUS_OVERALL_PROCESS_TIMEOUT:
		WPS_PRINT(("STATUS: WPS_STATUS_OVERALL_PROCESS_TIMEOUT\n"));
		break;
	case WPS_STATUS_REJOIN:
		WPS_PRINT(("STATUS: WPS_STATUS_REJOIN\n"));
		break;
	case WPS_STATUS_IDLE:
		WPS_PRINT(("STATUS: IDLE\n"));
		break;
	default:
		WPS_PRINT(("STATUS: Unknown %d\n", uiStatus));
	}
}

static wps_devinf *
_wps_my_devinf(wps_devinf *my_devinf, char *ptransport_uuid)
{
	if (my_devinf == NULL)
		return NULL;

	/* Clear it */
	memset(my_devinf, 0, sizeof(wps_devinf));

	/* Set my device informations */
	my_devinf->primDeviceCategory = DEV_CAT_COMPUTER;
	my_devinf->primDeviceSubCategory = DEV_SUB_CAT_COMP_PC;
	strncpy(my_devinf->deviceName, "My Broadcom Registrar",
		sizeof(my_devinf->deviceName));
	strncpy(my_devinf->manufacturer, "My Broadcom",
		sizeof(my_devinf->manufacturer));
	strncpy(my_devinf->modelName, "My WPS Wireless Registrar",
		sizeof(my_devinf->modelName));
	strncpy(my_devinf->modelNumber, "0123456789",
		sizeof(my_devinf->modelNumber));
	strncpy(my_devinf->serialNumber, "9876543210",
		sizeof(my_devinf->serialNumber));

	/* Set my WCN-NET VP transport UUID */
	if (ptransport_uuid) {
		memcpy(my_devinf->transport_uuid, ptransport_uuid,
			sizeof(my_devinf->transport_uuid));
	}

	return my_devinf;
}

static void
abort_wps()
{
	TESTER_WPS_T *wps = g_tester.wps;

	if (wps == NULL)
		return;

	wps->b_abort = TRUE;
	wps_api_abort();
}

static void
hup_hdlr(int sig)
{
	g_result = PROCESS_RESULT_CANCELED;

	abort_wps();
}

static bool
wps_single_run(TESTER_WPS_T *wps, wps_credentials *new_cred, bool b_async)
{
	bool bSucceeded = TRUE;

	WPS_PRINT(("Connecting to WPS AP %s\n", wps->ssid));
	if (wps_api_join((uint8*)wps->bssid, wps->ssid, wps->wsec) == FALSE) {
		/* Connecting Failed */
		WPS_PRINT(("\nConnecting %s failed\n", wps->ssid));
		bSucceeded = FALSE;
		goto err;
	}
	/* Inform link up */
	wps_api_set_linkup();

	/* Connected AP */
	WPS_PRINT(("Connected to AP %s\n", wps->ssid));
	WPS_PRINT(("Getting credential of AP - %s.\n", wps->ssid));

	/* 5. Run WPS */
	if (wps_api_run(DEVICE_PASSWORD_ID(wps->b_appin, wps->pin, new_cred),
		(uint8 *)(STRP(wps->bssid)), wps->ssid, wps->wsec,
		STRP(wps->pin), new_cred, b_async) == FALSE) {
		WPS_PRINT(("\nRun WPS failed!\n"));
		bSucceeded = FALSE;
		goto err;
	}

err:
	return bSucceeded;
}

static bool
start_wps(TESTER_T *tester, int argc, char* argv[])
{
	bool bSucceeded = TRUE;
	bool bFoundAP = FALSE;
	int nAP = 0;
	bool bRet;
	wps_credentials *new_cred = NULL;
	wps_devinf my_devinf;
	TESTER_WPS_T *wps = &g_wps;


	if (tester == NULL)
		return FALSE;

	WPS_PRINT(("*********************************************\n"));
	WPS_PRINT(("WPS - Enrollee App Broadcom Corp.\n"));
	WPS_PRINT(("Version: %s\n", MOD_VERSION_STR));
	WPS_PRINT(("*********************************************\n"));


	/* Parse arguments */
	tester->wps = wps;
	bRet = ui_wps_parse_args(wps, &tester->b_async, argc, argv);
	if (bRet == FALSE) {
		bSucceeded = FALSE;
		goto err;
	}

	/*
	 * What we do:
	 * 1. UI select mode (Enrollee with PIN or PBC) (Registrar with AP's PIN)
	 * 2. Open WPS
	 * 3. UI get an WPS AP
	 * 4. Association
	 * 5. Run WPS
	*/

	/*
	 * 1. UI select mode (Enrollee with PIN or PBC) (Registrar with AP's PIN) and
	 * request PIN or PBC if user didn't specified in wpsenr/wpsreg.
	 */
	new_cred = ui_wps_select_mode(wps);

	/* establish a handler to handle SIGTERM. */
	signal(SIGINT, hup_hdlr);

	/* 2. Open WPS */
#ifdef WFA_WPS_20_TESTBED
	bRet = wps_api_open(STRP(wps->ifname), NULL, _wps_join_callback,
		_wps_my_devinf(&my_devinf, wps->transport_uuid), &wps->wps20_tbinf, wps->b_appin,
		wps->b_v2);
#else
	bRet = wps_api_open(STRP(wps->ifname), NULL, _wps_join_callback,
		_wps_my_devinf(&my_devinf, wps->transport_uuid), wps->b_appin, wps->b_v2);
#endif
	if (bRet == FALSE) {
		WPS_PRINT(("\nOpen WPS failed!\n"));
		bSucceeded = FALSE;
		goto err;
	}

	/* If scan requested, display and exit */
	if (wps->b_scan) {
		struct wps_ap_list_info *aplist = wps_api_surveying(FALSE, wps->b_v2, FALSE);
		if (aplist) {
			ui_display_aplist(wps->b_v2);
			WPS_PRINT(("\nWPS Enabled AP list:"));
			bFoundAP = wps_api_find_ap(aplist, &nAP, FALSE, NULL, FALSE, NULL, FALSE);
			if (bFoundAP)
				ui_display_aplist(wps->b_v2);
		}
		return FALSE;
	}

	/* 3. UI get an WPS AP */
	bFoundAP = ui_wps_find_ap(wps, DEVICE_PASSWORD_ID(wps->b_appin, wps->pin, new_cred),
		&nAP, wps->b_v2);
	if (bFoundAP == FALSE) {
		if (nAP == 0)
			WPS_PRINT(("\nNo WPS capable AP found!\n"));
		else if (nAP > 0)
			WPS_PRINT(("\nMultiple WPS PBC capable AP found with their button "
				"pressed!\nPlease try again in about 5mns.\n"));
		bSucceeded = FALSE;
		goto err;
	}

	/* 4. Association */
#ifdef TARGETENV_android
	EnableSupplicantEvents(FALSE);
#endif

	bSucceeded = wps_single_run(wps, new_cred, tester->b_async);

err:
	return bSucceeded;
}

static void
stop_wps()
{
	wps_api_close();

#ifdef TARGETENV_android
	EnableSupplicantEvents(TRUE);
#endif
}

/* ############# */
/* TESTER MAIN STUFF  */
/* ############# */
static int
process_success()
{
	char keystr[65] = {0};
	wps_credentials credentials;
	TESTER_WPS_T *wps = g_tester.wps;

	if (wps_api_get_credentials(&credentials) == NULL) {
		WPS_PRINT(("\nERROR: Unable to retrieve credential\n"));
		return PROCESS_RESULT_ERROR;
	}

	WPS_PRINT(("\nWPS AP Credentials:\n"));
	WPS_PRINT(("SSID = %s\n", credentials.ssid));
	WPS_PRINT(("Key Mgmt type is %s\n", credentials.keyMgmt));
	strncpy(keystr, credentials.nwKey, strlen(credentials.nwKey));
	WPS_DEBUG(("Key : %s\n", keystr));
	WPS_PRINT(("Encryption : "));
	if (credentials.encrType == WPS_ENCRYPT_NONE)
		WPS_PRINT(("NONE\n"));
	if (credentials.encrType & WPS_ENCRYPT_WEP)
		WPS_PRINT((" WEP"));
	if (credentials.encrType & WPS_ENCRYPT_TKIP)
		WPS_PRINT((" TKIP"));
	if (credentials.encrType & WPS_ENCRYPT_AES)
		WPS_PRINT((" AES"));

	if (wps->b_v2)
		WPS_PRINT(("\nNetwork Key Shareable :  %s\n",
			credentials.nwKeyShareable ? "TRUE" : "FALSE"));

	WPS_PRINT(("\n\nCreating profile\n"));
	if (wps_api_create_profile(&credentials) == FALSE) {
		WPS_PRINT(("\nERROR: Unable to create a profile\n"));
	}
	else {
		/* For Linux, set run_ip command */
		if (wps->run_ip)
			wps_osl_set_run_ip(wps->run_ip, wps->ip_addr,
				wps->b_def_dhclient ? NULL : wps->dhcp_cmd);

		WPS_PRINT(("\nSUCCESS: Created profile\n"));
	}

	return PROCESS_RESULT_SUCCESS;
}

static int
process_wps_event(EVENT_T *event)
{
	int retVal;
	TESTER_WPS_T *wps = g_tester.wps;

	/* Now we only process WPS event */
	retVal = wps_api_process_data(event->buf, event->buf_len);
	if (retVal == WPS_STATUS_SUCCESS) {
		return process_success();
	}
	else if (retVal == WPS_STATUS_REJOIN) {
		if (wps_api_join((uint8 *)wps->bssid, wps->ssid, wps->wsec) == FALSE) {
			/* Connecting Failed */
			WPS_PRINT(("\nConnecting %s failed\n", wps->ssid));
			return PROCESS_RESULT_ERROR;
		}
		/* Tell wps_api link up */
		wps_api_set_linkup();

		return PROCESS_RESULT_REJOIN;
	}
	else if (retVal == WPS_STATUS_ERROR) {
		/* Asking user if we need run WPS in V1 again */
		if (wps_api_is_wep_incompatible() == TRUE)
			ui_wps_wep_incompatible_notify(wps);

		return PROCESS_RESULT_ERROR;
	}

	return PROCESS_RESULT_IDLE;
}

static int
process_wps_timeout()
{
	int retVal;
	TESTER_WPS_T *wps = g_tester.wps;

	/* Now we only process WPS timeout */
	retVal = wps_api_process_timeout();
	if (retVal == WPS_STATUS_REJOIN) {
		if (wps_api_join((uint8 *)wps->bssid, wps->ssid, wps->wsec) == FALSE) {
			/* Connecting Failed */
			WPS_PRINT(("\nConnecting %s failed\n", wps->ssid));
			return PROCESS_RESULT_ERROR;
		}
		/* Tell wps_api link up */
		wps_api_set_linkup();

		return PROCESS_RESULT_REJOIN;
	}
	else if (retVal == WPS_STATUS_ERROR) {
		/* Asking user if we need run WPS in V1 again */
		if (wps_api_is_wep_incompatible() == TRUE)
			ui_wps_wep_incompatible_notify(wps);

		return PROCESS_RESULT_ERROR;
	}
	else if (retVal == WPS_STATUS_SUCCESS) {
		WPS_PRINT(("\nEAP-Failure not received in 10 seconds, assume WPS Success!\n"));
		return process_success();
	}

	return PROCESS_RESULT_IDLE;
}

static int
process_error_post_action(EVENT_T *event)
{
	if (event->type == EVENT_TYPE_WPS) {
		TESTER_WPS_T *wps = g_tester.wps;
		wps_apinf apinf;

		/* check if WPS need to run again in V1 mode */
		if (wps->b_force_v1) {
			/* reset before other single run start */
			if (wps_api_force_v1_reset(NULL, _wps_join_callback) == FALSE)
				return PROCESS_RESULT_ERROR;

			/* start WPS */
			printf("\nForce to connect to WPS V1 AP:%s\n", wps->ssid);
			sleep(1);

			if (wps_single_run(wps, NULL, FALSE) == FALSE)
				return PROCESS_RESULT_ERROR;

			return PROCESS_RESULT_IDLE;
		}
		/* check if WPS need to continue run auto pin */
		else if (wps->b_auto && !wps->b_abort && wps->ap_index < wps->ap_count) {
			/* reset before other single run start */
			if (wps_api_auto_pin_reset(NULL, _wps_join_callback) == FALSE)
				return PROCESS_RESULT_ERROR;

			/* Get next AP info */
			wps->ap_index++;
			if (wps_api_get_ap((wps->ap_index-1), &apinf) == FALSE)
				return PROCESS_RESULT_ERROR;

			memcpy(wps->bssid, apinf.bssid, 6);
			wps_strncpy(wps->ssid, apinf.ssid, sizeof(wps->ssid));
			wps->wsec = apinf.wep;

			/* get next ap info and start WPS */
			printf("\nTry next AP:%s\n", wps->ssid);
			sleep(1);

			if (wps_single_run(wps, NULL, FALSE) == FALSE)
				return PROCESS_RESULT_ERROR;

			return PROCESS_RESULT_IDLE;
		}
	}

	return PROCESS_RESULT_ERROR;
}

static int
get_event(EVENT_T *event)
{
	uint32 retVal;

	/* Now we only have WPS event */
	event->buf_len = sizeof(event->buf);
	retVal = wps_api_poll_eapol_packet(event->buf, &event->buf_len);
	if (retVal == WPS_STATUS_SUCCESS) {
		event->type = EVENT_TYPE_WPS;
		return GET_EVENT_SUCCESS;
	}
	else if (retVal == WPS_STATUS_ERROR) {
		event->type = EVENT_TYPE_WPS;
		return GET_EVENT_ERROR;
	}
	else
		return GET_EVENT_IDLE;
}

static int
process_event()
{
	int retVal;
	EVENT_T event;

	retVal = get_event(&event);
	if (retVal != GET_EVENT_SUCCESS) {
		if (retVal == GET_EVENT_ERROR)
			return process_error_post_action(&event);

		return PROCESS_RESULT_IDLE;
	}

	if (event.type == EVENT_TYPE_WPS) {
		retVal = process_wps_event(&event);
		if (retVal == PROCESS_RESULT_ERROR)
			retVal = process_error_post_action(&event);
	}

	return retVal;
}

static int
process_timeout()
{
	int retVal;
	EVENT_T event;

	retVal = process_wps_timeout();
	if (retVal == PROCESS_RESULT_ERROR) {
		event.type = EVENT_TYPE_WPS;
		retVal = process_error_post_action(&event);
	}

	return retVal;
}

static void
async_process()
{
	/* Async mode wait for thread exit */
	while (g_uiStatus != WPS_STATUS_SUCCESS &&
		g_uiStatus != WPS_STATUS_CANCELED &&
		g_uiStatus != WPS_STATUS_ERROR) {
		WPS_PRINT(("."));
		fflush(stdout);
		sleep(1);
	}
	WPS_PRINT(("\n"));

	if (g_uiStatus == WPS_STATUS_SUCCESS) {
		char keystr[65] = {0};
		wps_credentials credentials;

		if (wps_api_get_credentials(&credentials) == NULL) {
			WPS_PRINT(("\nERROR: Unable to retrieve credential\n"));
			return;
		}

		WPS_PRINT(("\nWPS AP Credentials:\n"));
		WPS_PRINT(("SSID = %s\n", credentials.ssid));
		WPS_PRINT(("Key Mgmt type is %s\n", credentials.keyMgmt));
		strncpy(keystr, credentials.nwKey, strlen(credentials.nwKey));
		WPS_DEBUG(("Key : %s\n", keystr));
		WPS_PRINT(("Encryption : "));
		if (credentials.encrType == WPS_ENCRYPT_NONE)
			WPS_PRINT(("NONE\n"));
		if (credentials.encrType & WPS_ENCRYPT_WEP)
			WPS_PRINT((" WEP"));
		if (credentials.encrType & WPS_ENCRYPT_TKIP)
			WPS_PRINT((" TKIP"));
		if (credentials.encrType & WPS_ENCRYPT_AES)
			WPS_PRINT((" AES"));

		WPS_PRINT(("\n\nCreating profile\n"));
		if (wps_api_create_profile(&credentials) == FALSE) {
			WPS_PRINT(("\nERROR: Unable to create a profile\n"));
		}
		else {
			WPS_PRINT(("\nSUCCESS: Created profile\n"));
		}
	}
	else {
		switch (g_uiStatus) {
		case WPS_STATUS_CANCELED:
			WPS_PRINT(("WPS protocol CANCELED by user\n"));
			break;
		case WPS_STATUS_ERROR:
			WPS_PRINT(("WPS protocol error\n"));
			break;
		default:
			WPS_PRINT(("WPS protocol error unknown\n"));
			break;
		}
	}
}

static void
process()
{
	/* Async mode */
	if (g_tester.b_async) {
		async_process();
		return;
	}

	/* Not Async mode */
	while (1) {
		/* Event process */
		switch (process_event()) {
		case PROCESS_RESULT_SUCCESS:
		case PROCESS_RESULT_CANCELED:
		case PROCESS_RESULT_ERROR:
			return;

		default:
			break;
		}

		/* Timeout process */
		switch (process_timeout()) {
		case PROCESS_RESULT_SUCCESS:
		case PROCESS_RESULT_ERROR:
		case PROCESS_RESULT_CANCELED:
			return;

		default:
			break;
		}

		/* User canceled */
		if (g_result == PROCESS_RESULT_CANCELED)
			break;
	}
}

int main(int argc, char* argv[])
{

	memset(&g_tester, 0, sizeof(TESTER_T));

	if (start_wps(&g_tester, argc, argv) == FALSE)
		goto done;

	process();

done:
	stop_wps();

	return 0;
}
