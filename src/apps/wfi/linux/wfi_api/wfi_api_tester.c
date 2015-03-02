/* 
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wfi_api_tester.c,v 1.5 2010-05-13 23:30:19 $
 */

#include "wfi_api.h"
#include "wlioctl.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>

#define MAX_SSID_LEN 32

static int g_wfi_api_tester_done;
static 	wfi_param_t *wfi_handle = NULL;

static WFI_RET
wfi_event_monitor_start(wfi_param_t *wfi_handle);
static WFI_RET
wfi_event_monitor_stop();
void
wfi_rcv_wps_credentials(brcm_wpscli_nw_settings *credentials);

int g_quiet;

#ifdef DEBUG
#define DBGPRINT(x) printf x
#else
#define DBGPRINT(x)
#endif

void sigint_hndlr()
{
	g_wfi_api_tester_done = TRUE;
}

void
wfi_invite_rcvd_hndlr(wfi_context_t *context, void *param)
{
	char ssid[MAX_SSID_LEN+1];
	char bssid[MAX_SSID_LEN+1];
	char fname[49];
	char accept[20];

	DBGPRINT(("wfi_invite_rcvd_hndlr : Recieved a Wifi Invite... \n"));


	/* The validity checks for SSID len, FNAME len will be done by the WFI_API library. */
	strncpy(ssid, (char *)context->stBSS.ssid.SSID, context->stBSS.ssid.SSID_len);
	ssid[context->stBSS.ssid.SSID_len] = '\0';
	strncpy(fname, (char *)context->stWFI.fname.name, context->stWFI.fname.len);
	ssid[context->stWFI.fname.len] = '\0';
	sprintf(bssid, "%02X:%02X:%02X:%02X:%02X:%02X",
		context->stBSS.bssid.octet[0],
		context->stBSS.bssid.octet[1],
		context->stBSS.bssid.octet[2],
		context->stBSS.bssid.octet[3],
		context->stBSS.bssid.octet[4],
		context->stBSS.bssid.octet[5]);

	g_quiet = TRUE;
	printf("\r                            \r");
	printf("--------------------------------------------------------------\n");
	printf("A Wi-Fi Invite has been received. The details are as follows:\n");
	printf("SSID : %s\n", ssid);
	printf("BSSID : %s\n", bssid);
	printf("--------------------------------------------------------------\n");
	printf("Accept the Wi-Fi Invite? (Y/N/Q) : ");
	scanf("%s", accept);

	if ('Y' == accept[0] || 'y' == accept[0])
	{
		if (WFI_RET_SUCCESS != wfi_accept(wfi_handle, context))
			printf("WFI Accept failed.\n");
		else
		{
			wfi_rcv_wps_credentials(&wfi_handle->wps_cred);
			printf("This WI-FI invite has been accepted successfully\n");
		}

	}
	else if ('N' == accept[0] || 'n' == accept[0])
	{
		if (WFI_RET_SUCCESS != wfi_reject(wfi_handle, context))
			printf("WFI Reject failed.\n");
		else
			printf("This WI-FI invite has been rejected successfully\n");

		g_quiet = FALSE;

	}
	else
	{
		g_wfi_api_tester_done = TRUE;
	}

	DBGPRINT(("wfi_invite_rcvd_hndlr done\\n"));
}


void
wfi_rcv_wps_credentials(brcm_wpscli_nw_settings *credentials)
{
	char keystr[65] = { 0 };

	printf("--------------------------------------------------------------\n");
	printf("WPS AP Credentials:\n");
	printf("SSID = %s\n", credentials->ssid);
	strncpy(keystr, credentials->nwKey, strlen(credentials->nwKey));
	printf("Key : %s\n", keystr);

	printf("Authentication: : ");
	if (credentials->authType == BRCM_WPS_AUTHTYPE_OPEN)
		printf("OPEN\n");
	if (credentials->authType & BRCM_WPS_AUTHTYPE_SHARED)
		printf(" SHARED");
	if (credentials->authType & BRCM_WPS_AUTHTYPE_WPAPSK)
		printf(" WPAPSK");
	if (credentials->authType & BRCM_WPS_AUTHTYPE_WPA2PSK)
		printf(" WPA2PSK");
	printf("\n");

	printf("Encryption : ");
	if (credentials->encrType == BRCM_WPS_ENCRTYPE_NONE)
		printf("NONE\n");
	if (credentials->encrType & BRCM_WPS_ENCRTYPE_WEP)
		printf(" WEP");
	if (credentials->encrType & BRCM_WPS_ENCRTYPE_TKIP)
		printf(" TKIP");
	if (credentials->encrType & BRCM_WPS_ENCRTYPE_AES)
		printf(" AES");

	printf("\n");
	printf("--------------------------------------------------------------\n");
}
int main(int argc, char *argv[])
{
	int i = 0;

	printf("/*******************************************\\\n");
	printf("      Wi-Fi Invite Demo App                  \n");
	printf("\\*******************************************/\n");


	DBGPRINT(("Initializing...."));
	wfi_handle = wfi_init("WFI_API_TESTER", WFI_PIN_AUTO_GENERATE, TRUE);
	if (wfi_handle)
	{
		DBGPRINT(("Done.\n"));
		if (wfi_event_monitor_start(wfi_handle) != WFI_RET_SUCCESS)
		{
			wfi_deinit(wfi_handle);
			return -1;
		}

	}
	else
	{
		DBGPRINT(("WFI init failed.\n"));
		return -1;
	}
	wfi_handle->wfi_invite_rcvd_hndlr = wfi_invite_rcvd_hndlr;

	printf("WFI_API_TESTER successfully started.\nWaiting for Wi-Fi Invite.\n");

	while (!g_wfi_api_tester_done)
	{
		usleep(300000);
		i++;
		if (g_quiet)
			continue;
		if (i > 16)
		{
			i = 0;
			printf("\r                            \r");
		}
		else
			printf(".");
		fflush(stdout);
	}

	printf("\r                            \r");

	DBGPRINT(("De-Initializing WFI Library....\n"));
	wfi_event_monitor_stop();
	DBGPRINT(("thread stopped\n"));
	wfi_deinit(wfi_handle);
	DBGPRINT(("Done.\n"));

	return 0;

}

/* ------------ WFI PERIODIC SCAN THREAD -------------------- */

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
unsigned int wfi_evt_thread_sleep(wfi_param_t *wfi_handle, unsigned int interval)
{
	WFI_EVENT evt = WFI_EVENT_NONE;
	const unsigned int sec_num = 1000;

	while (interval >= sec_num && !g_evt_thread_done) {
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

/* g_evt_thread_hndlr : Handle to the thread that does
 * periodic WFI scan for WFI IEs.
 */

void* wfi_evt_thread(void* param)
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
		else if (ret == WFI_RET_ERROR)
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
	g_evt_thread_done = FALSE;
	g_active = TRUE;
	pthread_mutex_init(&g_evt_thread_completed_mutex, NULL);
	pthread_cond_init(&g_evt_thread_completed, NULL);

	if (0 == pthread_create(&g_evt_thread_hndlr, NULL, wfi_evt_thread, wfi_handle))
		return WFI_RET_SUCCESS;
	else
		return WFI_RET_ERR_UNKNOWN;
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
	else
	{
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
			DBGPRINT(("wfi_event_monitor_stop:"));
			DBGPRINT(("Thwfi_wps_process_callbacke waiting thread "));
			DBGPRINT(("did not stop within 10 seconds. Terminating the thread."));
			pthread_kill(g_evt_thread_hndlr, SIGTERM);
			return WFI_RET_ERR_UNKNOWN;
		}
	}
}

/* --------- End of WFI PERIODIC SCAN THREAD implemenation ------------ */
