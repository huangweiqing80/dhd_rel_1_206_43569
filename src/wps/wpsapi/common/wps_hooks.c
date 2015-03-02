/*
 * Broadcom WPS Enrollee platform independent hook function
 *
 * This file is necessary for implementing the WPS API for WPS enrollee code.
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wps_hooks.c 470127 2014-04-14 04:14:51Z $
 */

#include <wpsheaders.h>
#include <tutrace.h>

#include "wps_sdk.h"
#include "wps_api_osl.h"


/* ########### */
/* Need OSL HOOKS */
/* ########### */
#ifdef _TUDEBUGTRACE
void
wps_hook_print_buf(unsigned char *buff, int buflen)
{
	wps_osl_print_buf(buff, buflen);
}
#endif /* _TUDEBUGTRACE */

#ifdef ASYNC_MODE
void *
wps_hook_thread_create(fnAsyncThread start_routine, void *arg)
{
	return wps_osl_thread_create(start_routine, arg);
}

int
wps_hook_thread_join(void *thread, void **value_ptr)
{
	return wps_osl_thread_join(thread, value_ptr);
}
#endif /* ASYNC_MODE */

bool
wps_hook_create_profile(const struct _wps_credentials *credentials)
{
	return wps_osl_create_profile(credentials);
}

int
wps_hook_get_mac(uint8 *mac)
{
	int retVal = wps_osl_get_mac(mac);
	return ((retVal == WPS_OSL_SUCCESS) ? WPS_SUCCESS : WPS_ERR_SYSTEM);
}

/* Initial HW related */
bool
wps_hook_init(void *cb_ctx, void *cb, const char *adapter_id)
{
	uint32 retVal = wps_osl_init(cb_ctx, cb, adapter_id);
	return ((retVal == WPS_OSL_SUCCESS) ? true : false);
}

uint32
wps_hook_setup_802_1x(char *bssid)
{
	uint32 retVal = wps_osl_setup_802_1x((uint8 *)bssid);
	return ((retVal == WPS_OSL_SUCCESS) ? WPS_SUCCESS : WPS_ERR_SYSTEM);
}

void
wps_hook_deinit()
{
	wps_osl_deinit();
}

void
wps_hook_abort()
{
	wps_osl_abort();
}

uint32
wps_hook_wait_for_eapol_packet(char *buf, uint32 *len, uint32 timeout)
{
	uint32 retVal = wps_osl_eap_read_data(buf, len, timeout);

	if (retVal == WPS_OSL_SUCCESS)
		return WPS_SUCCESS;
	else if (retVal == WPS_OSL_TIMEOUT)
		return PORTAB_ERR_WAIT_TIMEOUT;
	else if (retVal == WPS_OSL_ADAPTER_NONEXISTED)
		return WPS_ERR_ADAPTER_NONEXISTED;
	return WPS_ERR_SYSTEM;
}

uint32
wps_hook_send_eapol_packet(char *packet, uint32 len)
{
	uint32 retVal = wps_osl_eap_send_data(packet, len);
	return ((retVal == WPS_OSL_SUCCESS) ? WPS_SUCCESS : WPS_ERR_SYSTEM);
}

unsigned long
wps_hook_get_current_time()
{
	return wps_osl_get_current_time();
}

int
wps_hook_wl_ioctl(int cmd, void *buf, int len, bool set)
{
	return wps_osl_wl_ioctl(cmd, buf, len, set);
}

/* HW Button */
bool
wps_hook_hwbutton_supported(const char *guid)
{
	return wps_osl_hwbutton_supported(guid);
}

bool
wps_hook_hwbutton_open(const char *guid)
{
	return wps_osl_hwbutton_open(guid);
}

void
wps_hook_hwbutton_close()
{
	wps_osl_hwbutton_close();
}

bool
wps_hook_hwbutton_state()
{
	return wps_osl_hwbutton_state();
}

void
wps_hook_update_led(unsigned int uiStatus, bool b_secure_nw)
{
	wps_osl_update_led(uiStatus, b_secure_nw);
}

void
wps_setProcessStates(int state)
{
	return;
}

void
wps_setStaDevName(char *str)
{
	return;
}

void
wps_setPinFailInfo(uint8 *mac, char *name, char *state)
{
	return;
}

/* Prototype defined in portability.h */
uint32
WpsHtonl(uint32 intlong)
{
	return wps_osl_htonl(intlong);
}

/* Prototype defined in portability.h */
uint16
WpsHtons(uint16 intshort)
{
	return wps_osl_htons(intshort);
}

/* Prototype defined in portability.h */
void
WpsSleepMs(uint32 ms)
{
	wps_osl_sleep(ms); /* in MS */
}


/* ############# */
/*     Common HOOK     */
/* ############# */
/* Prototype defined in portability.h */
uint16
WpsHtonsPtr(uint8 * in, uint8 * out)
{
	uint16 v;
	uint8 *c;

	c = (uint8 *)&v;
	c[0] = in[0]; c[1] = in[1];
	v = WpsHtons(v);
	out[0] = c[0]; out[1] = c[1];

	return v;
}

/* Prototype defined in portability.h */
uint32
WpsHtonlPtr(uint8 * in, uint8 * out)
{
	uint32 v;
	uint8 *c;

	c = (uint8 *)&v;
	c[0] = in[0]; c[1] = in[1]; c[2] = in[2]; c[3] = in[3];
	v = WpsHtonl(v);
	out[0] = c[0]; out[1] = c[1]; out[2] = c[2]; out[3] = c[3];

	return v;
}

/* Prototype defined in portability.h */
uint32
WpsNtohl(uint8 *a)
{
	uint32 v;

	v = (a[0] << 24) + (a[1] << 16) + (a[2] << 8) + a[3];
	return v;
}

/* Prototype defined in portability.h */
uint16
WpsNtohs(uint8 *a)
{
	uint16 v;

	v = (a[0]*256) + a[1];
	return v;
}

/* Prototype defined in portability.h */
void
WpsSleep(uint32 seconds)
{
	WpsSleepMs(1000*seconds);
}

uint32
wps_hook_poll_eapol_packet(char *buf, uint32 *len)
{
	return wps_hook_wait_for_eapol_packet(buf, len, 0);
}
