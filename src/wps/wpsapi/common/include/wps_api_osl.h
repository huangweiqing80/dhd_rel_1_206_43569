/*
 * WPS API OSL header file
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wps_api_osl.h 368046 2012-11-11 00:40:51Z $
 */

#ifndef __WPS_API_OSL_H__
#define __WPS_API_OSL_H__

#ifdef __cplusplus
extern "C" {
#endif

enum {
	WPS_OSL_SUCCESS = 0,
	WPS_OSL_ERROR,
	WPS_OSL_TIMEOUT,
	WPS_OSL_ADAPTER_NONEXISTED
};

#ifdef WIN32
#include <string.h>
#include <ctype.h>
#define strcasecmp(s1, s2)	_stricmp((s1), (s2))
#define bcopy(s, d, n)	memmove((d), (s), (n))
#else /* Linux */
#include <string.h>
#include <ctype.h>

#define WPS_PRINT(args)	printf args
#ifdef DEBUG
#define WPS_DEBUG(args)	WPS_PRINT(args)
#else
#define WPS_DEBUG(args)
#endif

#endif /* WIN32 */

#include "bcmendian.h"

#ifdef ASYNC_MODE
typedef void *(*fnAsyncThread)(void *arg);
extern void *wps_osl_thread_create(fnAsyncThread start_routine, void *arg);
extern int wps_osl_thread_join(void *thread, void **value_ptr);
#endif /* ASYNC_MODE */

#ifdef _TUDEBUGTRACE
extern void wps_osl_print_buf(unsigned char *buff, int buflen);
#endif /* _TUDEBUGTRACE */

extern bool wps_osl_create_profile(const struct _wps_credentials *credentials);
extern char *wps_osl_get_adapter_name();
extern char *wps_osl_get_short_adapter_name();
extern int wps_osl_get_mac(uint8 *mac);
extern char *wps_osl_get_ssid();
extern uint32 wps_osl_init(void *cb_ctx, void *cb, const char *adapter_id);
extern void wps_osl_deinit();
extern void wps_osl_abort();
extern uint32 wps_osl_setup_802_1x(uint8 *bssid);
extern int wps_osl_cleanup_802_1x();
extern uint32 wps_osl_eap_read_data(char *dataBuffer, uint32 *dataLen,
	uint32 timeout_val);
extern uint32 wps_osl_eap_send_data(char *dataBuffer, uint32 dataLen);
extern uint32 wps_osl_htonl(uint32 intlong);
extern uint16 wps_osl_htons(uint16 intshort);
extern void wps_osl_sleep(uint32 ms);
extern unsigned long wps_osl_get_current_time();
extern int wps_osl_wl_ioctl(int cmd, void *buf, int len, bool set);

extern bool wps_osl_hwbutton_supported(const char *guid);
extern bool wps_osl_hwbutton_open(const char *guid);
extern void wps_osl_hwbutton_close();
extern bool wps_osl_hwbutton_state();

extern void wps_osl_update_led(unsigned int uiStatus, bool b_secure_nw);

extern char *wps_osl_get_scan_results(char *buf, int buf_len);
extern int wps_osl_join_network(char* ssid, uint32 wsec);
extern int wps_osl_join_network_with_bssid(char* ssid, uint32 wsec, char *bssid);
extern int wps_osl_leave_network();
extern void wps_osl_set_run_ip(char *run_ip, char *ip_addr, char *user_dhcp);

/* IOCTL swapping mode for Big Endian host with Little Endian dongle.  Default to off */
extern bool wps_swap;

#define htod32(i) (wps_swap?bcmswap32(i):i)
#define htod16(i) (wps_swap?bcmswap16(i):i)
#define dtoh32(i) (wps_swap?bcmswap32(i):i)
#define dtoh16(i) (wps_swap?bcmswap16(i):i)
#define htodchanspec(i) htod16(i)
#define dtohchanspec(i) dtoh16(i)
#define htodenum(i) ((sizeof(i) == 4) ? htod32(i) : ((sizeof(i) == 2) ? htod16(i) : i))
#define dtohenum(i) ((sizeof(i) == 4) ? dtoh32(i) : ((sizeof(i) == 2) ? htod16(i) : i))

#if defined(D11AC_IOTYPES) && defined(BCM_WPS_IOTYPECOMPAT)
extern bool g_legacy_chanspec;
extern chanspec_t wps_wl_chspec_from_legacy(chanspec_t legacy_chspec);
extern chanspec_t wps_wl_chspec_to_legacy(chanspec_t chspec);

#define WPS_WL_CHSPEC_IOTYPE_HTOD(a) \
	((g_legacy_chanspec) ? wps_wl_chspec_to_legacy((a)):((a)))
#define WPS_WL_CHSPEC_IOTYPE_DTOH(a) \
	((g_legacy_chanspec) ? wps_wl_chspec_from_legacy((a)):((a)))

#else

#define WPS_WL_CHSPEC_IOTYPE_HTOD(a) ((a))
#define WPS_WL_CHSPEC_IOTYPE_DTOH(a) ((a))

#endif


#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* __WPS_API_OSL_H__ */
