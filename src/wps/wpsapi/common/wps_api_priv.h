/* 
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wps_api_priv.h 256665 2011-05-02 03:43:43Z $
 */

#ifndef _WPS_API_PRIV_H_
#define _WPS_API_PRIV_H_

#include "wps_sdk.h"
#include "wps_api_osl.h"


#ifdef __cplusplus
extern "C" {
#endif


/* Hooks */
#ifdef _TUDEBUGTRACE
extern void wps_hook_print_buf(unsigned char *buff, int buflen);
#endif /* _TUDEBUGTRACE */

#ifdef ASYNC_MODE
extern void *wps_hook_thread_create(fnAsyncThread start_routine, void *arg);
extern int wps_hook_thread_join(void *thread, void **value_ptr);

#endif /* ASYNC_MODE */

extern bool wps_hook_create_profile(const struct _wps_credentials *credentials);
extern int wps_hook_get_mac(uint8 *mac);
extern bool wps_hook_init(void *cb_ctx, void *cb, const char *adapter_id);
extern void wps_hook_deinit();
extern void wps_hook_abort();
extern uint32 wps_hook_setup_802_1x(char *bssid);
extern uint32 wps_hook_wait_for_eapol_packet(char *buf, uint32 *len, uint32 timeout);
extern uint32 wps_hook_send_eapol_packet(char *packet, uint32 len);
extern unsigned long wps_hook_get_current_time();
extern uint32 wps_hook_poll_eapol_packet(char *buf, uint32 *len);

extern int wps_hook_wl_ioctl(int cmd, void *buf, int len, bool set);

extern bool wps_hook_hwbutton_supported(const char *guid);
extern bool wps_hook_hwbutton_open(const char *guid);
extern void wps_hook_hwbutton_close();
extern bool wps_hook_hwbutton_state();

extern void wps_hook_update_led(unsigned int uiStatus, bool b_secure_nw);

#ifdef __cplusplus
}
#endif

#endif  /* _WPS_API_PRIV_H_ */
