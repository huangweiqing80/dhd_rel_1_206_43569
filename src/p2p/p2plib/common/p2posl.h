/* P2P Library low level OS abstraction layer (OSL) public APIs.
 *
 * These APIs are used by the generic high level OSL p2plib_generic_osl.c
 * used by all OSes except Vista.  Each OS-specific P2P Library OSL that
 * uses p2plib_generic_osl.c must implement all APIs declared here.
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: p2posl.h,v 1.12 2011-01-11 17:29:53 $
 */
#ifndef _P2POSL_H_
#define _P2POSL_H_

#include <stdio.h>
#include <p2pwl.h>
#include <p2plib_api.h>

/* Opaque type for the P2P Library OSL handle */
typedef void* P2POSL_HDL;


/* Initialize/Deinitialize the OSL.
 * Note: the P2P Library calls these APIs.  In system where the P2P Library
 *       is known to be initialized, there is no need to call these 2 APIs.
 */
P2PWL_BOOL p2posl_init(void);
P2PWL_BOOL p2posl_deinit(void);

/* Open a new instance of the OSL.
 * Returns a p2papi_osl_instance_t* ptr to the allocated and initialized OSL
 * data, or NULL if error.
 */
void* p2posl_open(void* app_hdl, const char *if_name,
	const char *primary_if_name);

/* Close an instance of the OSL and free the OSL data */
void p2posl_close(void* osl_handle);

/* Obtain a WL handle from an OSL handle */
void* p2posl_get_wl_hdl(P2POSL_HDL oslHdl);

/* Check if a WL driver handle is valid */
bool p2posl_wl_chk_hdl(void* wl_hdl, const char *file, int line);


/* Lock/Unlock a P2P Library instance for mutually exclusive access to its
 * data.  Returns 0 if successful.
 */
int p2posl_data_lock(P2POSL_HDL oslHdl);
int p2posl_data_unlock(P2POSL_HDL oslHdl);

/* Lock/Unlock a P2P Library instance for mutually exclusive access to its
 * ioctl_mutex.  Returns 0 if successful.
 */
int p2posl_ioctl_lock(P2PWL_HDL wlHdl);
int p2posl_ioctl_unlock(P2PWL_HDL wlHdl);

/* Start/stop the raw frame receiver/manager.  Returns 0 if successful.
 * This manager is responsible for receiving all raw frames received by
 * the device and delivering them to p2papi_process_raw_rx_frame().
 */
typedef void (*p2posl_rx_frame_hdlr_t)(void *rx_frame_cb_param,
	unsigned char *frame, unsigned int frame_bytes);
int p2posl_start_raw_rx_mgr(P2POSL_HDL oslHdl,
	p2posl_rx_frame_hdlr_t rx_frame_cb, void *rx_frame_cb_param);
int p2posl_stop_raw_rx_mgr(P2POSL_HDL oslHdl);

/* timer refresh */
int p2posl_timer_refresh(P2POSL_HDL oslHdl);

/* Sleep for a given number of milliseconds */
void p2posl_sleep_ms(unsigned int ms);

/* Invoke a WL driver ioctl using the current BSS */
int p2posl_wl_ioctl(P2PWL_HDL wlHdl, int cmd, void *buf, int len,
	P2PWL_BOOL set);

/* Invoke a WL driver ioctl on a selected BSS */
int p2posl_wl_ioctl_bss(void* wlHdl, int cmd, void *buf, int len,
	P2PWL_BOOL set, int bsscfg_idx);

/* Apply security settings to a device acting as an AP */
int p2posl_apply_ap_security(P2POSL_HDL hdl,
	char in_ssid[], unsigned int in_ssidLen, char *in_keyMgmt,
	char in_nwKey[], unsigned int in_nwKeyLen, unsigned int in_encrType,
	unsigned short in_wepIndex);


/* Create a thread */
int p2posl_create_thread(void (*in_thread_fn)(void*), void* in_arg,
	p2posl_thread_t* io_thread_hdl);

/* Wait for a thread to exit */
int p2posl_wait_for_thread_exit(p2posl_thread_t thread_hdl);


/* Initialize the timestamping mechanism used for timestamped logs */
void p2posl_init_timestamp(void);

/* Get the current time and print a timestamp relative to the time
 * p2posl_init_timestamp() was called.
 */
void p2posl_print_timestamp(BCMP2P_LOG_LEVEL level, FILE *stream);


/* Bring up an OS wireless network interface */
int p2posl_ifup(const char* ifname, void *hdl);

/* Bring down an OS wireless network interface */
int p2posl_ifdown(const char* ifname);

/* Do any necessary OS-specific configuration to prepare the P2P connection
 * network interface to run or stop.
 */
void p2posl_set_netif_for_ap_mode(void* wlHdl, bool is_ap_mode, char *ifname);
void p2posl_set_netif_for_sta_mode(void* wlHdl, bool run_or_stop, char *ifname);

/* Remember the BSSCFG index for the discovery or connection BSS */
int p2posl_save_bssidx(void* wlHdl, int bss_usage, int bssidx);

/* Remember the BSSCFG OS interface name for the discovery or connection BSS */
int p2posl_save_bssname(void* wlHdl, int bss_usage, char* ifname);


#endif /* _P2POSL_H_ */
