/*
 * P2P Library public API - Utility/debug functions
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: BcmP2PDbg.h,v 1.24 2010-11-10 02:37:56 $
 */
#ifndef _BCMP2PDBG_H_
#define _BCMP2PDBG_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <proto/ethernet.h>
#include <wpscommon.h>
#include <bcmutils.h>


/*
 * Name        : p2papi_get_mac_addr
 * Description : 
 * Arguments   : Get our wireless interface's MAC address
 * Return value: 0 if success
 * Notes       : 
 */
extern int p2papi_get_mac_addr(void *p2pHdl, struct ether_addr *out_mac_addr);

#ifndef SSID_FMT_BUF_LEN
#define SSID_FMT_BUF_LEN 4*32+1	/* max length for ouput SSID format string */
#endif /* SSID_FMT_BUF_LEN */

/* Format a SSID string for printing (in case it contains non-ASCII chars) */
extern int p2papi_format_ssid(char* out_ssid_buf, uint8* in_ssid, uint8 in_ssid_len);

/* Print the association status - call this only on the STA peer */
extern int p2papi_wl_status(void* p2pHdl, int logLevel);

/* Print the associated STAs - call this only on the AP peer */
extern int p2papi_wl_assoclist(void* p2pHdl);

/* print bytes formatted as hex to a log file */
extern void p2papi_log_hexdata(BCMP2P_LOG_LEVEL logLevel, char *heading,
	unsigned char *data, int dataLen);


/* Wait for the established connection to disconnect.
 * Notes       : This function only returns when the link is disconnected.
 *               A disconnection can be caused by the peer disconnecting from
 *               us or by an asynchronous call to p2p_teardown() from the app.
 */
extern int p2papi_wait_for_disconnect(void* p2pHdl);

/* Specify that this device can only act as a STA or an AP in future P2P
 * connections.  Returns 0 if successful, non-zero if not allowed.
 * Notes: 
 * - Acting only as a STA is not allowed if this device is already connected
 *   to an existing AP as a STA.
 * - Calling p2papi_only_act_as_sta(TRUE) overrides any previous call of
 *   of p2papi_only_act_as_ap(TRUE) and vice versa.
 */
extern int p2papi_act_only_as_sta(void* p2pHdl, bool onOff);
extern int p2papi_act_only_as_ap(void* p2pHdl, bool onOff);

/* Check if P2P Discovery is currently enabled */
extern bool p2papi_is_discovery_enabled(void* hdl);

/* Enable/disable PBC overlap detection.  Default is enabled. */
extern int p2papi_enable_pbc_overlap(void *handle, BCMP2P_BOOL enable);

/* Get our P2P Device Address */
struct ether_addr* p2papi_get_p2p_dev_addr(void *handle);

/* Get our P2P Interface Address */
struct ether_addr* p2papi_get_p2p_int_addr(void *handle);

/* Get peer P2P Device Address */
struct ether_addr* p2papi_get_peer_dev_addr(void *handle);

/* Get peer P2P Interface Address */
struct ether_addr* p2papi_get_peer_int_addr(void *handle);

/* Print a timestamped debug log at the given log level */
void p2papi_log(BCMP2P_LOG_LEVEL level, BCMP2P_BOOL print_timestamp,
	const char *fmt, ...);

/* Redirect debug logs to a file */
void p2papi_set_log_file(const char *filename);

/* Wrappers for malloc() and free() that allow adding debug logs */
extern void* p2papi_malloc(size_t size, const char *file, int line);
extern void* p2papi_realloc(void *p, size_t size, const char *file, int line);
extern void p2papi_free(void *p, const char *file, int line);
#define P2PAPI_MALLOC(size) p2papi_malloc(size, __FILE__, __LINE__)
#define P2PAPI_REALLOC(p, size) p2papi_realloc(p, size, __FILE__, __LINE__)
#define P2PAPI_FREE(p) p2papi_free(p, __FILE__, __LINE__)

/* Set action frame tx parameters */
extern int p2papi_set_af_tx_params(void* handle, unsigned int max_retries,
	unsigned int retry_timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* _BCMP2PDBG_H_ */
