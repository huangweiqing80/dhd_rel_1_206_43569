/* P2P Library WL driver access APIs usable by other P2P components.
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: p2pwl.h,v 1.41 2010-12-30 21:57:37 $
 *
 * Note:
 *   Parts of the P2P Library depends on the p2pwl API.  The p2pwl API
 *   must not depend on anything else in the P2P Library.  The p2pwl API
 *   only depends on an external OS-specific p2posl_wl_ioctl() function.
 */
#ifndef _P2PWL_H_
#define _P2PWL_H_

#include <wlioctl.h>
#include <proto/ethernet.h>

#ifdef __cplusplus
extern "C" {
#endif

#define P2PWL_JOIN_SCAN_PASSIVE_TIME 150
#define P2PWL_JOIN_SCAN_PASSIVE_TIME_LONG 1500

/* Opaque type for the WL driver ioctl handle */
typedef void* P2PWL_HDL;

/* Boolean type compatible with 'int' */
typedef int P2PWL_BOOL;	/* 0 means false, non-zero means true */


/* WL driver access APIs:
 * These are OS-independent and have a common implementation for all OSes.
 * All of them end up calling the os-dependent function p2posl_wl_ioctl().
 */
int p2pwl_check_wl_if(P2PWL_HDL wl);
int p2pwl_vndr_ie(P2PWL_HDL wl, int bsscfg_idx, uint32 pktflags,
	uint8 oui0, uint8 oui1, uint8 oui2, uint8 ie_id,
	const uint8 *old_data, int old_datalen,
	const uint8 *new_data, int new_datalen);
int p2pwl_get_mac_addr(P2PWL_HDL wl, struct ether_addr *out_mac_addr);
int p2pwl_set_mac_addr(P2PWL_HDL wl, struct ether_addr *mac_addr, int bssidx);
int p2pwl_up(P2PWL_HDL wl);
int p2pwl_down(P2PWL_HDL wl);
P2PWL_BOOL p2pwl_isup(P2PWL_HDL wl);
int p2pwl_bss(P2PWL_HDL hdl, int bsscfg_idx, P2PWL_BOOL up);
int p2pwl_scan(P2PWL_HDL wl, int channel, int nprobes);
wl_scan_params_t *p2pwl_alloc_scan_params(int channel, int nprobes, int *out_params_size);
int p2pwl_scan_abort(P2PWL_HDL wl);
int p2pwl_scan_channels(P2PWL_HDL wl, int nprobes, int chan_dwell_ms,
	int channel1, int channel2, int channel3, unsigned char *ioctl_buf,
	size_t ioctl_buf_size, uint8 *scanpar_buf, size_t scanpar_buf_size,
	bool abort, int bssidx);
int p2pwl_scan_nchannels(P2PWL_HDL wl, int nprobes, int chan_dwell_ms,
	BCMP2P_INT32 num_chans, BCMP2P_UINT16* channels, unsigned char *ioctl_buf,
	size_t ioctl_buf_size, BCMP2P_UINT8 *scanpar_buf, size_t scanpar_buf_size,
	BCMP2P_BOOL abort, int bssidx);
int p2pwl_passive_scan(P2PWL_HDL wl, int duration_ms, int channel);
int p2pwl_scan_get_results(P2PWL_HDL wl, wl_scan_results_t* scan_results, int bufsize);
int p2pwl_join(P2PWL_HDL wl, const char *ssid, unsigned long ssid_len,
	int bssidx);
int p2pwl_join_bssid(P2PWL_HDL wl, const char *ssid, unsigned long ssid_len,
	struct ether_addr *bssid, int num_chanspec, chanspec_t *chanspec,
	int bssidx);
int p2pwl_join_open(P2PWL_HDL wl, char *bss_ssid, int bssidx);
int p2pwl_disassoc(P2PWL_HDL wl, int bssidx);
int p2pwl_set_ap(P2PWL_HDL wl, P2PWL_BOOL up);
int p2pwl_get_ap(P2PWL_HDL wl);
int p2pwl_set_p2p_discovery(P2PWL_HDL wl, int on);
int p2pwl_set_p2p_mode(P2PWL_HDL wl, uint8 mode, chanspec_t chspec, uint16 listen_ms,
	int bssidx);
int p2pwl_get_p2p_disc_idx(P2PWL_HDL wl, int *index);
int p2pwl_set_p2p_fname(P2PWL_HDL wl, wlc_ssid_t *ssid);
int p2pwl_set_apsta(P2PWL_HDL wl, int val);
int p2pwl_get_apsta(P2PWL_HDL wl);
int p2pwl_set_ssid(P2PWL_HDL hdl, int bsscfg_idx, unsigned char *name,
	unsigned long len);
int p2pwl_get_ssid(P2PWL_HDL wl, int bsscfg_idx, wlc_ssid_t *ssid);
int p2pwl_set_chanspec(P2PWL_HDL wl, chanspec_t chspec, int bssidx);
int p2pwl_get_chanspec(P2PWL_HDL wl, chanspec_t *chspec, int bssidx);
int p2pwl_set_macmode(P2PWL_HDL wl, int val, int bssidx);
int p2pwl_get_macmode(P2PWL_HDL wl, int *val, int bssidx);
int p2pwl_set_maclist(P2PWL_HDL wl, uint8 *ioctl_buf, size_t ioctl_buf_size,
	struct ether_addr *in_mac_list, unsigned int in_mac_count, int bssidx);
int p2pwl_get_maclist(P2PWL_HDL wl, uint8 *ioctl_buf, size_t ioctl_buf_size,
	unsigned int mac_list_max, struct ether_addr *out_mac_list,
	unsigned int *out_mac_count, int bssidx);
extern int p2pwl_set_spect_mgmt(P2PWL_HDL wl, int spect_mgmt);
extern int p2pwl_get_spect_mgmt(P2PWL_HDL wl, int *val);

/* Check if we are associated to an AP on the P2P connection BSS. */
P2PWL_BOOL p2pwl_is_associated(P2PWL_HDL wl, struct ether_addr *out_bssid);

/* Check if we are associated to an AP on the specified BSS. */
P2PWL_BOOL p2pwl_is_associated_bss(P2PWL_HDL wl, struct ether_addr *out_bssid,
	int bssidx);

/* Check if peer has connected to our BSS on the AP peer */
int p2pwl_get_assoc_count(P2PWL_HDL wl, P2PWL_BOOL show_maclist,
	unsigned char *ioctl_buf, int *out_assoc_count, int bssidx);

/* Check if peer has authorized to our BSS on the AP peer */ 
int p2pwl_get_autho_sta_list(P2PWL_HDL wl, P2PWL_BOOL show_maclist, 
	unsigned char *ioctl_buf, int *out_assoc_count, int bssidx); 

int p2pwl_send_act_frame(P2PWL_HDL wl, wl_af_params_t *af_params,
	unsigned char *ioctl_buf, int bssidx);


/* Create a P2P BSS */
int p2pwl_p2p_ifadd(P2PWL_HDL wl, struct ether_addr *mac, uint8 if_type,
	chanspec_t chspec);

/* Delete a P2P BSS */
int p2pwl_p2p_ifdel(P2PWL_HDL wl, struct ether_addr *mac);

/* Get the bsscfg index of a created P2P BSS */
int p2pwl_p2p_ifidx(P2PWL_HDL wl, struct ether_addr *mac, int *index);

/* Update a P2P BSS (mainly use on Windows) */
int p2pwl_p2p_ifupd(P2PWL_HDL wl, struct ether_addr *mac, uint8 if_type,
	chanspec_t chspec, int bssidx);


/* Check if 'p2p' is supported in the driver */
int p2pwl_is_p2p_supported(P2PWL_HDL wl);
/*
 * Set or get ioctl/iovars
 */
int p2pwl_set_int(P2PWL_HDL wl, int ioctl_cmd, int val);
int p2pwl_set_int_bss(P2PWL_HDL wl, int ioctl_cmd, int val, int bssidx);
int p2pwl_get_int(P2PWL_HDL wl, int ioctl_cmd, int *val);
int p2pwl_get_int_bss(P2PWL_HDL wl, int ioctl_cmd, int *val, int bssidx);
int p2pwl_ioctl_get_bss(P2PWL_HDL wl, int cmd, void *buf, int len, int bssidx);
int p2pwl_iovar_get(P2PWL_HDL wl, const char *iovar, void *outbuf, int len);
int p2pwl_iovar_get_bss(P2PWL_HDL wl, const char *iovar, void *outbuf, int len,
	int bssidx);
int p2pwl_iovar_getint(P2PWL_HDL wl, const char *iovar, int *pval);
int p2pwl_iovar_getint_bss(P2PWL_HDL wl, const char *iovar, int *pval,
	int bssidx);
int p2pwl_iovar_getbuf(P2PWL_HDL wl, const char *iovar,
	void *param, int paramlen, void *bufptr, int buflen);
int p2pwl_iovar_getbuf_bss(P2PWL_HDL wl, const char *iovar, void *param,
	int paramlen, void *bufptr, int buflen, int bssidx);
int p2pwl_ioctl_set(P2PWL_HDL wl, int cmd, void *buf, int len);
int p2pwl_ioctl_set_bss(P2PWL_HDL wl, int cmd, void *buf, int len, int bssidx);
int p2pwl_iovar_set(P2PWL_HDL wl, const char *iovar, void *param,
	int paramlen);
int p2pwl_iovar_set_bss(P2PWL_HDL wl, const char *iovar, void *param,
	int paramlen, int bsscfg_idx);
int p2pwl_iovar_setint(P2PWL_HDL wl, const char *iovar, int val);
int p2pwl_iovar_setint_bss(P2PWL_HDL wl, const char *iovar, int val,
	int bssidx);
int p2pwl_iovar_setbuf(P2PWL_HDL wl, const char *iovar,
	void *param, int paramlen, void *bufptr, int buflen);
int p2pwl_iovar_setbuf_bss(P2PWL_HDL wl, const char *iovar,
	void *param, int paramlen, void *bufptr, int buflen, int bssidx);
int p2pwl_bssiovar_getbuf(P2PWL_HDL wl, const char *iovar, int bssidx,
	void *param, int paramlen, void *bufptr, int buflen);
int p2pwl_bssiovar_setbuf(P2PWL_HDL wl, const char *iovar, int bssidx,
	void *param, int paramlen, void *bufptr, int buflen);

/* Set or get iovars with a bsscfg-index (equivalent to "wl -C 1").
 * This allows the set/get of iovars on the AP network interface when
 * acting as an AP peer.
 * NOTE: These bsscfg-indexed functions only work on OSes where the WL driver
 *       expects commands for APSTA mode's secondary (AP) network interface
 *       to be issued through the primary (STA) interface.
 *
 *       Currently these APIs are called from the Linux OSL (and possibly
 *       from the Nucleus and other RTOS OSLs, in the future.)
 *
 *       DO NOT call these APIs from the Vista OSL because on that platform
 *       the iovar needs to be applied directly to the secondary network
 *       interface instead of through the primary interface.
 */
int p2pwl_bssiovar_get(P2PWL_HDL wl, const char *iovar, int bssidx,
	void *outbuf, int len);
int p2pwl_bssiovar_set(P2PWL_HDL wl, const char *iovar, int bssidx,
	void *param, int paramlen);
int p2pwl_bssiovar_setint(P2PWL_HDL wl, const char *iovar, int bssidx,
	int val);

/* Convert an Ethernet address to a string of the form "7c:2f:33:4a:00:21" */
char *p2pwl_ether_etoa(const struct ether_addr *n, char *etoa_buf);


/*
 * Common code implementations that can be called from OSLs.
 * Do not call these functions from the common code directly.
 */
/* Format a bsscfg indexed iovar buffer.  Call this from the OSLs only */
int p2pwl_common_bssiovar_mkbuf(const char *iovar, int bssidx, void *param,
	int paramlen, void *bufptr, int buflen, int *perr);
/* Check if a BSS is up.  Call this from the OSLs only */
P2PWL_BOOL p2pwl_common_bss_isup(P2PWL_HDL wl, int bsscfg_idx);

int p2pwl_set_PM(P2PWL_HDL wl, int val, int bssidx);
int p2pwl_get_PM(P2PWL_HDL wl, int *val, int bssidx);

int p2pwl_set_listen_interval(P2PWL_HDL wl, unsigned int interval, int bssidx);

int p2pwl_set_roam_off(P2PWL_HDL wl, unsigned int roam_off, int bssidx);

int
p2pwl_set_wme_apsd_sta(P2PWL_HDL wl, uint8 maxSPLen, uint8 acBE,
	uint8 acBK, uint8 acVI, uint8 acVO, int bssidx);
/* Implementation for compatibility with wl driver compiled with legacy iotypes */
#if defined(D11AC_IOTYPES) && defined(BCM_P2P_IOTYPECOMPAT)
extern bool g_legacy_chanspec;
extern chanspec_t p2pwl_chspec_from_legacy(chanspec_t legacy_chspec);
extern chanspec_t p2pwl_chspec_to_legacy(chanspec_t chspec);

#define P2PWL_CHSPEC_IOTYPE_HTOD(a) \
	((g_legacy_chanspec) ? p2pwl_chspec_to_legacy((a)):((a)))
#define P2PWL_CHSPEC_IOTYPE_DTOH(a) \
	((g_legacy_chanspec) ? p2pwl_chspec_from_legacy((a)):((a)))

#else

#define P2PWL_CHSPEC_IOTYPE_HTOD(a) ((a))
#define P2PWL_CHSPEC_IOTYPE_DTOH(a) ((a))

#endif

#ifdef __cplusplus
}
#endif

#endif /* _P2PWL_H_ */
