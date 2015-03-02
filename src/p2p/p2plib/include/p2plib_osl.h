/* P2P Library OS abstraction layer (OSL) definitions common to all OSes.
 * Each OS-specific implementation must implement all functions declared here.
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: p2plib_osl.h,v 1.75 2010-12-21 23:05:41 $
 */
#ifndef _P2PLIB_OSL_H_
#define _P2PLIB_OSL_H_

#include "BcmP2PAPI.h"
#include <typedefs.h>
#include <ethernet.h>
#include <wpscli_api.h>

#ifdef __cplusplus
extern "C" {
#endif


/* Use "struct p2papi_instance_s*" instead of "p2papi_instance_t*" in this
 * file - we cannot include p2plib_api.h due to dependency problems.
 */
struct p2papi_instance_s;


/* Extract a WL driver handle from a P2P Library handle.  Each OS-specific
 * p2plib_***_osl.h file must define P2PAPI_OSL_GET_WL_HDL(p2pHdl).
 */
#define P2PAPI_GET_WL_HDL(p2pHdl)	p2papi_osl_get_wl_hdl(p2pHdl)
extern void* p2papi_osl_get_wl_hdl(struct p2papi_instance_s* hdl);

#define P2PAPI_GET_PRM_WL_HDL(p2pHdl)	p2papi_osl_get_primary_wl_hdl(p2pHdl)
extern void* p2papi_osl_get_primary_wl_hdl(struct p2papi_instance_s* p2pHdl);

/* Check if a WL driver handle is valid.
 *
 * NOTE: p2papi_osl_wl_chk_hdl() was incorrectly named - the proper name should
 *       have been p2posl_wl_chk_hdl() because it is part of the low level OSL
 *       not the high level OSL.  ie. it takes a wl handle parameter instead of
 *       a p2papi_instance handle.
 */
#define P2PAPI_WL_CHECK_HDL(wl_hdl)   \
    p2papi_osl_wl_chk_hdl(wl_hdl, __FILE__, __LINE__)
extern bool p2papi_osl_wl_chk_hdl(void* wl, const char *file, int line);


/* Initialize/Deinitialize the OSL */
bool p2papi_osl_init(void);
bool p2papi_osl_deinit(void);

/* Open a new instance of the OSL, returns an OSL handle */
void* p2papi_osl_open(struct p2papi_instance_s* p2pHdl,
	const char *szAdapterName, const char *szPrimaryAdapterName);
/* Close an instance of the OSL */
void p2papi_osl_close(struct p2papi_instance_s* hdl, void* osl_handle);

/* Lock/Unlock a P2P Library instance for mutually exclusive access to its
 * data.  Returns 0 if successful.
 */
int p2papi_osl_data_lock(struct p2papi_instance_s* hdl);
int p2papi_osl_data_unlock(struct p2papi_instance_s* hdl);

/* Lock/Unlock a P2P Library instance for mutually exclusive access to its
 * ioctl.  Returns 0 if successful.
 */
int p2papi_osl_ioctl_lock(struct p2papi_instance_s* hdl);
int p2papi_osl_ioctl_unlock(struct p2papi_instance_s* hdl);

/* Start/stop the raw frame receiver/manager.  Returns 0 if successful.
 * This manager is responsible for receiving all raw frames received by
 * the device and delivering them to p2papi_process_raw_rx_frame().
 */
int p2papi_osl_start_raw_rx_mgr(struct p2papi_instance_s *hdl);
int p2papi_osl_stop_raw_rx_mgr(struct p2papi_instance_s *hdl);

/* Refresh timers */
int
p2papi_osl_timer_refresh(struct p2papi_instance_s *hdl);

#if P2PAPI_ENABLE_WPS
/* Get the driver's cached rx probe request wps ie and deliver it to WPSCLI.
 * This only needs to be implemented if the OSL has no ability to receive
 * WLC_E_* driver events.  Otherwise this function should be implemented as
 * an empty stub and the common code's p2papi_rx_wl_event() event handler will
 * parse and deliver probe req wps ies to WPSCLI.
 * Returns 0 if success.
 */
int p2papi_osl_get_probereq_wpsie(struct p2papi_instance_s *hdl,
	uint8 *mac, uint8 *bufdata, int *buflen);
#endif /* P2PAPI_ENABLE_WPS */

/*
 * Sleep function
 */
typedef enum {
	/* Generic sleep */
	P2PAPI_OSL_SLEEP_GENERIC,

	/* Discovery: initial 802.11 scan delay before reading results */
	P2PAPI_OSL_SLEEP_DISCOVERY_SCAN,

	/* Discovery search phase: dwell time on each channel */
	P2PAPI_OSL_SLEEP_DISCOVERY_SEARCH,

	/* Discovery listen phase: dwell time on listen channel */
	P2PAPI_OSL_SLEEP_DISCOVERY_LISTEN,

	/* Group Owner Negotiation delay between retries */
	P2PAPI_OSL_SLEEP_GO_NEGOTIATION_RETRY,

	/* Link create cancel: wait for cancel completion poll */
	P2PAPI_OSL_SLEEP_LINK_CREATE_CANCEL_POLL,

	/* STA peer: wait for WPS enrollee polling loop delay */
	P2PAPI_OSL_SLEEP_WPS_ENROLLEE_WAIT_POLL,

	/* Group Owner peer: wait before re-running the WPS registrar */
	P2PAPI_OSL_SLEEP_WPS_REGISTRAR_RERUN_WAIT,

	/* Group Owner peer: wait before re-trying opening WPS window after
	 * failing due to a PBC overlap.
	 */
	P2PAPI_OSL_SLEEP_WPS_PBC_OVERLAP_RETRY,

	/* Both peers: Delay for sending last packet after WPS handshake is
	 * done before attempting a secure connection.
	 */
	P2PAPI_OSL_SLEEP_WPS_DONE,

	/* STA peer: join to BSS polling loop delay */
	P2PAPI_OSL_SLEEP_STA_JOINED_POLL,

	/* AP peer: BSS joined polling loop delay */
	P2PAPI_OSL_SLEEP_AP_JOINED_POLL,

	/* AP peer: delay after peer has joined our BSS */
	P2PAPI_OSL_SLEEP_AP_JOIN_DONE,

	/* AP or STA peer: peer disconnect monitoring polling loop delay */
	P2PAPI_OSL_SLEEP_DISCONNECT_POLL,

	/* AP or STA peer: wait after issuing "wl up" to bring up driver */
	P2PAPI_OSL_SLEEP_WAIT_WL_UP,

	/* AP or STA peer: wait for APSTA mode BSSCFG to start */
	P2PAPI_OSL_SLEEP_WAIT_BSS_START,

	/* AP or STA peer: wait for APSTA mode BSSCFG to stop */
	P2PAPI_OSL_SLEEP_WAIT_BSS_STOP,

	/* STA peer: wait for the peer's Configuration Timeout before assoc */
	P2PAPI_OSL_SLEEP_PEER_CONFIG_TIMEOUT,

	/* P2P GO negotiation: wait for scan abort driver ioctl to complete */
	P2PAPI_OSL_SLEEP_SCAN_ABORT,

	/* STA peer: wait for BSS assoc-status info (GET_BSSID) is ready */
	P2PAPI_OSL_SLEEP_WAIT_ASSOC_STATUS,

	/* Discovery: initial 802.11 scan-channel delay due to blocked by another kind of scan */
	P2PAPI_OSL_SLEEP_SCAN_CHANNELS

} P2PAPI_OSL_SLEEP_REASON;

/* Generic sleep fns */
void p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_REASON reason, uint32 ms);


/* Random number generation */
long int p2papi_osl_random(void); /* ret rnd # between 0...RAND_MAX */
void p2papi_osl_rand_bytes(unsigned char *buf, int num_bytes);
							/* Generate num_bytes random bytes */

/* Call the application's notification callback */
extern void p2papi_osl_do_notify_cb(struct p2papi_instance_s* hdl,
	BCMP2P_NOTIFICATION_TYPE type, BCMP2P_NOTIFICATION_CODE code);

/* Invoke a WL driver ioctl given a P2P Library handle */
int p2papi_osl_wl_ioctl(struct p2papi_instance_s* hdl, int bsscfg_idx, int cmd,
	void *buf, int len, bool set);

/* Invoke a WL driver ioctl on primary wl interface given a WL driver handle */
int p2papi_osl_wl_primary_ioctl(void* wl_hdl, int cmd, void *buf, int len, bool set);


/* Invoke a WL driver ioctl given a WL driver handle */
int p2posl_wl_ioctl(void* wl_hdl, int cmd, void *buf, int len, int set);

/* Invoke a WL driver ioctl on a selected BSS given a WL driver handle */
int p2posl_wl_ioctl_bss(void* wlHdl, int cmd, void *buf, int len,
	int set, int bsscfg_idx);

/* Debug: Get the name of the default OS network interface that will be used
 * for p2posl_wl_ioctl()
 */
char* p2posl_get_netif_name_bss(void* wlHdl, int bssidx);
char* p2posl_get_netif_name_prefix(void* wlHdl);

/* Remember the BSSCFG index for the discovery or connection BSS */
int p2posl_save_bssidx(void* wlHdl, int bss_usage, int bssidx);

/* Remember the BSSCFG OS interface name for the discovery or connection BSS */
int p2posl_save_bssname(void* wlHdl, int bss_usage, char* ifname);

/* Format a bsscfg indexed iovar buffer */
int p2posl_bssiovar_mkbuf(const char *iovar, int bssidx, void *param,
    int paramlen, void *bufptr, int buflen, int *perr);

/* Check if a BSS is up */
bool p2posl_bss_isup(void* wl_hdl, int bsscfg_idx);

/* Check if we are connected to a BSS on the connection (virtual) BSS.
 * Call this only on the peer acting as a STA.
 */
bool p2papi_osl_is_associated(struct p2papi_instance_s *hdl,
	struct ether_addr *out_bssid);

/* Check if we are connected to a BSS on the primary BSS.
 * ie. check if we have an existing concurrent connection in addition to the
 * new P2P connection we are going to create on the virtual BSS.
 */
bool p2papi_osl_is_primary_bss_assoc(struct p2papi_instance_s *hdl,
	struct ether_addr *out_bssid);

/* Get the current channel of the primary (non-P2P) BSS.
 * ie. if we have an existing concurrent connection in addition to the
 * new P2P connection we are going to create on the virtual BSS, this call
 * gets the existing connection's channel.
 */
int p2papi_osl_get_primary_bss_channel(struct p2papi_instance_s *hdl,
	int *out_channel);

/* Join this STA device to a BSS with the given security credentials */
int p2papi_osl_sta_join_with_security(struct p2papi_instance_s* hdl,
	char in_ssid[],
	brcm_wpscli_authtype authType, brcm_wpscli_encrtype in_encrType,
	char in_nwKey[], uint16 in_wepIndex,
	struct ether_addr *in_bssid);

/* Apply security settings to a device acting as an AP */
int p2papi_osl_apply_ap_security(struct p2papi_instance_s* hdl, char in_ssid[],
	brcm_wpscli_authtype authType, brcm_wpscli_encrtype in_encrType,
	char in_nwKey[], uint16 in_wepIndex);

/* Get the AP or STA mode network interface name */
char* p2papi_osl_get_ap_mode_ifname(struct p2papi_instance_s* hdl);
char* p2papi_osl_get_sta_mode_ifname(struct p2papi_instance_s* hdl);

/* Do OS-specific actions needed after bringing up the AP or STA mode BSS */
int p2papi_osl_ap_mode_ifup(struct p2papi_instance_s* hdl, char *ifname);
int p2papi_osl_sta_mode_ifup(struct p2papi_instance_s* hdl, char *ifname);

/* Do OS-specific actions needed prior to bringing down the AP/STA mode BSS */
int p2papi_osl_ap_mode_ifdown(struct p2papi_instance_s* hdl);
int p2papi_osl_sta_mode_ifdown(struct p2papi_instance_s* hdl);

/* Delete a P2P connection BSS and set hdl->bsscfg_idx to 0. */
int p2papi_osl_delete_bss(struct p2papi_instance_s* hdl, int bssidx);

/* Create a P2P connection BSS and set hdl->bsscfg_idx. */
int p2papi_osl_create_bss(struct p2papi_instance_s* hdl, BCMP2P_BOOL is_ap);


/* Check if an OSL handle is valid */
#define P2PAPI_OSL_CHECK_HDL(osl_hdl)	\
	p2papi_osl_chk_hdl(osl_hdl, __FILE__, __LINE__)
bool p2papi_osl_chk_hdl(void* osl_hdl, const char *file, int line);

/* Given an OSL handle, return the P2P handle stored within the OSL data
 * during p2papi_osl_init().
 */
struct p2papi_instance_s* p2papi_osl_get_p2p_hdl(void* osl_hdl);


/* Group owner negotiation state to signal */
typedef enum {
	P2PAPI_OSL_GO_STATE_START,
	P2PAPI_OSL_GO_STATE_DONE,
	P2PAPI_OSL_GO_STATE_CANCEL
} P2PAPI_OSL_GO_STATE;

/* Signal that the Group Owner Negotiation handshake has started or is done.
 * - Signalling DONE unblocks any thread blocked on
 *   p2papi_osl_wait_for_go_negotiation().
 * - Signalling DONE can occur before p2papi_osl_wait_for_go_negotiation()
 *   is called, in which case p2papi_osl_wait_for_go_negotiation() returns
 *   SUCCESS immediately when it is called.
 */
int p2papi_osl_signal_go_negotiation(struct p2papi_instance_s *hdl,
	P2PAPI_OSL_GO_STATE state);

/* Wait for the Group Owner Negotiation handshake to complete.
 * This potentially blocks the caller, typically for 0 to 2 seconds.
 * Returns BCMP2P_SUCCESS if the GO negotiation is complete.
 * Returns BCMP2P_GO_NEGOTIATE_TIMEOUT on a timeout.
 */
int p2papi_osl_wait_for_go_negotiation(struct p2papi_instance_s *hdl,
	int timeout_ms);


/* escan state to signal */
typedef enum {
	P2PAPI_OSL_ESCAN_STATE_START,
	P2PAPI_OSL_ESCAN_STATE_DONE,
	P2PAPI_OSL_ESCAN_STATE_ABORT
} P2PAPI_OSL_ESCAN_STATE;

int p2papi_osl_signal_escan_state(struct p2papi_instance_s *hdl,
	P2PAPI_OSL_ESCAN_STATE state);

int p2papi_osl_wait_for_escan_complete(struct p2papi_instance_s *hdl,
	int timeout_ms);


/* When acting as an AP only: STA assoc/disassoc detection state to signal */
typedef enum {
	P2PAPI_OSL_CLIENT_ASSOC_STATE_START,
	P2PAPI_OSL_CLIENT_ASSOC_STATE_ASSOC,
	P2PAPI_OSL_CLIENT_ASSOC_STATE_DISASSOC,
	P2PAPI_OSL_CLIENT_ASSOC_STATE_ABORT
} P2PAPI_OSL_CLIENT_ASSOC_STATE;

int p2papi_osl_signal_client_assoc_state(struct p2papi_instance_s *hdl,
	P2PAPI_OSL_CLIENT_ASSOC_STATE state);

int p2papi_osl_wait_for_client_assoc_or_disassoc(struct p2papi_instance_s *hdl,
	int timeout_ms);


/* Signal a secure STA join has completed */
int p2papi_osl_signal_secure_join(struct p2papi_instance_s *hdl);

/* provision discovery request/response state to signal */
typedef enum {
	P2PAPI_OSL_PROVDIS_STATE_TX_REQUEST_START,
	P2PAPI_OSL_PROVDIS_STATE_RX_RESPONSE
} P2PAPI_OSL_PROVDIS_STATE;

int p2papi_osl_signal_provdis_state(struct p2papi_instance_s *hdl,
	P2PAPI_OSL_PROVDIS_STATE provdis_state);

int p2papi_osl_wait_for_rx_provdis_response(struct p2papi_instance_s *hdl,
	int timeout_ms);

/* Get time since process start in millisec */
unsigned int p2papi_osl_gettime(void);
/* Diff newtime and oldtime in ms */
unsigned int p2papi_osl_difftime(unsigned int newtime, unsigned int oldtime);

/*
 * DHCP server-related OSL APIs - these are called only on the AP peer.
 */

/* Open or close firewall ports needed for the DHCP server:
 * - allow incoming packets from 0.0.0.0 or dhcp-pool to dhcp-ip
 * - allow incoming packets from any address to 255.255.255.255
 * - allow outgoing packets from dhcp-ip to dhcp-pool or 255.255.255.255
 * where dhcp-ip is the IP address of the dhcp server host and dhcp-pool
 * is the address pool from which the DHCP server assigns addresses.
 */
bool p2papi_osl_dhcp_open_firewall(struct p2papi_instance_s* hdl);
bool p2papi_osl_dhcp_close_firewall(struct p2papi_instance_s* hdl);

/* Set the static IP addr/netmask of the AP peer device's network interface.
 * - Call this only on the AP peer.
 * - This static IP addr must match the hardcoded one in the DHCP server.
 * - This IP address must not conflict with the IP address of any other
 *   network interfaces on the same device.
 */
bool p2papi_osl_set_ap_ipaddr(struct p2papi_instance_s* hdl, uint32 ipaddr,
	uint32 netmask);

/* Clear the static IP addr of the AP peer device's network interface */
bool p2papi_osl_clear_ap_ipaddr(struct p2papi_instance_s* hdl);

/* Run the DHCP server asynchronously (eg. start a thread) */
bool p2papi_osl_dhcp_run_server(struct p2papi_instance_s* hdl, void *dhcpd_hdl);

/* Stop the asynchronous DHCP server (eg. end the thread) */
bool p2papi_osl_dhcp_end_server(struct p2papi_instance_s* hdl, void *dhcpd_hdl);


/*
 * Logging definitions
 */

/* Compile flag to allow compiling out all logging fns and calls to them
 * to reduce code size.  This can be set to 0 or 1 from a makefile.
 */
#ifndef P2PLOGGING
#define P2PLOGGING 1
#endif

#if P2PLOGGING
#define BCMP2PLOG(args)			p2papi_log args
#else
#define BCMP2PLOG(args)
#endif

/* Redirect debug logs to a file */
void p2papi_osl_set_log_file(const char *filename);

/* Output a debug log.
 * Do not call this fn directly.  Use the BCMP2PLOG() macro instead so that
 * the call may be compiled out completely to reduce code space.
 */
void p2papi_osl_log(BCMP2P_LOG_LEVEL level, BCMP2P_BOOL print_timestamp,
	char *formatted_log_str);

/* Old logging macros maintained for compatibility with existing code.
 * These will be removed soon.  Do not use them in any new code.
 * - P2PERRx is for printing error logs with timestamps.
 * - P2PLOGx is for printing medium-verbosity logs with timestamps.
 * - DBGPRINTx is for printing medium-verbosity logs without timestamps.
 * - P2PVERBx is for printing verbose logs with timestamps.
 */
#if P2PLOGGING
#define P2PERR(fmt)			p2papi_log(BCMP2P_LOG_ERR, TRUE, fmt)
#define P2PERR1(fmt, a)		p2papi_log(BCMP2P_LOG_ERR, TRUE, fmt, a)
#define P2PERR2(fmt, a, b)	p2papi_log(BCMP2P_LOG_ERR, TRUE, fmt, a, b)
#define P2PERR3(fmt, a, b, c)	p2papi_log(BCMP2P_LOG_ERR, TRUE, fmt, a, b, c)
#define P2PERR7(fmt, a, b, c, d, e, f, g) \
	p2papi_log(BCMP2P_LOG_ERR, TRUE, fmt, a, b, c, d, e, f, g)
#define P2PVERB(fmt)		p2papi_log(BCMP2P_LOG_VERB, TRUE, fmt)
#define P2PVERB1(fmt, a)		p2papi_log(BCMP2P_LOG_VERB, TRUE, fmt, a)
#define P2PVERB2(fmt, a, b)	p2papi_log(BCMP2P_LOG_VERB, TRUE, fmt, a, b)
#define P2PVERB6(fmt, a, b, c, d, e, f) \
	p2papi_log(BCMP2P_LOG_VERB, TRUE, fmt, a, b, c, d, e, f)
#define P2PLOG(fmt)			p2papi_log(BCMP2P_LOG_MED, TRUE, fmt)
#define P2PLOG1(fmt, a)		p2papi_log(BCMP2P_LOG_MED, TRUE, fmt, a)
#define P2PLOG2(fmt, a, b)	p2papi_log(BCMP2P_LOG_MED, TRUE, fmt, a, b)
#define P2PLOG3(fmt, a, b, c)	p2papi_log(BCMP2P_LOG_MED, TRUE, fmt, a, b, c)
#define P2PLOG4(fmt, a, b, c, d)	p2papi_log(BCMP2P_LOG_MED, TRUE, fmt, a, b, c, d)
#define P2PLOG5(fmt, a, b, c, d, e)	p2papi_log(BCMP2P_LOG_MED, TRUE, fmt, a, b, c, d, e)
#define P2PLOG6(fmt, a, b, c, d, e, f) \
	p2papi_log(BCMP2P_LOG_MED, TRUE, fmt, a, b, c, d, e, f)
#define P2PLOG7(fmt, a, b, c, d, e, f, g) \
	p2papi_log(BCMP2P_LOG_MED, TRUE, fmt, a, b, c, d, e, f, g)
#define P2PLOG8(fmt, a, b, c, d, e, f, g, h) \
	p2papi_log(BCMP2P_LOG_MED, TRUE, fmt, a, b, c, d, e, f, g, h)
#define P2PLOG9(fmt, a, b, c, d, e, f, g, h, i) \
	p2papi_log(BCMP2P_LOG_MED, TRUE, fmt, a, b, c, d, e, f, g, h, i)
#define DBGPRINT(fmt)			\
	p2papi_log(BCMP2P_LOG_MED, FALSE, fmt)
#define DBGPRINT1(fmt, a)		\
	p2papi_log(BCMP2P_LOG_MED, FALSE, fmt, a)
#define DBGPRINT2(fmt, a, b)		\
	p2papi_log(BCMP2P_LOG_MED, FALSE, fmt, a, b)
#define DBGPRINT3(fmt, a, b, c)	\
	p2papi_log(BCMP2P_LOG_MED, FALSE, fmt, a, b, c)
#define DBGPRINT4(fmt, a, b, c, d)	\
	p2papi_log(BCMP2P_LOG_MED, FALSE, fmt, a, b, c, d)
#else /* P2PLOGGING */
#define P2PERR(fmt)
#define P2PERR1(fmt, a)
#define P2PERR2(fmt, a, b)
#define P2PERR7(fmt, a, b, c, d, e, f, g)
#define P2PVERB(fmt)
#define P2PVERB1(fmt, a)
#define P2PVERB2(fmt, a, b)
#define P2PVERB6(fmt, a, b, c, d, e, f)
#define DBGPRINT(fmt)
#define DBGPRINT1(fmt, a)
#define DBGPRINT2(fmt, a, b)
#define DBGPRINT3(fmt, a, b, c)
#define DBGPRINT4(fmt, a, b, c, d)
#define P2PLOG(fmt)
#define P2PLOG1(fmt, a)
#define P2PLOG2(fmt, a, b)
#define P2PLOG3(fmt, a, b, c)
#define P2PLOG4(fmt, a, b, c, d)
#define P2PLOG5(fmt, a, b, c, d, e)
#define P2PLOG6(fmt, a, b, c, d, e, f)
#define P2PLOG7(fmt, a, b, c, d, e, f, g)
#define P2PLOG9(fmt, a, b, c, d, e, f, g, h, i)
#endif /* P2PLOGGING */

#ifdef __cplusplus
}
#endif

#endif /* _P2PLIB_OSL_H_ */
