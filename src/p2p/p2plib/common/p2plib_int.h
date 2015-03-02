/* P2P API internal definitions
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: p2plib_int.h,v 1.158 2011-01-08 00:54:23 $
 */

#ifndef _p2plib_int_h_
#define _p2plib_int_h_

#include <wpscli_api.h>

/* P2P Library include files */
#include <BcmP2PAPI.h>
#include <BcmP2PDbg.h>
#include <p2plib_api.h>
#include <p2plib_osl.h>

#include <typedefs.h>
#include <wpscommon.h>
#include <wlioctl.h>

#ifdef __cplusplus
extern "C" {
#endif


/*
 * P2P Library compile options
 */

/* Set this to 1 in the makefile to enable the WPS registrar and enrollee.
 * If not enabled then no security will be used in the connection.
 */
#ifndef P2PAPI_ENABLE_WPS
	#define P2PAPI_ENABLE_WPS 0	/* default */
#endif /* P2PAPI_ENABLE_WPS */

/* Set this to 1 in the makefile to enable support for more than 1 P2P channel
 * (otherwise it will only support the social channel in the connect API).
 */
#ifndef P2PAPI_ENABLE_MULTI_CHANNEL
	#define P2PAPI_ENABLE_MULTI_CHANNEL 0	/* default */
#endif /* P2PAPI_ENABLE_MULTI_CHANNEL */

/* Set this to 1 in the makefile to enable the DHCP server.
 */
#ifndef P2PAPI_ENABLE_DHCPD
	#define P2PAPI_ENABLE_DHCPD 0	/* default */
#endif /* P2PAPI_ENABLE_DHCPD */

/* Set this to 1 in the makefile to enable using the in-driver WPA2-PSK
 * supplicant instead of an external supplicant.
 */
#ifndef P2PAPI_USE_IDSUP
	#define P2PAPI_USE_IDSUP 1	/* default */
#endif /* P2PAPI_USE_IDSUP */

/* Set this to 1 in the makefile to enable using the in-driver WPA2-PSK
 * authenticator instead of an external authenticator.
 */
#ifndef P2PAPI_USE_IDAUTH
	#define P2PAPI_USE_IDAUTH 1	/* default */
#endif /* P2PAPI_USE_IDAUTH */

/* Set this to 1 in the makefile to enable printing security keys+wpsPin
 * in clear/unencrypted format.
 * This is mainly used for debug. For a produce release build, this flag
 * should be set to 0.
 */
#ifndef P2PAPI_ENABLE_DEBUG_SHOWKEY
	#define P2PAPI_ENABLE_DEBUG_SHOWKEY 0		/* default */
#endif

/* Time required for STA peer to wait for AP peer to start WPS registrar.
 * By default, STA peer needs to wait P2PAPI_WPS_AP_CONFIG_TMO_MS
 * for AP peer to get configured . However, the max value can be
 * set in P2PAPI_WPS_AP_CONFIG_TMO_MS is limited to 2550 ms. This is
 * not enough since AP peer may take 4 seconds to start DHCP on Windows.
*/
#ifndef P2PAPI_EXTRA_AP_CONFIG_TMO_MS
#define P2PAPI_EXTRA_AP_CONFIG_TMO_MS 0
#endif

/* Parameters for sending the provision discovery request to the target peer
 * and wait for a response.
 * If no response is received from the peer, retry up to N times D ms apart.
 * N and D are selected to ensure the frame can be received by the target
 * even if the target is a GO running cycling in and out of power save.
*/
#ifndef P2PAPI_MAX_PROVDIS_RETRIES
#define P2PAPI_MAX_PROVDIS_RETRIES 2
#endif
#ifndef P2PAPI_PROVDIS_RETRY_DELAY_MS
#define P2PAPI_PROVDIS_RETRY_DELAY_MS 554
#endif
#ifndef P2PAPI_PROVDIS_RESP_WAIT_MS
#define P2PAPI_PROVDIS_RESP_WAIT_MS 500
#endif

/* Parameters for action frame tx retries.
 * If no 802.11 ack is received from the peer, retry up to N times D ms apart.
 * The value of D is a prime number chosen to avoid lining up with the
 * multiples of 100ms for the Listen state duration. (And also to avoid lining
 * up with the Broadcom-specific multiples of 10ms for the Search state.)
 */
#ifndef P2PAPI_MAX_AF_TX_RETRIES
#define P2PAPI_MAX_AF_TX_RETRIES 30
#endif
#ifndef P2PAPI_AF_TX_RETRY_DELAY_MS
#define P2PAPI_AF_TX_RETRY_DELAY_MS 37
#endif

/*
 * Macros
 */

/* IOCTL swapping mode for Big Endian host with Little Endian dongle.
 * Default to off.
 */
#define htod32(i) i
#define htod16(i) i
#define dtoh32(i) i
#define dtoh16(i) i
#define htodchanspec(i) i
#define dtohchanspec(i) i
#define htodenum(i) i
#define dtohenum(i) i

#ifndef P2PLIB_ASSERT
extern void p2plib_assert(char *fmt, int line);
#define P2PLIB_ASSERT_MSG "*** P2PLIB ASSERTION FAILED: "
#define P2PLIB_ASSERT(test) \
	do { \
		(test) ? (void)0 : p2plib_assert(P2PLIB_ASSERT_MSG __FILE__ ":%u\n", __LINE__); \
	} while (0)
#endif /* P2PLIB_ASSERT */


/*
 * Constants and Types
 */

/* Default discovery parameters */
#define P2PAPI_DEFAULT_DISCOVERY_TIMEOUT 60
#define P2PAPI_DEFAULT_DISCOVERY_INIT_SCAN_MS 2500
#ifndef P2PAPI_DEFAULT_LISTEN_CHANNEL
#define P2PAPI_DEFAULT_LISTEN_CHANNEL 11
#endif /* P2PAPI_DEFAULT_LISTEN_CHANNEL */
#define P2PAPI_DEFAULT_FRIENDLY_NAME "P2PDEVICE"

/* P2P spec timeouts */
#ifndef P2PAPI_GROUP_OWNER_NEG_TMO_MS
#define P2PAPI_GROUP_OWNER_NEG_TMO_MS	700
#endif /* P2PAPI_GROUP_OWNER_NEG_TMO_MS */

#define P2PAPI_GROUP_FORMATION_TMO_SEC	15
#ifndef P2PAPI_CHANNEL_SYNC_TMO_MS
#define P2PAPI_CHANNEL_SYNC_TMO_MS	5000
#endif

#ifndef P2PAPI_GONREQ_RETRY_TMO_MS
#define P2PAPI_GONREQ_RETRY_TMO_MS	2000
#endif

/* P2P spec social channels */
#define P2PAPI_SOCIAL_CHAN_CLASS	BCMP2P_LISTEN_CHANNEL_CLASS
#define P2PAPI_SOCIAL_CHAN_1	1
#define P2PAPI_SOCIAL_CHAN_2	6
#define P2PAPI_SOCIAL_CHAN_3	11

/* Scan parameters */
#define P2PAPI_SCAN_NPROBES 1
#define P2PAPI_SCAN_DWELL_TIME_MS 40
#define P2PAPI_SCAN_HOME_TIME_MS 10

/* Dwell time to stay off-channel to wait for a response action frame after
 * transmitting an GO Negotiation action frame.
 */
#ifndef P2PAPI_AF_DWELL_TIME
#define P2PAPI_AF_DWELL_TIME 200
#endif

/* Each discovered peer's expiry_count is decremented about once every 300ms
 * When it reaches 0, the peer is pruned from the peers list.
 */
#define P2PAPI_PEER_INFO_EXPIRY_COUNT 20

/* Max buffer size for vndr IE set or get */
#define P2PAPI_MAX_VNDR_IE_SIZE	2048

/* Time required for AP peer to start up WPS registrar after completing GON */
#ifndef P2PAPI_WPS_AP_CONFIG_TMO_MS
#define P2PAPI_WPS_AP_CONFIG_TMO_MS 2550
#endif

/* Structure used to encode a WiFi P2P IE */
typedef struct p2papi_p2p_ie_enc {
	uint8	*subelts;	/* points to variable len subelements in 'data' field */
	uint8	id;			/* IE ID: P2P_IE_ID */
	uint8	len;		/* IE length */
	uint8	OUI[3];		/* WiFi Alliance OUI */
	uint8	data[400];
} p2papi_p2p_ie_enc_t;

/* decode tie breaker and intent */
#define p2papi_decode_tie_breaker(x)	((x) & 0x01)
#define p2papi_decode_intent(x) 		(((x) >> 1) < 15 ? ((x) >> 1) : 15)

/*
 * OS-independent functions to invoke WL driver features.
 */
int p2pwlu_check_wl_if(p2papi_instance_t *hdl);
int p2pwlu_vndr_ie(p2papi_instance_t* hdl, char *add_del_cmd, uint32 pktflag,
	uint8 oui0, uint8 oui1, uint8 oui2, uint8 ie_id,
	const uint8 *data, int datalen);
int p2pwlu_get_mac_addr(p2papi_instance_t *hdl, struct ether_addr *out_mac_addr);
int p2pwlu_up(p2papi_instance_t *hdl);
int p2pwlu_down(p2papi_instance_t *hdl);
BCMP2P_BOOL p2pwlu_isup(p2papi_instance_t *hdl);
int p2pwlu_bss(p2papi_instance_t *hdl, bool up);
BCMP2P_BOOL p2pwlu_bss_isup(p2papi_instance_t *hdl);
int p2pwlu_scan_channels(p2papi_instance_t *hdl, int nprobes, int chan_dwell_ms,
	int channel1, int channel2, int channel3);
int p2pwlu_scan(p2papi_instance_t *hdl, int channel, int nprobes);
int p2pwlu_scan_nchannels(p2papi_instance_t *hdl, int nprobes,
	int chan_dwell_ms, BCMP2P_INT32 num_channels, BCMP2P_UINT16* channels_list);
int p2pwlu_escan_abort(p2papi_instance_t *hdl);
int p2pwlu_scan_abort(p2papi_instance_t *hdl,
	BCMP2P_BOOL wait_for_abort_complete);
int p2pwlu_join(p2papi_instance_t *hdl, char *ssid, size_t ssid_len);
int p2pwlu_join_bssid(p2papi_instance_t *hdl, char *ssid, size_t ssid_len,
	struct ether_addr *bssid, int num_chanspec, chanspec_t *chanspec);
int p2pwlu_join_open(p2papi_instance_t *hdl, char *bss_ssid);
int p2pwlu_disassoc(p2papi_instance_t *hdl);
int p2pwlu_set_apsta(p2papi_instance_t* hdl, int val);
int p2pwlu_get_apsta(p2papi_instance_t* hdl);
int p2pwlu_set_ssid(p2papi_instance_t* hdl, uint8 *name, uint32 len);
int p2pwlu_get_ssid(p2papi_instance_t* hdl, wlc_ssid_t *ssid);
int p2pwlu_set_wsec_restrict(p2papi_instance_t* hdl, int val);
int p2pwlu_get_quiet_channel(p2papi_instance_t *hdl, chanspec_t *chspec);
int p2pwlu_set_chanspec(p2papi_instance_t *hdl, chanspec_t chspec, int bssidx);
int p2pwlu_get_chanspec(p2papi_instance_t *hdl, chanspec_t *chspec, int bssidx);
int p2pwlu_p2p_apsta_setup(p2papi_instance_t *hdl);
int p2pwlu_set_listen_interval(p2papi_instance_t *hdl, unsigned int interval, int bssidx);
int p2pwlu_set_roam_off(p2papi_instance_t *hdl, unsigned int roam_off, int bssidx);
int p2pwlu_send_act_frame(p2papi_instance_t *hdl, wl_af_params_t *af_params, int bssidx);
int p2pwlu_set_event_mask(p2papi_instance_t* hdl, uint8 *mask, size_t mask_len);
int p2pwlu_get_event_mask(p2papi_instance_t* hdl, uint8 *mask, size_t mask_len);
int p2pwlu_get_assoclist(p2papi_instance_t* hdl, uint32 max_entries,
	struct ether_addr out_assoclist[], uint32 *out_num_entries);

/* Get a list of all STAs authorized to this AP */
int p2pwlu_get_autho_sta_list(p2papi_instance_t* hdl, uint32 max_entries,
	uint32 *out_num_entries);

/* Check if connected to a BSS (call this only on the STA peer) */
bool p2pwlu_is_associated(p2papi_instance_t* hdl);

/* Check if peer has connected to our BSS on the AP peer */
int p2pwlu_get_assoc_count(p2papi_instance_t *hdl, bool show_maclist,
	int *out_assoc_count);

/* For debug */
void p2pwlu_dbg_show_all_status(void* handle);

/* Deauthenticate an associated STA.  Returns 0 if success */
int p2pwlu_deauth_sta(p2papi_instance_t* hdl, unsigned char* sta_mac,
	int dot11_reason);

/*
 * Miscellaneous shared functions
 */
/* Traverse to next TLV */
uint8 *p2papi_next_tlv(uint8 *tlv_buf, uint *buflen);

/* Parse a tag-length-variable-value IE buffer */
uint8 * p2papi_parse_tlvs(uint8 *tlv_buf, uint *buflen, uint *ielen, uint key,
	BCMP2P_LOG_LEVEL log);

/* Returns TRUE if P2P IE */
BCMP2P_BOOL p2papi_is_p2p_ie(uint8 *p2pie);

/* Returns TRUE if WPS IE */
BCMP2P_BOOL p2papi_is_wps_ie(uint8 *wpsie);

/* Returns TRUE if WPA IE */
BCMP2P_BOOL p2papi_is_wpa_ie(uint8 *wpsie);



/* Set the driver's P2P discovery state */
int p2pwlu_set_p2p_mode(p2papi_instance_t* hdl, uint8 wl_p2p_disc_state,
	chanspec_t chspec, uint16 ms);

/* Check if 'p2p' is supported in the driver */
int p2pwlu_is_p2p_supported(p2papi_instance_t* hdl);

/* Create or delete a P2P connection BSS */
int p2papi_create_ap_bss(p2papi_instance_t* hdl);
int p2papi_delete_ap_bss(p2papi_instance_t* hdl);
int p2papi_create_sta_bss(p2papi_instance_t* hdl);
int p2papi_delete_sta_bss(p2papi_instance_t* hdl);

/* Set the soft AP network interface to the DHCP server's hardcoded static IP
 * address.
 */
BCMP2P_BOOL p2papi_set_ap_ipaddr(p2papi_instance_t* hdl);

/* Get the BSSCFG index for a P2P Library BSS of the specified type */
int p2papi_get_bsscfg_idx(p2papi_instance_t* hdl,
	p2papi_bsscfg_type_t bss_usage_id);

/* Search for a RSN IE or WPA IE in the given IE data. */
int p2papi_search_for_security_ies(uint8* cp, uint len);

/* Search for and decode P2P and WPS IEs in the given IE data. */
int p2papi_search_ies(uint8* cp, uint len, uint32 *out_channel,
	p2papi_p2p_ie_t *out_p2p_ie, p2papi_wps_ie_t *out_wps_ie,
	BCMP2P_LOG_LEVEL log);

/* Encode a P2P Device Discoverability Request P2P IE */
void p2papi_encode_dev_discb_req_p2p_ie(p2papi_instance_t* hdl,
	struct ether_addr *gc_dev_addr, wifi_p2p_ie_t *p2p_ie, uint16 *ie_len);

/* Encode a P2P Invitation Request P2P IE */
void p2papi_encode_inv_req_p2p_ie(p2papi_instance_t* hdl,
    uint16 go_cfg_tmo_ms, uint16 gc_cfg_tmo_ms, BCMP2P_CHANNEL *op_channel,
	uint8 *p2p_grp_bssid, uint8 invite_flags,
	char *country, p2p_chanlist_t *chanlist,
	uint8 *p2pgrpid_dev_addr, uint8 *p2pgrpid_ssid, int p2pgrpid_ssid_len,
	uint8 *dev_addr, uint8 *name, uint8 name_len,
	wifi_p2p_ie_t *p2p_ie, uint16 *ie_len);

/* Encode a P2P Invitation Response P2P IE */
void p2papi_encode_inv_rsp_p2p_ie(p2papi_instance_t* hdl, uint8 status,
    uint16 go_cfg_tmo_ms, uint16 gc_cfg_tmo_ms, BCMP2P_CHANNEL *op_channel,
	uint8 *p2p_grp_bssid,
	char *country, p2p_chanlist_t *chanlist,
	wifi_p2p_ie_t *p2p_ie, uint16 *ie_len);

/* encode presence request P2P IEs */
void p2papi_encode_presence_req_p2p_ie(p2papi_instance_t* hdl,
	uint8 index, BCMP2P_BOOL oppps, uint8 ctwindow,
	uint8 num_noa_desc, wifi_p2p_noa_desc_t *noa_desc,
	wifi_p2p_ie_t *p2p_ie, uint16 *ie_len);

/* encode presence request P2P IEs */
void p2papi_encode_presence_rsp_p2p_ie(p2papi_instance_t* hdl, uint8 status,
	uint8 index, BCMP2P_BOOL oppps, uint8 ctwindow,
	uint8 num_noa_desc, wifi_p2p_noa_desc_t *noa_desc,
	wifi_p2p_ie_t *p2p_ie, uint16 *ie_len);

/* Encode a Device Discoverability Request P2P IE */
extern void
p2papi_encode_discb_req_p2p_ie(p2papi_instance_t* hdl, uint8 *client_dev_addr,
	uint8 *go_dev_addr, uint8 *go_ssid, int go_ssid_len,
	wifi_p2p_ie_t *p2p_ie, uint16 *ie_len);

/* Encode a Device Discoverability Response P2P IE */
extern void
p2papi_encode_discb_rsp_p2p_ie(p2papi_instance_t* hdl, uint8 status,
	wifi_p2p_ie_t *p2p_ie, uint16 *ie_len);

/* Encode a Group Owner Negotiation P2P IE */
void p2papi_encode_gon_req_p2p_ie(p2papi_instance_t* hdl, uint8 intent,
	BCMP2P_CHANNEL *listen_channel, BCMP2P_CHANNEL *op_channel,
	uint8 status, uint8 *dev_addr,
	BCMP2P_BOOL is_ext_listen, uint16 ext_listen_period, uint16 ext_listen_interval,
	char *country, p2p_chanlist_t *chanlist,
	uint8 *name, uint8 name_len, wifi_p2p_ie_t *p2p_ie, uint16 *ie_len);
void p2papi_encode_gon_rsp_p2p_ie(p2papi_instance_t* hdl,
	char *grp_ssid, int grp_ssid_len,
	uint8 intent, BCMP2P_CHANNEL *channel, uint8 status, uint8 *dev_addr,
	char *country, p2p_chanlist_t *chanlist,
	uint8 *friendly_name, uint8 friendly_name_len,
	wifi_p2p_ie_t *p2p_ie, uint16 *ie_len);
void p2papi_encode_gon_conf_p2p_ie(p2papi_instance_t* hdl,
	uint8 intent, BCMP2P_CHANNEL *channel, uint8 status, uint8 *dev_addr,
	char *country, p2p_chanlist_t *chanlist,
	char *grp_ssid, uint8 grp_ssid_len,
	wifi_p2p_ie_t *p2p_ie, uint16 *ie_len);

/* Encode a Provision Discovery P2P IE */
extern void
p2papi_encode_provdis_p2p_ie(p2papi_instance_t* hdl,
	uint8 *dev_addr, uint8 *name, uint8 name_len,
	uint8 *ssid, int ssid_len, uint8 *peer_dev_addr,
	wifi_p2p_ie_t *p2p_ie, uint16 *ie_len);

/* Encode a Provision Discovery WPS IE */
extern void
p2papi_encode_provdis_wps_ie(p2papi_instance_t* hdl, p2papi_p2p_ie_enc_t *wps_ie,
	uint8 *name, uint8 name_len, BCMP2P_BOOL enc_cfg_meth, uint16 cfg_methods,
	uint16 *total_ie_len);
extern void
p2papi_encode_gon_wps_ie(p2papi_instance_t* hdl, p2papi_p2p_ie_enc_t *wps_ie,
	uint8 *name, uint8 name_len, BCMP2P_BOOL enc_cfg_meth, uint16 cfg_methods,
	uint16 dev_pwdid, uint16 *total_ie_len);


/* Decode a P2P IE */
extern uint16
p2papi_decode_p2p_ie(uint8* buf, p2papi_p2p_ie_t *out_p2p_ie, BCMP2P_LOG_LEVEL log);
uint16 p2papi_decode_p2p_ie_length(uint8 *buf);

/* Decode a WPS IE */
extern uint16
p2papi_decode_wps_ie(uint8* buf, p2papi_wps_ie_t *out_wps_ie, BCMP2P_LOG_LEVEL log);

/* Search for and decode P2P and WPS IEs in the given IE data.
 * Currently only correctly handles at most 1 P2P IE and 1 WPS IE.
 * If IEs found, copies the IE data into out_p2p_ie and out_wps_ie.
 * Returns 0 if any P2P or WPS IEs were found and decoded.
 */
int p2papi_search_p2pwps_ies(uint8* cp, uint len,
	p2papi_p2p_ie_t *out_p2p_ie, p2papi_wps_ie_t *out_wps_ie, bool dbg);

/* Update P2P and WPS IEs in Probe Response frames */
int p2papi_update_prbresp_ies(p2papi_instance_t* hdl,
	p2papi_bsscfg_type_t bsscfg_type);

/* Update P2P and WPS IEs in all frame types based on the connection state */
int p2papi_update_p2p_wps_ies(p2papi_instance_t* hdl,
	p2papi_bsscfg_type_t bss_usage_id);
int p2papi_update_p2p_wps_ies_nolock(p2papi_instance_t* hdl,
	p2papi_bsscfg_type_t bss_usage_id);

/* Reset all saved P2P and WPS IEs */
int p2papi_reset_saved_p2p_wps_ies(p2papi_instance_t* hdl,
	p2papi_bsscfg_type_t bss_usage_id);
int p2papi_reset_saved_p2p_wps_ies_nolock(p2papi_instance_t* hdl,
	p2papi_bsscfg_type_t bss_usage_id);


/* Check if a received frame is a P2P Action Frame */
int p2papi_is_p2p_action_frm(p2papi_instance_t *hdl, void *frame, uint32 frame_len);

/* Check if a received frame is a P2P Public Action Frame */
int p2papi_is_p2p_pub_act_frm(p2papi_instance_t *hdl, void *frame, uint32 frame_len);

/* Enable/Disable the softAP */
int p2papi_softap_enable(p2papi_instance_t* hdl, BCMP2P_BOOL is_wps_pbc_mode);
int p2papi_softap_disable(p2papi_instance_t* hdl);
int p2papi_softap_disable_nolock(p2papi_instance_t* hdl);

wl_af_params_t *
p2plib_build_p2p_pub_act_frm(p2papi_instance_t* hdl, struct ether_addr *dst_ea,
	uint8 *oui, uint8 oui_type, uint8 oui_subtype, uint8 dialog_token,
	uint8 *ie, uint16 ie_len, uint8 *ie2, uint16 ie2_len, uint8 *ie3, uint16 ie3_len,
	BCMP2P_CHANNEL *channel, int32 dwell_time_ms);

wl_af_params_t *
p2plib_build_p2p_act_frm(p2papi_instance_t* hdl, struct ether_addr *dst_ea,
	uint8 *oui, uint8 oui_type, uint8 oui_subtype, uint8 dialog_token,
	uint8 *ie, uint16 ie_len, uint8 *ie2, uint16 ie2_len, uint8 *ie3, uint16 ie3_len,
	BCMP2P_CHANNEL *channel, int32 dwell_time_ms);

/* Process a client STA association WLC_E_ASSOC_IND event */
int p2papi_proc_client_assoc(p2papi_instance_t *hdl, wl_event_msg_t *event,
	void *data, uint32 data_len);

/* Process a client STA association WLC_E_DISASSOC_IND event */
int p2papi_proc_client_disassoc(p2papi_instance_t *hdl, wl_event_msg_t *event,
	void *data, uint32 data_len);

/* Process a WLC_E_ASSOC_RESP_IE event which carries the IE data in the association
 * response from peer AP
 */
void p2papi_proc_ap_assoc_resp_ie(p2papi_instance_t *hdl, wl_event_msg_t *event,
	void *data, uint32 data_len);

/* Find a Group Client STA in our associated clients list */
p2papi_client_info_t* p2papi_find_group_client(p2papi_instance_t *hdl,
	struct ether_addr *client_addr);

BCMP2P_STATUS p2papi_reset_state(p2papi_instance_t* hdl);

/* Send the given action frame to the peer after performing the Find Phase's
 * search-listen procedure to arrive on a common channel with the peer.
 */
extern int
p2papi_send_at_common_channel(p2papi_instance_t* hdl, BCMP2P_CHANNEL *search_channel,
	wl_af_params_t *tx_act_frame, BCMP2P_AFTX_CALLBACK tx_complete_cb,
	BCMP2P_BOOL do_scans, p2papi_aftx_instance_t** aftx_hdlp,
	const char* dbg_af_name);
int p2papi_cancel_send_at_common_channel(p2papi_instance_t* hdl);

/* Send an action frame immediately without doing channel synchronization.
 *
 * This function does not wait for a completion event before returning.
 * The WLC_E_ACTION_FRAME_COMPLETE event will be received when the action
 * frame is transmitted.
 * The WLC_E_ACTION_FRAME_OFFCHAN_COMPLETE event will be received when an
 * 802.11 ack has been received for the sent action frame.
 */
int p2papi_tx_af(p2papi_instance_t* hdl, wl_af_params_t *af_params, int bssidx);

/* Enable P2P discovery before AF tx channel synchronization */
void p2papi_chsync_discov_enable(p2papi_instance_t* hdl);

/* Disable P2P discovery after AF tx channel synchronization */
void p2papi_chsync_discov_disable(p2papi_instance_t* hdl);

#ifndef SOFTAP_ONLY
/* Cancel any action frame tx in progress */
void p2papi_cancel_all_aftx_send(p2papi_instance_t* hdl);
#endif /* not SOFTAP_ONLY */

/*
 * Set/Get WL driver ioctl/iovars
 */
int p2pwlu_ioctl_get_bss(p2papi_instance_t *hdl, int cmd, void *buf, int len,
	int bsscfg_idx);
int p2pwlu_iovar_get(p2papi_instance_t *hdl, const char *iovar, void *outbuf,
	int len);
int p2pwlu_iovar_getint(p2papi_instance_t *hdl, const char *iovar, int *pval);
int p2pwlu_iovar_getbuf(p2papi_instance_t *hdl, const char *iovar,
	void *param, int paramlen, void *bufptr, int buflen);
int p2pwlu_ioctl_set_bss(p2papi_instance_t *hdl, int cmd, void *buf, int len,
	int bssidx);
int p2pwlu_iovar_set(p2papi_instance_t *hdl, const char *iovar, void *param,
	int paramlen);
int p2pwlu_iovar_setint(p2papi_instance_t *hdl, const char *iovar, int val);
int p2pwlu_iovar_setbuf(p2papi_instance_t *hdl, const char *iovar,
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
int p2pwlu_bssiovar_get(p2papi_instance_t *hdl, const char *iovar, int bssidx,
	void *outbuf, int len);
int p2pwlu_bssiovar_set(p2papi_instance_t *hdl, const char *iovar, int bssidx,
	void *param, int paramlen);
int p2pwlu_bssiovar_setint(p2papi_instance_t *hdl, const char *iovar, int bssidx,
	int val);


/*
 * WPS-related Functions
 */
/* Do the WPS registrar initial EAPOL Start/Identity handshake */
int p2papi_reg_eap_start(int timeout);

void p2papi_wps_cleanup(void);

uint32 p2papi_wait_for_eapol_packet(char* buf, uint32* len,
	uint32 timeout);


/*
 * Debug functions
 */
/* Debug: print out a set of WPS credentials */
void print_credential(brcm_wpscli_nw_settings *credential, char *title);

/* Debug: check a P2PAPI instance handle and print an error if bad */
bool p2papi_chk_p2phdl(void* p2pHdl, const char *file, int line);
#define P2PAPI_CHECK_P2PHDL(hdl)	p2papi_chk_p2phdl(hdl, __FILE__, __LINE__)


/*
 * Global variables
 */

/* Event notification configuration data */
typedef struct p2papi_notif_config_s {
	BCMP2P_NOTIFICATION_TYPE		type;
	BCMP2P_NOTIFICATION_CALLBACK	callback;
	void							*cbContext;
} p2papi_notif_config_t;
extern p2papi_notif_config_t p2papi_notifs;

extern BCMP2P_LOG_LEVEL p2papi_log_level;	/* Debug log verbosity */


/*
 * Instance data accessor functions
 */

/* Get ptr to our current event notifications configuration */
p2papi_notif_config_t* p2papi_get_notifs(p2papi_instance_t *hdl);

/* Get/Set our OSL handle */
void* p2papi_get_osl_hdl(p2papi_instance_t *hdl);
void p2papi_set_osl_hdl(p2papi_instance_t *hdl, void *oslhdl);

/* Get our discovered peers list */
void p2papi_get_peers_array(p2papi_instance_t *hdl,
	p2papi_peer_info_t** peers_array, unsigned int *peers_count);

/* Get our discovered peers count */
unsigned int p2papi_get_peers_count(p2papi_instance_t *hdl);

/* Get our negotiated WPS credentials */
brcm_wpscli_nw_settings* p2papi_get_wps_credentials(p2papi_instance_t *hdl);

/* Get our social timeout */
int p2papi_get_discovery_timeout(p2papi_instance_t *hdl);

/* Get our peer's P2P Device Address */
struct ether_addr* p2papi_get_peer_mac(p2papi_instance_t *hdl);

/* Generate random P2P character */
char p2papi_random_char(void);

/* Generate a GO SSID compliant with P2P spec 1.01 section 3.2.1 */
void p2papi_generate_go_ssid(p2papi_instance_t *hdl,
	brcm_wpscli_nw_settings *credential);

/* Conditional sleep */
bool p2papi_conditional_sleep_ms(P2PAPI_OSL_SLEEP_REASON reason,
	bool *cancel, uint32 ms);

void passphrase_to_pmk(char *passphrase, int passphrase_length,
        unsigned char *ssid, int ssid_length, char *pmk);

/* opportunistic power save */
int p2pwlu_set_ops(p2papi_instance_t* hdl, bool enable, uint8 ctwindow);
int p2pwlu_get_ops(p2papi_instance_t* hdl, bool *enable, uint8 *ctwindow);

/* notice of absence */
int p2pwlu_set_noa(p2papi_instance_t* hdl, uint8 type, uint8 action, uint8 option,
	int num_desc, wl_p2p_sched_desc_t *desc);
int p2pwlu_get_noa(p2papi_instance_t* hdl,
	uint8 *type, uint8 *action, uint8 *option,
	int max_num_desc, int *num_desc, wl_p2p_sched_desc_t *desc);

int p2pwlu_set_PM(p2papi_instance_t* hdl, int val, int bssidx);
int p2pwlu_get_PM(p2papi_instance_t* hdl, int* val, int bssidx);


/* Wrappers for p2papi_osl_data_lock/unlock() that add debug logs */
int p2papi_data_lock(p2papi_instance_t *hdl, const char *file, int line,
	BCMP2P_LOG_LEVEL log_level);
int p2papi_data_unlock(p2papi_instance_t *hdl, const char *file, int line,
	BCMP2P_LOG_LEVEL log_level);
#define P2PAPI_DATA_LOCK(hdl) \
	p2papi_data_lock(hdl, __FILE__, __LINE__, BCMP2P_LOG_INFO)
#define P2PAPI_DATA_UNLOCK(hdl) \
	p2papi_data_unlock(hdl, __FILE__, __LINE__, BCMP2P_LOG_INFO)
#define P2PAPI_DATA_LOCK_VERB(hdl) \
	p2papi_data_lock(hdl, __FILE__, __LINE__, BCMP2P_LOG_VERB_DATALOCK)
#define P2PAPI_DATA_UNLOCK_VERB(hdl) \
	p2papi_data_unlock(hdl, __FILE__, __LINE__, BCMP2P_LOG_VERB_DATALOCK)

/* Atomic test and set using the instance data lock */
BCMP2P_BOOL p2papi_atomic_test_and_set(p2papi_instance_t *hdl,
	BCMP2P_BOOL *flag, const char *file, int line);
#define P2PAPI_TEST_AND_SET(hdl, flag) \
	p2papi_atomic_test_and_set(hdl, flag, __FILE__, __LINE__)

void
p2papi_add_timer(void* p2pHandle, bcmseclib_timer_t *t, uint ms, bool periodic);

uint8
p2papi_create_dialog_token(uint8 token);


/* Check if a received action frame is a duplicate */
extern BCMP2P_BOOL
p2papi_is_duplicate_rx_frame(p2papi_instance_t *hdl,
	struct ether_addr *src_mac, uint8 frame_subtype, uint8 dialog_token);

/* Clear the duplicate rx action frame detector */
extern void
p2papi_clear_duplicate_rx_actframe_detect(p2papi_instance_t* hdl);


int p2papi_decode_p2pwps_ies(uint8* ie, uint32 ie_len,
	p2papi_p2p_ie_t *out_p2p_ie, p2papi_wps_ie_t *out_wps_ie);

/* add timer */
void
p2papi_add_timer(void* p2pHandle, bcmseclib_timer_t *t, uint ms, bool periodic);

void
p2papi_negotiate_chanlist(p2p_chanlist_t *dst, p2p_chanlist_t *self, p2p_chanlist_t *peer);

void
p2papi_update_chanlist(p2p_chanlist_t *dst, p2p_chanlist_t *src);

/* Look up the regulatory class (band) for a given channel */
BCMP2P_STATUS p2papi_get_channel_class(uint8 channel, uint8 *band);

/* channel array/list conversion functions */
BCMP2P_BOOL p2papi_channel_array_to_list(
	int num_channels, BCMP2P_CHANNEL *channels, p2p_chanlist_t *channel_list);
BCMP2P_BOOL p2papi_channel_list_to_array(p2p_chanlist_t *channel_list,
	int maxNumChannels, BCMP2P_CHANNEL *channels, int *numChannels);

/* get driver channel list or user configured channel list if defined */
p2p_chanlist_t *p2papi_get_channel_list(p2papi_instance_t* hdl);

/* get non-dfs channel list or user configured channel list if defined */
p2p_chanlist_t *p2papi_get_non_dfs_channel_list(p2papi_instance_t* hdl);


BCMP2P_STATUS
p2papi_add_mgmt_custom_ie(p2papi_instance_t *hdl, BCMP2P_MGMT_IE_FLAG ie_flag,
	BCMP2P_UINT8 *ie_buf, int ie_buf_len, BCMP2P_BOOL set_immed);

BCMP2P_STATUS
p2papi_add_acf_custom_ie(p2papi_instance_t *hdl, BCMP2P_ACF_IE_FLAG ie_flag,
	BCMP2P_UINT8 *ie_buf, int ie_buf_len);

BCMP2P_STATUS
p2papi_del_mgmt_custom_ie(p2papi_instance_t *hdl, BCMP2P_MGMT_IE_FLAG ie_flag);

BCMP2P_STATUS
p2papi_del_acf_custom_ie(p2papi_instance_t *hdl, BCMP2P_ACF_IE_FLAG ie_flag);

BCMP2P_STATUS
p2papi_register_gon_req_cb(p2papi_instance_t *hdl, int notificationType,
	BCMP2P_GONREQ_CALLBACK funcCallback, void *pCallbackContext,
	void *pReserved);

int
p2papi_replace_and_save_ie(p2papi_instance_t* hdl, uint32 pktflag,
	uint8 oui0, uint8 oui1, uint8 oui2, uint8 ie_id, int bssidx,
	uint8 **old_ie_bufp, int *old_ie_lenp, uint8 *new_ie, int new_ie_len);
int
p2pwlu_set_wme_apsd_sta(p2papi_instance_t *hdl, uint8 maxSPLen,
	uint8 acBE, uint8 acBK, uint8 acVI, uint8 acVO, int bssidx);

#ifdef __cplusplus
}
#endif

#endif /* _p2plib_int_h_ */
