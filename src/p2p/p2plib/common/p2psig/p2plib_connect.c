/*
 * P2P Library API - Connection creation-related functions (OS-independent)
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: p2plib_connect.c,v 1.397 2011-01-26 04:44:52 $
 */
#include <stdlib.h>
#include <ctype.h>

/* P2P Library include files */
#include <BcmP2PAPI.h>
#include <p2plib_api.h>
#include <p2plib_int.h>
#include <p2pwl.h>

/* WL driver include files */
#include <bcmendian.h>
#include <wlioctl.h>
#include <bcmutils.h>
#include <wpserror.h>

#if P2PAPI_ENABLE_DHCPD
#include <dhcp.h>
#endif /* P2PAPI_ENABLE_DHCPD */


#define WPSREG_MGR_LOOP_MS 200
#define WPSREG_MGR_PBC_OVERLAP_RETRY_MS 800
#define P2PAPI_DEFAULT_WPS_WINDOW_OPEN_SECS 120
#define P2PAPI_PBC_TIMEOUT	120
#define WPS_MAX_ATTEMPTS 2

#ifdef TARGETOS_symbian
	#define P2PAPI_WAIT_FOR_JOIN_LOOP_MS 500
#else
	#define P2PAPI_WAIT_FOR_JOIN_LOOP_MS 100
#endif

/* This must match WPS_OUI in 802.11.h */
const unsigned char p2plib_wps_oui[4] = { 0x00, 0x50, 0xf2, 0x04 };

#if P2PAPI_ENABLE_DHCPD
static unsigned char p2plib_bcast_mac[] =
	{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
#endif /* P2PAPI_ENABLE_DHCPD */

extern char *ether_ntoa(const struct ether_addr *addr);

static BCMP2P_STATUS p2papi_group_create_core(p2papi_instance_t* hdl,
	bool repeat_wps, bool open_wps_window);
static BCMP2P_STATUS p2papi_softap_cleanup(p2papi_instance_t* hdl);
static void p2papi_notify_timeout_wps_pbc(void *arg);
static void p2papi_notify_timeout_wps_reg(void *arg);
static brcm_wpscli_status p2papi_process_eapol(p2papi_instance_t *hdl, uint32 event_type,
                                               char *buf, int len);

/* scan is optional as the peer information is known from p2p */
#define P2PAPI_ENABLE_WPS_SCAN	0

/*
 * Constants and types
 */

/* Callback fn type for processing a STA disassociating from the soft AP */
typedef void (*p2papi_sta_assoc_cb_t) (p2papi_instance_t* hdl,
	struct ether_addr *sta_mac);


void
print_credential(brcm_wpscli_nw_settings *credential, char *title)
{
	static const char *ENCR_STR[] = {"None", "WEP", "TKIP", "AES"};
	static const char *AUTH_STR[] = {"OPEN", "SHARED", "WPA-PSK", "WPA2-PSK"};

	if (title)
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "%s\n", title));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "  SSID: %s\n", credential->ssid));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "  Key Mgmt type: %s\n",
		AUTH_STR[credential->authType]));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "  Encryption type: %s\n",
		ENCR_STR[credential->encrType]));
#if P2PAPI_ENABLE_DEBUG_SHOWKEY
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "  Network key: %s\n", credential->nwKey));
#endif /* P2PAPI_ENABLE_DEBUG_SHOWKEY */
}

#if P2PAPI_ENABLE_WPS

static char*
p2papi_wps_status_str(brcm_wpscli_status status)
{
	char *errstr = "";
	switch (status) {
		case WPS_STATUS_SUCCESS:
			errstr = "(success)";
			break;
		case WPS_STATUS_WINDOW_NOT_OPEN:
			errstr = "(wps window not open)";
			break;
		case WPS_STATUS_PROTOCOL_FAIL_TIMEOUT:
			errstr = "(timeout)";
			break;
		case WPS_STATUS_PROTOCOL_FAIL_MAX_EAP_RETRY:
			errstr = "(max eap retries exceeded)";
			break;
		case WPS_STATUS_PROTOCOL_FAIL_OVERLAP:
			errstr = "(PBC overlap)";
			break;
		case WPS_STATUS_PROTOCOL_FAIL_WRONG_PIN:
			errstr = "(wrong pin)";
			break;
		case WPS_STATUS_PROTOCOL_FAIL_EAP:
			errstr = "(eap failure)";
			break;
		case WPS_STATUS_WLAN_CONNECTION_ATTEMPT_FAIL:
			errstr = "(connection fail)";
			break;
		case WPS_STATUS_PKTD_SEND_PKT_FAIL:
			errstr = "(send pkt fail)";
			break;
		case WPS_STATUS_PKTD_NO_PKT:
			errstr = "(no rx pkt)";
			break;
		default:
			break;
	}
	return errstr;
}


/* Parse a set of scan results looking for a given bssid.
 * Returns a ptr to the found entry or NULL if not found.
 */
wl_bss_info_t *
p2papi_parse_for_bssid(p2papi_instance_t* hdl, wl_scan_results_t* list,
	struct ether_addr *bssid)
{
	wl_bss_info_t *found_item = NULL;
	wl_bss_info_t *bi;
	uint32 i;

	if (list == NULL || list->count == 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_parse_for_bssid: empty\n"));
		return NULL;
	}

	if (list->version != WL_BSS_INFO_VERSION &&
		list->version != LEGACY_WL_BSS_INFO_VERSION) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_parse_for_bssid: scan_results version mismatch: %d (%d)\n",
			list->version, WL_BSS_INFO_VERSION));
		return NULL;
	}

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_parse_for_bssid: count=%u\n",
		list->count));

	/* Traverse the scan results list to find items with a matching bssid */
	for (i = 0, bi = list->bss_info;
		 i < list->count;
		 i++, bi = (wl_bss_info_t*)((int8*)bi + dtoh32(bi->length))) {

		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
			"  i=%d BSSID=%02x:%02x:%02x:%02x:%02x:%02x SSID_len=%d\n", i,
			bi->BSSID.octet[0], bi->BSSID.octet[1], bi->BSSID.octet[2],
			bi->BSSID.octet[3], bi->BSSID.octet[4], bi->BSSID.octet[5],
			bi->SSID_len));

		if (memcmp(bi->BSSID.octet, bssid->octet, sizeof(bssid->octet)) == 0) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"  Found i=%d bssid=%02x:%02x:%02x:%02x:%02x:%02x ssidlen=%u\n",
				i,
				bi->BSSID.octet[0], bi->BSSID.octet[1], bi->BSSID.octet[2],
				bi->BSSID.octet[3], bi->BSSID.octet[4], bi->BSSID.octet[5],
				bi->SSID_len));
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"  ssid_len=%u ssid=%s\n", bi->SSID_len, bi->SSID));
			found_item = bi;
			break;
		}
	}

	return found_item;
}

/* Do a 802.11 scan for the AP with the given bssid on the given channel list.
 * If found, returns 0 and copies out the AP's SSID.
 */
int
p2papi_bssid_scan(p2papi_instance_t* hdl, struct ether_addr *bssid,
	int num_channels, int chanlist[], char *out_ssid, size_t out_ssid_len)
{
	int ret = BCMP2P_ERROR;

	(void) hdl;
	(void) bssid;
	(void) num_channels;
	(void) chanlist;
	(void) out_ssid,
	(void) out_ssid_len;
	return ret;
}

#ifndef SOFTAP_ONLY
/* Run the WPS enrollee to obtain security credentials from the peer's WPS
 * registrar.
 */
static int
p2papi_run_wps_enrollee(p2papi_instance_t* hdl)
{
#if P2PAPI_ENABLE_WPS_SCAN
	bool bFoundAP = FALSE;
	uint32 nAP = 0;
	uint32 ap_total;
	int i = 0;
	int retry;
	#define WPS_APLIST_BUF_SIZE \
		(BRCM_WPS_MAX_AP_NUMBER*sizeof(brcm_wpscli_ap_entry) + \
		sizeof(brcm_wpscli_ap_list))
	char buf[WPS_APLIST_BUF_SIZE] = { 0 };
	brcm_wpscli_ap_entry *ap = NULL;
#endif
	int nRetryCount = 0;
	char *pin = NULL;
	char registrar_ssid[DOT11_MAX_SSID_LEN+1];
	brcm_wpscli_status status;
	brcm_wpscli_nw_settings *nw_cred = &hdl->credentials;
	char *ifname;
	char *errstr;
	BCMP2P_NOTIFICATION_CODE notif;

	P2PAPI_CHECK_P2PHDL(hdl);

	/* The AP peer generates a SSID with the random prefix "DIRECT-xy" which
	 * is not passed to the STA peer.
	 *
	 * If using our WL driver to associate to the AP peer's registrar
	 *     Use the wildcard P2P SSID + the AP peer's bssid to associate.
	 * else
	 *     Use the AP peer's SSID to associate.  Obtain this SSID by doing a
	 *     scan on the channel list negotiated during GO Negotiation.
	 */
	/* Use the 802.11 wildcard SSID instead of the P2P Wildcard SSID.
	 * The P2P Wildcard SSID may cause a WLC_SET_SSID failure if a P2P
	 * Discovery BSS exists simultaneously with the connection BSS.
	 */
	/* strncpy(registrar_ssid, "DIRECT-", sizeof(registrar_ssid)); */
	strncpy(registrar_ssid, "", sizeof(registrar_ssid));

	if (hdl->ap_config.WPSConfig.wpsPinMode) {
		pin = hdl->ap_config.WPSConfig.wpsPin;
#if P2PAPI_ENABLE_DEBUG_SHOWKEY
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_wps_enr: pin=%s ap_bssid=%02x:%02x:%02x:%02x:%02x:%02x\n",
			pin,
			hdl->peer_int_addr.octet[0], hdl->peer_int_addr.octet[1],
			hdl->peer_int_addr.octet[2], hdl->peer_int_addr.octet[3],
			hdl->peer_int_addr.octet[4], hdl->peer_int_addr.octet[5]));
#else
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_wps_enr: pin=*** ap_bssid=%02x:%02x:%02x:%02x:%02x:%02x\n",
			hdl->peer_int_addr.octet[0], hdl->peer_int_addr.octet[1],
			hdl->peer_int_addr.octet[2], hdl->peer_int_addr.octet[3],
			hdl->peer_int_addr.octet[4], hdl->peer_int_addr.octet[5]));
#endif /* P2PAPI_ENABLE_DEBUG_SHOWKEY */
	} else {
		pin = NULL;
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_wps_enr: pin=NULL ap_bssid=%02x:%02x:%02x:%02x:%02x:%02x\n",
			hdl->peer_int_addr.octet[0], hdl->peer_int_addr.octet[1],
			hdl->peer_int_addr.octet[2], hdl->peer_int_addr.octet[3],
			hdl->peer_int_addr.octet[4], hdl->peer_int_addr.octet[5]));
	}
	hdl->is_wps_enrolling = TRUE;

	if (hdl->conn_ifname[0] == '\0') {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_wps_enr: no conn_ifname! Using %s\n",
			hdl->if_name));
		strncpy(hdl->conn_ifname, hdl->if_name,
			sizeof(hdl->conn_ifname));
		hdl->conn_ifname[sizeof(hdl->conn_ifname) - 1] = '\0';
	}

	/* Open WPS for enrollee mode and specify the network interface to use */
	ifname = hdl->conn_ifname;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_wps_enr: primary_if_name=%s, conn_ifname=%s, nw_cred.ssid=%s\n",
		hdl->primary_if_name, hdl->conn_ifname,
		nw_cred->ssid));

	status = brcm_wpscli_open(ifname, BRCM_WPSCLI_ROLE_STA, NULL, NULL);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_wps_enr: brcm_wpscli_open(%s) returned status=%d\n",
		ifname, status));

	if (status != WPS_STATUS_SUCCESS) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"brcm_wpscli_open(%s) failed, status=%d\n", ifname, status));
		goto enr_exit;
	}
	hdl->conn_state = P2PAPI_ST_WPS_HANDSHAKE;

#if P2PAPI_ENABLE_WPS_SCAN
	/* Loop to repeatedly search for a WPS registrar */
	for (retry = 0; retry < 10; retry++) {
		p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_WPS_ENROLLEE_WAIT_POLL, 200);

		status = brcm_wpscli_sta_search_wps_ap(&nAP);
		if (status != WPS_STATUS_SUCCESS) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_wps_enr: search found no WPS AP, status=%d\n", status));
			continue;
		}

		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_wps_enr: brcm_wpscli_sta_search_wps_ap, status=%d nAP=%u\n",
			status, nAP));

		/* Get the list of wps APs */
		status = brcm_wpscli_sta_get_wps_ap_list((brcm_wpscli_ap_list *)buf,
			sizeof(brcm_wpscli_ap_entry)*BRCM_WPS_MAX_AP_NUMBER, &ap_total);
		if (status != WPS_STATUS_SUCCESS) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_wps_enr: get wps ap list failed: %d\n", status));
			continue;
		}
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_wps_enr: registrar search %u: ap_tot=%u nAP=%u\n",
			retry, ap_total, nAP));
		for (i = 0; i < (int) ap_total; i++) {
			ap = &(((brcm_wpscli_ap_list *)buf)->ap_entries[i]);
			P2PLOG3("          : AP %d: ssid=%s mode=%s\n", i, ap->ssid,
			   ap->pwd_type == BRCM_WPS_PWD_TYPE_PBC? "PBC" : "PIN");
			if (memcmp(ap->bssid, hdl->peer_int_addr.octet,
				sizeof(ap->bssid)) == 0) {
				bFoundAP = TRUE;
				break;
			}
		}
		if (bFoundAP)
			break;
		if (!bFoundAP || nAP == 0) {
			status = WPS_STATUS_WLAN_NO_WPS_AP_FOUND;
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_wps_enr: WPS AP %s not in list.\n", registrar_ssid));
		}

		if (hdl->cancel_link_create || hdl->cancel_group_create)
			break;
	}

	if (!bFoundAP || nAP == 0 || ap == NULL) {
		goto enr_exit;
	}
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_wps_enr: search found %d WPS APs, isPBC=%d\n",
		nAP, (ap->pwd_type == BRCM_WPS_PWD_TYPE_PBC)));
	if (ap->pwd_type == BRCM_WPS_PWD_TYPE_PBC)
		pin = NULL;
#endif /* P2PAPI_ENABLE_WPS_SCAN */

	nRetryCount = 0;
	status = WPS_STATUS_PROTOCOL_FAIL_MAX_EAP_RETRY;
	
	while (status != WPS_STATUS_SUCCESS) {
		
		status = brcm_wpscli_sta_start_wps(registrar_ssid,
						   nw_cred->encrType == BRCM_WPS_ENCRTYPE_NONE ? 0 : 1,
						   hdl->peer_int_addr.octet,
						   hdl->num_join_chanspec, hdl->join_chanspec,
						   BRCM_WPS_MODE_STA_ENR_JOIN_NW,
						   pin == NULL ? BRCM_WPS_PWD_TYPE_PBC : BRCM_WPS_PWD_TYPE_PIN,
						   pin, P2PAPI_PBC_TIMEOUT, nw_cred);
		nRetryCount++;
		if (nRetryCount > WPS_MAX_ATTEMPTS)
			break;

		if (hdl->cancel_link_create || hdl->cancel_group_create)
			break;

	}

	/* clear WPS pushbutton */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_wps_enr: clear provision\n"));
	p2papi_clear_provision(hdl);

	if (status != WPS_STATUS_SUCCESS) {
		errstr = p2papi_wps_status_str(status);

		if (status == WPS_STATUS_PROTOCOL_FAIL_WRONG_PIN)
			notif = BCMP2P_NOTIF_WPS_WRONG_PIN;
		else if (status == WPS_STATUS_PROTOCOL_FAIL_TIMEOUT)
			notif = BCMP2P_NOTIF_WPS_TIMEOUT;
		else if (status == WPS_STATUS_PROTOCOL_FAIL_OVERLAP)
			notif = BCMP2P_NOTIF_WPS_SESSION_OVERLAP;
		else
			notif = BCMP2P_NOTIF_WPS_FAIL;

		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"WPS negotiation failed. status=%d %s\n", status, errstr));
		p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_WPS_STATE, notif);
		goto enr_exit;
	}
	hdl->conn_state = P2PAPI_ST_CONNECTING;
	print_credential(nw_cred, "WPS enrollee successful");
	p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_WPS_STATE, BCMP2P_NOTIF_WPS_COMPLETE);

enr_exit:
	brcm_wpscli_close();
	hdl->is_wps_enrolling = FALSE;
	hdl->is_provisioning = FALSE;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_run_wps_enrollee: is_prov=%d\n", hdl->is_provisioning));

	hdl->conn_state = P2PAPI_ST_IDLE;
	errstr = p2papi_wps_status_str(status);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_wps_enr: status=%d %s\n",
		status, errstr));
	return status;
}

#endif /* P2PAPI_ENABLE_WPS */
#endif /* SOFTAP_ONLY */

#if P2PAPI_ENABLE_WPS
static brcm_wpscli_status
p2papi_do_open_wps_win(p2papi_instance_t* hdl)
{
	brcm_wpscli_pwd_type	wps_mode;
	brcm_wpscli_status		status;
	uint8 *sta_mac;

	wps_mode = hdl->ap_config.WPSConfig.wpsPinMode
		? BRCM_WPS_PWD_TYPE_PIN	: BRCM_WPS_PWD_TYPE_PBC;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_do_open_wps_win: t=%u ifname=%s ispin=%d\n",
		hdl->wps_auto_close_secs,
		p2papi_osl_get_ap_mode_ifname(hdl), wps_mode));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"    ssid=%s authType=%d encrType=%d wepIndex=%d\n",
		hdl->credentials.ssid,
		(int) hdl->credentials.authType, (int) hdl->credentials.encrType,
		hdl->credentials.wepIndex));
#if P2PAPI_ENABLE_DEBUG_SHOWKEY
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "    nwKey=%s wpsPin=%s\n",
			hdl->credentials.nwKey,
			hdl->ap_config.WPSConfig.wpsPin));
#endif /* P2PAPI_ENABLE_DEBUG_SHOWKEY */

	/* Start the WPS registrar.  This call only returns when a STA has been
	 * enrolled or the WPS window has timed out.
	 */
	sta_mac = &hdl->wpsreg_enrollee_mac.octet[0];
#ifdef WPSCLI_WSCV2
	if (wps_mode == BRCM_WPS_PWD_TYPE_PBC) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_do_open_wps_win: start_wps with PBC\n"));
		status = brcm_wpscli_softap_start_wps(
			BRCM_WPS_MODE_STA_ENR_JOIN_NW, wps_mode, NULL,
			&hdl->credentials, hdl->wps_auto_close_secs, sta_mac,
			NULL, 0); /* For now, empty AuthorizedMACs */
	} else {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_do_open_wps_win: start_wps with pin=%s\n",
			hdl->ap_config.WPSConfig.wpsPin));
		status = brcm_wpscli_softap_start_wps(
			BRCM_WPS_MODE_STA_ENR_JOIN_NW, wps_mode,
			hdl->ap_config.WPSConfig.wpsPin,
			&hdl->credentials, hdl->wps_auto_close_secs, sta_mac,
			NULL, 0); /* For now, empty AuthorizedMACs */
	}
#else
	if (wps_mode == BRCM_WPS_PWD_TYPE_PBC) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_do_open_wps_win: start_wps with PBC\n"));
		status = brcm_wpscli_softap_start_wps(
			BRCM_WPS_MODE_STA_ENR_JOIN_NW, wps_mode, NULL,
			&hdl->credentials, hdl->wps_auto_close_secs, sta_mac);
	} else {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_do_open_wps_win: start_wps with pin=%s\n",
			hdl->ap_config.WPSConfig.wpsPin));
		status = brcm_wpscli_softap_start_wps(
			BRCM_WPS_MODE_STA_ENR_JOIN_NW, wps_mode,
			hdl->ap_config.WPSConfig.wpsPin,
			&hdl->credentials, hdl->wps_auto_close_secs, sta_mac);
	}

	/*  wpsreg thread doesn't exist, this is the only place we can make this test.
	    In any case this notification relying
	    on p2papi_do_open_wps_win, so why not doing it here ?
	 */
	if (status == WPS_STATUS_SUCCESS) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "Open WPS window succeeded.\n"));
	} else {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "Open WPS window failed.\n"));
		p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_CREATE_LINK,
		                        BCMP2P_NOTIF_WPS_FAIL);
	}
#endif /* WPSCLI_WSCV2 */
	return status;
}

static brcm_wpscli_status
p2papi_do_close_wps_win(p2papi_instance_t* hdl, brcm_wpscli_status   status)
{
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_do_close_wps_win: enter\n"));

	/* clear provision */
	p2papi_clear_provision(hdl);
	hdl->is_provisioning = FALSE;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_do_close_wps_win: is_prov=%d\n", hdl->is_provisioning));

	/* If we have just enrolled a STA */
	if (status == WPS_STATUS_SUCCESS) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_do_open_wps_win: enrolled %02x:%02x:%02x:%02x:%02x:%02x\n",
			hdl->enrolled_sta_mac.octet[0], hdl->enrolled_sta_mac.octet[1],
			hdl->enrolled_sta_mac.octet[2], hdl->enrolled_sta_mac.octet[3],
			hdl->enrolled_sta_mac.octet[4], hdl->enrolled_sta_mac.octet[5]));

	/* Generate WPS complete event */
	p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_WPS_STATE,
		BCMP2P_NOTIF_WPS_COMPLETE);

	} else { /* else we did not enroll a STA */
	  /* Clear our memory of the previous enrolled STA */
		memset(&hdl->enrolled_sta_mac, 0, sizeof(hdl->enrolled_sta_mac));

		if (status == WPS_STATUS_PROTOCOL_FAIL_OVERLAP) {

			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "PBC session overlap\n"));
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_do_close_wps_win: start_wps overlap\n"));

		} else if (status == WPS_STATUS_PROTOCOL_FAIL_TIMEOUT) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_do_close_wps_win: start_wps timeout\n"));
			p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_CREATE_LINK,
				BCMP2P_NOTIF_WPS_TIMEOUT);
		} else {
			char *errstr = p2papi_wps_status_str(status);
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_do_close_wps_win: start_wps returned status=%d %s\n",
				status, errstr));
			p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_CREATE_LINK,
				BCMP2P_NOTIF_WPS_FAIL);
		}
	}

	return status;
}

/* Main body of the WPS registrar enrollment thread */
void
p2papi_start_wpsreg_mgr(void* p2papi_hdl)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) p2papi_hdl;
	brcm_wpscli_status result;
	char dev_pwd[BRCM_WPS_PIN_SIZE+10] = { 0 };

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_start_wpsreg_mgr: enter\n"));

#ifdef WPSCLI_WSCV2
	result = brcm_wpscli_softap_enable_wps((char*)hdl->fname_ssid,
		hdl->ap_config.WPSConfig.wpsConfigMethods, NULL, 0);
	/* For now, empty AuthorizedMACs */
#else
	result = brcm_wpscli_softap_enable_wps((char*)hdl->fname_ssid,
		hdl->ap_config.WPSConfig.wpsConfigMethods);
#endif

	if (result != WPS_STATUS_SUCCESS) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"wpsreg_mgr: softap_enable_wps failed\n"));
	}

	/* Generate a random pin as the EAP Monitoring WPS device password */

	brcm_wpscli_generate_pin(dev_pwd, sizeof(dev_pwd));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_start_wpsreg_mgr:  pwd=%s\n", dev_pwd));


	/* Generate WPS start event */
	p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_WPS_STATE,
		BCMP2P_NOTIF_WPS_START);

	/* set initial context for enrollee mode (could set more default values).
	   In general, it could be nice to define a structure to pass down context
	   parameters to the wps library instead of passing many parameters.
	 */
#ifdef WPSCLI_WSCV2
	brcm_wpscli_softap_set_wps_context(&(hdl->credentials),
		hdl->ap_config.WPSConfig.wpsPin, NULL, 0); /* For now, empty AuthorizedMACs */
#else
	brcm_wpscli_softap_set_wps_context(&(hdl->credentials),
		hdl->ap_config.WPSConfig.wpsPin);
#endif

	/* Register a periodic 100ms timer. */
	hdl->wps_reg_timer =
	   bcmseclib_init_timer_ex(hdl->timer_mgr, p2papi_notify_timeout_wps_reg,
	                        hdl, "wps-reg");
	p2papi_add_timer(hdl, hdl->wps_reg_timer, 100, 1);

	hdl->is_wpsreg_mgr_running = TRUE;
}


/* Do OS-independent shutdown of the wpsreg mgr. */
void
p2papi_shutdown_wpsreg_mgr(p2papi_instance_t* hdl)
{
	brcm_wpscli_status result;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_shutdown_wpsreg_mgr\n"));

	hdl->is_wpsreg_mgr_running = FALSE;

	/* Stop the WPS registrar periodic timer. */
	if (hdl->wps_reg_timer != NULL) {
		bcmseclib_free_timer(hdl->wps_reg_timer);
		hdl->wps_reg_timer = NULL;
	}

	result = brcm_wpscli_softap_disable_wps();
	if (result != WPS_STATUS_SUCCESS) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_shutdown_wpsreg_mgr: softap_disable_wps failed\n"));
	}

	/* clear provision */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_shutdown_wpsreg_mgr loop exit: clear provision\n"));
	p2papi_clear_provision(hdl);

}
#endif /* P2PAPI_ENABLE_WPS */

/* Convert softAP config to WPS credentials */
static void
config_to_credentials(BCMP2P_CONFIG *in_config,
	brcm_wpscli_nw_settings *out_credentials)
{
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "config_to_credentials\n"));

	/* Convert the encryption type */
	switch (in_config->encryption) {
	case BCMP2P_ALGO_OFF:
		out_credentials->encrType = BRCM_WPS_ENCRTYPE_NONE;
		break;
	case BCMP2P_ALGO_TKIP:
		out_credentials->encrType = BRCM_WPS_ENCRTYPE_TKIP;
		break;
	case BCMP2P_ALGO_WEP128:
		out_credentials->encrType = BRCM_WPS_ENCRTYPE_WEP;
		break;
	case BCMP2P_ALGO_AES:
		out_credentials->encrType = BRCM_WPS_ENCRTYPE_AES;
		break;
	case BCMP2P_ALGO_TKIP_AES:
		out_credentials->encrType = BRCM_WPS_ENCRTYPE_TKIP_AES;
		break;
	default:
		out_credentials->encrType = BRCM_WPS_ENCRTYPE_NONE;
		break;
	}

	/* Convert the authentication type */
	switch (in_config->authentication) {
	case BCMP2P_WPA_AUTH_NONE:
		out_credentials->authType = BRCM_WPS_AUTHTYPE_OPEN;
		break;
	case BCMP2P_WPA_AUTH_SHARED:
		out_credentials->authType = BRCM_WPS_AUTHTYPE_SHARED;
		break;
	case BCMP2P_WPA_AUTH_WPAPSK:
		out_credentials->authType = BRCM_WPS_AUTHTYPE_WPAPSK;
		break;
	case BCMP2P_WPA_AUTH_WPA2PSK:
		out_credentials->authType = BRCM_WPS_AUTHTYPE_WPA2PSK;
		break;
	case BCMP2P_WPA_AUTH_WPAPSK_WPA2PSK:
		out_credentials->authType = BRCM_WPS_AUTHTYPE_WPAPSK_WPA2PSK;
		break;
	default:
		out_credentials->authType = BRCM_WPS_AUTHTYPE_OPEN;
	}

	/* Convert the encryption key */
	if (in_config->encryption == BCMP2P_ALGO_WEP128) {
		if (in_config->WEPKeyIndex < 4) {
			strncpy(out_credentials->nwKey,
				(char*)in_config->WEPKey[in_config->WEPKeyIndex],
				sizeof(out_credentials->nwKey));
		} else {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
				"config_to_credentials: bad WEP key index %d\n",
				in_config->WEPKeyIndex));
		}
	} else {
		strncpy(out_credentials->nwKey, (char*)in_config->keyWPA,
			sizeof(out_credentials->nwKey));
	}
	out_credentials->wepIndex = in_config->WEPKeyIndex;
}

/* refresh IEs based on updated configuration */
void
p2papi_refresh_ies(p2papi_instance_t* hdl)
{
	/* If device discovery is enabled or if we are active as a P2P AP or STA
	 *     Update our P2P and WPS IEs.
	 */
	if (hdl->enable_p2p) {
		if (hdl->is_p2p_discovery_on) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_refresh_ies: update discovery bsscfg IEs\n"));
			p2papi_update_p2p_wps_ies(hdl, P2PAPI_BSSCFG_DEVICE);
		}
		if (hdl->is_connected || hdl->is_connecting) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_refresh_ies: update connection bsscfg IEs\n"));
			p2papi_update_p2p_wps_ies(hdl, P2PAPI_BSSCFG_CONNECTION);
		}
	}
}

/* Save our link security configuration */
BCMP2P_STATUS
p2papi_save_link_config(p2papi_instance_t* hdl, BCMP2P_CONFIG *pConfig,
	uint8 *ssid)
{
	P2PWL_HDL wl;
	struct ether_addr my_mac_addr;
	BCMP2P_BOOL is_ssid_changed = FALSE;
	BCMP2P_BOOL is_passphrase_changed = FALSE;
	int val;
	int ret;

	P2PAPI_CHECK_P2PHDL(hdl);
	P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);

	if (pConfig == NULL) {
		return BCMP2P_ERROR;
	}

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_save_link_config: pConfig=%p ssid=%s di=%u cg=%u cd=%u\n",
		pConfig, ssid, hdl->is_discovering, hdl->is_connecting,
		hdl->is_connected));

	memcpy(&hdl->op_channel, &pConfig->operatingChannel,
		sizeof(hdl->op_channel));
#ifdef BCM_P2P_OPTEXT
    hdl->opch_force = pConfig->opch_force;
    hdl->opch_high = pConfig->opch_high;
#endif
	hdl->enable_dhcp = (pConfig->DHCPConfig.DHCPOption != BCMP2P_DHCP_OFF);
	hdl->dhcp_subnet = pConfig->ip_addr & pConfig->netmask;
	hdl->dhcp_start_ip = pConfig->DHCPConfig.starting_ip;
	hdl->dhcp_end_ip = pConfig->DHCPConfig.ending_ip;
	if (hdl->dhcp_subnet == 0 && hdl->dhcp_start_ip == 0 &&
		hdl->dhcp_end_ip == 0) {
		if (hdl->enable_dhcp) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"save_link_config: using default DHCP settings\n"));
		}
		hdl->dhcp_subnet = BCMP2P_DHCP_DEFAULT_SUBNET;
		hdl->dhcp_start_ip = BCMP2P_DHCP_DEFAULT_STARTING_IP;
		hdl->dhcp_end_ip = BCMP2P_DHCP_DEFAULT_ENDING_IP;
	}

	/* WPS device password id used during GON */
	hdl->wps_device_pwd_id = strlen(pConfig->WPSConfig.wpsPin)
		? BCMP2P_WPS_DEFAULT : BCMP2P_WPS_PUSH_BTN;

	hdl->persistent_grp = pConfig->wantPersistentGroup;

	p2papi_enable_p2p(hdl, !pConfig->disableP2P);

	/* Save a copy of the configuration data */
	memcpy(&hdl->ap_config, pConfig, sizeof(hdl->ap_config));

	if (hdl->enable_p2p)
	{
		is_ssid_changed = (strncmp(hdl->credentials.ssid, (char*)ssid,
			sizeof(hdl->credentials.ssid)) != 0);
		if (is_ssid_changed) {
			strncpy(hdl->credentials.ssid, (char*)ssid,
				sizeof(hdl->credentials.ssid));
			hdl->credentials.ssid[sizeof(hdl->credentials.ssid) - 1] = '\0';
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_save_link_config: using given ssid=%s\n",
				hdl->credentials.ssid));
		} else {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_save_link_config: not replacing ssid\n"));
		}
	}

	/* Convert the configuration data to WPS credentials */
	config_to_credentials(pConfig, &hdl->credentials);

	if (hdl->enable_p2p) {
		/* If the passphrase has changed or the passphrase has not been
		 * converted to a 64 hex digit PMK yet
		 *     Flag that the passphrase has changed.
		 *     Store the new passphrase.
		 */
		is_passphrase_changed = (
			strncmp(hdl->passphrase, (char*)pConfig->keyWPA,
				sizeof(pConfig->keyWPA)) != 0 ||
			strncmp(hdl->passphrase, (char*)hdl->credentials.nwKey,
				sizeof(hdl->passphrase)) == 0);
		if (is_passphrase_changed) {
			memset(hdl->passphrase, 0, sizeof(hdl->passphrase));
			strncpy(hdl->passphrase, (char *)pConfig->keyWPA,
				sizeof(pConfig->keyWPA));
#if P2PAPI_ENABLE_DEBUG_SHOWKEY
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_save_link_config: changing passphrase to %s\n",
				hdl->passphrase));
#else
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_save_link_config: changing passphrase\n"));
#endif
		}

		/* If the SSID or passphrase has changed
		 *     Create 64-hex-digit PMK from passphrase and store it.
		 */
		if (is_ssid_changed || is_passphrase_changed)
		{
			passphrase_to_pmk((char *)pConfig->keyWPA,
				strlen((char *)pConfig->keyWPA),
				(unsigned char *)hdl->credentials.ssid,
				strlen(hdl->credentials.ssid), hdl->credentials.nwKey);
		}
	}

	hdl->pri_dev_type = pConfig->primaryDevType;
	hdl->pri_dev_subcat = pConfig->primaryDevSubCat;

	hdl->use_same_int_dev_addrs = pConfig->sameIntDevAddrs ? true : false;

	hdl->is_managed_device = pConfig->enableManagedDevice ? true : false;

	hdl->use_wps = hdl->ap_config.WPSConfig.wpsEnable;
	hdl->wps_auto_close_secs = P2PAPI_DEFAULT_WPS_WINDOW_OPEN_SECS;
	if (hdl->pri_dev_type == 0)
		hdl->pri_dev_type = BCMP2P_DEVICE_TYPE_CAT_COMPUTER;
	if (hdl->pri_dev_subcat == 0)
		hdl->pri_dev_subcat = BCMP2P_DEVICE_TYPE_SUB_CAT_COMP_NOTEBOOK;

#ifdef SECONDARY_DEVICE_TYPE
		hdl->sec_dev_type	= pConfig->secDevType;
		hdl->sec_dev_subcat = pConfig->secDevSubCat;
		hdl->sec_dev_oui	= pConfig->secDevOui;
#endif

	/* Channel 0 means do not set the channel.
	 * Use auto-channel to find best channel.
	 */
	if (hdl->op_channel.channel == 0) {
		chanspec_t chspec;

		p2pwlu_get_quiet_channel(hdl, &chspec);
		p2papi_chspec_to_channel(chspec, &hdl->op_channel);
		hdl->ap_config.operatingChannel.channel_class = hdl->op_channel.channel_class;
		hdl->ap_config.operatingChannel.channel = hdl->op_channel.channel;

		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"auto-channel selects channel %d:%d\n",
			hdl->op_channel.channel_class, hdl->op_channel.channel));
	}
	/* If the specified operating channel is a 5 GHz channel, print a
	 * warning if the driver's Dynamic Frequency Selection (DFS) feature is
	 * enabled.  DFS may override the specified operating channel.
	 */
	if (hdl->op_channel.channel > CH_MAX_2G_CHANNEL) {
		ret = p2pwl_get_spect_mgmt(wl, &val) < 0;
		if (ret < 0)
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
				"'wl spect' failed with %d\n", ret));
		else if (val != 0)
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"Warning: 'wl spect' not 0, may override op channel %d\n",
				hdl->op_channel.channel));
	}

	/* Generate our P2P Interface Address based on our P2P Device Address
	 * and whether we are configured to use the same interface address as
	 * our device address.
	 */
	p2pwl_get_mac_addr(wl, &my_mac_addr);
	p2papi_generate_bss_mac(hdl->use_same_int_dev_addrs, &my_mac_addr,
		&hdl->p2p_dev_addr, &hdl->conn_ifaddr);

	/* initialize WPS CLI */
#ifdef WPSCLI_WSCV2
	/* We initialzed P2P Mode with WPS v2 */
	if (hdl->enable_p2p)
		p2papi_set_wps_use_ver_1(FALSE);

	brcm_wpscli_product_info prod_info;

	memset(&prod_info, 0x00, sizeof(prod_info));
	memcpy(prod_info.manufacturer, pConfig->prodInfo.manufacturer, sizeof(prod_info.manufacturer));
	memcpy(prod_info.modelName, pConfig->prodInfo.modelName, sizeof(prod_info.modelName));
	memcpy(prod_info.modelNumber, pConfig->prodInfo.modelNumber, sizeof(prod_info.modelNumber));
	memcpy(prod_info.serialNumber, pConfig->prodInfo.serialNumber, sizeof(prod_info.serialNumber));
	prod_info.osVersion = pConfig->prodInfo.osVersion;

	if (wpscli_sta_init((const char *)&hdl->conn_ifaddr) != WPS_STATUS_SUCCESS) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "wpscli_sta_init failed\n"));
	}
	else
	{
		if (wpscli_sta_set_prod_info(&prod_info) != WPS_STATUS_SUCCESS) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "wpscli_sta_set_prod_info failed\n"));
		}
	}
	
	if (wpscli_softap_init((const char *)&hdl->conn_ifaddr) != WPS_STATUS_SUCCESS) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "wpscli_softap_init failed\n"));
	}
	else
	{
		if (wpscli_softap_set_prod_info(&prod_info) != WPS_STATUS_SUCCESS) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "wpscli_softap_set_prod_info failed\n"));
		}
	}	
#endif /* WPSCLI_WSCV2 */

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_save_link_config: ch=%d:%d auth=%d enc=%d ix=%d cm=%d\n",
		hdl->op_channel.channel_class,
		hdl->op_channel.channel,
		hdl->credentials.authType, hdl->credentials.encrType,
		hdl->credentials.wepIndex,
		hdl->ap_config.WPSConfig.wpsConfigMethods));
#if P2PAPI_ENABLE_DEBUG_SHOWKEY
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "    key=%s wpsPin=%s\n",
		hdl->credentials.nwKey, hdl->ap_config.WPSConfig.wpsPin));
#endif /* P2PAPI_ENABLE_DEBUG_SHOWKEY */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "    we_want_persist_grp=%u\n",
		hdl->persistent_grp));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"    ssid=%s hide=%d wpsEn=%u p2pEn=%u intent=%u pg=%u\n",
		hdl->credentials.ssid, hdl->ap_config.hideSSID,
		hdl->ap_config.WPSConfig.wpsEnable,
		hdl->enable_p2p, hdl->ap_config.grp_owner_intent));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"    DHCP: enab=%u subnet=0x%08x range=0x%02x,%02x\n",
		hdl->enable_dhcp, hdl->dhcp_subnet, hdl->dhcp_start_ip,
		hdl->dhcp_end_ip));

	p2papi_refresh_ies(hdl);

	return BCMP2P_SUCCESS;
}

/* Set or update the WPA key */
BCMP2P_STATUS
p2papi_save_wpa_key(p2papi_instance_t* hdl, char *key, char *passphrase)
{
#if P2PAPI_ENABLE_DEBUG_SHOWKEY
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_save_wpa_key: pp=%s key=%s\n",
		passphrase, key));
#else
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_save_wpa_key\n"));
#endif /* P2PAPI_ENABLE_DEBUG_SHOWKEY */

	if (key)
		strncpy(hdl->credentials.nwKey, key, sizeof(hdl->credentials.nwKey));
	if (passphrase)
		strncpy(hdl->passphrase, passphrase, sizeof(hdl->passphrase));

	return BCMP2P_SUCCESS;
}

/* restart WPS registrar  */
static BCMP2P_STATUS
p2papi_wpsreg_restart(p2papi_instance_t* hdl, BCMP2P_BOOL enable)
{
	int i;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"Enter p2papi_wpsreg_restart(enable=%d)\n", enable));

	if (hdl->is_ap || hdl->is_p2p_group) {
		/* If the WPS window is currently open, close it. */
		if (brcm_wpscli_softap_is_wps_window_open()) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_wpsreg_restart: closing WPS window\n"));
			p2papi_close_wpsreg_window(hdl);

			/* Wait for the WPS window to close */
			for (i = 0; i < 20; i++) {
				if (! brcm_wpscli_softap_is_wps_window_open()) {
					BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"p2papi_wpsreg_restart: WPS window closed\n"));
					break;
				}

				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"p2papi_wpsreg_restart:wait for closing (100ms, i=%d)\n",
					i));
				p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_WPS_REGISTRAR_RERUN_WAIT, 100);
			}
		}

		if (enable) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_wpsreg_restart: reopening WPS window\n"));
			p2papi_open_wpsreg_window(hdl, hdl->wps_auto_close_secs);
		}
	} else {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_wpsreg_restart: do nothing\n"));
	}

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"Exit p2papi_wpsreg_restart(enable=%d)\n", enable));

	return BCMP2P_SUCCESS;
}

/* Set or update the WPS PIN in the link configuration. */
BCMP2P_STATUS
p2papi_save_wps_pin(p2papi_instance_t* hdl, char *pin)
{
	BCMP2P_STATUS ret = BCMP2P_BAD_WPS_PIN;
	int length;

	if (pin == NULL)
		return ret;

	length = strlen(pin);

	/* WPS PIN should be either 8 or 4 digit */
	if (brcm_wpscli_validate_pin(pin) != WPS_STATUS_SUCCESS) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "p2papi_save_wps_pin: invalid pin=%s\n", pin));
		return ret;
	}

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_save_wps_pin: pin=%s\n", pin));

	/* clear WPS pushbutton */
	p2papi_set_push_button(hdl, BCMP2P_FALSE);

	hdl->ap_config.WPSConfig.wpsPinMode = TRUE;
	strncpy(hdl->ap_config.WPSConfig.wpsPin, pin,
		sizeof(hdl->ap_config.WPSConfig.wpsPin));
	ret = BCMP2P_SUCCESS;

	/* set provision */
	p2papi_set_provision(hdl);

	/* restart WPS registrar with updated pin */
	p2papi_wpsreg_restart(hdl, TRUE);

	return ret;
}

/* Prune a disassociated STA from the associated STAs list and call the
 * disassociation callback
 */
static void
p2papi_prune_diassoc_sta(p2papi_instance_t* hdl, int index,
	p2papi_sta_assoc_cb_t sta_disassoc_cback)
{
	struct ether_addr *disassoc_sta = &hdl->assoclist[index];

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_prune_disassoc_sta: "
		"del STA %02x:%02x:%02x:%02x:%02x:%02x at %d, %d remain\n",
		disassoc_sta->octet[0], disassoc_sta->octet[1],
		disassoc_sta->octet[2], disassoc_sta->octet[3],
		disassoc_sta->octet[4], disassoc_sta->octet[5],
		index, hdl->assoclist_count - 1));

	/* Call the disassociatd STA callback fn */
	if (sta_disassoc_cback) {
		sta_disassoc_cback(hdl, disassoc_sta);
		p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_CREATE_LINK,
			BCMP2P_NOTIF_SOFTAP_STA_DISASSOC);
	}

	/* Remove the dissassociated STA from the associated STA list:
	 *   If the STA is not the last item on the list
	 *     Shift all subsequent items up to fill this item's place.
	 *   Decrement the associated STA list count
	 */
	if (index != hdl->assoclist_count - 1) {
		memcpy(&hdl->assoclist[index], &hdl->assoclist[index + 1],
			(hdl->assoclist_count - (index + 1)) *
			sizeof(hdl->assoclist[0]));
	}
	if (hdl->assoclist_count > 0) {
		hdl->assoclist_count--;
	} else {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_prune_diassoc_sta: assoclist already empty!"));
	}
}

/* Wait for a STA peer to join our BSS with a timeout.
 * Update our list of associated STAs if any STA joins or leaves our BSS.
 * Input:  hdl -
 *         timeout_secs - join wait timeout.
 *         is_wpa - whether our BSS has WPA/WPA2-PSK security.
 *         do_notif - whether to send a join complete/timeout notification.
 * Output: out_new_sta_mac - MAC address of the new STA that joined, unmodified
 *                           if no new STA has joined.
 * Returns TRUE if a new STA peer has joined our BSS.
 */
static bool
p2papi_bss_wait_for_join(p2papi_instance_t* hdl, uint32 timeout_secs,
	bool do_notif, p2papi_sta_assoc_cb_t sta_assoc_cback,
	p2papi_sta_assoc_cb_t sta_disassoc_cback,
	struct ether_addr *out_new_sta_mac)
{
	uint32 i;
	BCMP2P_NOTIFICATION_CODE notif_code = BCMP2P_NOTIF_NONE;
	bool have_new_sta = FALSE;
	uint32 sleep_ms = P2PAPI_WAIT_FOR_JOIN_LOOP_MS;
	uint32 loops = 1000 / sleep_ms * timeout_secs;

	BCMP2PLOG((BCMP2P_LOG_INFO,
		TRUE, "p2papi_bss_wait_for_join: timeout=%ds do_notif=%d\n",
		timeout_secs, do_notif));

	/* Polling loop to check if a STA peer has joined our BSS.
	 * Repeat until success or a timeout.
	 */
	for (i = 0; i < loops && !have_new_sta; i++) {
		struct ether_addr	*old_assoc_sta;
		struct ether_addr	new_assoc_sta;
		struct ether_addr	disassoc_sta;
		int32 j = 0;
		bool found;
#if P2PAPI_ENABLE_WPS
		uint8 *bufdata;
		int datalen;
		int res;
#endif /* P2PAPI_ENABLE_WPS */

/*
		BCMP2PLOG((BCMP2P_LOG_VERB, TRUE, "bss_wait_for_join: poll %d\n", i));
*/
		if (hdl->cancel_group_create) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_bss_wait_for_join: group create cancelled\n"));
			return FALSE;
		}

		/* Wait for a STA client to associate or disassociate to be signalled
		 * by the WLC event handler thread.
		 * The wait has a short timeout so that we can frequently check
		 * hdl->cancel_group_create to abort this loop.
		 */
		p2papi_osl_wait_for_client_assoc_or_disassoc(hdl,
			P2PAPI_WAIT_FOR_JOIN_LOOP_MS);

		/* If a disassociated STA was detected by the event handler thread
		 *    Prune the STA from the associated STAs list and call the callback
		 */
		found = FALSE;
		P2PAPI_DATA_LOCK_VERB(hdl);
		if (hdl->disassoc_sta_count > 0) {
			hdl->disassoc_sta_count--;
			memcpy(&disassoc_sta, &hdl->disassoc_sta_mac, sizeof(disassoc_sta));

			/* Find the disassociated STA on our associated STA list */
			for (j = 0; j < hdl->assoclist_count; j++) {
				old_assoc_sta = &hdl->assoclist[j];
				if (memcmp(old_assoc_sta, &disassoc_sta,
					sizeof(*old_assoc_sta)) == 0) {
					found = TRUE;
					break;
				}
			}
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_bss_wait_for_join: detected %s disassoc"
				" %02x:%02x:%02x:%02x:%02x:%02x\n",
				found ? "confirmed" : "bogus",
				disassoc_sta.octet[0], disassoc_sta.octet[1],
				disassoc_sta.octet[2], disassoc_sta.octet[3],
				disassoc_sta.octet[4], disassoc_sta.octet[5]));
		}
		P2PAPI_DATA_UNLOCK_VERB(hdl);
		if (found) {
			p2papi_prune_diassoc_sta(hdl, j, sta_disassoc_cback);
		}


		/* If a new associated STA was detected by the event handler thread
		 *    Add the STA to the associated STAs list and call the callback
		 */
		found = FALSE;
		P2PAPI_DATA_LOCK_VERB(hdl);
		if (hdl->assoc_sta_count > 0) {
			hdl->assoc_sta_count--;
			memcpy(&new_assoc_sta, &hdl->assoc_sta_mac, sizeof(new_assoc_sta));
			found = TRUE;

			/* if the STA is already on our associated STA list
			 *   This is a bogus new assoc detect
			 */
			for (j = 0; j < hdl->assoclist_count; j++) {
				old_assoc_sta = &hdl->assoclist[j];
				if (memcmp(old_assoc_sta, &new_assoc_sta,
					sizeof(*old_assoc_sta)) == 0) {
					found = FALSE;
					break;
				}
			}
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_bss_wait_for_join: detected %s assoc"
				" %02x:%02x:%02x:%02x:%02x:%02x\n",
				found ? "confirmed" : "bogus",
				new_assoc_sta.octet[0], new_assoc_sta.octet[1],
				new_assoc_sta.octet[2], new_assoc_sta.octet[3],
				new_assoc_sta.octet[4], new_assoc_sta.octet[5]));
		}
		P2PAPI_DATA_UNLOCK_VERB(hdl);
		if (found)
			have_new_sta = TRUE;

		/* Do associated STA processing */
		if (have_new_sta) {
			/* Call the new associated STA callback which will register
			 * the STA's MAC address with the DHCP server.
			 */
			if (sta_assoc_cback) {
				sta_assoc_cback(hdl, &new_assoc_sta);
			}

			/* If there is room, add the new associated STA to the associated
			 * STAs list.
			 */
			if (hdl->assoclist_count >=
				(sizeof(hdl->assoclist) / sizeof(hdl->assoclist[0]))) {
				BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
					"p2papi_bss_wait_for_join: assoclist full!\n"));
			} else {
				memcpy(&hdl->assoclist[hdl->assoclist_count],
					&new_assoc_sta, sizeof(hdl->assoclist[0]));
				hdl->assoclist_count++;

				memcpy(out_new_sta_mac, &new_assoc_sta,
					sizeof(*out_new_sta_mac));
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_bss_wait_for_join: "
					"add STA %02x:%02x:%02x:%02x:%02x:%02x at idx %u\n",
					out_new_sta_mac->octet[0], out_new_sta_mac->octet[1],
					out_new_sta_mac->octet[2], out_new_sta_mac->octet[3],
					out_new_sta_mac->octet[4], out_new_sta_mac->octet[5],
					hdl->assoclist_count));
				p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_CREATE_LINK,
					BCMP2P_NOTIF_SOFTAP_STA_ASSOC);
			}
		}
		hdl->is_connected = (hdl->assoclist_count > 0);


		/* Poll an iovar for a received probe request WPS IE and deliver it
		 * to WPSCLI.
		 */
#if P2PAPI_ENABLE_WPS
		if (hdl->use_wps)
		{
			struct ether_addr mac;

			/* Lock our instance data; we will be writing its ioctl buffer */
			P2PAPI_DATA_LOCK_VERB(hdl);

			datalen = P2PAPI_IOCTL_BUF_SIZE;
			bufdata = P2PAPI_IOCTL_BUF(hdl);
			memset(bufdata, 0, datalen);
			/* This OSL fn is only needed for Windows and WinMob.  On OSes where
			 * WL driver events are available, this OSL fn is an empty stub
			 * returning non-zero and the probe request WPS IE parsing and
			 * delivery is done in the driver event handler p2papi_rx_wl_event()
			 * case WLC_E_PROBREQ_MSG.
			 */
			res = p2papi_osl_get_probereq_wpsie(hdl, mac.octet, bufdata,
				&datalen);
			if (res == 0) {
				if (datalen > 0) {
					/* wps ie is found in STA probe request */
					BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
						"p2papi_bss_wait_for_join:"
						" WPS IE found in STA's probe request.\n"));
						brcm_wpscli_softap_on_sta_probreq_wpsie(
							mac.octet, bufdata, datalen);
				}
			}
			else {
/*
				BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
					"p2papi_bss_wait_for_join: Error retrieving WPS IE: %d\n",
					res));
*/
			}

			P2PAPI_DATA_UNLOCK_VERB(hdl);
		}

#endif /* P2PAPI_ENABLE_WPS */

	}


	if (have_new_sta) {
		hdl->conn_state = P2PAPI_ST_CONNECTED;
/*		p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_AP_JOIN_DONE, 1000); */
		uint32 num_entries = 0;
		for (i = 0; i < 3 && !num_entries; i++) {
			p2pwlu_get_autho_sta_list(hdl, 10, &num_entries);
			p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_AP_JOIN_DONE, 1000);
		}

		notif_code = BCMP2P_NOTIF_CREATE_LINK_COMPLETE;
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_bss_wait_for_join: %u STAs connected\n",
			hdl->assoclist_count));
	} else if (hdl->assoclist_count == 0) {
		hdl->conn_state = P2PAPI_ST_IDLE;
		notif_code = BCMP2P_NOTIF_CREATE_LINK_TIMEOUT;
		BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
			"p2papi_bss_wait_for_join: no STAs connected\n"));
	} else {
		do_notif = FALSE;
		BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
			"p2papi_bss_wait_for_join: no new STA, assoc_count=%d, no notif\n",
			hdl->assoclist_count));
	}

	if (do_notif) {
		P2PLOG2("p2papi_bss_wait_for_join: do cback, is_ap=%d is_conn=%d\n",
			hdl->is_ap, hdl->is_connected);
		p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_CREATE_LINK, notif_code);
	}

	return have_new_sta;
}


#ifndef SOFTAP_ONLY
/* Initialize P2P discoverability settings needed for the pre-Group Owner
 * Negotiation channel alignment procedure.
 */
static void
p2papi_init_gon_discoverability(p2papi_instance_t* hdl)
{
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_init_gon_dy: is_dis=%d is_p2p_dis_on=%d\n",
		hdl->is_discovering, hdl->is_p2p_discovery_on));

	/* If P2P Discovery is actively running
	 *   Disable our P2P discovery's Search state active scans to prevent
	 *   them from interfering with action frame rx.
	 * else
	 *   if wl driver P2P discoverability is not on
	 *     Turn it on so we can receive the p2p probe requests from the peer.
	 */
	if (hdl->is_discovering) {
/*		p2papi_discover_cancel_sync(hdl); */
		p2papi_discover_enable_search(hdl, FALSE);
		/* Wait for any remaining discovery scan to complete */
		p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_GENERIC, 330);
	} else {
		if (!hdl->is_p2p_discovery_on)
			p2papi_enable_discovery(hdl);
	}
}

/* Undo any P2P discoverability settings applied for the pre-Group Owner
 * Negotiation channel alignment procedure.
 */
static void
p2papi_deinit_gon_discoverability(p2papi_instance_t* hdl)
{
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_deinit_gon_dy: is_dis=%d is_p2p_dis_on=%d\n",
		hdl->is_discovering, hdl->is_p2p_discovery_on));

	/* If P2P Discovery is actively running
	 *   Re-enable our P2P discovery's Search state active scans.
	 * else
	 *   if wl driver P2P discoverability is on
	 *     Turn it off
	 */
	if (hdl->is_discovering) {
		p2papi_discover_enable_search(hdl, TRUE);
	} else if (hdl->is_p2p_discovery_on && !hdl->is_p2p_group) {
		p2papi_disable_discovery(hdl);
	}
}
#endif /* SOFTAP_ONLY */


/* Process an associated STA */
void
p2papi_proc_sta_assoc(p2papi_instance_t* hdl, struct ether_addr *sta_mac)
{
#if P2PAPI_ENABLE_DHCPD
	/* Register the new STA's MAC address with the DHCP server mac filter */
	if (hdl->enable_dhcp && hdl->dhcpd_hdl) {
		if (memcmp(sta_mac->octet, p2plib_bcast_mac,
			sizeof(p2plib_bcast_mac)) == 0) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_proc_sta_assoc: STA mac is bcast, not registering.\n"));
		} else {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_proc_sta_assoc: Registering new STA mac\n"));
			DHCP_Register_Mac_addr(hdl->dhcpd_hdl, sta_mac->octet);
		}
	}
#endif /* P2PAPI_ENABLE_DHCPD */
}

/* Process a disassociated STA */
void
p2papi_proc_sta_disassoc(p2papi_instance_t* hdl, struct ether_addr *sta_mac)
{
#if P2PAPI_ENABLE_DHCPD
	if (hdl->dhcpd_hdl != NULL) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_proc_sta_disassoc: Deregistering STA mac\n"));
		DHCP_Deregister_Mac_addr(hdl->dhcpd_hdl, sta_mac->octet);
	}
#endif /* P2PAPI_ENABLE_DHCPD */
}

/* Process a client STA association WLC_E_ASSOC_IND event */
int
p2papi_proc_client_assoc(p2papi_instance_t *hdl, wl_event_msg_t *event,
	void *data, uint32 data_len)
{
	BCMP2P_BOOL is_secure_join = FALSE;
	BCMP2P_BOOL is_p2p_client = FALSE;
	uint8 *tlvs = (uint8*)data;
	uint8 *client_addr;
	p2papi_client_info_t* item = NULL;
	p2papi_p2p_ie_t *p2p_ie = NULL;
	p2papi_wps_ie_t *wps_ie = NULL;
	uint32 channel;
	int ret;
	int i;
	BCMP2P_BOOL  is_data_locked = false;

#if P2PAPI_ENABLE_WPS
	if (hdl->use_wps && hdl->enable_p2p)
	{
		/* Check for security IEs in the association request.
		 * If none found then ignore this association (this association is
		 * probably a WPS enrollee initial open association).
		 */
		is_secure_join = (p2papi_search_for_security_ies(tlvs, data_len) == 0);
		if (!is_secure_join) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "proc_client_assoc:"
				" ignoring open assoc from %02x:%02x:%02x:%02x:%02x:%02x\n",
				event->addr.octet[0], event->addr.octet[1], event->addr.octet[2],
				event->addr.octet[3], event->addr.octet[4], event->addr.octet[5]));
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"    enr_mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
				hdl->enrolled_sta_mac.octet[0], hdl->enrolled_sta_mac.octet[1],
				hdl->enrolled_sta_mac.octet[2], hdl->enrolled_sta_mac.octet[3],
				hdl->enrolled_sta_mac.octet[4], hdl->enrolled_sta_mac.octet[5]));
			return 0;
		}
	}
	else
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"proc_client_assoc: use_wps=0, assoc from %02x:%02x:%02x:%02x:%02x:%02x\n",
			event->addr.octet[0], event->addr.octet[1], event->addr.octet[2],
			event->addr.octet[3], event->addr.octet[4], event->addr.octet[5]));

#endif /* P2PAPI_ENABLE_WPS */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"proc_client_assoc: data=%p data_len=%u\n",
		data, data_len));

	/* Find and decode all P2P IEs in the WLC_E_ASSOC_IND event to extract
	 * and store the associating client's Capabilities Info attribute's
	 * Device Capabilities Bitmap and the client's Device Info attribute.
	 */
	p2p_ie = (p2papi_p2p_ie_t *) P2PAPI_MALLOC(sizeof(*p2p_ie));
	if (p2p_ie == NULL) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"proc_client_assoc: p2p_ie malloc error\n"));
		goto pca_exit;
	}
	wps_ie = (p2papi_wps_ie_t *) P2PAPI_MALLOC(sizeof(*wps_ie));
	if (wps_ie == NULL) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"proc_client_assoc: wps_ie malloc error\n"));
		goto pca_exit;
	}
	ret = p2papi_search_ies(tlvs, data_len, &channel, p2p_ie, wps_ie,
		BCMP2P_LOG_MED);
	/* If no P2P IE then the associating client is a legacy client */
	if (ret != 0) {
		is_p2p_client = BCMP2P_FALSE;
	} else {
		is_p2p_client = BCMP2P_TRUE;
	}

	/* set peer device addr */
	memcpy(&hdl->peer_dev_addr, p2p_ie->devinfo_subelt.mac, sizeof(hdl->peer_dev_addr));

	/* Save the MAC address of the associating STA. */
	memcpy(&hdl->assoc_sta_mac, &event->addr, sizeof(event->addr));
	hdl->assoc_sta_count++;

	/* Enter a critical section while we do an atomic read/write on our GO
	 * client info list.
	 */
	P2PAPI_DATA_LOCK(hdl);
	is_data_locked = true;

	/* Check if the STA already exists in our client info list. */
	item = NULL;
	client_addr = is_p2p_client
		? p2p_ie->devinfo_subelt.mac
		: event->addr.octet;
	for (i = 0; i < hdl->client_list_count; i++) {
		if (memcmp(hdl->client_list[i].p2p_dev_addr, client_addr,
			sizeof(hdl->client_list[i].p2p_dev_addr)) == 0) {
			item = &hdl->client_list[i];
			break;
		}
	}

	/* If found
	 *     Update the existing entry to the client info list
	 * else
	 *     Add a new entry to the client info list
	 */
	if (item != NULL) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"proc_client_assoc: updating existing client %d on list\n", i));
	} else {
		/* If our client info list is full, ignore this association */
		if (hdl->client_list_count >= P2PAPI_MAX_CONNECTED_PEERS) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
				"proc_client_assoc: no room on client info list!\n"));
			goto pca_exit;
		}
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"proc_client_assoc: adding client %d to list\n",
			hdl->client_list_count));
		item = &hdl->client_list[hdl->client_list_count];
		++hdl->client_list_count;
	}


	/* Copy the associating STA's info into the client info list entry */
	memset(item, 0, sizeof(*item));
	item->is_p2p_client = is_p2p_client;
	memcpy(item->p2p_dev_addr, client_addr, sizeof(item->p2p_dev_addr));
	item->dev_cap_bitmap = p2p_ie->capability_subelt.dev;
	memcpy(&item->devinfo, &p2p_ie->devinfo_subelt, sizeof(item->devinfo));

	if (data_len > sizeof(item->ie_data))
	{
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_proc_client_assoc: ie-data (%d bytes) over the limit %d bytes\n",
			data_len, sizeof(item->ie_data)));
		data_len = sizeof(item->ie_data);
	}
	item->ie_data_len = data_len;
	memcpy(item->ie_data, tlvs, data_len);

	p2papi_log_hexdata(BCMP2P_LOG_INFO, "proc_client_assoc: ie data", item->ie_data, item->ie_data_len);

	/* If the associating STA's assocreq P2P IE has a P2P Interface attribute
	 * with a P2P Interface Address List
	 *     Get the STA's interface address from the 1st element in the
	 *     attribute's Interface Address List.
	 * else
	 *     Get the STA's Interface Address from the event src addr
	 */
	if (p2p_ie->interface_subelt.pia_list_count > 0) {
		memcpy(item->p2p_int_addr, &p2p_ie->interface_pia_list[0],
			sizeof(item->p2p_int_addr));
	} else {
		memcpy(item->p2p_int_addr, &event->addr, sizeof(item->p2p_int_addr));
	}

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"proc_client_assoc: devcap=0x%x devaddr=%02x:%02x:%02x:%02x:%02x:%02x\n",
		item->dev_cap_bitmap,
		item->p2p_dev_addr[0], item->p2p_dev_addr[1],
		item->p2p_dev_addr[2], item->p2p_dev_addr[3],
		item->p2p_dev_addr[4], item->p2p_dev_addr[5]));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"    intaddr=%02x:%02x:%02x:%02x:%02x:%02x cfgmeth=0x%x"
		" devnameTLV=0x%02x%02x,%d,%s\n",
		item->p2p_int_addr[0], item->p2p_int_addr[1], item->p2p_int_addr[2],
		item->p2p_int_addr[3], item->p2p_int_addr[4], item->p2p_int_addr[5],
		item->devinfo.wps_cfg_meths,
		item->devinfo.name_type_be[0], item->devinfo.name_type_be[1],
		(item->devinfo.name_len_be[0] << 8) | item->devinfo.name_len_be[1],
		item->devinfo.name_val));

	/* Update the P2P IEs to rebuild the P2P Group Info attribute based on
	 * the updated client info list.
	 */
	p2papi_update_p2p_wps_ies_nolock(hdl, P2PAPI_BSSCFG_CONNECTION);

	/* Signal the Connection thread that a client has associated */
	p2papi_osl_signal_client_assoc_state(hdl,
		P2PAPI_OSL_CLIENT_ASSOC_STATE_ASSOC);

pca_exit:
	if (is_data_locked)
		P2PAPI_DATA_UNLOCK(hdl);

	if (item != NULL) {
		/* Do this outside the critical section */
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "proc_client_assoc: "
			"added %02x:%02x:%02x:%02x:%02x:%02x devbm=0x%x count=%d isp2p=%d\n",
			item->p2p_dev_addr[0], item->p2p_dev_addr[1], item->p2p_dev_addr[2],
			item->p2p_dev_addr[3], item->p2p_dev_addr[4], item->p2p_dev_addr[5],
			item->dev_cap_bitmap, hdl->client_list_count, is_p2p_client));
	}

	if (p2p_ie)
		P2PAPI_FREE(p2p_ie);
	if (wps_ie)
		P2PAPI_FREE(wps_ie);
	return 0;
}

/* Process a client STA association WLC_E_DISASSOC_IND event */
int
p2papi_proc_client_disassoc(p2papi_instance_t *hdl, wl_event_msg_t *event,
	void *data, uint32 data_len)
{
	p2papi_client_info_t* item = NULL;
	p2papi_client_info_t deleted_item;
	int i;


	P2PAPI_DATA_LOCK(hdl);

	/* Save the MAC address of the disassociating STA. */
	memcpy(&hdl->disassoc_sta_mac, &event->addr, sizeof(event->addr));
	hdl->disassoc_sta_count++;

	/* If our client info list is empty, ignore this disassociation */
	if (hdl->client_list_count == 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"proc_client_disassoc: empty client info list\n"));
		goto pcd_exit;
	}

	/* Find the STA in our client info list */
	for (i = 0; i < hdl->client_list_count; i++) {
		if (memcmp(hdl->client_list[i].p2p_int_addr, &event->addr,
			sizeof(event->addr)) == 0) {
			item = &hdl->client_list[i];
			break;
		}
	}
	if (item == NULL) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"proc_client_disassoc: client not found on list\n"));
		goto pcd_exit;
	}

	/* Remove the STA from our client info list and pack the list. */
	if (i != hdl->client_list_count - 1) {
		/* Save a copy of the deleted item for later debug logging */
		memcpy(&deleted_item, item, sizeof(deleted_item));
		item = &deleted_item;

		/* Shift up the list to fill the hole */
		memcpy(&hdl->client_list[i],
			&hdl->client_list[i + 1],
			sizeof(hdl->client_list[i]) * (hdl->client_list_count - (i + 1)));
	}
	--hdl->client_list_count;

	/* Update the P2P IEs to rebuild the P2P Group Info attribute based on
	 * the updated client info list.
	 */
	p2papi_update_p2p_wps_ies_nolock(hdl, P2PAPI_BSSCFG_CONNECTION);

	/* Signal the Connection thread that a client has disassociated */
	p2papi_osl_signal_client_assoc_state(hdl,
		P2PAPI_OSL_CLIENT_ASSOC_STATE_DISASSOC);

pcd_exit:
	P2PAPI_DATA_UNLOCK(hdl);

	if (item != NULL)
		/* Do this outside the critical section */
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "proc_client_disassoc: "
			"removed %02x:%02x:%02x:%02x:%02x:%02x count=%d\n",
			item->p2p_dev_addr[0], item->p2p_dev_addr[1], item->p2p_dev_addr[2],
			item->p2p_dev_addr[3], item->p2p_dev_addr[4], item->p2p_dev_addr[5],
			hdl->client_list_count));

	return 0;
}

void
p2papi_proc_ap_assoc_resp_ie(p2papi_instance_t *hdl, wl_event_msg_t *event,
	void *data, uint32 data_len)
{
	P2PAPI_DATA_LOCK(hdl);

	if (!hdl->is_wps_enrolling) {
		if (data_len > sizeof(hdl->peer_assocrsp_ie_data))
		{
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_proc_ap_assoc_resp_ie: ie-data (%d bytes) over the limit %d bytes\n",
				data_len, sizeof(hdl->peer_assocrsp_ie_data)));

			data_len = sizeof(hdl->peer_assocrsp_ie_data);
		}
		hdl->peer_assocrsp_ie_len = data_len;
		memcpy(hdl->peer_assocrsp_ie_data, data, data_len);
	}

	P2PAPI_DATA_UNLOCK(hdl);
}

/* Find a Group Client STA in our associated clients list */
p2papi_client_info_t*
p2papi_find_group_client(p2papi_instance_t *hdl, struct ether_addr *client_addr)
{
	p2papi_client_info_t* item = NULL;
	int i;

	/* Find the STA in our client info list */
	for (i = 0; i < hdl->client_list_count; i++) {
		if (memcmp(hdl->client_list[i].p2p_dev_addr, client_addr->octet,
			sizeof(*client_addr)) == 0) {
			item = &hdl->client_list[i];
			break;
		}
	}

	if (item == NULL)
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_find_group_client: client not found\n"));
	else
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_find_group_client: client found at client_info[%d]\n", i));

	return item;
}

BCMP2P_STATUS
p2papi_reset_state(p2papi_instance_t* hdl)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_reset_state\n"));

	hdl->is_connecting = FALSE;
	hdl->is_connected = FALSE;
	hdl->is_p2p_group = FALSE;
	hdl->ap_ready = FALSE;
	hdl->is_ap = FALSE;
	hdl->use_wps = hdl->ap_config.WPSConfig.wpsEnable;
	hdl->ap_config.WPSConfig.wpsIsButtonPushed = FALSE;
	hdl->is_in_softap_cleanup = FALSE;
	hdl->client_list_count = 0;

	memcpy(&hdl->op_channel, &hdl->ap_config.operatingChannel,
		sizeof(hdl->op_channel));
	memset(&hdl->peer_channel, 0, sizeof(hdl->peer_channel));
	memset(&hdl->gon_channel, 0, sizeof(hdl->gon_channel));
	memset(&hdl->gon_peer_listen_channel, 0, sizeof(hdl->gon_peer_listen_channel));

	memset(&hdl->negotiated_channel_list, 0, sizeof(hdl->negotiated_channel_list));

	return BCMP2P_SUCCESS;
}


#ifndef SOFTAP_ONLY

/* Continue with a P2P link creation after the Group Owner Negotiation -
 * do the Provisioning phase of a P2P connection.
 *
 * This function blocks - it only returns when the connection has succeeded,
 * failed, or has been cancelled by p2papi_teardown().
 */
static BCMP2P_STATUS
p2papi_continue_link_create(p2papi_instance_t* hdl,
	BCMP2P_BOOL peer_is_existing_go)
{
	BCMP2P_STATUS status = BCMP2P_SUCCESS;
	int result = 0;
	uint16 tmp_peer_go_cfg_tmo_ms;
	bool is_ap_peer_info_set;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2p_link_cont: credentials ssid=%s opch=%d:%d peer_is_existing_go=%d\n",
		hdl->credentials.ssid, hdl->op_channel.channel_class,
		hdl->op_channel.channel, peer_is_existing_go));
#if P2PAPI_ENABLE_DEBUG_SHOWKEY
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"               credentials nwKey=%s\n",
		hdl->credentials.nwKey));
#endif /* P2PAPI_ENABLE_DEBUG_SHOWKEY */

	/* If we are a persistent P2P group, skip all the actions in this fn
	 * because they are already done by the loop in p2papi_group_create().
	 */
	if (hdl->is_p2p_group) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2p_link_cont: is p2p group, returning.\n"));
		return status;
	}

	/* Disable P2P discovery synchronously to prevent it conflicting with
	 * creating the connection.
	 */
	p2papi_discover_cancel_sync(hdl);

	/*
	 * If we are acting as the AP
	 */
	if (hdl->is_ap || hdl->is_p2p_group) {

		/* Before creating an AP, wait for the peer's
		 * Configuration Timeout specified by the peer during the GON.
		 * (WFA P2P P2P spec 1.00 section 3.1.4.3 page 36 line 7-10)
		 */
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2p_link_cont: wait for peer client config timeout %u ms\n",
			hdl->peer_cl_cfg_tmo_ms));
		p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_PEER_CONFIG_TIMEOUT,
			hdl->peer_cl_cfg_tmo_ms);

		/* Create an AP mode BSS and a soft AP */
		status = p2papi_group_create_core(hdl, TRUE, TRUE);
		if (status != BCMP2P_SUCCESS) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
				"p2p_link_cont: softap create error %d\n", status));
			goto link_create_err;
		}

	/*
	 * else we are acting as the STA
	 */
	} else {
		int i, j;
		p2p_chanlist_t *chanlist;

		/* initialize join chanspec from negotiated channel list */
		/* first chanspec is operating channel */
		hdl->num_join_chanspec = 0;
		p2papi_channel_to_chspec(&hdl->op_channel,
			&hdl->join_chanspec[hdl->num_join_chanspec++]);

		/* If we have a negotiated channel list
		 *   Use the negotiated channel list for the join.
		 * else
		 *   Use the driver's channel list for the join.
		 *   This case occurs when we join an existing GO without doing GO
		 *   negotiation and without a P2P Invitation.
		 */
		if (hdl->negotiated_channel_list.num_entries > 0) {
			chanlist = &hdl->negotiated_channel_list;
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2p_link_cont: using negotiated channel list\n"));
		} else {
			chanlist = p2papi_get_channel_list(hdl);
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2p_link_cont: using driver channel list\n"));
		}
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "join channels:\n"));
		for (i = 0; i < chanlist->num_entries; i++) {
			for (j = 0; j < chanlist->entries[i].num_channels; j++) {
				BCMP2P_CHANNEL channel;
				char str[CHANSPEC_STR_LEN];
				channel.channel_class = (BCMP2P_CHANNEL_CLASS)chanlist->entries[i].band;
				channel.channel = chanlist->entries[i].channels[j];
				p2papi_channel_to_chspec(&channel,
					&hdl->join_chanspec[hdl->num_join_chanspec++]);
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "   %s\n",	p2papi_chspec_ntoa(
					hdl->join_chanspec[hdl->num_join_chanspec - 1], str)));
			}
		}

		/* This is for disconnecting the original connection in client discovery */
		if (hdl->is_connected) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2p_link_cont: disconnect existing connection\n"));
			p2papi_teardown(hdl);
		}

		/* Before connecting to the peer, wait for the peer's
		 * Configuration Timeout specified by the peer during the GON.
		 * (WFA P2P P2P spec 1.00 section 3.1.4.3 page 36 line 7-10)
		 */
		if (!peer_is_existing_go) {
			tmp_peer_go_cfg_tmo_ms = hdl->peer_go_cfg_tmo_ms +
				hdl->extra_peer_go_cfg_tmo_ms;
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2p_link_cont: wait for peer GO config timeout %u (+ %u) ms\n",
				hdl->peer_go_cfg_tmo_ms, hdl->extra_peer_go_cfg_tmo_ms));

			p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_PEER_CONFIG_TIMEOUT,
				tmp_peer_go_cfg_tmo_ms);
		}

		/* Create a STA mode BSS for the P2P connection */
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2p_link_cont: create STA bsscfg\n"));
		result = p2papi_create_sta_bss(hdl);
		if (result != 0) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
				"p2p_link_cont: create STA BSSCFG failed\n"));
			status = BCMP2P_FAIL_TO_START_STA;
			goto link_create_err;
		}
		

		/* Set listen interval if not using default value. */
		if (hdl->listen_interval != 0) {
			p2pwlu_set_listen_interval(hdl, hdl->listen_interval,
			                           hdl->bssidx[P2PAPI_BSSCFG_CONNECTION]);
		}

		/* Add the P2P IE to our probe requests and assoc requests.  This is
		 * needed for the association to succeed using the P2P BSS.
		 */
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2p_link_cont: add P2P STA IEs\n"));
		p2papi_update_p2p_wps_ies(hdl, P2PAPI_BSSCFG_CONNECTION);

		/* No need to bring up the STA BSSCFG.  It is up when created. */
		/* (void) p2pwlu_bss(hdl, TRUE); */

		is_ap_peer_info_set = true;
#if P2PAPI_ENABLE_WPS
		if (hdl->use_wps) {
			/*
			 * Run the WPS enrollee which will initiate the WPS handshake.
			 * This call returns when the WPS handshake completes or times out.
			 */
			result = p2papi_run_wps_enrollee(hdl);
			if (result != 0) {
				if (hdl->cancel_link_create) {
					BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
						"p2p_link_cont: enrollee cancelled\n"));
				} else {
					BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
						"p2p_link_cont: enrollee failed with %d\n",
						result));
					status = BCMP2P_WPS_ENROLLEE_FAILED;
				}
				goto link_create_err;
			}
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2p_link_cont: enrollee done\n"));
			is_ap_peer_info_set = true;
		}
		else
		{
			is_ap_peer_info_set = false;
		}
#else /* !P2PAPI_ENABLE_WPS */
		result = 0;
#endif /* P2PAPI_ENABLE_WPS */

		/* Join to the AP using the security settings previously configured
		 * or received from WPS.
		 */
		if (result == 0) {
			if (is_ap_peer_info_set)
				p2papi_osl_sta_join_with_security(hdl, hdl->credentials.ssid,
					hdl->credentials.authType, hdl->credentials.encrType,
					hdl->credentials.nwKey, hdl->credentials.wepIndex,
					&hdl->peer_int_addr);
			else
			{
				/* if WPS is not enabled */
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2p_link_cont: STA join <%s,%02x:%02x:%02x:%02x:%02x:%02x>\n",
					hdl->peer_ssid,
					hdl->peer_int_addr.octet[0], hdl->peer_int_addr.octet[1],
					hdl->peer_int_addr.octet[2], hdl->peer_int_addr.octet[3],
					hdl->peer_int_addr.octet[4], hdl->peer_int_addr.octet[5]));
				/* join AP using the wildcard SSID 'DIRECT-' & AP peer's bssid */
				p2papi_osl_sta_join_with_security(hdl, "",
					hdl->credentials.authType, hdl->credentials.encrType,
					hdl->credentials.nwKey, hdl->credentials.wepIndex,
					&hdl->peer_int_addr);
			}
		}
		if (hdl->is_connected) {
			p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_CREATE_LINK,
				BCMP2P_NOTIF_CREATE_LINK_COMPLETE);
		} else {
			p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_CREATE_LINK,
				BCMP2P_NOTIF_CREATE_LINK_TIMEOUT);
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "p2p_link_cont: join timeout\n"));
			goto link_create_err;
		}
	}

	status = BCMP2P_SUCCESS;
	goto link_create_done;

link_create_err:
	P2PERR1("p2p_link_cont: error exit, error=%d\n", result);
	p2papi_fsm_reset(hdl);

	/* If we have created a BSSCFG for the connection, tear it down */
	if (hdl->bssidx[P2PAPI_BSSCFG_CONNECTION] != 0) {
		if (hdl->is_ap || hdl->is_p2p_group) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
				"p2p_link_cont end: AP connection bsscfg still exists!\n"));
		} else {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2p_link_cont end: deleting STA connection bsscfg\n"));
			p2papi_delete_sta_bss(hdl);
		}
	}

	/* Call the app notif callback to indicate link create failed */
	p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_CREATE_LINK,
		hdl->cancel_link_create ? BCMP2P_NOTIF_CREATE_LINK_CANCEL
								: BCMP2P_NOTIF_CREATE_LINK_FAIL);

link_create_done:
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2p_link_cont: done. is_conn=%d\n",
		hdl->is_connected));
	hdl->is_connecting = FALSE;
	hdl->cancel_link_create = FALSE;
	p2papi_deinit_gon_discoverability(hdl);
	return status;
}

/* Initiate setting up a P2P connection to a peer, specifying the peer using
 * a discovered peers list entry.
 * This function blocks - it only returns when the connection has succeeded,
 * failed, or has been cancelled by p2papi_teardown().
 */
BCMP2P_STATUS
p2papi_link_create(p2papi_instance_t* hdl, uint32 timeout,
	p2papi_peer_info_t *peer)
{
	BCMP2P_STATUS status;
	struct ether_addr *peer_intaddr;
	int ret;
	p2papi_state_t	old_conn_state;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;
	P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_link_create: begin, timeout=%u opch=%d:%d\n",
		timeout,  hdl->op_channel.channel_class, hdl->op_channel.channel));

	if (!peer) {
		P2PERR("p2p_link_create: no peer specified\n");
		return BCMP2P_INVALID_PARAMS;
	}
	if (hdl->is_connecting) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2p_link_create: ignored, another instance active.\n"));
		return BCMP2P_NESTED_CALL;
	}

	hdl->cancel_link_create = FALSE;
	hdl->cancel_group_create = FALSE;
	hdl->is_connecting = TRUE;
	hdl->conn_state = P2PAPI_ST_IDLE;

	hdl->join_timeout_secs = timeout;
	if (hdl->join_timeout_secs == 0)
		hdl->join_timeout_secs = P2PAPI_GROUP_FORMATION_TMO_SEC;

	/* Save the information about the peer */
	if (peer->ssid_len > sizeof(hdl->peer_ssid) - 1)
		peer->ssid_len = sizeof(hdl->peer_ssid) - 1;
	memcpy(hdl->peer_ssid, peer->ssid, peer->ssid_len);
	hdl->peer_ssid[peer->ssid_len] = '\0';

	/* Save the peer's P2P Device Address */
	memcpy(&hdl->peer_dev_addr, &peer->mac, sizeof(hdl->peer_dev_addr));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2p_link_create: "
		"peer_dev_addr=%02x:%02x:%02x:%02x:%02x:%02x tmo=%u peer_ch=%d:%d\n",
		hdl->peer_dev_addr.octet[0], hdl->peer_dev_addr.octet[1],
		hdl->peer_dev_addr.octet[2], hdl->peer_dev_addr.octet[3],
		hdl->peer_dev_addr.octet[4], hdl->peer_dev_addr.octet[5],
		hdl->join_timeout_secs, peer->listen_channel.channel_class,
		peer->listen_channel.channel));

	/* If the peer is an existing P2P Group Owner
	 *   Set the peer P2P Interface Address to the peer's BSSID.
	 *   (The BSSID is the only place we can get the peer's Interface Address.
	 *   The P2P IE obtained from the peer's probe response during device
	 *   discovery does not contain any attributes with an Interface Address.)
	 * else
	 *   Set the peer P2P Interface Address to the P2P Device Address for now.
	 *   Later this will be overwritten with the true P2P Interface Address
	 *   obtained from a GO negotiation frame.
	 */
	if (peer->is_p2p_group)
		peer_intaddr = &peer->bssid;
	else
		peer_intaddr = &peer->mac;
	memcpy(&hdl->peer_int_addr, peer_intaddr, sizeof(hdl->peer_int_addr));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2p_link_create: "
		"peer_int_addr=%02x:%02x:%02x:%02x:%02x:%02x peer_isgo=%d\n",
		hdl->peer_int_addr.octet[0], hdl->peer_int_addr.octet[1],
		hdl->peer_int_addr.octet[2], hdl->peer_int_addr.octet[3],
		hdl->peer_int_addr.octet[4], hdl->peer_int_addr.octet[5],
		peer->is_p2p_group));

	if (!hdl->enable_p2p) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2p_link_create: skipping GON, p2p not enabled\n"));
		hdl->intent = 8;
		hdl->peer_intent = 8;
	} else if (peer->is_p2p_group) {
		/* Set our Operating Channel to the GO's operating channel */
		memcpy(&hdl->op_channel, &peer->op_channel, sizeof(hdl->op_channel));
		/* Set our peer channel to the GO's operating channel */
		memcpy(&hdl->peer_channel, &peer->op_channel, sizeof(hdl->peer_channel));
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2p_link_create: skipping GON, peer is GO ch=%d:%d\n",
			hdl->op_channel.channel_class, hdl->op_channel.channel));
	} else {
		p2papi_init_gon_discoverability(hdl);

		/* Start a Group Owner Negotiation handshake with the peer by sending
		 * the peer a GO negotiation request frame.
		 */
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2p_link_create: Starting GO negotiation.\n"));
		p2papi_fsm_reset(hdl);
		ret = p2papi_fsm_start_go_neg(hdl, &peer->mac, &peer->listen_channel,
			peer->is_p2p_group);

		/* When we reach here, the GO negotiation has completed or timed out */
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2p_link_create: GO neg end, ret=%d state=%d\n",
			ret, hdl->conn_state));

		if (hdl->cancel_link_create) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2p_link_create: cancelled\n"));
			status = BCMP2P_ERROR;
			goto err_exit;
		}
		if (ret != BCMP2P_SUCCESS || hdl->conn_state == P2PAPI_ST_IDLE) {
			old_conn_state = hdl->conn_state;
			p2papi_fsm_reset(hdl);
			if (ret == BCMP2P_GO_NEGOTIATE_TIMEOUT) {
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"p2p_link_create: GO neg timed out.\n");
				p2papi_osl_do_notify_cb(hdl,
					BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION,
					BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_FAIL);
				p2papi_osl_do_notify_cb(hdl,
					BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION,
					BCMP2P_NOTIF_CREATE_LINK_TIMEOUT));
				status = BCMP2P_GO_NEGOTIATE_TIMEOUT;
				goto err_exit;
			}
			if (old_conn_state == P2PAPI_ST_IDLE) {
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"p2p_link_create: peer rejected our connect request.\n"));

				if (hdl->gon_notif ==
				                BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_INFO_UNAVAIL)
				{
					/* no notification needed here - we already
					 *      sent an INFO_UNAVAIL
					 *  in p2plib_negotiate.c: p2papi_fsm_proc_gonrsp()
					 */
				}
				else
				{
					p2papi_osl_do_notify_cb(hdl,
						BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION,
						BCMP2P_NOTIF_CREATE_LINK_FAIL);
					status = BCMP2P_CONNECT_REJECTED;
				}
				/*  clear last gon notification */
				hdl->gon_notif = BCMP2P_NOTIF_NONE;				
				goto err_exit;
			} else {
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"p2p_link_create: GO neg error.\n"));
				status = BCMP2P_ERROR;
				goto err_exit;
			}
		}
		P2PLOG("p2p_link_create: GO neg complete.\n");
	}

	/* success exit */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_link_create: continue\n"));
	return p2papi_continue_link_create(hdl, peer->is_p2p_group);

err_exit: /* error exit */
	hdl->is_connecting = FALSE;
	if (hdl->enable_p2p) {
		p2papi_deinit_gon_discoverability(hdl);
	}

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_link_create: end, status=%d\n",
		status));
	return status;
}

/* Initiate a P2P connection to a peer, specifying the peer using its device
 * address.
 * This function blocks - it only returns when the connection has succeeded,
 * failed, or has been cancelled by p2papi_teardown().
 */
BCMP2P_STATUS
p2papi_link_create_to_devaddr(p2papi_instance_t* hdl, uint32 timeout,
	struct ether_addr *peer_dev_addr, BCMP2P_CHANNEL *peer_listen_channel,
	BCMP2P_BOOL is_peer_go, struct ether_addr *peer_int_addr)
{
	p2papi_peer_info_t peer;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;
	P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_link_create_to_dev_addr: ch=%d:%d\n",
		peer_listen_channel->channel_class, peer_listen_channel->channel));

	memset(&peer, 0, sizeof(peer));
	peer.is_p2p_group = is_peer_go ? true : false;
	peer.ssid_len = 0;
	peer.ssid[0] = '\0';
	memcpy(&(peer.mac), peer_dev_addr, sizeof(peer.mac));
	memcpy(&peer.listen_channel, peer_listen_channel, sizeof(peer.listen_channel));
	if (peer.is_p2p_group) {
		memcpy(&(peer.bssid), peer_int_addr, sizeof(peer.bssid));
		memcpy(&peer.op_channel, peer_listen_channel, sizeof(peer.op_channel));
	}

	return p2papi_link_create(hdl, timeout, &peer);
}


/* Associate to an existing P2P Group using credentials */
BCMP2P_STATUS
p2papi_join_group_with_credentials(p2papi_instance_t *hdl,
	struct ether_addr *devAddr, BCMP2P_CHANNEL *channel,
	char *ssid, struct ether_addr *bssid,
	brcm_wpscli_authtype authType, brcm_wpscli_encrtype encrType,
	char *key, uint16 wepIndex)
{
	int ssid_len;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;
	P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl);

	if (hdl->is_connecting) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_join_group_with_cred: ignored, already is_connecting\n"));
		return BCMP2P_NESTED_CALL;
	}
	p2papi_enable_p2p(hdl, TRUE);

	/* Disable P2P discovery synchronously to prevent it conflicting with
	 * creating the connection.
	 */
	p2papi_discover_cancel_sync(hdl);

	hdl->cancel_link_create = FALSE;
	hdl->cancel_group_create = FALSE;
	hdl->is_connecting = TRUE;
	hdl->conn_state = P2PAPI_ST_IDLE;
	hdl->join_timeout_secs = P2PAPI_GROUP_FORMATION_TMO_SEC;

	memcpy(&hdl->op_channel, channel, sizeof(hdl->op_channel));

	/* Save the target group's SSID */
	ssid_len = strlen(ssid);
	if (ssid_len > sizeof(hdl->peer_ssid) - 1)
		ssid_len = sizeof(hdl->peer_ssid) - 1;
	memcpy(hdl->peer_ssid, ssid, ssid_len);
	hdl->peer_ssid[ssid_len] = '\0';
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_join_group_with_cred: opch=%d:%d ssid=%s\n",
		channel->channel_class, channel->channel, hdl->peer_ssid));

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"    bssid=%02x:%02x:%02x:%02x:%02x:%02x"
		" grpDevAddr=%02x:%02x:%02x:%02x:%02x:%02x\n",
		bssid->octet[0], bssid->octet[1],
		bssid->octet[2], bssid->octet[3],
		bssid->octet[4], bssid->octet[5],
		hdl->peer_dev_addr.octet[0], hdl->peer_dev_addr.octet[1],
		hdl->peer_dev_addr.octet[2], hdl->peer_dev_addr.octet[3],
		hdl->peer_dev_addr.octet[4], hdl->peer_dev_addr.octet[5]));
	memcpy(&hdl->peer_int_addr, bssid, sizeof(hdl->peer_int_addr));

	/* Force not using WPS regardless of the wpsEnable config setting */
	hdl->use_wps = FALSE;

	strncpy(hdl->credentials.ssid, ssid, sizeof(hdl->credentials.ssid));
	hdl->credentials.authType = authType;
	hdl->credentials.encrType = encrType;
	strncpy(hdl->credentials.nwKey, key, sizeof(hdl->credentials.nwKey));
	hdl->credentials.wepIndex = wepIndex;

	memcpy(&hdl->peer_dev_addr, devAddr, sizeof(hdl->peer_dev_addr));

	return p2papi_continue_link_create(hdl, TRUE);
}

/* Associate to an existing P2P Group and start the WPS handshake.
 * This function blocks - it only returns when the connection has succeeded,
 * failed, or has been cancelled by p2papi_teardown().
 */
BCMP2P_STATUS
p2papi_join_group_with_wps(p2papi_instance_t* hdl,
	struct ether_addr *grp_bssid,
	uint8 *grp_ssid, uint32 grp_ssid_len, struct ether_addr *grp_dev_addr,
	BCMP2P_CHANNEL *grp_op_channel)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;
	P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl);

	if (hdl->is_connecting) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_join_group_with_wps: ignored, already is_connecting\n"));
		return BCMP2P_NESTED_CALL;
	}
	p2papi_enable_p2p(hdl, TRUE);

	/* Disable P2P discovery synchronously to prevent it conflicting with
	 * creating the connection.
	 */
	p2papi_discover_cancel_sync(hdl);

	hdl->cancel_link_create = FALSE;
	hdl->cancel_group_create = FALSE;
	hdl->is_connecting = TRUE;
	hdl->conn_state = P2PAPI_ST_IDLE;
	hdl->join_timeout_secs = P2PAPI_GROUP_FORMATION_TMO_SEC;

	/* Save the target group's SSID */
	if (grp_ssid_len > sizeof(hdl->peer_ssid) - 1)
		grp_ssid_len = sizeof(hdl->peer_ssid) - 1;
	memcpy(hdl->peer_ssid, grp_ssid, grp_ssid_len);
	hdl->peer_ssid[grp_ssid_len] = '\0';
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_join_group_with_wps: opch=%d ssid=%s\n",
		grp_op_channel, hdl->peer_ssid));

	/* Save the target group's P2P Device Address */
	memcpy(&hdl->peer_dev_addr, grp_dev_addr->octet,
		sizeof(hdl->peer_dev_addr));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"    bssid=%02x:%02x:%02x:%02x:%02x:%02x"
		" grpDevAddr=%02x:%02x:%02x:%02x:%02x:%02x\n",
		grp_bssid->octet[0], grp_bssid->octet[1],
		grp_bssid->octet[2], grp_bssid->octet[3],
		grp_bssid->octet[4], grp_bssid->octet[5],
		hdl->peer_dev_addr.octet[0], hdl->peer_dev_addr.octet[1],
		hdl->peer_dev_addr.octet[2], hdl->peer_dev_addr.octet[3],
		hdl->peer_dev_addr.octet[4], hdl->peer_dev_addr.octet[5]));
	memcpy(&hdl->peer_int_addr, grp_bssid, sizeof(hdl->peer_int_addr));

	/* Force using WPS regardless of the wpsEnable config setting */
	hdl->use_wps = TRUE;

	/* Set our Operating Channel to the GO's operating channel */
	memcpy(&hdl->op_channel, grp_op_channel, sizeof(hdl->op_channel));

	return p2papi_continue_link_create(hdl, TRUE);
}

/* Process an incoming connection.
 * On the peer that received a connection request, the app calls this fn in
 * response to BCMP2P_NOTIF_GROUP_OWNER_NEGOTIATION_COMPLETE to provide the
 * thread context to run WPS.
 * (The peer that initiated a connection does not need to call this because
 * its call to p2papi_link_create() provides the thread context for WPS.)
 */
BCMP2P_STATUS
p2papi_process_incoming_conn(p2papi_instance_t* hdl, int timeout_sec)
{
	BCMP2P_STATUS status;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_process_incoming_conn: begin, timeout=%d\n", timeout_sec));

	hdl->is_connecting = TRUE;
	hdl->join_timeout_secs = timeout_sec;
	if (hdl->join_timeout_secs == 0)
		hdl->join_timeout_secs = P2PAPI_GROUP_FORMATION_TMO_SEC;

	/* Establish a connection */
	status = p2papi_continue_link_create(hdl, FALSE);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_process_incoming_conn: end\n"));
	return status;
}

/* Cancel any action frame tx in progress */
void
p2papi_cancel_all_aftx_send(p2papi_instance_t* hdl)
{
	if (hdl->provdis_aftx_hdl != NULL) {
		p2papi_aftx_cancel_send(hdl->provdis_aftx_hdl);
		hdl->provdis_aftx_hdl = NULL;
	}
	if (hdl->gon_aftx_hdl != NULL) {
		p2papi_aftx_cancel_send(hdl->gon_aftx_hdl);
		hdl->gon_aftx_hdl = NULL;
	}
	if (hdl->invite_aftx_hdl != NULL) {
		p2papi_aftx_cancel_send(hdl->invite_aftx_hdl);
		hdl->invite_aftx_hdl = NULL;
	}
	if (hdl->presence_aftx_hdl != NULL) {
		p2papi_aftx_cancel_send(hdl->presence_aftx_hdl);
		hdl->presence_aftx_hdl = NULL;
	}
	if (hdl->discb_aftx_hdl != NULL) {
		p2papi_aftx_cancel_send(hdl->discb_aftx_hdl);
		hdl->discb_aftx_hdl = NULL;
	}

	return;
}

/* Tear down a connection created by p2papi_link_create() or stop a
 * p2papi_link_create() in progress.
 */
BCMP2P_STATUS
p2papi_teardown(p2papi_instance_t* hdl)
{
	BCMP2P_STATUS ret = BCMP2P_SUCCESS;
	uint32 sleep_ms;
	BCMP2P_BOOL isSoftApOn;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;
	P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_teardown: di=%u cg=%u cd=%u dg=%u we=%u win=%u st=%u ap=%u\n",
		hdl->is_discovering, hdl->is_connecting, hdl->is_connected,
		hdl->is_disconnecting, hdl->is_wps_enrolling,
		brcm_wpscli_softap_is_wps_window_open(), hdl->conn_state, hdl->is_ap));

	if (hdl->is_disconnecting) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_teardown: ignored, another instance active.\n"));
		return BCMP2P_NESTED_CALL;
	}
	hdl->is_disconnecting = TRUE;

	/* Cancel any action frame tx in progress */
	p2papi_cancel_all_aftx_send(hdl);
	p2papi_cancel_send_at_common_channel(hdl);

	/* If link creation is in progress
	 *     Cancel link creation.
	 *     Enter a polling loop to wait for the cancel to complete.
	 */
	if (hdl->is_connecting || hdl->is_connected) {
		hdl->cancel_link_create = TRUE;

		/* Abort any Group Owner Negotiation in progress */
		if (hdl->enable_p2p) {
			p2papi_fsm_abort(hdl);
		}

#if P2PAPI_ENABLE_WPS
		/* Abort any leftover WPS handshake in progress */
		if (hdl->use_wps) {
			if (brcm_wpscli_softap_is_wps_window_open() || hdl->is_wps_enrolling) {
				BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
					"p2papi_teardown: brcm_wpscli_abort\n"));
				(void) brcm_wpscli_abort();
				p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_GENERIC, 1500);
			}
		}
#endif /* P2PAPI_ENABLE_WPS */

		p2papi_stop_pbc_timer(hdl);

		if (hdl->is_ap || hdl->is_p2p_group) {
			/* If acting as soft AP or p2p group owner, tell it to shut down */
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_teardown: p2papi_group_cancel\n"));
			p2papi_group_cancel(hdl);
		} else {
			/* If acting as a STA, disassociate only if already associated */
			if (p2pwlu_is_associated(hdl)) {
				P2PLOG("p2papi_teardown: p2pwlu_disassoc\n");
				if (0 != p2pwlu_disassoc(hdl)) {
					BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
						"p2papi_teardown: p2pwlu_disassoc failed\n"));
				}
				hdl->is_connecting = FALSE;
				hdl->is_connected = FALSE;
				p2papi_delete_sta_bss(hdl);
				p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_CREATE_LINK,
					BCMP2P_NOTIF_CREATE_LINK_CANCEL);
			}
		}

		/* Poll for the connection teardown to complete */
		for (sleep_ms = 0; sleep_ms < hdl->cancel_connect_timeout_ms;
			sleep_ms += 500) {
			BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
				"p2papi_teardown: poll for connect cancel...\n"));
			if (!hdl->is_connecting && !hdl->is_connected)
				break;
			p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_LINK_CREATE_CANCEL_POLL, 500);
		}

		if (hdl->is_connecting || hdl->is_connected)
			P2PERR("p2papi_teardown: connect cancel timed out\n");
		else
			P2PLOG("p2papi_teardown: connect cancel confirmed\n");

		hdl->cancel_link_create = FALSE;
		hdl->cancel_group_create = FALSE;
	}
	p2papi_cancel_send_at_common_channel(hdl);

	/* If the link is still connected
	 *     Disconnect it.
	 */
	if (hdl->is_connecting || hdl->is_connected || hdl->is_wps_enrolling) {
		/* Disconnect */
		if (hdl->is_ap) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
				"p2papi_teardown: AP not cleaned up! cg=%u cd=%u we=%u\n",
				hdl->is_connecting, hdl->is_connected, hdl->is_wps_enrolling));
		} else {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
				"p2papi_teardown: STA still associated! cg=%u cd=%u we=%u\n",
				hdl->is_connecting, hdl->is_connected, hdl->is_wps_enrolling));
		}
		hdl->is_connected = FALSE;
		p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_CREATE_LINK,
			BCMP2P_NOTIF_CREATE_LINK_CANCEL);
	}

	p2papi_fsm_reset(hdl);
	hdl->in_persist_grp = FALSE;

	/* Clear the MAC filter */
/*	p2papi_clr_mac_filter(hdl); */

	/* If we are acting as an AP and the soft AP is up, disable the soft AP. */
	isSoftApOn = p2papi_is_softap_on(hdl);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_teardown: is_ap=%d is_softap_on=%d\n", hdl->is_ap, isSoftApOn));
	if (hdl->is_ap && isSoftApOn) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2papi_teardown: soft AP still on!\n"));
		ret = BCMP2P_SOFTAP_DISABLE_FAIL;
	}

	/* If somehow a connection BSSCFG still exists, delete it */
	if (hdl->bssidx[P2PAPI_BSSCFG_CONNECTION]) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_teardown: connection bsscfg still exists\n"));
		hdl->cancel_link_create = TRUE;
		hdl->cancel_group_create = TRUE;
		(void) brcm_wpscli_abort();
		p2papi_shutdown_wpsreg_mgr(hdl);
		p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_GENERIC, 2000);

		if (hdl->bssidx[P2PAPI_BSSCFG_CONNECTION]) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_teardown: do failsafe delete of STA bsscfg\n"));
			p2papi_delete_sta_bss(hdl);
		}
		if (hdl->bssidx[P2PAPI_BSSCFG_CONNECTION]) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_teardown: do failsafe delete of AP bsscfg\n"));
			p2papi_delete_ap_bss(hdl);
		}
	}

	p2papi_reset_state(hdl);

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_teardown() finished, cfgmeth=0x%x\n",
		hdl->ap_config.WPSConfig.wpsConfigMethods));
	hdl->is_disconnecting = FALSE;
	return ret;
}
#endif /* SOFTAP_ONLY */

/* Do soft AP shutdown cleanup actions */
static BCMP2P_STATUS
p2papi_softap_cleanup(p2papi_instance_t* hdl)
{
	BCMP2P_STATUS status = BCMP2P_SUCCESS;
	BCMP2P_BOOL is_in_cleanup;

	is_in_cleanup = P2PAPI_TEST_AND_SET(hdl, &hdl->is_in_softap_cleanup);
	if (!is_in_cleanup) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_softap_cleanup: begin\n"));
		hdl->is_in_softap_cleanup = TRUE;
		
		/* Allow p2papi_disable_discovery() to delete the device bsscfg */
		hdl->ap_ready = FALSE;

		/* If in P2P mode, remove any added P2P IEs, disable discovery. */
#ifndef SOFTAP_ONLY
		if (hdl->enable_p2p) {
			hdl->is_connecting = FALSE;
			p2papi_update_p2p_wps_ies(hdl, P2PAPI_BSSCFG_CONNECTION);
			p2papi_discover_cancel_sync(hdl);
		}
#endif


#if P2PAPI_ENABLE_DHCPD
		/* Disable our DHCP server if required */
		if (hdl->enable_dhcp) {
			p2papi_dhcp_enable(hdl, FALSE);

			/* Clear our virtual AP network interface's IP address */
			p2papi_osl_clear_ap_ipaddr(hdl);
		}
#endif /* P2PAPI_ENABLE_DHCPD */

		/* Disable the softAP */
		if (p2papi_softap_disable(hdl) != 0) {
			P2PLOG("p2papi_softap_cleanup: softap_disable failed!\n");
			status = BCMP2P_SOFTAP_DISABLE_FAIL;
		}

		p2papi_reset_state(hdl);
		hdl->intent = 8;
		p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_CREATE_LINK,
			BCMP2P_NOTIF_SOFTAP_STOP);

		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_softap_cleanup: end\n"));
	} else {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_softap_cleanup: already started or done\n"));
	}
	return status;
}


static BCMP2P_STATUS
p2papi_group_create_core(p2papi_instance_t* hdl, bool repeat_wps, bool open_wps_window)
{
	brcm_wpscli_pwd_type wps_mode = BRCM_WPS_PWD_TYPE_PIN;
	BCMP2P_STATUS status = BCMP2P_SUCCESS;
	BCMP2P_STATUS status2 = BCMP2P_SUCCESS;
	int i;
	struct ether_addr new_sta_mac;
	bool new_sta_joined;
	P2PWL_HDL wl;

	P2PAPI_CHECK_P2PHDL(hdl);
	P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);

	hdl->is_connecting = TRUE;

	memset(&new_sta_mac, 0, sizeof(new_sta_mac));

	print_credential(&hdl->credentials,
		"p2papi_group_create_core:AP Credentials");
	if (hdl->ap_config.hideSSID) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "  (hidden SSID)\n"));
	}

	/* Determine the WPS pin/pushbutton mode */
	if (hdl->use_wps) {
		if (hdl->ap_config.WPSConfig.wpsPinMode) {
			wps_mode = BRCM_WPS_PWD_TYPE_PIN;
#if P2PAPI_ENABLE_DEBUG_SHOWKEY
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2p_group_create_core: wps_mode=PIN, pin=%s\n",
				hdl->ap_config.WPSConfig.wpsPin));
#else
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2p_group_create_core: wps_mode=PIN, pin=***\n"));
#endif /* P2PAPI_ENABLE_DEBUG_SHOWKEY */
		} else {
			wps_mode = BRCM_WPS_PWD_TYPE_PBC;
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2p_group_create_core: wps_mode=PBC\n"));
		}
	}

	/* Initialize connection state */
	hdl->conn_state = P2PAPI_ST_IDLE;
	hdl->cancel_group_create = FALSE;
	hdl->cancel_link_create = FALSE;
	hdl->ap_ready = FALSE;

	hdl->ap_security_applied = FALSE;


	/* Ensure the wireless interface is up */
	if (!p2pwl_isup(wl)) {
		if (p2pwl_up(wl) != 0) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2p_group_create_core:"
				" failed to bring the wireless interface up\n"));
			status = BCMP2P_FAIL_TO_START_SOFT_AP;
			goto group_create_end;
		}
	}

	/* Debug - log various wl driver statuses */
	/* p2pwlu_dbg_show_all_status(hdl); */

	/* Reset the semaphore to wait for client assoc/disassocs */
	p2papi_osl_signal_client_assoc_state(hdl,
		P2PAPI_OSL_CLIENT_ASSOC_STATE_START);

	/* Create the soft AP connection BSSCFG but do not bring it up yet */
	hdl->is_ap = TRUE;
	if (p2papi_softap_enable(hdl, (wps_mode == BRCM_WPS_PWD_TYPE_PBC)) != 0) {
		hdl->is_ap = FALSE;
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2p_group_create_core: softap_enable failed\n"));
		status = BCMP2P_FAIL_TO_START_SOFT_AP;
		goto group_create_end;
	}

	/* Setting hdl->is_p2p_group to true tells our Group Owner Negotiation code
	 * to set our Group Owner Intent to 15 in subsequent GO negotiations.
	 * This ensures the negotiation will result in us being the group owner.
	 */
	if (hdl->enable_p2p) {
		hdl->is_p2p_group = TRUE;
		hdl->intent = 15;
	}

#ifdef SOFTAP_ONLY
	/* Set beacon interval */
	if (hdl->ap_config.BeaconInterval)
		p2papi_ioctl_set(hdl, WLC_SET_BCNPRD, &hdl->ap_config.BeaconInterval,
			sizeof(uint32), 0);

	/* Set DTIM */
	if (hdl->ap_config.Dtim)
		p2papi_ioctl_set(hdl, WLC_SET_DTIMPRD, &hdl->ap_config.Dtim,
			sizeof(uint32), 0);

	/* Set Tx power */
	if (hdl->ap_config.TxPower) {
		int val = (int)hdl->ap_config.TxPower;
		p2papi_iovar_integer_set(hdl, "qtxpower",  val);
	}

	/* Set RateSet */
	if (hdl->ap_config.RateSet.count)
		p2papi_ioctl_set(hdl, WLC_SET_RATESET, &hdl->ap_config.RateSet,
			sizeof(BCMP2P_RATESET), 0);

	/* Set plcp header */
	if (hdl->ap_config.PlcpShort) {
		int val = WLC_PLCP_SHORT;
		p2papi_ioctl_set(hdl, WLC_SET_PLCPHDR, &val, sizeof(uint32), 0);
	}
#endif /* SOFTAP_ONLY */

	/* Set intra-bss distribution */
	p2papi_iovar_integer_set(hdl, "ap_isolate", hdl->is_intra_bss ? 0 : 1);

	/* Apply security if it has not already been applied.  Doing this
	 * requires bringing down the bss which will disconnect existing
	 * associated STAs.  We want to make sure we do not reapply security
	 * if this is an existing p2p group with associated clients.
	 */
	if (!hdl->ap_security_applied) {
		/* Bring down the AP mode connection BSSCFG if it is up.
		 * Apply the AP security settings to the BSSCFG.
		 */
		if (p2pwlu_bss_isup(hdl)) {
			(void) p2pwlu_bss(hdl, FALSE);
		}
		if (hdl->enable_p2p) {
			passphrase_to_pmk(hdl->passphrase, strlen(hdl->passphrase),
				(unsigned char *)hdl->credentials.ssid,
				strlen(hdl->credentials.ssid),
				hdl->credentials.nwKey);
		}
		p2papi_osl_apply_ap_security(hdl, hdl->credentials.ssid,
			hdl->credentials.authType, hdl->credentials.encrType,
			hdl->credentials.nwKey, hdl->credentials.wepIndex);
		hdl->ap_security_applied = TRUE;
	}

	/* Add the P2P IE to our beacons and probe responses.  This is
	 * needed for clients associations to succeed using the P2P BSS.
	 */
	hdl->is_provisioning = open_wps_window;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2p_group_create_core: is_prov=%d\n", hdl->is_provisioning));
	if (hdl->enable_p2p) {
		if (hdl->persistent_grp)
			hdl->in_persist_grp = TRUE;

		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2p_group_create_core: add connection bsscfg IEs\n"));
		p2papi_update_p2p_wps_ies(hdl, P2PAPI_BSSCFG_CONNECTION);
	}

	/* Bring up the connection BSSCFG. */
	(void) p2pwlu_bss(hdl, TRUE);
	if (!p2pwlu_bss_isup(hdl))
	{
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2p_group_create_core: failed to bring up the AP mode BSS\n"));
		status = BCMP2P_FAIL_TO_START_SOFT_AP;
		goto group_create_end;
	}

	/* Set the AP mode network interface's static IP address.
	 * Note: in Windows this call will fail if done before the BSS is up.
	 */
	if (!p2papi_set_ap_ipaddr(hdl)) {
		status = BCMP2P_FAILED_TO_SET_AP_IPADDR;
		goto group_create_end;
	}

	/* Notify the application that the AP BSSCFG is up */
	p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_CREATE_LINK,
		BCMP2P_NOTIF_SOFTAP_START);

	hdl->ap_ready = TRUE;

#if P2PAPI_ENABLE_DHCPD
	/* Enable our DHCP server if requested */
	if (hdl->enable_dhcp) {
		/* Enable the DHCP server */
		if (p2papi_dhcp_enable(hdl, TRUE) != BCMP2P_SUCCESS) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2p_group_create_core: failed to enable DHCP\n"));
			status = BCMP2P_FAIL_TO_START_SOFT_AP;
			/* status = BCMP2P_FAIL_TO_ENABLE_DHCP */
			goto group_create_end;
		}
	} else {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2p_group_create_core: DHCP server not required\n"));
	}
#endif /* P2PAPI_ENABLE_DHCPD */

#if P2PAPI_ENABLE_WPS
	if (hdl->use_wps) {

		/* We only use WPS v2 in P2P Mode */
		if (hdl->enable_p2p)
			p2papi_set_wps_use_ver_1(FALSE);

		/* Start the WPS registrar manager */
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2p_group_create_core: start wpsreg_mgr\n"));
		hdl->is_wpsreg_mgr_running = FALSE;

		/* Initialize WPS registrar. */
		p2papi_start_wpsreg_mgr(hdl);

		if (open_wps_window) {
			/* Open WPS window */
			p2papi_open_wpsreg_window(hdl, hdl->wps_auto_close_secs);
		}
	}
#endif /* P2PAPI_ENABLE_WPS */

#ifndef SOFTAP_ONLY
	/* Create an idle discovery BSSCFG so that the GO can receive action
	 * frames sent to the GO's Device address.
	 */
	if (!hdl->use_same_int_dev_addrs && hdl->enable_p2p) {
		if (!hdl->is_p2p_discovery_on) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2p_group_create_core: create discovery bsscfg for AF rx\n"));
			p2papi_enable_discovery(hdl);
		}
	}
#endif /* not SOFTAP_ONLY */

	hdl->is_wps_enrolling = FALSE;
	hdl->is_wps_enrolling_old = hdl->is_wps_enrolling;
	p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_CREATE_LINK,
		BCMP2P_NOTIF_SOFTAP_READY);

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2p_group_create_core: is_ap=%d ap_ready=%d ena_p2p=%d\n",
		hdl->is_ap, hdl->ap_ready, hdl->enable_p2p));


	/* Repeat: wait for a STA to connect to our soft AP and then start
	 * our WPS registrar.  The actions in this loop are similar to the ones
	 * in p2papi_continue_link_create().
	 */
	i = 0;
	do {
		++i;
		BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
			"----------------------------- p2p_group_create_core: loop %d\n", i));

		/* Wait for a STA to associate to our BSS */
		new_sta_joined = p2papi_bss_wait_for_join(hdl, hdl->join_timeout_secs,
#if P2PAPI_ENABLE_WPS
			FALSE,
#else
			TRUE,
#endif /* P2PAPI_ENABLE_WPS */
			p2papi_proc_sta_assoc, p2papi_proc_sta_disassoc, &new_sta_mac);

		if (hdl->cancel_group_create) {
			BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
				"p2papi_group_create_core: cancelled\n"));
			break;
		}

		/* If no STA has associated, skip to the next loop iteration */
		if (!new_sta_joined) {
			BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
				"p2papi_group_create_core: no new STA joined\n"));
			goto loop_next;
		}

		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2p_group_create_core: STA join: %02x:%02x:%02x:%02x:%02x:%02x\n",
			new_sta_mac.octet[0], new_sta_mac.octet[1],
			new_sta_mac.octet[2], new_sta_mac.octet[3],
			new_sta_mac.octet[4], new_sta_mac.octet[5]));

#if P2PAPI_ENABLE_WPS
		/* Determine if this STA join is the secured join resulting from a
		 * successful WPS enrollment in the previous iteration of this loop.
		 * (If so, do not run the WPS registrar to enroll this STA.)
		 */
		if (hdl->use_wps && hdl->enable_p2p) {
			/* If this is a secured P2P join after a successful WPS enroll,
			 *   Notify the app that the link creation is complete.
			 * else
			 *   A WPS enrollee has joined to our AP.
			 */
			p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_CREATE_LINK,
				BCMP2P_NOTIF_CREATE_LINK_COMPLETE);
		}
		else {
			hdl->is_provisioning = TRUE;
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_group_create_core: is_prov=%d\n",
				hdl->is_provisioning));
		}
#endif /* P2PAPI_ENABLE_WPS */

loop_next:
		/* Delay a bit to prevent any possibility of this loop running without
		 * blocking and hogging the CPU.
		 */
		BCMP2PLOG((BCMP2P_LOG_INFO, TRUE,
			"p2papi_group_create_core: loop iteration delay\n"));
		p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_AP_JOINED_POLL, 500);

	} while (repeat_wps && !hdl->cancel_group_create);

group_create_end:

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_group_create_core: cleanup, cancel=%d status=%d\n",
		hdl->cancel_group_create, status));

#if P2PAPI_ENABLE_WPS
	/* End any WPS registrar enrollment in progress */
	if (brcm_wpscli_softap_is_wps_window_open()) {
		p2papi_close_wpsreg_window(hdl);
	}
	/* Signal the WPS enrollment thread to end */
	p2papi_shutdown_wpsreg_mgr(hdl);
#endif /* P2PAPI_ENABLE_WPS */

	status2 = p2papi_softap_cleanup(hdl);

	/* Check the softAP create status, not the softAP cleanup status */
	if (status != BCMP2P_SUCCESS) {
		p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_CREATE_LINK,
			BCMP2P_NOTIF_SOFTAP_FAIL);
	}

	hdl->is_connecting = FALSE;

	hdl->in_persist_grp = FALSE;

#ifndef SOFTAP_ONLY
	/* Delete the idle discovery BSSCFG previously created for the GO to
	 * receive action frames sent to the GO's Device address.
	 */
	if (!hdl->use_same_int_dev_addrs && hdl->enable_p2p &&
		hdl->is_p2p_discovery_on) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2p_group_create_core: delete device bsscfg\n"));
			p2papi_disable_discovery(hdl);
	} else {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2p_group_create_core: no del dev bsscfg: usid=%d ep=%d ido=%d\n",
			hdl->use_same_int_dev_addrs, hdl->enable_p2p,
			hdl->is_p2p_discovery_on));
	}
#endif /* not SOFTAP_ONLY */

	p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_CREATE_LINK,
		BCMP2P_NOTIF_CREATE_LINK_CANCEL);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_group_create_core: end, ic=%d\n",
		hdl->is_connecting));

	/* return the softAP cleanup status, not the softAP create status */
	return status2;
}

/* Create a P2P Group, acting as the Group Owner. */
BCMP2P_STATUS
p2papi_group_create(p2papi_instance_t* hdl, uint8 *ssid,
	bool bAutoRestartWPS)
{
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2p_group_create: ssid=%s\n", ssid));
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;
	P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl);

	/* If the softAP is already enabled, return an error */
	if (p2papi_is_softap_on(hdl)) {
#ifdef SOFTAP_ONLY
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2p_group_create: softAP already on (connection in progress?)\n"));
		return BCMP2P_SOFTAP_ALREADY_RUNNING;
#else
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2p_group_create: softAP already on, disabling it first.\n"));

		/* Disable the softAP */
		if (p2papi_softap_disable(hdl) != 0) {
			BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
				"p2p_group_create: softap_disable failed!\n"));
		}
		p2papi_reset_state(hdl);
		p2papi_osl_do_notify_cb(hdl, BCMP2P_NOTIF_CREATE_LINK,
			BCMP2P_NOTIF_SOFTAP_STOP);
#endif /* not SOFTAP_ONLY */
	}

	/* If an existing P2P connection is in progress, return an error */
	if (hdl->is_connecting || hdl->is_connected) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
			"p2p_group_create: connection already in progress\n"));
		return BCMP2P_CONNECT_ALREADY_IN_PROGRESS;
	}

#ifndef SOFTAP_ONLY
	/* Delete any existing discovery BSSCFG first.  This is necessary when
	 * - creating a non-P2P softA.  A non-P2P softAP always uses BSSCFG 1.
	 * - creating a P2P Group Owner.  The "p2p_ifadd" iovar will not work when
	 *   driver P2P discovery is active.
	 */
	if (p2papi_is_discovery_enabled(hdl)) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2p_group_create: disabling P2P Discovery first.\n"));
		p2papi_discover_cancel_sync(hdl);
	}
#endif /* not SOFTAP_ONLY */

	/* Some of the functions we call may succeed but with a warning code
	 * stored in hdl->warning.  We are responsible for checking this warning
	 * code before we return and propagating it up to our caller.
	 */
	hdl->warning = BCMP2P_SUCCESS;

	/* Store the group's connection parameters */
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2p_group_create: chan=%d:%d peer_ssid=%s\n",
		hdl->op_channel.channel_class, hdl->op_channel.channel,
		hdl->peer_ssid));
#if P2PAPI_ENABLE_DEBUG_SHOWKEY
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "                  wps_pin=%s\n",
		hdl->ap_config.WPSConfig.wpsPin));
#endif /* P2PAPI_ENABLE_DEBUG_SHOWKEY */
	hdl->join_timeout_secs = 20;

	/* If a "DIRECT-" prefixed ssid was passed in, use this ssid instead of
	 * the random "DIRECT-xy" ssid generated earlier.  This is for the case
	 * if reinvoking a persistent group.
	 */
	if (hdl->enable_p2p) {
		if (memcmp((char*)ssid, "DIRECT-", strlen("DIRECT-")) == 0) {
			strncpy(hdl->credentials.ssid, (char*)ssid,
				sizeof(hdl->credentials.ssid));
			hdl->credentials.ssid[sizeof(hdl->credentials.ssid) - 1] = '\0';
		} else {
			p2papi_generate_go_ssid(hdl, &hdl->credentials);
		}
	}

	return p2papi_group_create_core(hdl, bAutoRestartWPS, FALSE);
}

/* End a P2P Group Owner */
BCMP2P_STATUS
p2papi_group_cancel(p2papi_instance_t* hdl)
{
	BCMP2P_STATUS status = BCMP2P_SUCCESS;
	uint32 sleep_ms;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_group_cancel\n"));
	hdl->cancel_group_create = TRUE;

#if P2PAPI_ENABLE_WPS
	/* SoftAP reset to default to use WPS version 2 */
	if (!hdl->enable_p2p)
	{
		p2papi_set_wps_use_ver_1(FALSE);
		wpscli_softap_construct_def_devinfo();
	}

	/* End any WPS registrar enrollment in progress */
	if (brcm_wpscli_softap_is_wps_window_open()) {
		p2papi_close_wpsreg_window(hdl);
	}
	/* Signal the WPS enrollment thread to end */
	p2papi_shutdown_wpsreg_mgr(hdl);
#endif /* P2PAPI_ENABLE_WPS */

#ifndef SOFTAP_ONLY
	/* Cancel any action frame tx in progress */
	p2papi_cancel_all_aftx_send(hdl);
#endif /* not SOFTAP_ONLY */

	if (hdl->is_connecting || hdl->is_connected) {
		/* Set a flag to tell the p2papi_group_create() group main loop to exit.
		 * Poll for the completion of the exit.
		 */
		hdl->cancel_link_create = TRUE;
#ifndef SOFTAP_ONLY
		p2papi_cancel_send_at_common_channel(hdl);
#endif /* not SOFTAP_ONLY */
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_group_cancel: wait up to %d ms\n",
			hdl->cancel_connect_timeout_ms));
		for (sleep_ms = 0; sleep_ms < hdl->cancel_connect_timeout_ms;
			sleep_ms += 500) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_group_cancel: poll for cancel confirm...\n"));
			if (!hdl->is_connecting)
				break;
			p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_LINK_CREATE_CANCEL_POLL, 500);
		}

		/* if p2papi_group_create() group main loop failed to exit,
		 *   Do the soft AP cleanup actions that would have normally been
		 *   done at the end of p2papi_group_create().
		 */
		if (hdl->is_connecting) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_group_cancel: timed out, AP cleanup not done!\n"));
		} else {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_group_cancel: confirmed\n"));
		}
	}

	hdl->in_persist_grp = FALSE;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_group_cancel: end\n"));
	return status;
}


void
p2papi_open_wpsreg_window(p2papi_instance_t* hdl, int auto_close_secs)
{
#if P2PAPI_ENABLE_WPS
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_open_wpsreg_window: enable_wps=%d\n", hdl->use_wps));
	if (hdl->use_wps) {
		if (brcm_wpscli_softap_is_wps_window_open()) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_open_wpsreg_window: already open\n"));
			return;
		}

			hdl->wps_auto_close_secs = auto_close_secs;
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_open_wpsreg_window: %d secs, isrun=%d\n",
				hdl->wps_auto_close_secs, hdl->is_wpsreg_mgr_running));

		/* Open WPS window. */
		p2papi_do_open_wps_win(hdl);

		} else {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_open_wpsreg_window: ignoring nested request\n"));
		}
#endif /* P2PAPI_ENABLE_WPS */
}

/* Close the WPS registrar window.
 * Parameters:
 * - run_eap_monitor: Set this TRUE unless the WPS window is going to be
 *                    immediately re-opened.
 */
void
p2papi_close_wpsreg_window(p2papi_instance_t* hdl)
{
#if P2PAPI_ENABLE_WPS
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return;
	if (hdl->use_wps) {
		if (!brcm_wpscli_softap_is_wps_window_open()) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2papi_close_wpsreg_window: already closed\n"));
			return;
		}

		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2papi_close_wpsreg_window: brcm_wpscli_abort()\n"));
		(void) brcm_wpscli_abort();
	}
#endif /* P2PAPI_ENABLE_WPS */
}

BCMP2P_BOOL
p2papi_is_wpsreg_window_open(p2papi_instance_t* hdl)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;
	return brcm_wpscli_softap_is_wps_window_open();
}

BCMP2P_STATUS p2papi_set_wps_use_ver_1(bool use_wps_ver_1)
{
	brcm_wpscli_switch_wps_version(use_wps_ver_1);
	return BCMP2P_SUCCESS;
}

BCMP2P_STATUS
p2papi_push_button(p2papi_instance_t *hdl)
{
	p2papi_set_provision(hdl);
	p2papi_set_push_button(hdl, BCMP2P_TRUE);
	return BCMP2P_SUCCESS;
}

static BCMP2P_STATUS
set_push_button(p2papi_instance_t *hdl, BCMP2P_BOOL isPushed)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "set_push_button: old=%d new=%d\n",
		hdl->ap_config.WPSConfig.wpsIsButtonPushed, isPushed));

	if (isPushed)
		hdl->ap_config.WPSConfig.wpsPinMode = FALSE;

	if (hdl->ap_config.WPSConfig.wpsIsButtonPushed != isPushed) {
		hdl->ap_config.WPSConfig.wpsIsButtonPushed = isPushed;

		/* update IEs to reflect pushbutton state */
		if (hdl->enable_p2p) {
			if (hdl->is_p2p_discovery_on) {
				p2papi_update_p2p_wps_ies(hdl, P2PAPI_BSSCFG_DEVICE);
			}
			if (hdl->is_connected || hdl->is_connecting) {
				p2papi_update_p2p_wps_ies(hdl, P2PAPI_BSSCFG_CONNECTION);
			}
		}
	}

	/* restart WPS registrar with updated pbc */
	p2papi_wpsreg_restart(hdl, isPushed);

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"Exit set_push_button(isPushed=%d)\n", isPushed));

	return BCMP2P_SUCCESS;
}

BCMP2P_STATUS
p2papi_stop_pbc_timer(p2papi_instance_t *hdl)
{
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_stop_pbc_timer\n"));

	/* stop pbc timer */
	if (hdl->wps_pbc_timer != NULL) {
		bcmseclib_free_timer(hdl->wps_pbc_timer);
		hdl->wps_pbc_timer = NULL;
	}

	return BCMP2P_SUCCESS;
}

BCMP2P_STATUS
p2papi_start_pbc_timer(p2papi_instance_t *hdl)
{
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2papi_start_pbc_timer\n"));

	/* start pbc timer */
	hdl->wps_pbc_timer = bcmseclib_init_timer_ex(hdl->timer_mgr,
		p2papi_notify_timeout_wps_pbc, hdl, "wps-pbc");
	p2papi_add_timer(hdl, hdl->wps_pbc_timer, P2PAPI_PBC_TIMEOUT * 1000, 0);

	return BCMP2P_SUCCESS;
}

BCMP2P_STATUS
p2papi_set_push_button(p2papi_instance_t *hdl, BCMP2P_BOOL isPushed)
{
	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;

	p2papi_stop_pbc_timer(hdl);

	if (isPushed)
		p2papi_start_pbc_timer(hdl);

	return set_push_button(hdl, isPushed);
}

BCMP2P_BOOL p2papi_is_provision(p2papi_instance_t *hdl)
{
	return hdl->ap_config.WPSConfig.wpsIsProvision;
}

BCMP2P_STATUS p2papi_set_provision(p2papi_instance_t *hdl)
{
	hdl->ap_config.WPSConfig.wpsIsProvision = BCMP2P_TRUE;
	return BCMP2P_SUCCESS;
}

BCMP2P_STATUS p2papi_clear_provision(p2papi_instance_t *hdl)
{
	hdl->ap_config.WPSConfig.wpsIsProvision = BCMP2P_FALSE;
	p2papi_set_push_button(hdl, BCMP2P_FALSE);
	return BCMP2P_SUCCESS;
}

static brcm_wpscli_status
p2papi_process_eapol(p2papi_instance_t *hdl, uint32 event_type, char *buf, int len)
{
	brcm_wpscli_status result = WPS_STATUS_PROTOCOL_CONTINUE;
	int window_is_open;

	/* store to avoid races */
	window_is_open = brcm_wpscli_softap_is_wps_window_open();
	/* pass to wps module  */
	if (hdl->is_wpsreg_mgr_running) {
		if (event_type != WLC_E_EAPOL_MSG) {
			result = brcm_wpscli_softap_process_eapwps(NULL,
			              0, NULL, (uint8 *)&hdl->enrolled_sta_mac);
		}
		else {
			/* this is a trick used by AP to pass on both the original
			 * interface and the source mac address (but why didn't we
			 * pass the entire EAPOL packet ??)
			 */
			/* we should pass the whole event , but now ... */
			wl_event_msg_t *event = (wl_event_msg_t *)(buf - sizeof(wl_event_msg_t));

			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			           "%s passing to WPS module\n", __FUNCTION__));
			result = brcm_wpscli_softap_process_eapwps(buf, len,
			            (uint8 *)&event->addr, (uint8 *)&hdl->enrolled_sta_mac);
			/* Close window if the window was open and the registration finished */
			if (result != WPS_STATUS_PROTOCOL_CONTINUE && window_is_open) {
				p2papi_do_close_wps_win(hdl, result);
			}
		}
		return result;
	}
	return (WPS_STATUS_SUCCESS);
}

/* WPS PBC timer callback. */
static void
p2papi_notify_timeout_wps_pbc(void *arg)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) arg;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2papi_notify_timeout_wps_pbc: clearing pbc\n"));

	/* clear pbc */
	set_push_button(hdl, BCMP2P_FALSE);
}

/* WPS registrar periodic timer callback. */
static void
p2papi_notify_timeout_wps_reg(void *arg)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) arg;


	/* Process WPS registrar timeout. */
	p2papi_process_eapol(hdl, 0, NULL, 0);
}

/* Event handler for group formation. */
void
p2papi_wl_event_handler_formation(p2papi_instance_t *hdl, BCMP2P_BOOL is_primary,
                                wl_event_msg_t *event, void* data, uint32 data_len)
{
}

/* Event handler for group operational phase. */
void
p2papi_wl_event_handler_connect(p2papi_instance_t *hdl, BCMP2P_BOOL is_primary,
                                wl_event_msg_t *event, void* data, uint32 data_len)
{
	if (hdl->is_ap && !is_primary) {
		if (event && event->event_type == WLC_E_EAPOL_MSG) {
			p2papi_process_eapol(hdl, event->event_type, (char *)data, data_len);
		}
	}
}
