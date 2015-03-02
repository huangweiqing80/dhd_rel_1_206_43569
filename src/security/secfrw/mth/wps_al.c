/*
 * wps_al.c
 * WPS adaptation layer
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wps_al.c,v 1.1 2010-08-09 19:29:00 $
*/


#include <string.h>

#include <wpscli_osl.h>
#include <wpsclic.h>
#include <wpserror.h>
#include <proto/ethernet.h>
#include <proto/eapol.h>

#include <typedefs.h>			/* wpscli_osl.h first!!! */
#include <bcmendian.h>
#include <bcmutils.h>			/* BCME_XXX */
#include <bcmendian.h>
#include <debug.h>
#include <bcmseclib_timer.h>
#include <bcm_osl.h>			/* for bcm_lbuf.h */
#include <bcm_lbuf.h>			/* PKTXXX */
#include <bind_skp.h>
#define WPS_CFG_PRIVATE
#include <wps_al.h>

#include <wlss.h>				/* wlss_get_cur_etheraddr */
#include <wlssev.h>
#include <wlsstypes.h>
#include <l2.h>
#include <wps_cfg.h>			/* for shared cfg */

#include <bcmseclib_wps.h>

#define wps_sup_is_null_session(dat) ((dat)->is_session ? 0 : 1)
#define wps_auth_is_null_session(dat) ((dat)->is_session ? 0 : 1)

static void
wps_sup_session_start(struct wps_dat *dat);

static void
wps_auth_session_start(struct wps_dat *dat);

static void
wps_sup_session_end(struct wps_dat *dat);

static void
wps_auth_session_end(struct wps_dat *dat);

static void
wps_sup_stop(struct wps_dat *dat);

static void
wps_sup_status_hdlr(struct wps_dat *dat, brcm_wpscli_status status);

static brcm_wpscli_status
wps_sup_start(struct wps_dat *dat, const uint8 *peer_mac_addr);

static void
wps_sup_stop(struct wps_dat *dat);

static int
wps_sup_cleanup(struct wps_dat *dat);

static void
wps_notify(struct wps_dat *dat, const struct bcmseclib_ev_wps *ev);

static void
wps_recv_msg_cb(void *arg, char msg_type);

/*
 * wpscli osl
*/

static struct wpscli_osl_info {
	unsigned long now;	/* seconds */
	struct wps_dat *dat;
} s_osl;

void
wpsclich_rand_init(void)
{
	extern void RAND_init(void);
	RAND_init();
}

uint16
wpsclich_htons(uint16 v)
{
	return hton16(v);
}

uint32
wpsclich_htonl(uint32 v)
{
	return hton32(v);
}

uint16
wpsclich_ntohs(uint16 v)
{
	return ntoh16(v);
}

uint32
wpsclich_ntohl(uint32 v)
{
	return ntoh32(v);
}

brcm_wpscli_status
wpsclich_pktdisp_send_packet(char *data, uint32 data_len)
{
	struct cfg_ctx *ctx = wps_get_ctx(s_osl.dat);
	int err;
	brcm_wpscli_status status;
	void *p;

	CTXPRT((ctx, "-> wpscli_pktdisp_send_packet\n"));

	/* alloc pkt buffer */
	p = PKTGET(NULL, data_len, TRUE);
	if (NULL == p) {
		CTXERR((ctx, "no memory\n"));
		status = WPS_STATUS_NOT_ENOUGH_MEMORY;
		goto DONE;
	}

	/* copy data into pkt buffer */
	memcpy(PKTDATA(NULL, p), data, data_len);
	
	/* transmit frame */
	err = l2_tx(ctx, p, PKTLEN(NULL, p));
	if (err) {
		CTXERR((ctx, "l2_tx failed with %d\n", err));
		status = WPS_STATUS_PROTOCOL_SEND_MEG;
		goto DONE;
	}

	status = WPS_STATUS_SUCCESS;

DONE:
	/* free pkt buffer */
	if (NULL != p)
		PKTFREE(NULL, p, TRUE);

	CTXPRT((ctx, "<- wpscli_pktdisp_send_packet status=%d\n", status));
	return status;
}

unsigned long wpsclich_current_time(void)
{
	return s_osl.now;
}

void wpsclich_sleep(unsigned long millis)
{
	struct cfg_ctx *ctx = wps_get_ctx(s_osl.dat);
	UNUSED_PARAMETER(millis);
	CTXPRT((ctx, "wpscli_sleep stubbed\n"));
}

brcm_wpscli_status wpsclich_set_peer_addr(const uint8 *peer_addr)
{
	struct cfg_ctx *ctx = wps_get_ctx(s_osl.dat);
	UNUSED_PARAMETER(peer_addr);
	CTXPRT((ctx, "wpscli_set_peer_addr stubbed\n"));
	return WPS_STATUS_SUCCESS;
}

typedef int BOOL;

/* taken from wps_wl.h */
#define WPS_IE_TYPE_SET_BEACON_IE		1
#define WPS_IE_TYPE_SET_PROBE_RESPONSE_IE	3

int wpsclich_set_wps_ie(unsigned char *p_data, int length,
						unsigned int cmdtype)
{
	int err;
	unsigned type;
	struct cfg_ctx *ctx = wps_get_ctx(s_osl.dat);

	if (WPS_IE_TYPE_SET_BEACON_IE == cmdtype)
		type = WLSS_WPSIE_FT_BEACON;
	else
	if (WPS_IE_TYPE_SET_PROBE_RESPONSE_IE == cmdtype)
		type = WLSS_WPSIE_FT_PRBRSP;
	else {
		CTXERR((ctx, "wpscli_add_wpsie: unknown frame type %d\n", cmdtype));
		return -1;
	}

	err = wlss_add_wpsie(ctx, p_data, length, type);
	if (err) {
		CTXERR((ctx, "wlss_add_wpsie failed with %d\n", err));
		return -1;
	}

	return 0;
}


int wpsclich_del_wps_ie(unsigned int cmdtype)
{
	int err;
	unsigned type;
	struct cfg_ctx *ctx = wps_get_ctx(s_osl.dat);

	if (WPS_IE_TYPE_SET_BEACON_IE == cmdtype)
		type = WLSS_WPSIE_FT_BEACON;
	else
	if (WPS_IE_TYPE_SET_PROBE_RESPONSE_IE == cmdtype)
		type = WLSS_WPSIE_FT_PRBRSP;
	else {
		CTXERR((ctx, "wpscli_del_wpsie: unknown frame type %d\n", cmdtype));
		return -1;
	}

	err = wlss_del_wpsie(ctx, type);
	if (err) {
		CTXERR((ctx, "wlss_del_wpsie failed with %d\n", err));
		return -1;
	}

	return 0;
}

/*
 * everything else
*/

static void
wps_sup_timeout_hdlr(void *arg)
{
	struct wps_dat *dat = arg;
	brcm_wpscli_status status;
	struct cfg_ctx *ctx = wps_get_ctx(dat);

	CTXPRT((ctx, "wps_sup_timeout_hdlr\n"));

	/* tick */
	s_osl.now++;

	/* process timeout */
	status = wpsclic_process_ticktimer();
	wps_sup_status_hdlr(dat, status);
}

static int
wps_sup_cfg(struct wps_dat *dat)
{
	char *funstr = "wps_sup_cfg";
	struct cfg_ctx *ctx = wps_get_ctx(dat);
	uint8 my_mac_addr[6], peer_mac_addr[6];
	brcm_wpscli_status status = WPS_STATUS_SUCCESS;

	s_osl.dat = dat;
	dat->is_started = 0;
	dat->is_session = 0;

	/* validate cfg */
	if (ETHER_ISNULLADDR(dat->peer_mac_addr)) {
		CTXERR((ctx, "%s: peer_mac_addr not set\n", funstr));
		goto ERROR;
	}

	/* get my mac addr */
	if (wlss_get_cur_etheraddr(ctx, my_mac_addr, 6)) {
		CTXERR((ctx, "%s: failed to get hwaddr\n", funstr));
		goto ERROR;
	}

	/* get peer mac addr */
	if (wlss_get_bssid(ctx, (char *)peer_mac_addr, 6)) {
		CTXPRT((ctx, "%s: wlss_get_bssid failed (continuing)\n", funstr));
		memcpy(peer_mac_addr, &ether_null, 6);
	}

	/* check for peer mac addr agreement */
	if (!ETHER_ISNULLADDR(peer_mac_addr) &&
		0 != memcmp(peer_mac_addr, dat->peer_mac_addr, 6))
	{
		CTXERR((ctx, "%s: peer mac addr mismatch\n", funstr));
		goto ERROR;
	}

	dat->timer = bcmseclib_init_timer(wps_sup_timeout_hdlr, dat,
									  "wps_sup_timeout");
	if (NULL == dat->timer) {
		CTXERR((ctx, "%s: failed to initialize timer\n", funstr));
		goto ERROR;
	}

	wpsclic_set_my_mac_addr(my_mac_addr);

	/* open a wps session */
	wps_sup_session_start(dat);

	/* start wps */
	/* this will tx EAPOL-START until response or timeout */
	status = wps_sup_start(dat, dat->peer_mac_addr);
	if (WPS_STATUS_SUCCESS != status)
		goto ERROR;
		
	return BCME_OK;

ERROR:
	(void)wps_sup_cleanup(dat);

	return BCME_ERROR;
}

static int
wps_sup_cleanup(struct wps_dat *dat)
{
	if (dat->is_started)
		wps_sup_stop(dat);

	if (!wps_sup_is_null_session(dat))
		wps_sup_session_end(dat);
		
	if (NULL != dat->timer) {
		bcmseclib_free_timer(dat->timer);
		dat->timer = NULL;
	}

	return BCME_OK;
}

static bool
wps_sup_is_pbc(const char *pin)
{
	if (8 != strlen(pin))
		return FALSE;
	return strcmp(pin, "00000000") == 0 ? TRUE : FALSE;
}

static brcm_wpscli_status
wps_sup_start(struct wps_dat *dat, const uint8 *peer_mac_addr)
{
	brcm_wpscli_status status;
	char *pin;
	struct cfg_ctx *ctx = wps_get_ctx(dat);

	CTXPRT((ctx, "-> wps_sup_start\n"));
	
	if (dat->is_started) {
		CTXPRT((ctx, "wps_sup_start: restarting\n"));
		wps_sup_stop(dat);
	}

	/* pbc mode? */
	pin = wps_sup_is_pbc(dat->pin) ? NULL : dat->pin;
	if (NULL == pin)
		CTXPRT((ctx, "PBC mode\n"));

	/* start wps */
	status = wpsclic_sta_start_enroll_device(peer_mac_addr, pin);
	if (WPS_STATUS_SUCCESS == status)
		dat->is_started = 1;

	CTXPRT((ctx, "<- wps_sup_start (%d)\n", status));
	return status;
}

static void
wps_sup_stop(struct wps_dat *dat)
{
	if (0 == dat->is_started)
		return;
	wpsclic_sta_cleanup();
	dat->is_started = 0;
}

static void
wps_notify(struct wps_dat *dat, const struct bcmseclib_ev_wps *ev)
{
	struct cfg_ctx *ctx = wps_get_ctx(dat);

	if (NULL == dat->cb || NULL == dat->cb->result)
		return;

	(*dat->cb->result)(ctx, ev);
}

static void
wps_recv_msg_cb(void *arg, char msg_type)
{
	struct wps_dat *dat = arg;
	struct bcmseclib_ev_wps ev;

	ev.status = WPS_STATUS_PROTOCOL_RECV_MSG;
	ev.u.msg_type = msg_type;
	
	wps_notify(dat, &ev);
}

static void
wps_sup_session_start(struct wps_dat *dat)
{
	/* start tick timer */
	s_osl.now = 0;
	bcmseclib_add_timer(dat->timer, 1000, TRUE);

	/* start wps session */
	(void)wpsclic_sta_session_start(120, dat->peer_mac_addr);

	dat->is_session = 1;
}

static void
wps_auth_session_start(struct wps_dat *dat)
{
	/* start tick timer */
	s_osl.now = 0;
	bcmseclib_add_timer(dat->timer, 1000, TRUE);

	/* start wps session */
	wpsclic_softap_session_start(120);
	
	dat->is_session = 1;
}

static void
wps_sup_session_end(struct wps_dat *dat)
{
	bcmseclib_del_timer(dat->timer);
	dat->is_session = 0;
}

static void
wps_auth_session_end(struct wps_dat *dat)
{
	bcmseclib_del_timer(dat->timer);
	dat->is_session = 0;
}

static void
wps_sup_status_hdlr(struct wps_dat *dat, brcm_wpscli_status status)
{
	struct cfg_ctx *ctx = wps_get_ctx(dat);
	struct bcmseclib_ev_wps ev;

	CTXPRT((ctx, "wps_sup_status_hndlr status=%d\n", status));

	/* nothing to do */
	if (WPS_STATUS_SUCCESS == status)
		goto DONE;

	if (WPS_STATUS_PROTOCOL_CONTINUE == status) {
		/* restart */
		CTXPRT((ctx, "reconnect required to continue registration " \
			"protocol\n"));
		wps_sup_start(dat, dat->peer_mac_addr);
		goto DONE;
	}

	/* all other statuses require us to stop */

	ev.status = status;

	if (WPS_STATUS_PROTOCOL_SUCCESS == status) {
		wpsclic_sta_get_network_settings(dat->ssid, dat->ssid_len,
										 &ev.u.nw_settings);
		CTXPRT((ctx, "Registration protocol completed successfully!\n"));
		CTXPRT((ctx, "Provisioned data available.  ssid=%s\n", \
				ev.u.nw_settings.ssid));
	}
	else
	if (WPS_STATUS_PROTOCOL_FAIL_TIMEOUT == status) {
		CTXPRT((ctx, "protocol timed-out\n"));
	}

	wps_sup_stop(dat);
	wps_sup_session_end(dat);
	wps_notify(dat, &ev);

DONE:
	return;
}

int
wps_sup_eapol_hdlr(void *arg, void *pkt, int len)
{
	struct wps_dat *dat = arg;
	struct cfg_ctx *ctx = wps_get_ctx(dat);
	brcm_wpscli_status status;

	CTXPRT((ctx, "wps_sup_eapol_hdlr\n"));

	/* ignore traffic if we're not running */
	if (0 == dat->is_started) {
		CTXPRT((ctx, "wps_sup_eapol_hdlr: ignoring traffic\n"));
		goto DONE;
	}
	
	/* process EAP traffic */
	status = wpsclic_sta_process_eapol(((struct ether_header *)pkt)+1,
									   len-sizeof(struct ether_header));
	wps_sup_status_hdlr(dat, status);

DONE:
	return 0;
}

int
wps_sup_handle_event(void *arg, void *pevt, int len)
{
	struct wps_dat *dat = arg;
	struct cfg_ctx *ctx = wps_get_ctx(dat);
	brcm_wpscli_status status;

	UNUSED_PARAMETER(len);

	switch (ntoh32((SECLIB_BCM_EVENT_TYPE(pevt))))
	{
	case WLC_E_LINK:
		/* only handle link-up */
		if (!SECLIB_BCM_EVENT_FLAG_LINK_UP(pevt)) {
			wps_sup_stop(dat);
			goto DONE;
		}

		CTXPRT((ctx, "wps_sup_handle_event\n"));

		/* (re-)start the registration protocol */
		status = wps_sup_start(dat, (uint8 *)SECLIB_BCM_EVENT_ADDR(pevt));
		wps_sup_status_hdlr(dat, status);

		break;
	}

DONE:
	return 0;
}

int
wps_sup_enr_cfg(struct wps_dat *dat)
{
	return wps_sup_cfg(dat);
}

int
wps_sup_enr_cleanup(struct wps_dat *dat)
{
	return wps_sup_cleanup(dat);
}

void
wps_auth_stop(struct wps_dat *dat)
{
	wpsclic_softap_cleanup();
	dat->is_started = 0;
}

static void
wps_auth_status_hdlr(struct wps_dat *dat, brcm_wpscli_status status)
{
	struct cfg_ctx *ctx = wps_get_ctx(dat);
	struct bcmseclib_ev_wps ev;

	CTXPRT((ctx, "-> wps_auth_status_hndlr\n"));

	/* nothing to do */
	if (WPS_STATUS_SUCCESS == status)
		goto DONE;

	ev.status = status;

	if (WPS_STATUS_PROTOCOL_START_EXCHANGE == status) {
		memcpy(ev.u.peer_mac_addr, wpsclic_get_peer_mac_addr(), 6);
		wps_notify(dat, &ev);
		goto DONE;
	}

	/* stop on everything else */

	wps_notify(dat, &ev);

	wps_auth_stop(dat);
	wps_auth_session_end(dat);

DONE:
	CTXPRT((ctx, "<- wps_auth_status_hndlr (%d)\n", status));
	return;
}

static void
wps_auth_timeout_hdlr(void *arg)
{
	struct wps_dat *dat = arg;
	brcm_wpscli_status status;

	/* tick */
	s_osl.now++;

	/* process timeout */
	status = wpsclic_process_ticktimer();
	wps_auth_status_hdlr(dat, status);
}

int
wps_auth_eapol_hdlr(void *arg, void *pkt, int len)
{
	struct wps_dat *dat = arg;
	struct cfg_ctx *ctx = wps_get_ctx(dat);
	brcm_wpscli_status status;

	CTXPRT((ctx, "-> wps_auth_eapol_hdlr\n"));

	if (0 == dat->is_started) {
		CTXPRT((ctx, "dropping traffic: not started\n"));
		goto DONE;
	}

	/* process EAPOL traffic */
	status = wpsclic_softap_process_eapol(pkt, len);
	wps_auth_status_hdlr(dat, status);

DONE:
	CTXPRT((ctx, "<- wps_auth_eapol_hdlr\n"));
	return 0;
}

int
wps_auth_handle_event(void *arg, void *pevt, int len)
{
	UNUSED_PARAMETER(arg);
	UNUSED_PARAMETER(pevt);
	UNUSED_PARAMETER(len);
	return 0;
}

int
wps_auth_cfg(struct wps_dat *dat)
{
	brcm_wpscli_status status;
	int ret = BCME_ERROR;
	struct cfg_ctx *ctx = wps_get_ctx(dat);
	uint8 my_mac_addr[6];
	brcm_wpscli_pwd_type pwd_type;
	brcm_wpscli_nw_settings nw_settings;

	s_osl.dat = dat;
	dat->is_started = 0;
	dat->is_session = 0;
	
	if (wlss_get_cur_etheraddr(ctx, my_mac_addr, 6)) {
		CTXERR((ctx, "failed to get hwaddr\n"));
		goto DONE;
	}

	dat->timer = bcmseclib_init_timer(wps_auth_timeout_hdlr, dat,
									  "wps_auth_timeout");
	if (NULL == dat->timer) {
		CTXERR((ctx, "failed to initialize timer\n"));
		goto DONE;
	}

	wpsclic_set_my_mac_addr(my_mac_addr);
	wpsclic_sta_set_recv_msg_cb(dat, wps_recv_msg_cb);

	if (wps_sup_is_pbc(dat->pin)) {
		CTXPRT((ctx, "PBC mode\n"));
		pwd_type = BRCM_WPS_PWD_TYPE_PBC;
	}
	else {
		pwd_type = BRCM_WPS_PWD_TYPE_PIN;
	}

	/* copy nw configuration settings */
	memcpy(nw_settings.ssid, dat->ssid, 32);
	nw_settings.ssid[dat->ssid_len] = '\0';
	memcpy(nw_settings.nwKey, dat->nw_key, 64+1);
	nw_settings.authType = dat->auth_type;
	nw_settings.encrType = dat->encr_type;
	nw_settings.wepIndex = dat->wep_index;
	
	wps_auth_session_start(dat);

	status = wpsclic_softap_reg_cfg(BRCM_WPS_MODE_STA_ENR_JOIN_NW, pwd_type,
								    dat->pin, &nw_settings);
	if (WPS_STATUS_SUCCESS != status) {
		CTXERR((ctx, "wpsclic_softap_reg_cfg failed with %d\n", status));
		wps_auth_session_end(dat);
		goto DONE;
	}

	dat->is_started = 1;
	ret = BCME_OK;

DONE:
	if (BCME_OK != ret)
		wps_auth_cleanup(dat);

	return ret;
}

int
wps_auth_cleanup(struct wps_dat *dat)
{
	if (dat->is_started)
		wps_auth_stop(dat);

	if (!wps_auth_is_null_session(dat))
		wps_auth_session_end(dat);

	if (NULL != dat->timer) {
		bcmseclib_free_timer(dat->timer);
		dat->timer = NULL;
	}

	return BCME_OK;
}

void
wps_cbs(struct wps_dat *dat, const struct wps_cbs *cbs)
{
	dat->cb = cbs;
}

void
wps_set_eapol_tx(struct wps_dat *dat, void *path)
{
	dat->eapol_tx = path;
}

struct cfg_ctx *
wps_get_ctx(struct wps_dat *dat)
{
	return dat->ctx;
}

void
wps_set_ctx(struct wps_dat *dat, struct cfg_ctx *ctx)
{
	dat->ctx = ctx;
}
