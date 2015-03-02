/*
 * Broadcom 802.11 device interface
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: hal.c,v 1.7 2010-12-11 00:06:35 $
 */

#include <stdio.h>
#include <typedefs.h>
#include <string.h>

#include <bcmutils.h>
#include <wlutils.h>
#include <wlioctl.h>

#include <bcmwpa.h>
#include <debug.h>
#include <bcm_osl.h>
#include <bcm_lbuf.h>

#include <hal.h>

#include <wlsstypes.h>

int
hal_get_event_mask(char *ifname, int bsscfg_index, unsigned char *buf,
		int length)
{
	return wl_iovar_get(ifname, "event_msgs", buf, length);
}

int
hal_set_event_mask(char *ifname, int bsscfg_index, unsigned char *buf,
		int length)
{
	return wl_iovar_set(ifname, "event_msgs", buf, length);
}

int
hal_get_assoc_info(char *ifname, int bsscfg_index, unsigned char *buf,
	int length)
{
	return wl_bssiovar_get(ifname, "assoc_info", bsscfg_index, buf, length);
}

int
hal_get_assoc_req_ies(char *ifname, int bsscfg_index, unsigned char *buf, int length)
{
	return wl_bssiovar_get(ifname, "assoc_req_ies", bsscfg_index, buf, length);
}

int
hal_get_assoc_resp_ies(char *ifname, int bsscfg_index, unsigned char *buf, int length)
{
	return wl_bssiovar_get(ifname, "assoc_resp_ies", bsscfg_index, buf, length);
}

int
hal_get_key_seq(char *ifname, void *buf, int buflen)
{
	return wl_ioctl(ifname, WLC_GET_KEY_SEQ, buf, buflen);
}
int
hal_authorize(char *ifname, int bsscfg_index, struct ether_addr *ea)
{
	authops_t args;

	args.code = WLC_SCB_AUTHORIZE;
	args.ioctl_args.val = 0;
	memcpy(&args.ioctl_args.ea, ea, sizeof(struct ether_addr));
	return wl_bssiovar_set(ifname, "auth_ops", bsscfg_index, &args, sizeof(args));
}

int
hal_deauthorize(char *ifname, int bsscfg_index, struct ether_addr *ea)
{
	authops_t args;

	args.code = WLC_SCB_DEAUTHORIZE;
	args.ioctl_args.val = 0;
	memcpy(&args.ioctl_args.ea, ea, sizeof(struct ether_addr));
	return wl_bssiovar_set(ifname, "auth_ops", bsscfg_index, &args, sizeof(args));
}

int
hal_deauthenticate(char *ifname, int bsscfg_index, struct ether_addr *ea, int reason)
{
	authops_t args;

	args.code = WLC_SCB_DEAUTHENTICATE_FOR_REASON;
	args.ioctl_args.val = reason;
	memcpy(&args.ioctl_args.ea, ea, sizeof(struct ether_addr));

	/* remove the key if one is installed */
	hal_plumb_ptk(ifname, bsscfg_index, ea, NULL, 0, 0);

	return wl_bssiovar_set(ifname, "auth_ops", bsscfg_index, &args, sizeof(args));
}

int
hal_get_group_rsc(char *ifname, uint8 *buf, int index)
{
	union {
		int index;
		uint8 rsc[EAPOL_WPA_KEY_RSC_LEN];
	} u;

	u.index = index;
	if (wl_ioctl(ifname, WLC_GET_KEY_SEQ, &u, sizeof(u)) != 0)
		return -1;

	bcopy(u.rsc, buf, EAPOL_WPA_KEY_RSC_LEN);

	return 0;
}

int
hal_plumb_ptk(char *ifname, int bsscfg_index, struct ether_addr *ea, uint8 *tk, int tk_len, int cipher)
{
	wl_wsec_key_t key;

	PRINT(("hal_plumb_ptk:\n"));

	bzero((char*)&key, sizeof(key));
	key.len = tk_len;
	bcopy(tk, (char*)key.data, key.len);
	bcopy((char*)ea, (char*)&key.ea, ETHER_ADDR_LEN);
	/* NB: wlc_insert_key() will re-infer key.algo from key_len */
	key.algo = cipher;
	key.flags = WL_PRIMARY_KEY;

	return wl_bssiovar_set(ifname, "wsec_key", bsscfg_index, &key, sizeof(key));
}

void
hal_plumb_gtk(char *ifname, int bsscfg_index, uint8 *gtk, uint32 gtk_len,
	uint32 key_index, uint32 cipher, uint16 rsc_lo, uint32 rsc_hi, bool primary_key)
{
	wl_wsec_key_t key;

	bzero((char *)&key, sizeof(key));
	key.index = key_index;
	/* NB: wlc_insert_key() will re-infer key.algo from key_len */
	key.algo = cipher;
	key.len = gtk_len;
	bcopy(gtk, key.data, key.len);

	if (primary_key)
		key.flags |= WL_PRIMARY_KEY;


	key.iv_initialized = 1;
	key.rxiv.lo = rsc_lo;
	key.rxiv.hi = rsc_hi;

	PRINT(("hal_plumb_gtk: key.len %d key.algo %d \n",
			key.len, key.algo));
	PRINT(("hal_plumb_gtk: key data\n"));
	prhex(NULL, key.data, key.len);

	PRINT(("key->rxiv.lo 0x%x key->rxiv.hi 0x%x\n",
			key.rxiv.lo, key.rxiv.hi));


	wl_bssiovar_set(ifname, "wsec_key", bsscfg_index, &key, sizeof(key));
}

int
hal_wl_tkip_countermeasures(char *ifname, int enable)
{
	return wl_ioctl(ifname, WLC_TKIP_COUNTERMEASURES, &enable, sizeof(int));
}

int
hal_set_ssid(char *ifname, char *ssid)
{
	wlc_ssid_t wl_ssid;

	strncpy((char *)wl_ssid.SSID, ssid, sizeof(wl_ssid.SSID));
	wl_ssid.SSID_len = strlen(ssid);
	return wl_ioctl(ifname, WLC_SET_SSID, &wl_ssid, sizeof(wl_ssid));
}

int
hal_disassoc(char *ifname)
{
	return wl_ioctl(ifname, WLC_DISASSOC, NULL, 0);
}

/* get WPA capabilities */
int
hal_get_wpacap(char *ifname, uint8 *cap)
{
	int err;
	int cap_val;

	err = wl_iovar_getint(ifname, "wpa_cap", &cap_val);
	if (!err) {
		cap[0] = (cap_val & 0xff);
		cap[1] = ((cap_val >> 8) & 0xff);
	}

	return err;
}
/* get STA info */
int
hal_get_stainfo(char *ifname, char *macaddr, int len, char *ret_buf, int ret_buf_len)
{
	char *tmp_ptr;
	tmp_ptr = ret_buf;
	strcpy(ret_buf, "sta_info");
	tmp_ptr += strlen(ret_buf);
	tmp_ptr++;
	memcpy(tmp_ptr, macaddr, len);

	return wl_ioctl(ifname, WLC_GET_VAR, ret_buf, ret_buf_len);
}

/* All PKT's arriving here should have 170 bytes - etherheader (or ether snap)
 * of headroom
 */
int
hal_send_frame(char *ifname, int bsscfg_index, void *pkt, int len)
{
	return wl_bssiovar_set(ifname, "send_frame", bsscfg_index, pkt, len);
}

int
hal_get_bssid(char *ifname, int bsscfg_index, char *ret_buf, int ret_buf_len)
{
	return wl_bssiovar_get(ifname, "bssid", bsscfg_index, ret_buf, ret_buf_len);
}

int
hal_get_cur_etheraddr(char *ifname, int bsscfg_index, uint8 *ret_buf,
	int ret_buf_len)
{
	return wl_bssiovar_get(ifname, "cur_etheraddr", bsscfg_index, ret_buf, ret_buf_len);
}

int
hal_get_wpaie(char *ifname, int bsscfg_index, uint8 *ret_buf, int ret_buf_len,
		struct ether_addr *ea)
{
	return wl_bssiovar_getbuf(ifname, "wpaie", bsscfg_index, ea->octet,
			ETHER_ADDR_LEN, ret_buf, ret_buf_len);
}

int
hal_get_btampkey(char *ifname, struct ether_addr *ea, char *ret_buf, int ret_buf_len)
{
	char *tmp_ptr;

	tmp_ptr = ret_buf;
	strcpy(ret_buf, "btamp_key");
	tmp_ptr += strlen(ret_buf);
	tmp_ptr++;
	memcpy(tmp_ptr, ea->octet, ETHER_ADDR_LEN);

	return wl_ioctl(ifname, WLC_GET_VAR, ret_buf, ret_buf_len);
}

static const unsigned char HAL_WPS_OUI[] = { 0x00,0x50,0xf2,0x04 };

static int
hal_wpsie_op(char *ifname, int bsscfg_index, const char op[], void *ie,
			 int ie_len, uint32 pktflag)
{
	int err, buflen;
	vndr_ie_setbuf_t *ie_setbuf = NULL;

	/* alloc iovar buffer */
	buflen = sizeof(vndr_ie_setbuf_t) + ie_len;
	ie_setbuf = malloc(buflen);
	if (NULL == ie_setbuf) {
		err = BCME_NOMEM;
		goto DONE;
	}
	memset(ie_setbuf, 0, buflen);

	/* Copy the vndr_ie SET command ("add"/"del") to the buffer */
	strcpy(ie_setbuf->cmd, op);

	/* Buffer contains only 1 IE */
	{
	const int iecount = 1;
	memcpy(&ie_setbuf->vndr_ie_buffer.iecount, &iecount, sizeof iecount);
	}

	/* set pktflag */
	memcpy(&ie_setbuf->vndr_ie_buffer.vndr_ie_list[0].pktflag, &pktflag,
		   sizeof pktflag);

	/* set length */
	ie_setbuf->vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data.len =
		(uint8)ie_len + VNDR_IE_MIN_LEN + 1;

	/* set OUI (4-bytes!) */
	memcpy(ie_setbuf->vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data.oui,
		   HAL_WPS_OUI, 4);

	/* copy ie data (after 4-byte OUI!) */
	memcpy(ie_setbuf->vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data.data+1,
		   ie, ie_len);

	/* set */
	err =  wl_bssiovar_set(ifname, "vndr_ie", bsscfg_index, ie_setbuf, buflen);

DONE:
	if (NULL != ie_setbuf)
		free(ie_setbuf);

	return err;
}

int
hal_add_wpsie(char *ifname, int bsscfg_index, void *ie, int ie_len,
			  unsigned type)
{
	int err;
	uint32 pktflag;

	/* validate args */
	if (NULL == ie || 1 > ie_len) {
		err = BCME_BADARG;
		goto DONE;
	}

	if (WLSS_WPSIE_FT_BEACON == type)
		pktflag = VNDR_IE_BEACON_FLAG;
	else
	if (WLSS_WPSIE_FT_PRBRSP == type)
		pktflag = VNDR_IE_PRBRSP_FLAG;
	else {
		err = BCME_BADARG;
		goto DONE;
	}

	if (ie_len > VNDR_IE_MAX_LEN) {
		err = BCME_BADLEN;
		goto DONE;
	}

	/* always try to delete existing WPS IE first */
	(void)hal_del_wpsie(ifname, bsscfg_index, type);

	/* add wpsie */
	err = hal_wpsie_op(ifname, bsscfg_index, "add", ie, ie_len, pktflag);

DONE:
	return err;
}

int
hal_del_wpsie(char *ifname, int bsscfg_index, unsigned type)
{
	int i, err;
	vndr_ie_buf_t *iebuf;
	char getbuf[2048] = {0,};
	char *bufaddr;
	uint8 buflen;
	uint32 pktflag;

	if (WLSS_WPSIE_FT_BEACON == type)
		pktflag = VNDR_IE_BEACON_FLAG;
	else
	if (WLSS_WPSIE_FT_PRBRSP == type)
		pktflag = VNDR_IE_PRBRSP_FLAG;
	else {
		err = BCME_BADARG;
		goto DONE;
	}

	/* get all ies */
	err = wl_bssiovar_get(ifname, "vndr_ie", 0, getbuf, sizeof getbuf);
	if (err) {
		err = BCME_ERROR;
		goto DONE;
	}

	iebuf = (vndr_ie_buf_t *)getbuf;
	bufaddr = (char*)iebuf->vndr_ie_list;

	/* iterate thru ies until we find a wpsie */
	memcpy(&i, &iebuf->iecount, sizeof i);
	for (; i > 0; i--) {
		vndr_ie_info_t *ieinfo = (vndr_ie_info_t*)bufaddr;
		if (!memcmp(&pktflag, &ieinfo->pktflag, sizeof pktflag)) {
			if (!memcmp(ieinfo->vndr_ie_data.oui, HAL_WPS_OUI, 4)) {
				bufaddr = (char*)ieinfo->vndr_ie_data.data+1;
				buflen = ieinfo->vndr_ie_data.len - VNDR_IE_MIN_LEN - 1;
				break;
			}
		}

		/* ieinfo->vndr_ie_data.len represents the together size
		 * (number of bytes) of OUI + IE data
		*/
		bufaddr = (char *)ieinfo->vndr_ie_data.oui + ieinfo->vndr_ie_data.len;
	}

	if (i < 1) {
		err = BCME_NOTFOUND;
		goto DONE;
	}

	/* del ie */
	err = hal_wpsie_op(ifname, bsscfg_index, "del", bufaddr, buflen, pktflag);

DONE:
	return err;
}
