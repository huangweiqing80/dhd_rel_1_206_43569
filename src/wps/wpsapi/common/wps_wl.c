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
 * $Id: wps_wl.c 368046 2012-11-11 00:40:51Z $
 */

#include <wpsheaders.h>
#include <wps_enrapi.h>
#include <wps_sta.h>
#include <tutrace.h>

#include "wlioctl.h"
#include "wps_api_priv.h"

bool wps_swap = FALSE;

#define WPS_DUMP_BUF_LEN (127 * 1024)
#define WPS_SSID_FMT_BUF_LEN 4*32+1	/* Length for SSID format string */

#define WPS_SCAN_MAX_WAIT_SEC 10
#define WPS_JOIN_MAX_WAIT_SEC 60	/*
					 * Do not define this value too short,
					 * because AP/Router may reboot after got new
					 * credential and apply it.
					 */
#define WPS_IE_BUF_LEN	VNDR_IE_MAX_LEN * 8	/* 2048 */
#define WPS_IE_FRAG_MAX (WLC_IOCTL_SMLEN - sizeof(vndr_ie_setbuf_t) - strlen("vndr_ie") - 1)

wps_ap_list_info_t ap_list[WPS_MAX_AP_SCAN_LIST_LEN];
static char scan_result[WPS_DUMP_BUF_LEN];
static uint8 wps_ie_setbuf[WPS_IE_BUF_LEN];


typedef struct WPS_WL_S {
	fnWpsProcessCB cb;
	void *cb_ctx;
} WPS_WL_T;
WPS_WL_T *wps_wl_wksp = NULL;


#ifdef WFA_WPS_20_TESTBED
static int frag_threshold = 0;
static uint8 prbreq_updie_setbuf[WPS_IE_BUF_LEN];
static uint8 prbreq_updie_len = 0;
static uint8 assocreq_updie_setbuf[WPS_IE_BUF_LEN];
static uint8 assocreq_updie_len = 0;

int
set_wps_ie_frag_threshold(int threshold)
{
	/* 72 = OUI + OUITYPE + TLV, V <=64 case */
	if (threshold > WPS_IE_FRAG_MAX || threshold < 72)
		return -1;

	frag_threshold = threshold;

	return 0;
}

int
set_update_partial_ie(uint8 *updie_str, unsigned int pktflag)
{
	uchar *src, *dest;
	uchar val;
	int idx, len;
	char hexstr[3];

	uint8 *updie_setbuf;
	uint8 *updie_len;

	switch (pktflag) {
	case VNDR_IE_PRBREQ_FLAG:
		updie_setbuf = prbreq_updie_setbuf;
		updie_len = &prbreq_updie_len;
		break;
	case VNDR_IE_ASSOCREQ_FLAG:
		updie_setbuf = assocreq_updie_setbuf;
		updie_len = &assocreq_updie_len;
		break;
	default:
		return -1;
	}
	/* reset first */
	*updie_len = 0;

	if (!updie_str)
		return 0;

	/* Ensure in 2 characters long */
	len = strlen((char*)updie_str);
	if (len % 2) {
		TUTRACE((TUTRACE_ERR, "Please specify all the data bytes for this IE\n"));
		return -1;
	}
	*updie_len = (uint8) (len / 2);

	/* string to hex */
	src = updie_str;
	dest = updie_setbuf;
	for (idx = 0; idx < len; idx++) {
		hexstr[0] = src[0];
		hexstr[1] = src[1];
		hexstr[2] = '\0';

		val = (uchar) strtoul(hexstr, NULL, 16);

		*dest++ = val;
		src += 2;
	}

	return 0;
}
#endif /* WFA_WPS_20_TESTBED */

static int
wps_ioctl_get(int cmd, void *buf, int len)
{
	return wps_hook_wl_ioctl(cmd, buf, len, FALSE);
}

static int
wps_ioctl_set(int cmd, void *buf, int len)
{
	return wps_hook_wl_ioctl(cmd, buf, len, TRUE);
}

static int
wl_iovar_getbuf(char *iovar, void *param, int paramlen, void *bufptr, uint buflen)
{
	int err;
	uint namelen;
	uint iolen;

	namelen = (uint)strlen(iovar) + 1;	 /* length of iovar name plus null */
	iolen = namelen + paramlen;

	/* check for overflow */
	if (iolen > buflen)
		return (-1);

	memcpy(bufptr, iovar, namelen);	/* copy iovar name including null */
	memcpy((int8*)bufptr + namelen, param, paramlen);

	err = wps_ioctl_get(WLC_GET_VAR, bufptr, buflen);

	return (err);
}

static int
wl_iovar_get(char *iovar, void *bufptr, uint buflen)
{
	char smbuf[WLC_IOCTL_SMLEN];
	int ret;

	/* use the return buffer if it is bigger than what we have on the stack */
	if (buflen > sizeof(smbuf)) {
		ret = wl_iovar_getbuf(iovar, NULL, 0, bufptr, buflen);
	} else {
		ret = wl_iovar_getbuf(iovar, NULL, 0, smbuf, sizeof(smbuf));
		if (ret == 0)
			memcpy(bufptr, smbuf, buflen);
	}

	return ret;
}

/*
 * format an iovar buffer
 * iovar name is converted to lower case
 */
static uint
wps_iovar_mkbuf(const char *name, char *data, uint datalen, char *iovar_buf, uint buflen, int *perr)
{
	uint iovar_len;
	char *p;

	iovar_len = (uint)strlen(name) + 1;

	/* check for overflow */
	if ((iovar_len + datalen) > buflen) {
		*perr = -1;
		return 0;
	}

	/* copy data to the buffer past the end of the iovar name string */
	if (datalen > 0)
		memmove(&iovar_buf[iovar_len], data, datalen);

	/* copy the name to the beginning of the buffer */
	strcpy(iovar_buf, name);

	/* wl command line automatically converts iovar names to lower case for
	 * ease of use
	 */
	p = iovar_buf;
	while (*p != '\0') {
		*p = tolower((int)*p);
		p++;
	}

	*perr = 0;
	return (iovar_len + datalen);
}

/*
 * set named iovar providing both parameter and i/o buffers
 * iovar name is converted to lower case
 */
static int
wps_iovar_setbuf(const char *iovar,
	void *param, int paramlen, void *bufptr, int buflen)
{
	int err;
	int iolen;

	iolen = wps_iovar_mkbuf(iovar, param, paramlen, bufptr, buflen, &err);
	if (err)
		return err;

	return wps_ioctl_set(WLC_SET_VAR, bufptr, iolen);
}

/*
 * set named iovar given the parameter buffer
 * iovar name is converted to lower case
 */
static int
wps_iovar_set(const char *iovar, void *param, int paramlen)
{
	char smbuf[WLC_IOCTL_SMLEN];

	memset(smbuf, 0, sizeof(smbuf));

	return wps_iovar_setbuf(iovar, param, paramlen, smbuf, sizeof(smbuf));
}

#ifdef _TUDEBUGTRACE
static char *
_pktflag_name(unsigned int pktflag)
{
	if (pktflag == VNDR_IE_BEACON_FLAG)
		return "Beacon";
	else if (pktflag == VNDR_IE_PRBRSP_FLAG)
		return "Probe Resp";
	else if (pktflag == VNDR_IE_ASSOCRSP_FLAG)
		return "Assoc Resp";
	else if (pktflag == VNDR_IE_AUTHRSP_FLAG)
		return "Auth Resp";
	else if (pktflag == VNDR_IE_PRBREQ_FLAG)
		return "Probe Req";
	else if (pktflag == VNDR_IE_ASSOCREQ_FLAG)
		return "Assoc Req";
	else if (pktflag == VNDR_IE_CUSTOM_FLAG)
		return "Custom";
	else
		return "Unknown";
}
#endif /* _TUDEBUGTRACE */

/* 
 *		Endian check
 */
int
wps_wl_check()
{
	int ret;
	int val;

	if ((ret = wps_ioctl_get(WLC_GET_MAGIC, &val, sizeof(int)) < 0))
	{
		TUTRACE((TUTRACE_ERR, "Fail to get WLC_GET_MAGIC (%d)\n", ret));
		return ret;
	}

	/* Detect if IOCTL swapping is necessary */
	if (val == (int)bcmswap32(WLC_IOCTL_MAGIC))
	{
		val = bcmswap32(val);
		wps_swap = TRUE;
	}
	TUTRACE((TUTRACE_ERR, "val = %d(%d), swap=%d\n", val, WLC_IOCTL_MAGIC, wps_swap));
	if (val != WLC_IOCTL_MAGIC)
		return -1;
	if ((ret = wps_ioctl_get(WLC_GET_VERSION, &val, sizeof(int)) < 0))
	{
		TUTRACE((TUTRACE_ERR, "Fail to get WLC_GET_VERSION (%d)\n", ret));
		return ret;
	}
	val = dtoh32(val);
	if (val > WLC_IOCTL_VERSION) {
		fprintf(stderr, "val = %d(%d)Version mismatch, please upgrade\n", val, WLC_IOCTL_VERSION);
		return -1;
	}
#if defined(D11AC_IOTYPES) && defined(BCM_WPS_IOTYPECOMPAT)
	g_legacy_chanspec = (val == WLC_IOCTL_VERSION_LEGACY_IOTYPES);
#ifdef _TUDEBUGTRACE
	printf("g_legacy_chanspec = %d\n", g_legacy_chanspec);
#endif
#endif
	
	return 0;
}


static int
_del_vndr_ie(char *bufaddr, int buflen, uint32 frametype)
{
	int iebuf_len;
	int iecount, err;
	vndr_ie_setbuf_t *ie_setbuf;
#ifdef _TUDEBUGTRACE
	int frag_len = buflen - 6;
#endif

	iebuf_len = buflen + sizeof(vndr_ie_setbuf_t) - sizeof(vndr_ie_t);
	ie_setbuf = (vndr_ie_setbuf_t *) malloc(iebuf_len);
	if (!ie_setbuf) {
		TUTRACE((TUTRACE_ERR, "memory alloc failure\n"));
		return -1;
	}

	/* Copy the vndr_ie SET command ("add"/"del") to the buffer */
	strcpy(ie_setbuf->cmd, "del");

	/* Buffer contains only 1 IE */
	iecount = htod32(1);
	memcpy(&ie_setbuf->vndr_ie_buffer.iecount, &iecount, sizeof(int));
	frametype = htod32(frametype);
	memcpy(&ie_setbuf->vndr_ie_buffer.vndr_ie_list[0].pktflag, &frametype, sizeof(uint32));
	memcpy(&ie_setbuf->vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data, bufaddr, buflen);

#ifdef _TUDEBUGTRACE
	TUTRACE((TUTRACE_INFO, "\n_del_vndr_ie (%s, frag_len=%d)\n",
		_pktflag_name(dtoh32(frametype)), frag_len));
#endif /* _TUDEBUGTRACE */

	err = wps_iovar_set("vndr_ie", ie_setbuf, iebuf_len);

	free(ie_setbuf);

	return err;
}

static int
_set_vndr_ie(unsigned char *frag, int frag_len, unsigned char ouitype, unsigned int pktflag)
{
	vndr_ie_setbuf_t *ie_setbuf;
	int buflen, iecount, i;
	int err = 0;

	buflen = sizeof(vndr_ie_setbuf_t) + frag_len;
	ie_setbuf = (vndr_ie_setbuf_t *) malloc(buflen);
	if (!ie_setbuf) {
		TUTRACE((TUTRACE_ERR, "memory alloc failure\n"));
		return -1;
	}

	/* Copy the vndr_ie SET command ("add"/"del") to the buffer */
	strcpy(ie_setbuf->cmd, "add");

	/* Buffer contains only 1 IE */
	iecount = htod32(1);
	memcpy(&ie_setbuf->vndr_ie_buffer.iecount, &iecount, sizeof(int));

	/* 
	 * The packet flag bit field indicates the packets that will
	 * contain this IE
	 */
	pktflag=htod32(pktflag);
	memcpy(&ie_setbuf->vndr_ie_buffer.vndr_ie_list[0].pktflag, &pktflag, sizeof(uint32));

	/* Now, add the IE to the buffer, +1: one byte OUI_TYPE */
	ie_setbuf->vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data.len = (uint8) frag_len +
		VNDR_IE_MIN_LEN + 1;

	ie_setbuf->vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data.oui[0] = 0x00;
	ie_setbuf->vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data.oui[1] = 0x50;
	ie_setbuf->vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data.oui[2] = 0xf2;
	ie_setbuf->vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data.data[0] = ouitype;

	for (i = 0; i < frag_len; i++) {
		ie_setbuf->vndr_ie_buffer.vndr_ie_list[0].vndr_ie_data.data[i+1] = frag[i];
	}

#ifdef _TUDEBUGTRACE
#endif /* _TUDEBUGTRACE */

	err = wps_iovar_set("vndr_ie", ie_setbuf, buflen);

	free(ie_setbuf);

	return err;
}

/* Parsing TLV format WPS IE */
static unsigned char *
_get_frag_wps_ie(unsigned char *p_data, int length, int *frag_len, int max_frag_len)
{
	int next_tlv_len, total_len = 0;
	uint16 type;
	unsigned char *next;

	if (!p_data || !frag_len || max_frag_len < 4)
		return NULL;

	if (length <= max_frag_len) {
		*frag_len = length;
		return p_data;
	}

	next = p_data;
	while (1) {
		type = WpsNtohs(next);
		next += 2; /* Move to L */
		next_tlv_len = WpsNtohs(next) + 4; /* Include Type and Value 4 bytes */
		next += 2; /* Move to V */
		if (next_tlv_len > max_frag_len) {
			TUTRACE((TUTRACE_ERR, "Error, there is a TLV length %d bigger than "
				"Max fragment length %d. Unable to fragment it.\n",
				next_tlv_len, max_frag_len));
			return NULL;
		}

		/* Abnormal IE check */
		if ((total_len + next_tlv_len) > length) {
			TUTRACE((TUTRACE_ERR, "Error, Abnormal WPS IE.\n"));
			*frag_len = length;
			return p_data;
		}

		/* Fragment point check */
		if ((total_len + next_tlv_len) > max_frag_len) {
			*frag_len = total_len;
			return p_data;
		}

		/* Get this TLV length */
		total_len += next_tlv_len;
		next += (next_tlv_len - 4); /* Move to next TLV */
	}

}

static int
create_wps_ie(bool pbc, unsigned int pktflag)
{
	int err = 0;

	if (pktflag == VNDR_IE_PRBREQ_FLAG) {
		if (pbc)
			err = wps_build_pbc_proberq(wps_ie_setbuf, sizeof(wps_ie_setbuf));
		else
			err = wps_build_def_proberq(wps_ie_setbuf, sizeof(wps_ie_setbuf));
	}
	else if (pktflag == VNDR_IE_ASSOCREQ_FLAG) {
		err = wps_build_def_assocrq(wps_ie_setbuf, sizeof(wps_ie_setbuf));
	}
	else
		return -1;


	if (err == WPS_SUCCESS)
		err = 0;

	return err;
}

/* add probe request for enrollee */
static int
_add_wps_ie(bool pbc, unsigned int pktflag)
{
	int frag_len;
	int wps_ie_len;
	int err = 0;
	unsigned char *frag, *wps_ie;
	int frag_max = (int)WPS_IE_FRAG_MAX;
#ifdef WFA_WPS_20_TESTBED
	uint8 *updie_setbuf;
	uint8 *updie_len;
#endif /* WFA_WPS_20_TESTBED */


	if (pktflag != VNDR_IE_PRBREQ_FLAG && pktflag != VNDR_IE_ASSOCREQ_FLAG) {
		TUTRACE((TUTRACE_ERR, "_add_wps_ie : unsupported pktflag 0x%x\n", pktflag));
		return -1;
	}

	/* Generate wps_ie_setbuf */
	if (create_wps_ie(pbc, pktflag) != 0) {
		TUTRACE((TUTRACE_ERR, "_add_wps_ie : Create WPS IE failed\n"));
		return -1;
	}

	/*
	 * wps_ie_setbuf:
	 * [0] = len
	 * [1~3] = 0x00:0x50:0xF2
	 * [4] = 0x04
	 */
	wps_ie = &wps_ie_setbuf[5];
	wps_ie_len = wps_ie_setbuf[0] - 4;

	/* try removing first in case there was one left from previous call */
	rem_wps_ie(NULL, 0, pktflag);

#ifdef WFA_WPS_20_TESTBED
	/* WPS IE fragment threshold */
	if (frag_threshold)
		frag_max = frag_threshold;


	if (pktflag == VNDR_IE_PRBREQ_FLAG) {
		updie_setbuf = prbreq_updie_setbuf;
		updie_len = &prbreq_updie_len;
	}
	else {
		/* VNDR_IE_ASSOCREQ_FLAG */
		updie_setbuf = assocreq_updie_setbuf;
		updie_len = &assocreq_updie_len;
	}

	/* Update partial WPS IE in probe request */
	if (*updie_len) {
		if (wps_update_partial_ie(wps_ie_setbuf, sizeof(wps_ie_setbuf),
			wps_ie, (uint8)wps_ie_len, updie_setbuf, *updie_len) != WPS_SUCCESS) {
			TUTRACE((TUTRACE_ERR, "Failed to update partial WPS IE in %s\n",
				(pktflag == VNDR_IE_PRBREQ_FLAG) ? "probereq" : "assocreq"));
			return -1;
		}
		/* update new length */
		wps_ie_len = wps_ie_setbuf[0] - 4;
	}
#endif /* WFA_WPS_20_TESTBED */

	/* Separate a big IE to fragment IEs */
	frag = wps_ie;
	frag_len = wps_ie_len;
	while (wps_ie_len > 0) {
		if (wps_ie_len > frag_max)
			/* Find a appropriate fragment point */
			frag = _get_frag_wps_ie(frag, wps_ie_len, &frag_len, frag_max);

		if (!frag)
			return -1;

		/* Set fragment WPS IE */
		err |= _set_vndr_ie(frag, frag_len, 0x04, pktflag);

		/* Move to next */
		wps_ie_len -= frag_len;
		frag += frag_len;
		frag_len = wps_ie_len;
	}

	return (err);
}

/* ########## */
/* EXPORTED APIS */
/* ########## */
wps_ap_list_info_t *
wps_get_ap_list()
{
	return ap_list;
}

wps_ap_list_info_t *
create_aplist()
{
	wl_scan_results_t *list = (wl_scan_results_t*)scan_result;
	wl_bss_info_t *bi;
	wl_bss_info_107_t *old_bi_107;
	uint i, wps_ap_count = 0;

	wps_osl_get_scan_results(scan_result, sizeof(scan_result));

	list->version = dtoh32(list->version);
	list->count = dtoh32(list->count);
	list->buflen = dtoh32(list->buflen);

	memset(ap_list, 0, sizeof(ap_list));
	if (list->count == 0)
		return 0;

#ifdef LEGACY2_WL_BSS_INFO_VERSION
	if (list->version != WL_BSS_INFO_VERSION &&
		list->version != LEGACY_WL_BSS_INFO_VERSION &&
		list->version != LEGACY2_WL_BSS_INFO_VERSION) {
#else
	if (list->version != WL_BSS_INFO_VERSION &&
		list->version != LEGACY_WL_BSS_INFO_VERSION) {
#endif
			TUTRACE((TUTRACE_ERR, "Sorry, your driver has bss_info_version %d "
				"but this program supports only version %d.\n",
				list->version, WL_BSS_INFO_VERSION));
			return NULL;
	}

	if (list->version > WL_BSS_INFO_VERSION) {
		TUTRACE((TUTRACE_ERR, "your driver has bss_info_version %d "
			"but this program supports only version %d.\n",
			list->version, WL_BSS_INFO_VERSION));
	}

	bi = list->bss_info;
	for (i = 0; i < list->count; i++) {

		bi->version = dtoh32(bi->version);
		/* Convert version 107 to 108 */
		if (bi->version == LEGACY_WL_BSS_INFO_VERSION) {
			old_bi_107 = (wl_bss_info_107_t *)bi;
			bi->chanspec = CH20MHZ_CHSPEC(old_bi_107->channel);
#ifdef _TUDEBUGTRACE
			printf( "This is old bss_info_107. New chanspec convert table may required: channel= %x, chanspec=%d\n",
					old_bi_107->channel, bi->chanspec);
#endif
			bi->ie_length = dtoh32(old_bi_107->ie_length);
			bi->ie_offset = sizeof(wl_bss_info_107_t);
		}
		else
		{
			bi->chanspec = dtohchanspec(WPS_WL_CHSPEC_IOTYPE_DTOH(bi->chanspec));
			bi->ie_offset = dtoh16(bi->ie_offset);
			bi->ie_length = dtoh32(bi->ie_length);
		}
		/* Convert endian swap */
		bi->length = dtoh32(bi->length);
		bi->atim_window = dtoh16(bi->atim_window);
		bi->beacon_period = dtoh16(bi->beacon_period);
		bi->capability = dtoh16(bi->capability);
		bi->nbss_cap = dtoh32(bi->nbss_cap);
		bi->rateset.count = dtoh32(bi->rateset.count);
		bi->RSSI = dtoh16(bi->RSSI);
		bi->SNR = dtoh16(bi->SNR);

		if (bi->ie_length) {
			if (wps_ap_count < WPS_MAX_AP_SCAN_LIST_LEN) {
				int sb, chan_adj = 0;

				ap_list[wps_ap_count].used = TRUE;
				memcpy(ap_list[wps_ap_count].BSSID, bi->BSSID.octet, 6);
				strncpy((char *)ap_list[wps_ap_count].ssid, (char *)bi->SSID,
					bi->SSID_len);
				ap_list[wps_ap_count].ssid[bi->SSID_len] = '\0';
				ap_list[wps_ap_count].ssidLen = bi->SSID_len;
				ap_list[wps_ap_count].ie_buf = (uint8 *)(((uint8 *)bi) +
					bi->ie_offset);
				ap_list[wps_ap_count].ie_buflen = bi->ie_length;

				if ((bi->chanspec & WL_CHANSPEC_BW_MASK) == WL_CHANSPEC_BW_40) {
					sb = bi->chanspec & WL_CHANSPEC_CTL_SB_MASK;
					if (sb == WL_CHANSPEC_CTL_SB_LOWER)
						chan_adj = -2;
					else
						chan_adj = 2;
				}

				/* On Windows, we us standard Windows NativeWiFi API to get scan results which 
				 * do not include "chanspec" information, so we use "ctl_ch" to determine the band
				 */
#ifdef WIN32
				if (bi->chanspec)
					ap_list[wps_ap_count].band = (CHSPEC_IS2G(bi->chanspec) ? WPSAPI_BAND_2G : WPSAPI_BAND_5G);
				else {
					ap_list[wps_ap_count].channel = bi->ctl_ch;
					if (bi->ctl_ch <= CH_MAX_2G_CHANNEL)
						ap_list[wps_ap_count].band = WPSAPI_BAND_2G;
					else
						ap_list[wps_ap_count].band = WPSAPI_BAND_5G;
				}
#else
				ap_list[wps_ap_count].band = (CHSPEC_IS2G(bi->chanspec) ? WPSAPI_BAND_2G : WPSAPI_BAND_5G);
				ap_list[wps_ap_count].channel = CHSPEC_CHANNEL(bi->chanspec) + chan_adj;
#endif

				ap_list[wps_ap_count].wep = bi->capability & DOT11_CAP_PRIVACY;
				wps_ap_count++;
			}

		}
		bi = (wl_bss_info_t*)((int8*)bi + bi->length);
	}

	return ap_list;
}

/* add probe request for enrollee */
int
add_wps_ie(unsigned char *p_data, int length, bool pbc, bool b_wps_version2)
{
	int err = 0;

	/* Add WPS IE in probe request */
	if ((err = _add_wps_ie(pbc, VNDR_IE_PRBREQ_FLAG)) != 0) {
		TUTRACE((TUTRACE_ERR, "add_wps_ie : Add WPS IE in probe request failed\n"));
		return err;
	}

	/* Add WPS IE in associate request */
	if (b_wps_version2 && (err = _add_wps_ie(pbc, VNDR_IE_ASSOCREQ_FLAG)) != 0) {
		TUTRACE((TUTRACE_ERR, "add_wps_ie : Add WPS IE in associate request failed\n"));
		return err;
	}

	return 0;
}

/* Remove probe request WPS IEs */
int
rem_wps_ie(unsigned char *p_data, int length, unsigned int pktflag)
{
	int i, err = 0;
	char getbuf[WPS_IE_BUF_LEN] = {0};
	vndr_ie_buf_t *iebuf;
	vndr_ie_info_t *ieinfo;
	char wps_oui[4] = {0x00, 0x50, 0xf2, 0x04};
	char *bufaddr;
	int buflen = 0;
	int found = 0;
	uint32 ieinfo_pktflag, tot_ie;

	if (pktflag != VNDR_IE_PRBREQ_FLAG && pktflag != VNDR_IE_ASSOCREQ_FLAG) {
		TUTRACE((TUTRACE_ERR, "rem_wps_ie : unsupported pktflag 0x%x\n", pktflag));
		return -1;
	}

	/* Get all WPS IEs in probe request IE */
	if (wl_iovar_get("vndr_ie", getbuf, WPS_IE_BUF_LEN)) {
		TUTRACE((TUTRACE_ERR, "rem_wps_ie : No IE to remove\n"));
		return -1;
	}

	iebuf = (vndr_ie_buf_t *) getbuf;
	bufaddr = (char*) iebuf->vndr_ie_list;

	memcpy(&tot_ie, (void *)&iebuf->iecount, sizeof(int));
	tot_ie = htod32(tot_ie);

	/* Delete ALL specified ouitype IEs */
	for (i = 0; i < tot_ie; i++) {
		ieinfo = (vndr_ie_info_t*) bufaddr;
		bcopy((char*)&ieinfo->pktflag, (char*)&ieinfo_pktflag, (int) sizeof(uint32));
		if (dtoh32(ieinfo_pktflag) == pktflag) {
			if (!memcmp(ieinfo->vndr_ie_data.oui, wps_oui, 4)) {
				found = 1;
				bufaddr = (char*) &ieinfo->vndr_ie_data;
				buflen = (int)ieinfo->vndr_ie_data.len + VNDR_IE_HDR_LEN;
				/* Delete one vendor IE */
				err |= _del_vndr_ie(bufaddr, buflen, pktflag);
			}
		}
		bufaddr = (char*)(ieinfo->vndr_ie_data.oui + ieinfo->vndr_ie_data.len);
	}

	if (!found)
		return -1;

	return (err);
}

int
join_network(char* ssid, uint32 wsec)
{
	return wps_osl_join_network(ssid, wsec);
}

int
join_network_with_bssid(char* ssid, uint32 wsec, char *bssid)
{
	return wps_osl_join_network_with_bssid(ssid, wsec, bssid);
}

int
leave_network()
{
	if (wps_wl_wksp)
		wps_api_status_cb(&wps_wl_wksp->cb, wps_wl_wksp->cb_ctx,
			WPS_STATUS_DISCONNECTING, NULL);

	return wps_osl_leave_network();
}

int
wps_get_bssid(char *bssid)
{
	return wps_ioctl_get(WLC_GET_BSSID, bssid, 6);
}


int
wps_get_bands(uint *band_num, uint *active_band)
{
	int ret;
	uint list[3];

	*band_num = 0;
	*active_band = 0;

	if ((ret = wps_ioctl_get(WLC_GET_BANDLIST, list, sizeof(list))) < 0) {
		return ret;
	}

	/* list[0] is count, followed by 'count' bands */
	if (list[0] > 2)
		list[0] = 2;
	*band_num = list[0];

	/* list[1] is current band type */
	*active_band = list[1];

	return ret;
}

bool
wps_wl_init(void *cb_ctx, void *cb)
{
	/* Duplicate wps_wl_init detection */
	if (wps_wl_wksp)
		return false;

	/* Allocate wps_wl_wksp */
	if ((wps_wl_wksp = (WPS_WL_T *)malloc(sizeof(WPS_WL_T))) == NULL)
		return false;
	memset(wps_wl_wksp, 0, sizeof(WPS_WL_T));

	wps_wl_wksp->cb = (fnWpsProcessCB)cb;
	wps_wl_wksp->cb_ctx = cb_ctx;

	/* Setup endian swap*/
	if (wps_wl_check())
		return false;

	TUTRACE((TUTRACE_ERR, "wps_wl_init. Endian wps_swap = %d \n", wps_swap));

	return true;
}

void
wps_wl_deinit()
{
	if (wps_wl_wksp) {
		free(wps_wl_wksp);
		wps_wl_wksp = NULL;
	}

	return;
}

/* Add b_add_wpsie to reduce the add/rem vendor IE frequently. */
wps_ap_list_info_t *
wps_wl_surveying(bool b_pbc, bool b_v2, bool b_add_wpsie)
{
	wps_ap_list_info_t *aplist;

	if (wps_wl_wksp == NULL)
		return NULL;

	wps_api_status_cb(&wps_wl_wksp->cb, wps_wl_wksp->cb_ctx, WPS_STATUS_SCANNING, NULL);

	/* Add wps ie to probe */
	if (b_add_wpsie && add_wps_ie(NULL, 0, b_pbc, b_v2) != 0)
		return NULL;

	/* create_aplist is a "BLOCKING" call */
	aplist = create_aplist();

	wps_api_status_cb(&wps_wl_wksp->cb, wps_wl_wksp->cb_ctx, WPS_STATUS_SCANNING_OVER, NULL);

	return aplist;
}

bool
wps_wl_join(uint8 *bssid, char *ssid, uint8 wep)
{
	if (wps_wl_wksp == NULL)
		return false;

	leave_network();

	wps_api_status_cb(&wps_wl_wksp->cb, wps_wl_wksp->cb_ctx, WPS_STATUS_ASSOCIATING, ssid);

	if (join_network_with_bssid(ssid, wep, (char *)bssid)) {
		return false;
	}

	wps_api_status_cb(&wps_wl_wksp->cb, wps_wl_wksp->cb_ctx, WPS_STATUS_ASSOCIATED, ssid);

	return true;
}

#if defined(D11AC_IOTYPES) && defined(BCM_WPS_IOTYPECOMPAT)
bool g_legacy_chanspec = FALSE;
/* 80MHz channels in 5GHz band */
static const uint8 wf_5g_80m_chans[] =
{42, 58, 106, 122, 138, 155};
#define WF_NUM_5G_80M_CHANS \
	(sizeof(wf_5g_80m_chans)/sizeof(uint8))

static bool
wps_wf_chspec_malformed(chanspec_t chanspec)
{
	uint chspec_bw = CHSPEC_BW(chanspec);
	uint chspec_ch = CHSPEC_CHANNEL(chanspec);

	/* must be 2G or 5G band */
	if (CHSPEC_IS2G(chanspec)) {
		/* must be valid bandwidth */
		if (chspec_bw != WL_CHANSPEC_BW_20 &&
		    chspec_bw != WL_CHANSPEC_BW_40) {
			return TRUE;
		}
	} else if (CHSPEC_IS5G(chanspec)) {
		if (chspec_bw == WL_CHANSPEC_BW_8080) {
			uint ch1_id, ch2_id;

			/* channel number in 80+80 must be in range */
			ch1_id = CHSPEC_CHAN1(chanspec);
			ch2_id = CHSPEC_CHAN2(chanspec);
			if (ch1_id >= WF_NUM_5G_80M_CHANS || ch2_id >= WF_NUM_5G_80M_CHANS)
				return TRUE;

			/* ch2 must be above ch1 for the chanspec */
			if (ch2_id <= ch1_id)
				return TRUE;
		} else if (chspec_bw == WL_CHANSPEC_BW_20 || chspec_bw == WL_CHANSPEC_BW_40 ||
		           chspec_bw == WL_CHANSPEC_BW_80 || chspec_bw == WL_CHANSPEC_BW_160) {

			if (chspec_ch > MAXCHANNEL) {
				return TRUE;
			}
		} else {
			/* invalid bandwidth */
			return TRUE;
		}
	} else {
		/* must be 2G or 5G band */
		return TRUE;
	}

	/* side band needs to be consistent with bandwidth */
	if (chspec_bw == WL_CHANSPEC_BW_20) {
		if (CHSPEC_CTL_SB(chanspec) != WL_CHANSPEC_CTL_SB_LLL)
			return TRUE;
	} else if (chspec_bw == WL_CHANSPEC_BW_40) {
		if (CHSPEC_CTL_SB(chanspec) > WL_CHANSPEC_CTL_SB_LLU)
			return TRUE;
	} else if (chspec_bw == WL_CHANSPEC_BW_80) {
		if (CHSPEC_CTL_SB(chanspec) > WL_CHANSPEC_CTL_SB_LUU)
			return TRUE;
	}

	return FALSE;
}

chanspec_t
wps_wl_chspec_from_legacy(chanspec_t legacy_chspec)
{
	chanspec_t chspec;

	/* get the channel number */
	chspec = LCHSPEC_CHANNEL(legacy_chspec);

	/* convert the band */
	if (LCHSPEC_IS2G(legacy_chspec)) {
		chspec |= WL_CHANSPEC_BAND_2G;
	} else {
		chspec |= WL_CHANSPEC_BAND_5G;
	}

	/* convert the bw and sideband */
	if (LCHSPEC_IS20(legacy_chspec)) {
		chspec |= WL_CHANSPEC_BW_20;
	} else {
		chspec |= WL_CHANSPEC_BW_40;
		if (LCHSPEC_CTL_SB(legacy_chspec) == WL_LCHANSPEC_CTL_SB_LOWER) {
			chspec |= WL_CHANSPEC_CTL_SB_L;
		} else {
			chspec |= WL_CHANSPEC_CTL_SB_U;
		}
	}

	if (wps_wf_chspec_malformed(chspec)) {
		fprintf(stderr, "wl_chspec_from_legacy: output chanspec (0x%04X) malformed\n",
		        chspec);
		return INVCHANSPEC;
	}

	return chspec;
}

/* Return a legacy chanspec given a new chanspec
 * Returns INVCHANSPEC on error
 */
chanspec_t
wps_wl_chspec_to_legacy(chanspec_t chspec)
{
	chanspec_t lchspec;

	if (wps_wf_chspec_malformed(chspec)) {
		fprintf(stderr, "wl_chspec_to_legacy: input chanspec (0x%04X) malformed\n",
		        chspec);
		return INVCHANSPEC;
	}
	else
		fprintf(stderr, "wl_chspec_to_legacy: input chanspec (0x%04X) correct\n",
				chspec);

	/* get the channel number */
	lchspec = CHSPEC_CHANNEL(chspec);

	/* convert the band */
	if (CHSPEC_IS2G(chspec)) {
		lchspec |= WL_LCHANSPEC_BAND_2G;
	} else {
		lchspec |= WL_LCHANSPEC_BAND_5G;
	}

	/* convert the bw and sideband */
	if (CHSPEC_IS20(chspec)) {
		lchspec |= WL_LCHANSPEC_BW_20;
		lchspec |= WL_LCHANSPEC_CTL_SB_NONE;
	} else if (CHSPEC_IS40(chspec)) {
		lchspec |= WL_LCHANSPEC_BW_40;
		if (CHSPEC_CTL_SB(chspec) == WL_CHANSPEC_CTL_SB_L) {
			lchspec |= WL_LCHANSPEC_CTL_SB_LOWER;
		} else {
			lchspec |= WL_LCHANSPEC_CTL_SB_UPPER;
		}
	} else {
		/* cannot express the bandwidth */
		fprintf(stderr,
		        "wl_chspec_to_legacy: unable to convert chanspec (0x%04X) "
		        "to pre-11ac format\n",
		        chspec);
		return INVCHANSPEC;
	}

	return lchspec;
}
#endif /* defined(D11AC_IOTYPES) && defined(BCM_WPS_IOTYPECOMPAT) */
