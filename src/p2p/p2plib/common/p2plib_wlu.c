/*
 * P2P Library OS-independent WL driver access APIs.
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: p2plib_wlu.c,v 1.138 2010-11-09 02:56:47 $
 */
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

/* P2P Library include files */
#include "p2plib_int.h"
#include "p2pwl.h"

/* WL driver include files */
#include <bcmendian.h>
#include <wlioctl.h>
#include <bcmutils.h>



/*
 * Get named iovar providing both parameter and i/o buffers.
 * iovar name is converted to lower case
 */
int
p2pwlu_iovar_getbuf(p2papi_instance_t* hdl, const char *iovar,
	void *param, int paramlen, void *bufptr, int buflen)
{
	P2PWL_HDL wl = P2PAPI_GET_WL_HDL(hdl);
	return p2pwl_iovar_getbuf_bss(wl, iovar, param, paramlen, bufptr, buflen,
		0);
}

/*
 * Get the named integer iovar.
 * iovar name is converted to lower case
 */
int
p2pwlu_iovar_getint(p2papi_instance_t *hdl, const char *iovar, int *pval)
{
	P2PWL_HDL wl = P2PAPI_GET_WL_HDL(hdl);
	return p2pwl_iovar_getint_bss(wl, iovar, pval, 0);
}

/*
 * Set named iovar providing both parameter and i/o buffers.
 * iovar name is converted to lower case
 */
int
p2pwlu_iovar_setbuf(p2papi_instance_t *hdl, const char *iovar,
	void *param, int paramlen, void *bufptr, int buflen)
{
	P2PWL_HDL wl = P2PAPI_GET_WL_HDL(hdl);
	return p2pwl_iovar_setbuf_bss(wl, iovar, param, paramlen, bufptr, buflen,
		0);
}

/*
 * Set named iovar given an integer parameter.
 * iovar name is converted to lower case
 */
int
p2pwlu_iovar_setint(p2papi_instance_t *hdl, const char *iovar, int val)
{
	P2PWL_HDL wl = P2PAPI_GET_WL_HDL(hdl);
	return p2pwl_iovar_setint_bss(wl, iovar, val, 0);
}

/*
 * Get ioctl.
 */
int
p2pwlu_ioctl_get_bss(p2papi_instance_t *hdl, int cmd, void *buf, int len,
	int bssidx)
{
	P2PWL_HDL wl = P2PAPI_GET_WL_HDL(hdl);
	return p2pwl_ioctl_get_bss(wl, cmd, buf, len, bssidx);
}

/*
 * Set ioctl.
 */
int
p2pwlu_ioctl_set_bss(p2papi_instance_t *hdl, int cmd, void *buf, int len,
	int bssidx)
{
	P2PWL_HDL wl = P2PAPI_GET_WL_HDL(hdl);
	return p2pwl_ioctl_set_bss(wl, cmd, buf, len, bssidx);
}

/*
 * Get named iovar without parameters into a given buffer.
 * iovar name is converted to lower case
 */
int
p2pwlu_iovar_get(p2papi_instance_t* hdl, const char *iovar, void *outbuf,
	int len)
{
	P2PWL_HDL wl = P2PAPI_GET_WL_HDL(hdl);
	return p2pwl_iovar_get_bss(wl, iovar, outbuf, len, 0);
}

/*
 * Set named iovar given the parameter buffer.
 * iovar name is converted to lower case
 */
int
p2pwlu_iovar_set(p2papi_instance_t* hdl, const char *iovar, void *param,
	int paramlen)
{
	P2PWL_HDL wl = P2PAPI_GET_WL_HDL(hdl);
	return p2pwl_iovar_set_bss(wl, iovar, param, paramlen, 0);
}


/*
 * Get named & bss indexed driver variable to buffer value.
 */
int
p2pwlu_bssiovar_get(p2papi_instance_t *hdl, const char *iovar, int bssidx,
	void *outbuf, int len)
{
	P2PWL_HDL wl;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);
	return p2pwl_bssiovar_get(wl, iovar, bssidx, outbuf, len);
}

/*
 * Set named & bss indexed driver variable to buffer value.
 */
int
p2pwlu_bssiovar_set(p2papi_instance_t *hdl, const char *iovar, int bssidx,
	void *param, int paramlen)
{
	P2PWL_HDL wl;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);
	return p2pwl_bssiovar_set(wl, iovar, bssidx, param, paramlen);
}

/*
 * Set named & bsscfg indexed driver variable to int value.
 */
int
p2pwlu_bssiovar_setint(p2papi_instance_t *hdl, const char *iovar, int bssidx,
	int val)
{
	P2PWL_HDL wl;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);
	return p2pwl_bssiovar_setint(wl, iovar, bssidx, val);
}


/* Validate the wireless interface */
int
p2pwlu_check_wl_if(p2papi_instance_t* hdl)
{
	P2PWL_HDL wl;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);
	return p2pwl_check_wl_if(wl);
}

int
p2pwlu_get_mac_addr(p2papi_instance_t* hdl, struct ether_addr *out_mac_addr)
{
	P2PWL_HDL wl;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);
	return p2pwl_get_mac_addr(wl, out_mac_addr);
}

int
p2pwlu_scan(p2papi_instance_t *hdl, int channel, int nprobes)
{
	P2PWL_HDL wl;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);
	return p2pwl_scan(wl, channel, nprobes);
}

/* Scan 3 specific channels with the given channel dwell time,
 * equivalent to the WL command "wl p2p_scan -a <ms> -c <c1>,<c2>,<c3>"
 */
int
p2pwlu_scan_channels(p2papi_instance_t *hdl, int nprobes, int chan_dwell_ms,
	int channel1, int channel2, int channel3)
{
	P2PWL_HDL wl;
	int err = 0;
	wl_scan_results_t * scanresults;
	int max_retry = 5;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);

	while (max_retry-- > 0)
	{
		/* Lock our instance data because we will be writing our ioctl buffer */
		P2PAPI_DATA_LOCK_VERB(hdl);
		memset((void *)(P2PAPI_SCANRESULT_BUF(hdl)), 0, P2PAPI_SCANRESULT_BUF_SIZE);
		scanresults = (wl_scan_results_t *)P2PAPI_SCANRESULT_BUF(hdl);
		scanresults->buflen = OFFSETOF(wl_scan_results_t, bss_info);
		err = p2pwl_scan_channels(wl, nprobes, chan_dwell_ms,
			channel1, channel2, channel3,
			P2PAPI_IOCTL_BUF2(hdl), P2PAPI_IOCTL_BUF_SIZE2,
			P2PAPI_SCANPARAM_BUF(hdl), P2PAPI_SCANPARAM_BUF_SIZE,
			FALSE, hdl->bssidx[P2PAPI_BSSCFG_DEVICE]);
		P2PAPI_DATA_UNLOCK_VERB(hdl);

		/* if succeeds, out of the loop, otherwise, continue to re-try */
		if (err == 0)
			break;

		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2pwlu_scan_channels: err=%d, blocked by another scan, retry loop=%d\n",
			err, max_retry));
		p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_SCAN_CHANNELS, P2PAPI_SCAN_DWELL_TIME_MS);

	}

	return err;
}

/* Do a P2P scan of a list of channels with the given parameters */
int
p2pwlu_scan_nchannels(p2papi_instance_t *hdl, int nprobes, int active_dwell_ms,
	BCMP2P_INT32 num_channels, BCMP2P_UINT16* channels_list)
{
	P2PWL_HDL wl;
	int err = 0;
	wl_scan_results_t * scanresults;
	int max_retry = 5;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);

	while (max_retry-- > 0)
	{
		/* Lock our instance data because we will be writing our ioctl buffer */
		P2PAPI_DATA_LOCK_VERB(hdl);
		memset((void *)(P2PAPI_SCANRESULT_BUF(hdl)), 0,
			P2PAPI_SCANRESULT_BUF_SIZE);
		scanresults = (wl_scan_results_t *)P2PAPI_SCANRESULT_BUF(hdl);
		scanresults->buflen = OFFSETOF(wl_scan_results_t, bss_info);
		err = p2pwl_scan_nchannels(wl, nprobes, active_dwell_ms,
			num_channels, channels_list,
			P2PAPI_IOCTL_BUF2(hdl), P2PAPI_IOCTL_BUF_SIZE2,
			P2PAPI_SCANPARAM_BUF(hdl), P2PAPI_SCANPARAM_BUF_SIZE,
			BCMP2P_FALSE, hdl->bssidx[P2PAPI_BSSCFG_DEVICE]);
		P2PAPI_DATA_UNLOCK_VERB(hdl);

		/* if succeeds, out of the loop, otherwise, continue to re-try */
		if (err == 0)
			break;

		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2pwlu_scan_nchannels: scan err=%d, retries remaining=%d\n",
			err, max_retry));
		p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_SCAN_CHANNELS,
			P2PAPI_SCAN_DWELL_TIME_MS);
	}

	return err;
}


int
p2pwlu_escan_abort(p2papi_instance_t *hdl)
{
	P2PWL_HDL wl;
	int err;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);

	err = p2pwl_scan_channels(wl, 0, 0, 0, 0, 0,
		P2PAPI_IOCTL_BUF2(hdl), P2PAPI_IOCTL_BUF_SIZE2,
		P2PAPI_SCANPARAM_BUF(hdl), P2PAPI_SCANPARAM_BUF_SIZE,
		TRUE, hdl->bssidx[P2PAPI_BSSCFG_DEVICE]);

	return err;
}

int
p2pwlu_scan_abort(p2papi_instance_t *hdl, BCMP2P_BOOL wait_for_abort_complete)
{
	P2PWL_HDL wl;
	int ret;
	int bssidx = 0; /* hdl->bssidx[P2PAPI_BSSCFG_DEVICE]; */

	P2PAPI_CHECK_P2PHDL(hdl);

	/* Scan abort can only apply to primary interface to take effect */
	wl = P2PAPI_GET_PRM_WL_HDL(hdl);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"---wl%s%s scan -c -1\n",
		p2posl_get_netif_name_prefix(wl),
		p2posl_get_netif_name_bss(wl, bssidx)));

	ret = p2pwl_scan_abort(wl);
	if (wait_for_abort_complete) {
		p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_SCAN_ABORT,
			P2PAPI_SCAN_DWELL_TIME_MS);
	}
	return ret;
}

/*
 * Input:
 *       scan_result: caller-provided input buffer that is used to stor
 *                    the scan-result
 *       bufsize: size of the caller-provided buffer in bytes
 * Output:
 *       return 0 if succeeds and scan-results will be stored in the buffer
 *       return -1 if error (e.g. buffer is too small)
 */
int
p2pwlu_scan_get_results(p2papi_instance_t* hdl,
	wl_scan_results_t *scan_results, int bufsize)
{
	P2PWL_HDL wl;
	int ret;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);
	ret = p2pwl_scan_get_results(wl, scan_results, bufsize);
	return ret;
}


/* Join a BSS with previously set security settings */
int
p2pwlu_join(p2papi_instance_t *hdl, char *ssid, size_t ssid_len)
{
	P2PWL_HDL wl;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);
	return p2pwl_join(wl, ssid, ssid_len,
		hdl->bssidx[P2PAPI_BSSCFG_CONNECTION]);
}

/* Join a BSS with previously set security settings */
int
p2pwlu_join_bssid(p2papi_instance_t *hdl, char *ssid, size_t ssid_len,
	struct ether_addr *bssid, int num_chanspec, chanspec_t *chanspec)
{
	P2PWL_HDL wl;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);
	return p2pwl_join_bssid(wl, ssid, ssid_len, bssid,
		num_chanspec, chanspec,
		hdl->bssidx[P2PAPI_BSSCFG_CONNECTION]);
}

/* Join a BSS with no security */
int
p2pwlu_join_open(p2papi_instance_t* hdl, char *bss_ssid)
{
	P2PWL_HDL wl;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);
	return p2pwl_join_open(wl, bss_ssid,
		hdl->bssidx[P2PAPI_BSSCFG_CONNECTION]);
}

int
p2pwlu_disassoc(p2papi_instance_t* hdl)
{
	P2PWL_HDL wl;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);
	return p2pwl_disassoc(wl, hdl->bssidx[P2PAPI_BSSCFG_CONNECTION]);
}

/* Check if we are connected to a BSS.
 * Call this only on the peer acting as a STA.
 */
bool
p2pwlu_is_associated(p2papi_instance_t* hdl)
{
	struct ether_addr bssid;

	P2PAPI_CHECK_P2PHDL(hdl);
	return p2papi_osl_is_associated(hdl, &bssid);
}

/* Check if any peers have connected to our BSS.
 * Call this only on the peer acting as an AP.
 */
int
p2pwlu_get_assoc_count(p2papi_instance_t* hdl, bool show_maclist,
	int *out_assoc_count)
{
	uint8 *ioctl_buf = P2PAPI_IOCTL_BUF(hdl);
	P2PWL_HDL wl;
	int ret;
	int bssidx = hdl->bssidx[P2PAPI_BSSCFG_CONNECTION];

	/* Lock our instance data because we will be writing its ioctl buffer */
	P2PAPI_DATA_LOCK_VERB(hdl);

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);
	ret = p2pwl_get_assoc_count(wl, show_maclist, ioctl_buf, out_assoc_count,
		bssidx);

	P2PAPI_DATA_UNLOCK_VERB(hdl);
	return ret;
}

/* Get a list of all STAs authorized to this AP */
int
p2pwlu_get_autho_sta_list(p2papi_instance_t* hdl, uint32 max_entries,
	uint32 *out_num_entries)
{
	P2PWL_HDL wl;
	int status = BCMP2P_SUCCESS;
	uint8 *ioctl_buf = P2PAPI_IOCTL_BUF(hdl);
	struct maclist *maclist = (struct maclist *) ioctl_buf;
	int result;
	int count = 0;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;
	wl = P2PAPI_GET_WL_HDL(hdl);
	*out_num_entries = 0;

	P2PAPI_DATA_LOCK(hdl);

	result = p2pwl_get_autho_sta_list(wl, FALSE, ioctl_buf, &count,
		hdl->bssidx[P2PAPI_BSSCFG_CONNECTION]);
	if (result != 0) {
		status = result;
	} else if (count > 0) {
		*out_num_entries = dtoh32(maclist->count);
	}

	P2PAPI_DATA_UNLOCK(hdl);

	return status;
}

/* Check if the connection BSS is up */
BCMP2P_BOOL
p2pwlu_bss_isup(p2papi_instance_t* hdl)
{
	P2PWL_HDL wl;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);

	return p2posl_bss_isup(wl, hdl->bssidx[P2PAPI_BSSCFG_CONNECTION]);
}

/* Bring up or down the connection BSS */
int
p2pwlu_bss(p2papi_instance_t *hdl, bool up)
{
	P2PWL_HDL wl;
	BCMP2P_BOOL is_up;
	int ret, i;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);
	if (hdl->bssidx[P2PAPI_BSSCFG_CONNECTION] == 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2pwlu_bss: do nothing, conn-bssidx=0\n"));
		return 0;
	}

	ret = p2pwl_bss(wl, hdl->bssidx[P2PAPI_BSSCFG_CONNECTION], up);
	if (ret != 0)
	{
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "p2pwlu_bss(up=%d): failed\n", up));
		return ret;
	}

	if (!up)
		return ret;

	/* Check if the connection BSS is up */
	for (i = 0; i < 40; i++) {
		is_up = p2pwlu_bss_isup(hdl);
		if (is_up) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2pwlu_bss(up): BSS is up (loop %d)\n", i));
			break;
		} else {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2pwlu_bss(up): BSS is not up! (loop %d)\n", i));
			p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_WAIT_BSS_START, 100);
		}
	}
	if (!is_up) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "p2pwlu_bss(up): failed\n"));
		return -1;
	}

	return 0;
}

int
p2pwlu_set_chanspec(p2papi_instance_t *hdl, chanspec_t chspec, int bssidx)
{
	P2PWL_HDL wl;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2pwlu_set_chanspec: 0x%x\n", chspec));
	return p2pwl_set_chanspec(wl, chspec, bssidx);
}

/* Check if the BSS is 11g by checking if its rateset has OFDM rate(s) */
static bool
p2pwlu_cs_is_11gbss(wl_bss_info_t *bi)
{
	static int ofdm_rates[] = {12, 18, 24, 36, 48, 72, 96, 108};
	uint r1;
	int r2, nr;

	for (r1 = 0; r1 < bi->rateset.count; r1 ++) {
		if (bi->rateset.rates[r1] & 0x80) continue;
		nr = bi->rateset.rates[r1] & 0x7F;
		for (r2 = 0; r2 < sizeof(ofdm_rates)/sizeof(ofdm_rates[0]); r2 ++)
			if (nr == ofdm_rates[r2])
				return TRUE;
	}
	return FALSE;
}

typedef struct {
	chanspec_t chspec;	/* scan chspec */
	uint8 aAPs;	/* # of 11a/n BSSs seen in 5.2G band */
	uint8 bAPs;	/* # of 11b BSSs seen in 2.4G band */
	uint8 gAPs;	/* # of 11g/n BSSs seen in 2.4G band */
} p2pwlu_cs_chan_info;

/* find a,b,g APs from scan results */
static void
p2pwlu_cs_parse_scanresults(chanspec_t chspec,
	p2pwlu_cs_chan_info *ci, wl_scan_results_t *list)
{
	wl_bss_info_t *bi;
	uint32 i;

	memset(ci, 0, sizeof(p2pwlu_cs_chan_info));
	ci->chspec = chspec;

	bi = list->bss_info;
	for (i = 0; i < list->count; i++,
		bi = (wl_bss_info_t*)((int8*)bi + dtoh32(bi->length))) {
		if (chspec != dtohchanspec(bi->chanspec)) continue;
		/* count BSSs in 2.4G band */
		if (CHSPEC_IS2G(chspec)) {
			if (p2pwlu_cs_is_11gbss(bi)) {
				if (ci->gAPs < MAXNBVAL(sizeof(ci->gAPs)))
					ci->gAPs ++;
			}
			else {
				if (ci->bAPs < MAXNBVAL(sizeof(ci->bAPs)))
					ci->bAPs ++;
			}
		}
		/* count BSSs in 5G band */
		else {
			if (ci->aAPs < MAXNBVAL(sizeof(ci->aAPs)))
				ci->aAPs ++;
		}
	}
}

static int
p2pwlu_cs_get_chspec_list(p2papi_instance_t *hdl, chanspec_t *chspec_list)
{
	/* 5Ghz bands have highest priority */
	int bands[] = {
		IEEE_5GHZ_20MHZ_CLASS_1,
		IEEE_5GHZ_20MHZ_CLASS_3,
		IEEE_5GHZ_20MHZ_CLASS_5,
		IEEE_2GHZ_20MHZ_CLASS_12};
	p2p_chanlist_t *cl = &hdl->non_dfs_channel_list;
	int c, i, j, count = 0;

	for (c = 0; c < sizeof(bands)/sizeof(int); c++) {
		for (i = 0; i < cl->num_entries; i++) {
			if (cl->entries[i].band == bands[c]) {
				BCMP2P_CHANNEL ch;
				ch.channel_class = (BCMP2P_CHANNEL_CLASS)cl->entries[i].band;
				for (j = 0; j < cl->entries[i].num_channels; j++) {
					ch.channel = cl->entries[i].channels[j];
					p2papi_channel_to_chspec(&ch, &chspec_list[count++]);
				}
			}
		}
	}
	return count;
}

/* scan a list of channels, parse scan results to find quite channel */
int
p2pwlu_get_quiet_channel(p2papi_instance_t *hdl, chanspec_t *chspec)
{
	p2pwlu_cs_chan_info ci[WL_NUMCHANSPECS];
	chanspec_t chspec_list[WL_NUMCHANSPECS];
	chanspec_t chspec_sel,
	chspec_max, i;
	chanspec_t chspec_cur;
	int nprobes;
	wl_scan_results_t *sr_buffer;
	int sr_bufsize;
	int ret;
	uint16 aps;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return -1;

	nprobes = 2; /* num of probes for active scan */
	ret = 0;
	chspec_sel = 0;
	chspec_max = p2pwlu_cs_get_chspec_list(hdl, chspec_list);
	if (chspec_max == 0) goto out;

	memset(&ci, 0, sizeof(ci));

	sr_bufsize = 8192;
	sr_buffer = (wl_scan_results_t *)malloc(sr_bufsize);

	if (sr_buffer == NULL) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE,
		           "p2pwlu_get_quiet_channel: sr_buffer malloc failed\n"));
		return -1;
	}

	/* walk thru all scan channels to collect needed channel info */
	for (i = 0; i < chspec_max; i++) {
		memset(sr_buffer, 0, sr_bufsize);
		chspec_cur = chspec_list[i];

		/* scan a channel */
		ret = p2pwlu_scan(hdl, CHSPEC_CHANNEL(chspec_cur), nprobes);
		if (ret) {
			printf("p2pwlu_scan() error: %d\n", ret);
			break;
		}
		ret = -1;
		while (ret != 0) {
			p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_GENERIC, 100);
			ret = p2pwlu_scan_get_results(hdl, sr_buffer, sr_bufsize);
		}

		/* parse scan results to find APs */
		p2pwlu_cs_parse_scanresults(chspec_cur, &ci[i], sr_buffer);
	}

	free(sr_buffer);
	if (ret) goto out;

	/* walk thru all scan channels to find out a channel with the least APs */
	aps = MAXNBVAL(sizeof(aps));
	chspec_sel = chspec_list[0];
	for (i = 0; i < chspec_max; i++) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2pwlu_get_quiet_channel: 0x%04x - %d %d %d\n",
			ci[i].chspec, ci[i].aAPs, ci[i].bAPs, ci[i].gAPs));
		if (ci[i].bAPs)
			continue;
		if (ci[i].gAPs + ci[i].aAPs < aps) {
			aps = ci[i].gAPs + ci[i].aAPs;
			chspec_sel = ci[i].chspec;
		}
	}

out:
	*chspec = chspec_sel;

	return ret;
}


int
p2pwlu_get_chanspec(p2papi_instance_t *hdl, chanspec_t *chspec, int bssidx)
{
	P2PWL_HDL wl;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);
	*chspec = 0;
	return p2pwl_get_chanspec(wl, chspec, bssidx);
}


int
p2pwlu_up(p2papi_instance_t* hdl)
{
	P2PWL_HDL wl;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);
	return p2pwl_up(wl);
}

int
p2pwlu_down(p2papi_instance_t* hdl)
{
	P2PWL_HDL wl;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);
	return p2pwl_down(wl);
}

BCMP2P_BOOL
p2pwlu_isup(p2papi_instance_t* hdl)
{
	P2PWL_HDL wl;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);
	return p2pwl_isup(wl);
}



int
p2pwlu_set_apsta(p2papi_instance_t* hdl, int val)
{
	P2PWL_HDL wl;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);
	return p2pwl_set_apsta(wl, val);
}

int
p2pwlu_get_apsta(p2papi_instance_t* hdl)
{
	P2PWL_HDL wl;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);
	return p2pwl_get_apsta(wl);
}

int
p2pwlu_set_ssid(p2papi_instance_t* hdl, uint8 *name, uint32 len)
{
	P2PWL_HDL wl;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);
/*
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2pwlu_set_ssid: bssidx=%u ssid=%s\n",
		hdl->bssidx[P2PAPI_BSSCFG_CONNECTION], name));
*/
	return p2pwl_set_ssid(wl, hdl->bssidx[P2PAPI_BSSCFG_CONNECTION], name, len);
}

int
p2pwlu_get_ssid(p2papi_instance_t* hdl, wlc_ssid_t *ssid)
{
	P2PWL_HDL wl;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);
	return p2pwl_get_ssid(wl, hdl->bssidx[P2PAPI_BSSCFG_CONNECTION], ssid);
}

int
p2pwlu_set_wsec_restrict(p2papi_instance_t* hdl, int val)
{
	int ret;

	P2PAPI_CHECK_P2PHDL(hdl);

	ret = p2pwlu_bssiovar_setint(hdl, "wsec_restrict",
		hdl->bssidx[P2PAPI_BSSCFG_CONNECTION], val);
	if (ret < 0)
		return BCMP2P_IOCTL_OPERATION_NOT_ALLOWED;
	else
		return BCMP2P_SUCCESS;
}

/* Turn on APSTA mode if not already on.  Returns BCMP2P_SUCCESS if success */
static BCMP2P_STATUS
p2pwlu_enable_apsta(p2papi_instance_t* hdl, bool wl_down_allowed)
{
	int val;
	int ret;

	/* If APSTA mode is already on, we're done */
	val = p2pwlu_get_apsta(hdl);
	if (val == 1) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2pwlu_enable_apsta: APSTA already on\n"));
		return BCMP2P_SUCCESS;
	}

	/* if the WL driver is up, bring it down first.  APSTA mode can only be
	 * changed when the WL driver is down.
	 */
	if (p2pwlu_isup(hdl)) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2pwlu_enable_apsta: APSTA not on but driver is already up.\n"));
		if (wl_down_allowed) {
			p2pwlu_down(hdl);
			/* Sleep to wait for the driver to go down - not needed? */
	/*		p2papi_osl_sleep_ms(P2PAPI_OSL_SLEEP_WAIT_WL_DOWN, 100); */
		} else {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				"p2pwlu_enable_apsta: need to do WL down but not allowed!\n"));
			return BCMP2P_FAIL_TO_SETUP_P2P_APSTA;
		}
	}

	/* Turn on APSTA mode */
	ret = p2pwlu_set_apsta(hdl, 1);
	if (ret < 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2pwlu_enable_apsta: set APSTA 1 failed (ret=%d)\n", ret));
		return BCMP2P_FAIL_TO_SETUP_P2P_APSTA;
	}

	/* Check that APSTA did get turned on */
	val = p2pwlu_get_apsta(hdl);
	if (val < 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2pwlu_enable_apsta: get APSTA failed (ret=%d)\n", ret));
		return BCMP2P_FAIL_TO_SETUP_P2P_APSTA;
	}
	if (val == 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"p2pwlu_enable_apsta: set APSTA 1 had no effect\n"));
		if (p2pwlu_isup(hdl)) {
			BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
				" because the WL driver is still up!\n"));
		}
		return BCMP2P_FAIL_TO_SETUP_P2P_APSTA;
	}

	return BCMP2P_SUCCESS;
}

/* Apply the APSTA and P2P WL settings that need to be applied before
 * bringing up the WL interface.
 * Returns:
 * - 0 if success.
 * - BCMP2P_FAIL_TO_SETUP_P2P_APSTA if the apsta enable ioctl fails.
 * - BCMP2P_IOCTL_OPERATION_NOT_ALLOWED if other ioctls fail.
 */
int
p2pwlu_p2p_apsta_setup(p2papi_instance_t* hdl)
{
	BCMP2P_UINT32 val;
	int ret;
	BCMP2P_STATUS retval = BCMP2P_SUCCESS;
	P2PWL_HDL wl;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2pwlu_p2p_apsta_setup: disc-bssidx=%d conn-bssidx=%d\n",
		hdl->bssidx[P2PAPI_BSSCFG_DEVICE],
		hdl->bssidx[P2PAPI_BSSCFG_CONNECTION]));


	/* if APSTA mode is not on, turn it on */
	ret = p2pwlu_enable_apsta(hdl, FALSE);
	if (ret != 0) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "Failed to set APSTA mode\n"));
		retval = BCMP2P_FAIL_TO_SETUP_P2P_APSTA;
		return (int) retval;
	}

	val = WLC_PLCP_SHORT;
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl plcphdr auto\n"));
	ret = p2papi_ioctl_set(hdl, WLC_SET_PLCPHDR, &val, sizeof(val), 0);
	if (ret != 0) {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "WLC_SET_PLCPHDR failed\n"));
	}

	/* Turn off P2P discovery in case it was previously left on */
	(void) p2pwl_set_p2p_discovery(wl, 0);

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2pwlu_p2p_apsta_setup: done\n"));
	return (int) retval;
}

void
p2pwlu_dbg_show_all_status(void* handle)
{
	p2papi_instance_t* hdl = (p2papi_instance_t*) handle;
	chanspec_t chspec;
	BCMP2P_BOOL on;
	BCMP2P_IP_ADDR ipaddr, netmask;

	P2PAPI_CHECK_P2PHDL(hdl);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"+++++++++++++++ p2pwlu_dbg_show_all_status: begin\n"));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"state=%u conn-ing=%d conn-ed=%d ap=%d wpsenr-ing=%d discon-ing=%d\n",
		hdl->conn_state, hdl->is_connecting, hdl->is_connected, hdl->is_ap,
		hdl->is_wps_enrolling, hdl->is_disconnecting));
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"discov-ing=%d discov_on=%d search-ena=%d discov-bssidx=%d\n",
		hdl->is_discovering, hdl->is_p2p_discovery_on,
		hdl->discovery_search_enabled,
		hdl->bssidx[P2PAPI_BSSCFG_DEVICE]));
	on = p2pwlu_isup(hdl);
	on = p2pwlu_bss_isup(hdl);
	on = p2pwlu_is_associated(hdl);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "---wl status: %d\n", on));
	p2pwlu_get_chanspec(hdl, &chspec, 0);
	p2pwlu_get_chanspec(hdl, &chspec, hdl->bssidx[P2PAPI_BSSCFG_DEVICE]);
	p2pwlu_get_chanspec(hdl, &chspec, hdl->bssidx[P2PAPI_BSSCFG_CONNECTION]);
	p2pwlu_get_apsta(hdl);

	p2papi_get_ip_addr(hdl, &ipaddr, &netmask);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "ipaddr=0x%x netmask=0x%x\n",
		ipaddr, netmask));

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"--------------- p2pwlu_dbg_show_all_status: end\n"));
}

int
p2pwlu_send_act_frame(p2papi_instance_t *hdl, wl_af_params_t *af_params, int bssidx)
{
	P2PWL_HDL wl;
	int ret;
	uint8 *ioctl_buf;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);
	BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "p2pwlu_send_act_frame: wlp2pstate=%u\n",
		hdl->wl_p2p_state));

	/* Lock our instance data because we will be writing its ioctl buffer */
	P2PAPI_DATA_LOCK(hdl);

	ioctl_buf = P2PAPI_IOCTL_BUF(hdl);
	ret = p2pwl_send_act_frame(wl, af_params, ioctl_buf, bssidx);

	P2PAPI_DATA_UNLOCK(hdl);

	return ret;
}


/* Set the WL driver event mask that filters which WLC events to send up
 * to the applciation.
 */
int
p2pwlu_set_event_mask(p2papi_instance_t* hdl, uint8 *event_mask,
	size_t mask_len)
{
	int ret;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"---wl%s%s event_msgs 0x%02x%02x%02x%02x%02x%02x%02x%02x\n",
		p2posl_get_netif_name_prefix(P2PAPI_GET_WL_HDL(hdl)),
		p2posl_get_netif_name_bss(P2PAPI_GET_WL_HDL(hdl), 0),
		event_mask[7], event_mask[6], event_mask[5],
		event_mask[4], event_mask[3], event_mask[2],
		event_mask[1], event_mask[0]));
	ret = p2pwlu_bssiovar_set(hdl, "event_msgs", 0, event_mask, mask_len);
	if (ret != 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE, "wl event_msgs error %d!\n",
			ret));
	}
	return ret;
}

/* Get the WL driver event mask */
int
p2pwlu_get_event_mask(p2papi_instance_t* hdl, uint8 *event_mask, size_t mask_len)
{
	int ret;

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"---wl%s%s event_msgs\n",
		p2posl_get_netif_name_prefix(P2PAPI_GET_WL_HDL(hdl)),
		p2posl_get_netif_name_bss(P2PAPI_GET_WL_HDL(hdl), 0)));
	ret = p2pwlu_bssiovar_get(hdl, "event_msgs", 0, event_mask, mask_len);
	if (ret == 0) {
		BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
			"                       ==> 0x%02x%02x%02x%02x%02x%02x%02x%02x\n",
			event_mask[7], event_mask[6], event_mask[5],
			event_mask[4], event_mask[3], event_mask[2],
			event_mask[1], event_mask[0]));
	} else {
		BCMP2PLOG((BCMP2P_LOG_ERR, TRUE, "---wl event_msgs: error %d\n", ret));
	}
	return ret;
}

/* Get a list of all STAs associated to this AP */
int
p2pwlu_get_assoclist(p2papi_instance_t* hdl, uint32 max_entries,
	struct ether_addr out_assoclist[], uint32 *out_num_entries)
{
	int i;
	P2PWL_HDL wl;
	int status = BCMP2P_SUCCESS;
	uint8 *ioctl_buf = P2PAPI_IOCTL_BUF(hdl);
	struct maclist *maclist = (struct maclist *) ioctl_buf;
	uint32 maclist_count;
	struct ether_addr *ea;
	int result;
	int count = 0;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;
	wl = P2PAPI_GET_WL_HDL(hdl);
	*out_num_entries = 0;

	P2PAPI_DATA_LOCK(hdl);
	result = p2pwl_get_assoc_count(wl, FALSE, ioctl_buf, &count,
		hdl->bssidx[P2PAPI_BSSCFG_CONNECTION]);
	if (result != 0) {
		status = result;
	} else if (count > 0) {
		maclist_count = dtoh32(maclist->count);
		if (maclist_count > max_entries) {
			/* caller provided buffer is not large enough */
			status = BCMP2P_NOT_ENOUGH_SPACE;
			maclist_count = max_entries;
		}

		*out_num_entries = maclist_count;
		for (i = 0, ea = maclist->ea;
			i < (int) maclist_count;
			i++, ea++) {
			memcpy(&out_assoclist[i], ea, sizeof(out_assoclist[i]));
			BCMP2PLOG((BCMP2P_LOG_VERB, TRUE,
				"p2pwlu_get_assoclist: %d) %02x:%02x:%02x:%02x:%02x:%02x\n",
				i, out_assoclist[i].octet[0], out_assoclist[i].octet[1],
				out_assoclist[i].octet[2], out_assoclist[i].octet[3],
				out_assoclist[i].octet[4], out_assoclist[i].octet[5]));
		}
	}
	P2PAPI_DATA_UNLOCK(hdl);

	return status;
}



/* Deauthenticate an associated STA.  Returns 0 if success */
int
p2pwlu_deauth_sta(p2papi_instance_t* hdl, unsigned char* sta_mac,
	int dot11_reason)
{
	P2PWL_HDL wl;
	scb_val_t scb_val;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);

	memcpy(scb_val.ea.octet, sta_mac, sizeof(scb_val.ea.octet));
	scb_val.val = htod32(dot11_reason);
	return p2posl_wl_ioctl_bss(wl, WLC_SCB_DEAUTHENTICATE_FOR_REASON,
		&scb_val, sizeof(scb_val), TRUE,
		hdl->bssidx[P2PAPI_BSSCFG_CONNECTION]);
}

/* Set the driver's P2P discovery state */
int
p2pwlu_set_p2p_mode(p2papi_instance_t* hdl, uint8 wl_p2p_disc_state,
	chanspec_t chspec, uint16 ms)
{
	int ret;
	P2PWL_HDL wl;

	P2PAPI_CHECK_P2PHDL(hdl);
	if (!P2PAPI_OSL_CHECK_HDL(hdl->osl_hdl))
		return -1;
	wl = P2PAPI_GET_WL_HDL(hdl);

	ret = p2pwl_set_p2p_mode(wl, wl_p2p_disc_state, chspec, ms,
		hdl->bssidx[P2PAPI_BSSCFG_DEVICE]);
	if (ret == 0)
		hdl->wl_p2p_state = wl_p2p_disc_state;

	return ret;
}

/* Check if 'p2p' is supported in the driver */
int
p2pwlu_is_p2p_supported(p2papi_instance_t* hdl)
{
	P2PWL_HDL wl;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);
	return p2pwl_is_p2p_supported(wl);
}

/* opportunistic power save */
int
p2pwlu_set_ops(p2papi_instance_t* hdl, bool enable, uint8 ctwindow)
{
	P2PWL_HDL wl;
	wl_p2p_ops_t ops;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);

	memset(&ops, 0, sizeof(ops));
	if (enable) {
		ops.ops = 1;
		ops.ctw = ctwindow;
	}
	return p2pwl_iovar_set_bss(wl, "p2p_ops", &ops, sizeof(ops),
		hdl->bssidx[P2PAPI_BSSCFG_CONNECTION]);
}

int
p2pwlu_get_ops(p2papi_instance_t* hdl, bool *enable, uint8 *ctwindow)
{
	P2PWL_HDL wl;
	wl_p2p_ops_t ops;
	int ret = -1;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);

	memset(&ops, 0, sizeof(ops));
	ret = p2pwl_iovar_get_bss(wl, "p2p_ops", &ops, sizeof(ops),
		hdl->bssidx[P2PAPI_BSSCFG_CONNECTION]);
	if (ret == 0) {
		*enable = (ops.ops == 0) ? false : true;
		*ctwindow = ops.ctw;
	}
	return ret;
}

/* notice of absence */
int
p2pwlu_set_noa(p2papi_instance_t* hdl,
	uint8 type, uint8 action, uint8 option,
	int num_desc, wl_p2p_sched_desc_t *desc)
{
	P2PWL_HDL wl;
	int size;
	wl_p2p_sched_t *noa;
	int ret = -1;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);

	/* no desc for reset */
	if (action == WL_P2P_SCHED_ACTION_RESET)
		num_desc = 0;

	/* buffer size */
	size = sizeof(wl_p2p_sched_t) - sizeof(wl_p2p_sched_desc_t) +
		num_desc * sizeof(wl_p2p_sched_desc_t);

	noa = (wl_p2p_sched_t *) P2PAPI_MALLOC(size);

	if (noa != 0) {
		int i;
		memset(noa, 0, size);
		noa->type = type;
		noa->action = action;
		noa->option = option;
		for (i = 0; i < num_desc; i++) {
			noa->desc[i].start = htod32(desc[i].start),
			noa->desc[i].interval = htod32(desc[i].interval),
			noa->desc[i].duration = htod32(desc[i].duration),
			noa->desc[i].count = htod32(desc[i].count);
		}
		ret = p2pwl_iovar_set_bss(wl, "p2p_noa", noa, size,
			hdl->bssidx[P2PAPI_BSSCFG_CONNECTION]);
	}

	P2PAPI_FREE(noa);
	return ret;
}

int
p2pwlu_get_noa(p2papi_instance_t* hdl,
	uint8 *type, uint8 *action, uint8 *option,
	int max_num_desc, int *num_desc, wl_p2p_sched_desc_t *desc)
{
	P2PWL_HDL wl;
	int max_desc = 16;
	int size;
	wl_p2p_sched_t *noa;
	int ret = -1;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);

	/* buffer size */
	size = sizeof(wl_p2p_sched_t) - sizeof(wl_p2p_sched_desc_t) +
		max_desc * sizeof(wl_p2p_sched_desc_t);

	noa = (wl_p2p_sched_t *)P2PAPI_MALLOC(size);

	if (noa != 0) {
		memset(noa, 0, size);
		ret = p2pwl_iovar_get_bss(wl, "p2p_noa", noa, size,
			hdl->bssidx[P2PAPI_BSSCFG_CONNECTION]);
		if (ret == 0) {
			int i;
			*type = noa->type;
			*action = noa->action;
			*option = noa->option;
			for (i = 0; i < max_desc; i++) {
				if (i == max_num_desc || noa->desc[i].count == 0)
					break;
				desc[i].start = dtoh32(noa->desc[i].start),
				desc[i].interval = dtoh32(noa->desc[i].interval),
				desc[i].duration = dtoh32(noa->desc[i].duration),
				desc[i].count = dtoh32(noa->desc[i].count);
			}
			*num_desc = i;
		}
	}

	P2PAPI_FREE(noa);
	return ret;
}

int
p2pwlu_set_PM(p2papi_instance_t* hdl, int val, int bssidx)
{
	P2PWL_HDL wl;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);
	return p2pwl_set_PM(wl, val, bssidx);
}

int
p2pwlu_get_PM(p2papi_instance_t* hdl, int* val, int bssidx)
{
	P2PWL_HDL wl;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);
	return p2pwl_get_PM(wl, val, bssidx);
}


int
p2pwlu_set_listen_interval(p2papi_instance_t *hdl, unsigned int interval, int bssidx)
{
	P2PWL_HDL wl;
	int ret;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2pwlu_set_listen_interval: interval=%u\n", interval));

	ret = p2pwl_set_listen_interval(wl, interval, bssidx);

	return ret;
}

int
p2pwlu_set_wme_apsd_sta(p2papi_instance_t *hdl, uint8 maxSPLen,
	uint8 acBE, uint8 acBK, uint8 acVI, uint8 acVO, int bssidx)
{
	P2PWL_HDL wl;
	int ret;

	P2PAPI_CHECK_P2PHDL(hdl);
	wl = P2PAPI_GET_WL_HDL(hdl);

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2pwlu_set_wme_apsd_sta: maxSPLen = 0x%x acBE= 0x%x acBK = 0x%x\n"
		"acVI = 0x%x acVO = 0x%x\n", maxSPLen, acBE, acBK, acVI, acVO));

	ret = p2pwl_set_wme_apsd_sta(wl, maxSPLen, acBE, acBK, acVI, acVO, bssidx);

	return ret;
}

int
p2pwlu_set_roam_off(p2papi_instance_t *hdl, unsigned int roam_off, int bssidx)
{
	P2PWL_HDL wl;
	int ret;

	if (!P2PAPI_CHECK_P2PHDL(hdl))
		return BCMP2P_INVALID_HANDLE;
	wl = P2PAPI_GET_WL_HDL(hdl);

	BCMP2PLOG((BCMP2P_LOG_MED, TRUE,
		"p2pwlu_set_roam_off: roam_off=%u\n", roam_off));

	ret = p2pwl_set_roam_off(wl, roam_off, bssidx);

	return ret;
}
