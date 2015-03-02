/*
 * wl rrm command module
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wluc_rrm.c 458728 2014-02-27 18:15:25Z $
 */

#ifdef WIN32
#include <windows.h>
#endif

#include <wlioctl.h>


/* Because IL_BIGENDIAN was removed there are few warnings that need
 * to be fixed. Windows was not compiled earlier with IL_BIGENDIAN.
 * Hence these warnings were not seen earlier.
 * For now ignore the following warnings
 */
#ifdef WIN32
#pragma warning(push)
#pragma warning(disable : 4244)
#pragma warning(disable : 4761)
#endif

#include <bcmutils.h>
#include <bcmendian.h>
#include "wlu_common.h"
#include "wlu.h"

static cmd_func_t wl_rrm;
static cmd_func_t wl_rrm_nbr_req;
static cmd_func_t wl_rrm_bcn_req;
static cmd_func_t wl_rrm_chload_req;
static cmd_func_t wl_rrm_noise_req;
static cmd_func_t wl_rrm_frame_req;
static cmd_func_t wl_rrm_stat_req;
static cmd_func_t wl_rrm_stat_rpt;
static cmd_func_t wl_rrm_lm_req;
static cmd_func_t wl_rrm_nbr_list;
static cmd_func_t wl_rrm_nbr_del_nbr;
static cmd_func_t wl_rrm_nbr_add_nbr;

static cmd_t wl_rrm_cmds[] = {
	{ "rrm", wl_rrm, WLC_GET_VAR, WLC_SET_VAR,
	"enable or disable RRM feature\n"
	"\tUsage: wl rrm [0/1] to disable/enable RRM feature"},
	{ "rrm_bcn_req", wl_rrm_bcn_req, -1, WLC_SET_VAR,
	"send 11k beacon measurement request\n"
	"\tUsage: wl rrm_bcn_req [bcn mode] [da] [duration] [random int] [channel] [ssid]"
	" [repetitions]"},
	{ "rrm_chload_req", wl_rrm_chload_req, -1, WLC_SET_VAR,
	"send 11k channel load measurement request\n"
	"\tUsage: wl rrm_chload_req [regulatory] [da] [duration] [random int] [channel]"
	" [repetitions]"},
	{ "rrm_noise_req", wl_rrm_noise_req, -1, WLC_SET_VAR,
	"send 11k noise measurement request\n"
	"\tUsage: wl rrm_noise_req [regulatory] [da] [duration] [random int] [channel]"
	" [repetitions] "},
	{ "rrm_frame_req", wl_rrm_frame_req, -1, WLC_SET_VAR,
	"send 11k frame measurement request\n"
	"\tUsage: wl rrm_frame_req [regulatory] [da] [duration] [random int] [channel] [ta]"
	" [repetitions]"},
	{ "rrm_stat_req", wl_rrm_stat_req, -1, WLC_SET_VAR,
	"send 11k stat measurement request\n"
	"\tUsage: wl rrm_stat_req [da] [random int] [duration] [peer] [group id] [repetitions]"},
	{ "rrm_stat_rpt", wl_rrm_stat_rpt, -1, WLC_GET_VAR,
	"Read 11k stat measurement report from STA\n"
	"\tUsage: wl rrm_stat_rpt [mac]"},
	{ "rrm_lm_req", wl_rrm_lm_req, -1, WLC_SET_VAR,
	"send 11k link measurement request\n"
	"\tUsage: wl rrm_lm_req [da]"},
	{ "rrm_nbr_req", wl_rrm_nbr_req, -1, WLC_SET_VAR,
	"send 11k neighbor report measurement request\n"
	"\tUsage: wl rrm_nbr_req [ssid]"},
	{ "rrm_nbr_list", wl_rrm_nbr_list, WLC_GET_VAR, -1,
	"get 11k neighbor report list\n"
	"\tUsage: wl rrm_nbr_list"},
	{ "rrm_nbr_del_nbr", wl_rrm_nbr_del_nbr, -1, WLC_SET_VAR,
	"delete node from 11k neighbor report list\n"
	"\tUsage: wl rrm_nbr_del_nbr [bssid]"},
	{ "rrm_nbr_add_nbr", wl_rrm_nbr_add_nbr, -1, WLC_SET_VAR,
	"add node to 11k neighbor report list\n"
	"\tUsage: wl rrm_nbr_add_nbr [bssid] [bssid info] [regulatory] [channel] [phytype]"},
	{ NULL, NULL, 0, 0, NULL }
};

static char *buf;

/* module initialization */
void
wluc_rrm_module_init(void)
{
	/* get the global buf */
	buf = wl_get_buf();

	/* register rrm commands */
	wl_module_cmds_register(wl_rrm_cmds);
}

/* RM Enable Capabilities */
static dbg_msg_t rrm_msgs[] = {
	{DOT11_RRM_CAP_LINK,	"Link_Measurement"},				/* bit0 */
	{DOT11_RRM_CAP_NEIGHBOR_REPORT,	"Neighbor_Report"},			/* bit1 */
	{DOT11_RRM_CAP_PARALLEL,	"Parallel_Measurement"},		/* bit2 */
	{DOT11_RRM_CAP_REPEATED,	"Repeated_Measurement"},		/* bit3 */
	{DOT11_RRM_CAP_BCN_PASSIVE,	"Beacon_Passive"},			/* bit4 */
	{DOT11_RRM_CAP_BCN_ACTIVE,	"Beacon_Active"},			/* bit5 */
	{DOT11_RRM_CAP_BCN_TABLE,	"Beacon_Table"},			/* bit6 */
	{DOT11_RRM_CAP_BCN_REP_COND,	"Beacon_measurement_Reporting_Condition"}, /* bit7 */
	{DOT11_RRM_CAP_FM,	"Frame_Measurement"},				/* bit8 */
	{DOT11_RRM_CAP_CLM,	"Channel_load_Measurement"},			/* bit9 */
	{DOT11_RRM_CAP_NHM,	"Noise_Histogram_measurement"},			/* bit10 */
	{DOT11_RRM_CAP_SM,	"Statistics_Measurement"},			/* bit11 */
	{DOT11_RRM_CAP_LCIM,	"LCI_Measurement"},				/* bit12 */
	{DOT11_RRM_CAP_LCIA,	"LCI_Azimuth"},					/* bit13 */
	{DOT11_RRM_CAP_TSCM,	"Tx_Stream_Category_Measurement"},		/* bit14 */
	{DOT11_RRM_CAP_TTSCM,	"Triggered_Tx_stream_Category_Measurement"},	/* bit15 */
	{DOT11_RRM_CAP_AP_CHANREP,	"AP_Channel_Report"},			/* bit16 */
	{DOT11_RRM_CAP_RMMIB,	"RM_MIB"},					/* bit17 */
	/* bit 18-26, unused */
	{DOT11_RRM_CAP_MPTI,	"Measurement_Pilot_Transmission_Information"},	/* bit27 */
	{DOT11_RRM_CAP_NBRTSFO,	"Neighbor_Report_TSF_Offset"},			/* bit28 */
	{DOT11_RRM_CAP_RCPI,	"RCPI_Measurement"},				/* bit29 */
	{DOT11_RRM_CAP_RSNI,	"RSNI_Measurement"},				/* bit30 */
	{DOT11_RRM_CAP_BSSAAD,	"BSS_Average_Access_Delay"},			/* bit31 */
	{DOT11_RRM_CAP_BSSAAC,	"BSS_Available_Admission_Capacity"},		/* bit32 */
	{DOT11_RRM_CAP_AI,	"Antenna_Information"},				/* bit33 */
	{0,		NULL}
};

static bool rrm_input_validation(uint val, uint hval, dbg_msg_t *dbg_msg)
{
	int i;
	uint32 flag = 0;

	if ((val == 0) && (hval == 0))
		return TRUE;

	for (i = 0; dbg_msg[i].value <= DOT11_RRM_CAP_BSSAAD; i++)
		flag |= 1 << dbg_msg[i].value;
	flag = ~flag;
	if (val & flag)
		return FALSE;

	flag = 0;
	if (hval != 0) {
		for (; dbg_msg[i].value; i++) {
			flag |= 1 << (dbg_msg[i].value - DOT11_RRM_CAP_BSSAAC);
		}
		flag = ~flag;
		if (hval & flag)
			return FALSE;
	}

	return TRUE;
}

static int
wl_rrm(void *wl, cmd_t *cmd, char **argv)
{
	int err, i;
	uint hval = 0, val = 0, len, found, rmcap_del = 0, rmcap2_del = 0;
	uint rmcap_add = 0, rmcap2_add = 0;
	char *endptr = NULL;
	dbg_msg_t *dbg_msg = rrm_msgs;
	void *ptr = NULL;
	dot11_rrm_cap_ie_t rrm_cap, *reply;
	uint high = 0, low = 0, bit = 0, hbit = 0;
	const char *cmdname = "rrm";

	UNUSED_PARAMETER(cmd);

	err = wlu_var_getbuf_sm(wl, cmdname, &rrm_cap, sizeof(rrm_cap), &ptr);
	if (err < 0)
		return err;
	reply = (dot11_rrm_cap_ie_t *)ptr;

	high = reply->cap[4];
	low = reply->cap[0] | (reply->cap[1] << 8) | (reply->cap[2] << 16) | (reply->cap[3] << 24);
	if (!*++argv) {
		if (high != 0)
			printf("0x%x%08x", high, low);
		else
			printf("0x%x ", low);
		for (i = 0; ((bit = dbg_msg[i].value) <= DOT11_RRM_CAP_BSSAAD); i++) {
			if (low & (1 << bit))
				printf(" %s", dbg_msg[i].string);
		}
		for (; (hbit = dbg_msg[i].value); i++) {
			if (high & (1 << hbit))
				printf(" %s", dbg_msg[i].string);
		}
		printf("\n");

		return err;
	}
	while (*argv) {
		char *s = *argv;
		char t[32];

		found = 0;
		if (*s == '+' || *s == '-')
			s++;
		else {
			/* used for clearing previous value */
			rmcap_del = ~0;
			rmcap2_del = ~0;
		}
		val = strtoul(s, &endptr, 0);
		/* Input is decimal number or hex with prefix 0x and > 32 bits */
		if (val == 0xFFFFFFFF) {
			if (!(*s == '0' && *(s+1) == 'x')) {
				fprintf(stderr,
				"Msg bits >32 take only numerical input in hex\n");
				val = 0;
			} else {
				/* Input number with prefix 0x */
				char c[32] = "0x";
				len = strlen(s);
				hval = strtoul(strncpy(t, s, len-8), &endptr, 0);
				*endptr = 0;
				s = s + strlen(t);
				s = strcat(c, s);
				val = strtoul(s, &endptr, 0);
				/* Input number > 64bit */
				if (hval == 0xFFFFFFFF) {
					fprintf(stderr, "Invalid entry for RM Capabilities\n");
					hval = 0;
					val = 0;
				}
			}
		}
		/* validet the input number */
		if (!rrm_input_validation(val, hval, dbg_msg))
			goto usage;
		/* Input is a string */
		if (*endptr != '\0') {
			for (i = 0; ((bit = dbg_msg[i].value) <= DOT11_RRM_CAP_BSSAAD); i++) {
				if (stricmp(dbg_msg[i].string, s) == 0) {
					found = 1;
					break;
				}
			}
			if (!found) {
				for (; (hbit = dbg_msg[i].value); i++) {
					if (stricmp(dbg_msg[i].string, s) == 0)
						break;
				}
				if (hbit)
					hval = 1 << (hbit - DOT11_RRM_CAP_BSSAAC);
				else
					hval = 0;
			} else {
				val = 1 << bit;
			}
			if (!val && !hval)
			      goto usage;
		}
		if (**argv == '-') {
			rmcap_del |= val;
			if (!found)
				rmcap2_del |= hval;
		}
		else {
			rmcap_add |= val;
			if (!found)
				rmcap2_add |= hval;
		}
		++argv;
	}

	low &= ~rmcap_del;
	high &= ~rmcap2_del;
	low |= rmcap_add;
	high |= rmcap2_add;

	rrm_cap.cap[4] = high;
	rrm_cap.cap[0] = low & 0x000000ff;
	rrm_cap.cap[1] = (low & 0x0000ff00) >> 8;
	rrm_cap.cap[2] = (low & 0x00ff0000) >> 16;
	rrm_cap.cap[3] = (low & 0xff000000) >> 24;

	err = wlu_var_setbuf(wl, cmdname, &rrm_cap, sizeof(dot11_rrm_cap_ie_t));
	return err;

usage:
	fprintf(stderr, "msg values may be a list of numbers or names from the following set.\n");
	fprintf(stderr, "Use a + or - prefix to make an incremental change.");
	for (i = 0; (bit = dbg_msg[i].value) <= DOT11_RRM_CAP_BSSAAD; i++) {
		fprintf(stderr, "\n0x%04x %s", (1 << bit), dbg_msg[i].string);
	}
	for (; (hbit = dbg_msg[i].value); i++) {
		hbit -= DOT11_RRM_CAP_BSSAAC;
		fprintf(stderr, "\n0x%x00000000 %s", (1 << hbit), dbg_msg[i].string);
	}
	fprintf(stderr, "\n");
	return BCME_OK;
}

static int
wl_rrm_stat_req(void *wl, cmd_t *cmd, char **argv)
{
	int err = 0;
	const char *cmdname = "rrm_stat_req";
	statreq_t sreq_buf;

	UNUSED_PARAMETER(cmd);
	memset(&sreq_buf, 0, sizeof(statreq_t));

	if (argv[1]) {
		/* da */
		if (!wl_ether_atoe(argv[1], &sreq_buf.da)) {
			printf("wl_rrm_stat_req parsing da failed\n");
			return BCME_USAGE_ERROR;
		}
	}
	/* random interval */
	if (argv[2]) {
		sreq_buf.random_int = htod32(strtoul(argv[2], NULL, 0));
	}
	/* duration */
	if (argv[3]) {
		sreq_buf.dur = htod32(strtoul(argv[3], NULL, 0));
	}
	/* peer address */
	if (argv[4]) {
		if (!wl_ether_atoe(argv[4], &sreq_buf.peer)) {
			printf("wl_rrm_stat_req parsing peer failed\n");
			return BCME_USAGE_ERROR;
		}
	}
	/* group id */
	if (argv[5]) {
		sreq_buf.group_id =
			htod32(strtoul(argv[5], NULL, 0));
	}
	/* repetitions */
	if (argv[6]) {
		sreq_buf.reps = htod32(strtoul(argv[6], NULL, 0));
	}
	err = wlu_iovar_set(wl, cmdname, &sreq_buf, sizeof(sreq_buf));
	return err;
}

static int
wl_rrm_stat_rpt(void *wl, cmd_t *cmd, char **argv)
{
	int ret = BCME_USAGE_ERROR;
	statrpt_t *rpt_ptr, rpt;
	int cnt;

	if (!*++argv) return -1;

	/* get sta mac address */
	if (!wl_ether_atoe(*argv++, &rpt.addr))
		goto done;

	memset(buf, 0, WLC_IOCTL_MEDLEN);
	if ((ret = wlu_iovar_getbuf(wl, cmd->name, (void *) &rpt,
		sizeof(rpt), buf, WLC_IOCTL_MEDLEN)) < 0) {
		fprintf(stderr, "ERROR: cmd:%s\n", cmd->name);
		goto done;
	}

	/* display the sta info */
	rpt_ptr = (statrpt_t *)buf;
	rpt_ptr->ver = dtoh16(rpt_ptr->ver);

	/* Report unrecognized version */
	if (rpt_ptr->ver != WL_RRM_RPT_VER) {
		fprintf(stderr, "ERROR: Mismatch ver[%d] Driver ver[%d]\n",
			WL_RRM_RPT_VER, rpt_ptr->ver);
		goto done;
	}

	printf("ver:%d timestamp:%u flag:%d len:%d\n",
		rpt_ptr->ver, dtoh32(rpt_ptr->timestamp),
		dtoh16(rpt_ptr->flag), rpt_ptr->len);
	for (cnt = 0; cnt < rpt_ptr->len; cnt++) {
		if (cnt % 8 == 0)
			printf("\n[%d]:", cnt);
		printf("[0x%02x][%d] ", rpt_ptr->data[cnt], (signed char)(rpt_ptr->data[cnt]));
	}
	printf("\n");

done:
	return ret;
}

static int
wl_rrm_frame_req(void *wl, cmd_t *cmd, char **argv)
{
	int err = 0;
	const char *cmdname = "rrm_frame_req";
	framereq_t freq_buf;

	UNUSED_PARAMETER(cmd);

	memset(&freq_buf, 0, sizeof(framereq_t));
	if (argv[1]) {
		/* Regulatory class */
		freq_buf.reg = htod32(strtoul(argv[1], NULL, 0));
	}

	/* da */
	if (argv[2]) {
		if (!wl_ether_atoe(argv[2], &freq_buf.da)) {
			printf("wl_rrm_frame_req parsing da failed\n");
			return BCME_USAGE_ERROR;
		}
	}
	/* duration */
	if (argv[3]) {
		freq_buf.dur = htod32(strtoul(argv[3], NULL, 0));
	}
	/* random interval */
	if (argv[4]) {
		freq_buf.random_int = htod32(strtoul(argv[4], NULL, 0));
	}
	/* channel */
	if (argv[5]) {
		freq_buf.chan = htod32(strtoul(argv[5], NULL, 0));
	}
	/* transmit address */
	if (argv[6]) {
		if (!wl_ether_atoe(argv[6], &freq_buf.ta)) {
			printf("wl_rrm_frame_req parsing ta failed\n");
			return BCME_USAGE_ERROR;
		}
	}
	/* repetitions */
	if (argv[7]) {
		freq_buf.reps = htod32(strtoul(argv[7], NULL, 0));
	}
	err = wlu_iovar_set(wl, cmdname, &freq_buf, sizeof(freq_buf));
	return err;
}

static int
wl_rrm_chload_req(void *wl, cmd_t *cmd, char **argv)
{
	int err = 0;
	const char *cmdname = "rrm_chload_req";
	rrmreq_t chreq_buf;

	UNUSED_PARAMETER(cmd);
	memset(&chreq_buf, 0, sizeof(rrmreq_t));

	if (argv[1]) {
		/* Regulatory class */
		chreq_buf.reg = htod32(strtoul(argv[1], NULL, 0));
	}
	/* da */
	if (argv[2]) {
		if (!wl_ether_atoe(argv[2], &chreq_buf.da)) {
			printf("wl_rrm_chload_req parsing da failed\n");
			return BCME_USAGE_ERROR;
		}
	}
	/* duration */
	if (argv[3]) {
		chreq_buf.dur = htod32(strtoul(argv[3], NULL, 0));
	}
	/* random interval */
	if (argv[4]) {
		chreq_buf.random_int = htod32(strtoul(argv[4], NULL, 0));
	}
	/* channel */
	if (argv[5]) {
		chreq_buf.chan = htod32(strtoul(argv[5], NULL, 0));
	}
	/* repetitions */
	if (argv[6]) {
		chreq_buf.reps = htod32(strtoul(argv[6], NULL, 0));
	}
	err = wlu_iovar_set(wl, cmdname, &chreq_buf, sizeof(chreq_buf));
	return err;
}

static int
wl_rrm_noise_req(void *wl, cmd_t *cmd, char **argv)
{
	int err = 0;
	const char *cmdname = "rrm_noise_req";
	rrmreq_t nreq_buf;

	UNUSED_PARAMETER(cmd);
	printf("wl_rrm_noise_req\n");

	memset(&nreq_buf, 0, sizeof(rrmreq_t));
	if (argv[1]) {
		/* Regulatory class */
		nreq_buf.reg = htod32(strtoul(argv[1], NULL, 0));
	}
	/* da */
	if (argv[2]) {
		if (!wl_ether_atoe(argv[2], &nreq_buf.da)) {
			printf("wl_rrm_noise_req parsing da failed\n");
			return BCME_USAGE_ERROR;
		}
	}
	/* duration */
	if (argv[3]) {
		nreq_buf.dur = htod32(strtoul(argv[3], NULL, 0));

	}
	/* random interval */
	if (argv[4]) {
		nreq_buf.random_int = htod32(strtoul(argv[4], NULL, 0));
	}
	/* channel */
	if (argv[5]) {
		nreq_buf.chan = htod32(strtoul(argv[5], NULL, 0));
	}
	/* repetitions */
	if (argv[6]) {
		nreq_buf.reps = htod32(strtoul(argv[6], NULL, 0));
	}
	err = wlu_iovar_set(wl, cmdname, &nreq_buf, sizeof(nreq_buf));
	return err;
}

static int
wl_rrm_bcn_req(void *wl, cmd_t *cmd, char **argv)
{
	int err = 0;
	uint8 mode = 0;
	const char *cmdname = "rrm_bcn_req";
	bcnreq_t bcnreq_buf;
	wlc_ssid_t ssid;

	UNUSED_PARAMETER(cmd);
	memset(&bcnreq_buf, 0, sizeof(bcnreq_t));

	if (argv[1]) {
		/* bcn mode: ACTIVE/PASSIVE/SCAN_CACHE */
		mode = htod32(strtoul(argv[1], NULL, 0));
		if (mode > 2) {
			printf("wl_rrm_bcn_req parsing bcn mode failed\n");
			return BCME_BADARG;
		}
		bcnreq_buf.bcn_mode = mode;
	}
	/* da */
	if (argv[2]) {
		if (!wl_ether_atoe(argv[2], &bcnreq_buf.da)) {
			printf("wl_rrm_bcn_req parsing da failed\n");
			return BCME_USAGE_ERROR;
		}
	}
	/* duration */
	if (argv[3]) {
		bcnreq_buf.dur = htod32(strtoul(argv[3], NULL, 0));
	}

	/* random interval */
	if (argv[4]) {
		bcnreq_buf.random_int = htod32(strtoul(argv[4], NULL, 0));
	}

	/* channel */
	if (argv[5]) {
		bcnreq_buf.channel = htod32(strtoul(argv[5], NULL, 0));
	}
	printf("wl_rrm_bcn_req:bcn mode: %d, duration: %d, "
			"chan: %d\n", mode,
			bcnreq_buf.dur, bcnreq_buf.channel);

	/* SSID */
	if (argv[6]) {
		uint32 len;

		len = strlen(argv[6]);
		if (len > DOT11_MAX_SSID_LEN) {
			printf("ssid too long\n");
			return BCME_BADARG;
		}
		memset(&ssid, 0, sizeof(wlc_ssid_t));
		memcpy(ssid.SSID, argv[6], len);
		ssid.SSID_len = len;
		memcpy(&bcnreq_buf.ssid, &ssid, sizeof(wlc_ssid_t));
	}

	/* repetitions */
	if (argv[7]) {
		bcnreq_buf.reps = htod32(strtoul(argv[7], NULL, 0));
	}

	err = wlu_iovar_set(wl, cmdname, &bcnreq_buf, sizeof(bcnreq_buf));
	return err;
}

static int
wl_rrm_lm_req(void *wl, cmd_t *cmd, char **argv)
{
	int err = 0;
	const char *cmdname = "rrm_lm_req";

	struct ether_addr da;
	UNUSED_PARAMETER(cmd);

	if (argv[1]) {
		if (!wl_ether_atoe(argv[1], &da)) {
			printf("wl_rrm_lm_req parsing arg1 failed\n");
			return BCME_USAGE_ERROR;
		}
	}
	err = wlu_iovar_set(wl, cmdname, &da, sizeof(da));
	return err;
}

static int
wl_rrm_nbr_req(void *wl, cmd_t *cmd, char **argv)
{
	int err, buflen;
	wlc_ssid_t ssid;

	UNUSED_PARAMETER(cmd);

	strcpy(buf, "rrm_nbr_req");
	buflen = strlen("rrm_nbr_req") + 1;

	if (*++argv) {
		uint32 len;

		len = strlen(*argv);
		if (len > DOT11_MAX_SSID_LEN) {
			printf("ssid too long\n");
			return BCME_BADARG;
		}
		memset(&ssid, 0, sizeof(wlc_ssid_t));
		memcpy(ssid.SSID, *argv, len);
		ssid.SSID_len = len;
		memcpy(&buf[buflen], &ssid, sizeof(wlc_ssid_t));
		buflen += sizeof(wlc_ssid_t);
	}

	err = wlu_set(wl, WLC_SET_VAR, buf, buflen);

	return err;
}

/* For mapping customer's user space command, two calls of the same iovar. */
static int
wl_rrm_nbr_list(void *wl, cmd_t *cmd, char **argv)
{
	int err = 0, buflen, i;
	uint16 list_cnt;
	nbr_element_t *nbr_elt;
	uint8 *ptr;

	UNUSED_PARAMETER(cmd);

	memset(buf, 0, WLC_IOCTL_MAXLEN);
	strcpy(buf, "rrm_nbr_list");
	buflen = strlen("rrm_nbr_list") + 1;

	if (*++argv != NULL)
		return BCME_USAGE_ERROR;

	if ((err = wlu_get(wl, WLC_GET_VAR, buf, buflen)) < 0)
		return err;

	list_cnt = *(uint16 *)buf;

	if (list_cnt == 0)
		return err;

	memset(buf, 0, WLC_IOCTL_MAXLEN);
	strcpy(buf, "rrm_nbr_list");
	buflen = strlen("rrm_nbr_list") + 1;

	memcpy(&buf[buflen], &list_cnt, sizeof(uint16));

	printf("RRM Neighbor Report List:\n");

	if ((err = wlu_get(wl, WLC_GET_VAR, buf, WLC_IOCTL_MAXLEN)) < 0)
		return err;

	ptr = (uint8 *)buf;

	for (i = 0; i < list_cnt; i++) {
		nbr_elt = (nbr_element_t *)ptr;
		printf("AP %2d: ", i + 1);
		printf("bssid %02x:%02x:%02x:%02x:%02x:%02x ", nbr_elt->bssid.octet[0],
			nbr_elt->bssid.octet[1], nbr_elt->bssid.octet[2], nbr_elt->bssid.octet[3],
			nbr_elt->bssid.octet[4], nbr_elt->bssid.octet[5]);

		printf("bssid_info %08x ", load32_ua(&nbr_elt->bssid_info));
		printf("reg %2d channel %3d phytype %d\n", nbr_elt->reg,
			nbr_elt->channel, nbr_elt->phytype);

		ptr += TLV_HDR_LEN + DOT11_NEIGHBOR_REP_IE_FIXED_LEN;
	}

	return err;
}

static int
wl_rrm_nbr_del_nbr(void *wl, cmd_t *cmd, char **argv)
{
	int err = 0;
	const char *cmdname = "rrm_nbr_del_nbr";
	struct ether_addr ea;

	UNUSED_PARAMETER(cmd);

	if (*++argv == NULL) {
		printf("no bssid specified\n");
		return BCME_USAGE_ERROR;
	} else {
		if (!wl_ether_atoe(*argv, &ea)) {
			printf("Incorrect bssid format\n");
			return BCME_ERROR;
		}
		err = wlu_iovar_set(wl, cmdname, &ea, sizeof(ea));
	}

	return err;
}

static int
wl_rrm_nbr_add_nbr(void *wl, cmd_t *cmd, char **argv)
{
	int argc;
	int err = 0;
	const char *cmdname = "rrm_nbr_add_nbr";
	nbr_element_t nbr_elt;

	UNUSED_PARAMETER(cmd);
	memset(&nbr_elt, 0, sizeof(nbr_element_t));

	for (argc = 0; argv[argc]; argc++)
		;

	if (argc != 6)
		return BCME_USAGE_ERROR;

	/* bssid */
	if (!wl_ether_atoe(argv[1], &nbr_elt.bssid)) {
		printf("wl_rrm_nbr_add_nbr parsing bssid failed\n");
		return BCME_USAGE_ERROR;
	}

	/* bssid info */
	nbr_elt.bssid_info = htod32(strtoul(argv[2], NULL, 0));

	/* Regulatory class */
	nbr_elt.reg = htod32(strtoul(argv[3], NULL, 0));

	/* channel */
	nbr_elt.channel = htod32(strtoul(argv[4], NULL, 0));

	/* phytype */
	nbr_elt.phytype = htod32(strtoul(argv[5], NULL, 0));

	nbr_elt.id = DOT11_MNG_NEIGHBOR_REP_ID;
	nbr_elt.len = DOT11_NEIGHBOR_REP_IE_FIXED_LEN;

	err = wlu_iovar_set(wl, cmdname, &nbr_elt, TLV_HDR_LEN + DOT11_NEIGHBOR_REP_IE_FIXED_LEN);
	return err;
}
