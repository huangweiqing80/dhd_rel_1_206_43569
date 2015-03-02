/*
 * wl proxd command module
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wluc_proxd.c 458728 2014-02-27 18:15:25Z $
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

#ifdef WIN32
#define bzero(b, len)	memset((b), 0, (len))
#endif

#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/if_packet.h>

#include <miniopt.h>

static cmd_func_t wl_proxd;
static cmd_func_t wl_proxd_tune;
static cmd_func_t wl_proxd_collect;
static cmd_func_t wl_proxd_params;
static cmd_func_t wl_proxd_status;
static cmd_func_t wl_proxd_payload;
static cmd_func_t wl_proxd_event_check;

#define WL_PROXD_PAYLOAD_LEN	1026

#define PROXD_PARAMS_USAGE	\
"\tUsage: wl proxd_params method [-c channel] [-i interval] [-d duration] [-s rssi_thresh]"	\
" [-p tx_power] [-r tx_rate] [-t timeout] [-m maxconvergetime] [-g <xx:xx:xx:xx:xx:xx>]"	\
" [-y retrycnt]\n\n" \
"\tMandatory args:\n"		\
"\t\tmethod: == 1 (RSSI) or == 2 (TOF) methods are supported) \n\n"	\
"\tOptional method specific args - for method 1: \n"	\
"\t\t-c chanspec     : (all methods) channel to use for Proximity Detection\n"	\
"\t\t                :  e.g: 161/80, if [/BW] omitted, driver will assume 20Mhz by default\n" \
"\t\t-i interval     : (RSSI method) interval between neighbor finding attempts (in TU)\n"	\
"\t\t                : (Once associated as STA mode, this value is ignored and\n"	\
"\t\t                :  the interval follows DTIM)\n"	\
"\t\t-d duration     : (RSSI method) duration of neighbor finding attempts (in ms)\n"		\
"\t\t                : == dwelling time on home channel specificed by -c channel\n"	\
"\t\t-s rssi_thresh  : RSSI threshold for Proximity Detection criteria (in dBm)\n"	\
"\t\t                : (-99 to -1)\n"	\
"\t\t-p tx_power     : (RSSI method) tx power of Proximity Detection frames (in dBm)\n"	\
"\t\t-r tx_rate      : (all methods) tx rate of Proximity Detection frames (in Mbps)\n" \
"\t\t                : (TOF) tx_rate format is {R|{hM|vM[xS]}[s][l][g]}[eT][bB]\n" \
"\t\t                : R - legacy rate, hM - HT MCS index[0-23], " \
"vMxS - VHT MCS index[0-9] and Nss[1-8]\n" \
"\t\t                : s - Use STBC expansion, l - Use LDPC encoding, " \
"g - SGI, Short Guard Interval\n" \
"\t\t                : eT - Tx expansion, number of tx chains[0-3], " \
"bB - tx bandwidth, MHz: 20, 40, 80\n" \
"\t\t-t timeout      : (all methods) state machine receive timeout of Proximity Detection " \
"frames (in ms)\n" \
"\t\t-m maxconverge  : (RSSI method) device stays up for a whole interval to detect the peer\n"	\
"\t\t                : when no peer found after max converge time (in ms)\n\n"	\
"\t\t-g tgt_mac      : (TOF) proximity target mac address for a method  \n" \
"\t\t-f ftm_cnt      : (TOF) number of ftm frames requested by initiator from target  \n" \
"\t\t-y retry_cnt    : (TOF) number of retransmit attempts for FTM frames \n" \
"\tExample: wl proxd_params 1 -c 36 -i 100 -d 10 -s -40 -p 12 -r 6 -t 20 -m 1000\n" \
"\tExample: wl proxd_params 1 -s -55\n" \
"\tExample: wl proxd_params 2 -c 11 -f 10 -g 00:90:4c:a5:01:32 -r v0"

#define PROXD_TUNE_USAGE	\
"\tUsage: wl proxd_tune method [operations]\n\n" \
"\tMandatory args:\n"		\
"\t\tmethod: == 2 (TOF) methods are supported \n\n" \
"\tOperations:\n"		\
"\t\t-k K factor     : hardware dependant RTD delay adjustment factor \n" \
"\t\t-b bcmack       : 0:disable BCM ACK, 1:enable BCM ACK\n" \
"\t\t-n minDT        : min time difference of T1 and T4 or T2 and T3 \n" \
"\t\t-x maxDT		 : max time difference of T1 and T4 or T2 and T3 \n" \
"\t\t-t total_frmcnt : total count limit of measurement frames transmitted \n" \
"\t\t-N threshold_log2 : log2 number of simple threshold crossing \n" \
"\t\t-S threshold_scale: scale number of simple threshold crossing \n" \
"\t\t-F ftm_cnt      : number of measurement frames requested by initiator \n" \
"\t\t-r rsv_media_value: reserve media duration value for TOF \n" \
"\t\t-f flags        : TOF state machine control flags\n" \
"\t\t-A timestamp_adj : enable/disable sw/hw/seq assisted timestamp adjustment, " \
"the data format is s[0|1]h[0|1]r[0|1] \n" \
"\t\t-W window_adjust : set search window length and offset, " \
"the data format is bBlLoO, B is bandwidth \n" \
"\t\t                 : with value 20, 40 or 80, L is window length, O is offset"

static cmd_t wl_proxd_cmds[] = {
	{ "proxd", wl_proxd, WLC_GET_VAR, WLC_SET_VAR,
	"Enable/Disable Proximity Detection\n"
	"\t0 : disable\n"
	"\t1 [initiator|target|neutral] [u/r]: enable with the specified mode and wakeup"
	" mechanism\n\n"
	"\tExample: wl proxd 1 initiator"},
	{ "proxd_collect", wl_proxd_collect, WLC_GET_VAR, WLC_SET_VAR,
	"collect the debugging informations of Proximity Detection \n\n"
	"Optional parameters is:\n"
	"\tenable to enable the proxd collection.\n"
	"\tdisable to disable the proxd collection.\n"
	"\t-l, dump local collect data and request load remote AP collect data.\n"
	"\t-r, dump remote collect data or request load remote AP collect data.\n"
	"\t-f File name to dump the sample buffer (default \"proxd_collect.dat\")"},
	{ "proxd_params", wl_proxd_params, WLC_GET_VAR, WLC_SET_VAR,
	"Set/Get operational parameters for a method of Proximity Detection\n\n"
	PROXD_PARAMS_USAGE},
	{ "proxd_tune", wl_proxd_tune, WLC_GET_VAR, WLC_SET_VAR,
	"Set/Get tune parameters for TOF method of Proximity Detection\n\n"
	PROXD_TUNE_USAGE},
	{ "proxd_bssid", wl_iov_mac, WLC_GET_VAR, WLC_SET_VAR,
	"Set/Get BSSID to be used in proximity detection frames\n\n"
	"\tUsage: wl proxd_bssid <xx:xx:xx:xx:xx:xx>"},
	{ "proxd_mcastaddr", wl_iov_mac, WLC_GET_VAR, WLC_SET_VAR,
	"Set/Get Multicast MAC address of Proximity Detection Frames\n\n"
	"\tUsage: wl proxd_mcastaddr <xx:xx:xx:xx:xx:xx>"},
	{ "proxd_find", wl_var_void, -1, WLC_SET_VAR,
	"Start Proximity Detection" },
	{ "proxd_stop", wl_var_void, -1, WLC_SET_VAR,
	"Stop Proximity Detection" },
	{ "proxd_status", wl_proxd_status, WLC_GET_VAR, -1,
	"Get status of Proximity Detection" },
	{ "proxd_monitor", wl_iov_mac, -1, WLC_SET_VAR,
	"Monitor detected peer status in proximity\n\n"
	"\tUsage: wl proxd_monitor <xx:xx:xx:xx:xx:xx>"},
	{ "proxd_payload", wl_proxd_payload, WLC_GET_VAR, WLC_SET_VAR,
	"Get/Set payload content transferred between the proximity detected peers\n\n"
	"\tUsage: wl proxd_payload [len hexstring]"},
	{ "proxd_event_check", wl_proxd_event_check, -1, -1,
	"Listen and print Location Based Service events\n"
	"\tproxd_event_check syntax is: proxd_event_check ifname"},
	{ NULL, NULL, 0, 0, NULL }
};

static char *buf;

/* module initialization */
void
wluc_proxd_module_init(void)
{
	/* get the global buf */
	buf = wl_get_buf();

	/* register proxd commands */
	wl_module_cmds_register(wl_proxd_cmds);
}

static int
wl_proxd(void *wl, cmd_t *cmd, char **argv)
{
	uint16 var[2], *reply;
	uint16 method = 0, role = 0;
	void *ptr;
	int ret;

	/* skip the command name and check if NULL */
	if (!*++argv) {
		/* Get */
		ret = wlu_var_getbuf(wl, cmd->name, &var, sizeof(var), &ptr);
		if (ret != BCME_OK) {
			return ret;
		}

		reply = (uint16 *)ptr;

		method = dtoh16(reply[0]);

		printf("%d\n", method);

		if (method > 0) {
			char c = 'u';
			role = dtoh16(reply[1]);
			if (role & WL_PROXD_RANDOM_WAKEUP) {
				c = 'r';
				role &= ~WL_PROXD_RANDOM_WAKEUP;
			}
			if (role == WL_PROXD_MODE_INITIATOR)
				printf("%s %c\n", "initiator", c);
			else if (role == WL_PROXD_MODE_TARGET)
				printf("%s %c\n", "target", c);
			else if (role == WL_PROXD_MODE_NEUTRAL)
				printf("%s %c\n", "neutral", c);
		}
	} else {
		/* Set */

		/* parse method and role */
		method = (uint16)atoi(argv[0]);
		if (method > 0) {
			if (!argv[1]) {
				/* Default when it is not specified */
				role = WL_PROXD_MODE_NEUTRAL | WL_PROXD_RANDOM_WAKEUP;
			}
			else {
				if (stricmp(argv[1], "initiator") == 0)
					role = WL_PROXD_MODE_INITIATOR;
				else if (stricmp(argv[1], "target") == 0)
					role = WL_PROXD_MODE_TARGET;
				else if (stricmp(argv[1], "neutral") == 0) {
					role = WL_PROXD_MODE_NEUTRAL;
					role |= WL_PROXD_RANDOM_WAKEUP;
				}
				else
					return BCME_USAGE_ERROR;

				if (argv[2]) {
					if (*argv[2] == 'R' || *argv[2] == 'r')
						role |= WL_PROXD_RANDOM_WAKEUP;
					else if (*argv[2] == 'u' || *argv[2] == 'U')
						role &= ~WL_PROXD_RANDOM_WAKEUP;
				}
			}
		}

		var[0] = htod16(method);
		var[1] = htod16(role);

		ret = wlu_var_setbuf(wl, cmd->name, &var, sizeof(var));
	}

	return ret;
}

static int
wl_proxd_get_debug_data(void *wl, cmd_t *cmd, int index)
{
	int ret;
	void *buff;
	wl_proxd_collect_query_t query;
	wl_proxd_debug_data_t *replay;

	bzero(&query, sizeof(query));
	query.method = htol32(PROXD_TOF_METHOD);
	query.request = PROXD_COLLECT_QUERY_DEBUG;
	query.index = htol16(index);

	ret = wlu_var_getbuf(wl, cmd->name, &query, sizeof(query), &buff);
	if (ret != BCME_OK)
		return ret;

	replay = (wl_proxd_debug_data_t *)buff;

	if (index == 0)
		printf("\n/* Debug Informations */\n");

	printf("%s[%u,%u]: type %u action(%u,%u) token(%u, %u)\n",
		replay->received? "RX" : "TX",
		replay->count, replay->stage,
		replay->paket_type,
		replay->category, replay->action,
		replay->token, replay->follow_token);

	if (replay->tof_cmd == 0 && replay->tof_rsp == 0) {
		printf("\n");
		return BCME_OK;
	}

	printf("Index=%d\n", ltoh16(replay->index));
	printf("M_TOF_CMD=0x%04x\tM_TOF_RSP=0x%04x\tM_TOF_ID=0x%04x\n",
		ltoh16(replay->tof_cmd), ltoh16(replay->tof_rsp), ltoh16(replay->tof_id));
	printf("M_TOF_AVB_RX_L=0x%04x\tM_TOF_AVB_RX_H=0x%04x\t",
		ltoh16(replay->tof_avb_rxl), ltoh16(replay->tof_avb_rxh));
	printf("M_TOF_AVB_TX_L=0x%04x\tM_TOF_AVB_TX_H=0x%04x\n",
		ltoh16(replay->tof_avb_txl), ltoh16(replay->tof_avb_txh));
	printf("M_TOF_STATUS0=0x%04x\tM_TOF_STATUS2=0x%04x\t",
		ltoh16(replay->tof_status0), ltoh16(replay->tof_status2));
	printf("M_TOF_CHNSM_0=0x%04x\tM_TOF_CHNSM_1=0x%04x\n",
		ltoh16(replay->tof_chsm0), 0);
	printf("M_TOF_PHYCTL0=0x%04x\tM_TOF_PHYCTL1=0x%04x\tM_TOF_PHYCTL2=0x%04x\n",
		ltoh16(replay->tof_phyctl0), ltoh16(replay->tof_phyctl1),
		ltoh16(replay->tof_phyctl2));
	printf("M_TOF_LSIG=0x%04x\tM_TOF_VHTA0=0x%04x\tM_TOF_VHTA1=0x%04x\n",
		ltoh16(replay->tof_lsig), ltoh16(replay->tof_vhta0), ltoh16(replay->tof_vhta1));
	printf("M_TOF_VHTA2=0x%04x\tM_TOF_VHTB0=0x%04x\tM_TOF_VHTB1=0x%04x\n",
		ltoh16(replay->tof_vhta2), ltoh16(replay->tof_vhtb0), ltoh16(replay->tof_vhtb1));
	printf("M_TOF_AMPDU_CTL=0x%04x\tM_TOF_AMPDU_DLIM=0x%04x\tM_TOF_AMPDU_LEN=0x%04x\n\n",
		ltoh16(replay->tof_apmductl), ltoh16(replay->tof_apmdudlim),
		ltoh16(replay->tof_apmdulen));

	return BCME_OK;
}

static void
wlc_proxd_collec_header_dump(wl_proxd_collect_header_t *pHdr)
{
	int i;

	printf("total_frames %lu\n", (unsigned long)ltoh16(pHdr->total_frames));
	printf("nfft %lu\n", (unsigned long)ltoh16(pHdr->nfft));
	printf("bandwidth %lu\n", (unsigned long)ltoh16(pHdr->bandwidth));
	printf("channel %lu\n", (unsigned long)ltoh16(pHdr->channel));
	printf("chanspec %lu\n", (unsigned long)ltoh32(pHdr->chanspec));
	printf("fpfactor %lu\n", (unsigned long)ltoh32(pHdr->fpfactor));
	printf("fpfactor_shift %lu\n", (unsigned long)ltoh16(pHdr->fpfactor_shift));
	printf("distance %li\n", (long)ltoh32(pHdr->distance));
	printf("meanrtt %lu\n", (unsigned long)ltoh32(pHdr->meanrtt));
	printf("modertt %lu\n", (unsigned long)ltoh32(pHdr->modertt));
	printf("medianrtt %lu\n", (unsigned long)ltoh32(pHdr->medianrtt));
	printf("sdrtt %lu\n", (unsigned long)ltoh32(pHdr->sdrtt));
	printf("clkdivisor %lu\n", (unsigned long)ltoh32(pHdr->clkdivisor));
	printf("chipnum %lu\n", (unsigned long)ltoh16(pHdr->chipnum));
	printf("chiprev %lu\n", (unsigned long)pHdr->chiprev);
	printf("phyver %lu\n", (unsigned long)pHdr->phyver);
	printf("loaclMacAddr %s\n", wl_ether_etoa(&(pHdr->loaclMacAddr)));
	printf("remoteMacAddr %s\n", wl_ether_etoa(&(pHdr->remoteMacAddr)));
	printf("params_Ki %lu\n", (unsigned long)ltoh32(pHdr->params.Ki));
	printf("params_Kt %lu\n", (unsigned long)ltoh32(pHdr->params.Kt));
	printf("params_vhtack %li\n", (long)ltoh16(pHdr->params.vhtack));
	printf("params_N_log2 %d\n", TOF_BW_NUM);
	for (i = 0; i < TOF_BW_NUM; i++) {
		printf("%li\n", (long)ltoh16(pHdr->params.N_log2[i]));
	}
	printf("params_N_scale %d\n", TOF_BW_NUM);
	for (i = 0; i < TOF_BW_NUM; i++) {
		printf("%li\n", (long)ltoh16(pHdr->params.N_scale[i]));
	}
	printf("params_sw_adj %lu\n", (unsigned long)pHdr->params.sw_adj);
	printf("params_hw_adj %lu\n", (unsigned long)pHdr->params.hw_adj);
	printf("params_seq_en %lu\n", (unsigned long)pHdr->params.seq_en);
	printf("params_core %lu\n", (unsigned long)pHdr->params.core);
	printf("params_N_log2_seq 2\n");
	for (i = 0; i < 2; i++) {
		printf("%li\n", (long)ltoh16(pHdr->params.N_log2[i + TOF_BW_NUM]));
	}
	printf("params_N_scale_seq 2\n");
	for (i = 0; i < 2; i++) {
		printf("%li\n", (long)ltoh16(pHdr->params.N_scale[i + TOF_BW_NUM]));
	}
	printf("params_w_offset %d\n", TOF_BW_NUM);
	for (i = 0; i < TOF_BW_NUM; i++) {
		printf("%li\n", (long)ltoh16(pHdr->params.w_offset[i]));
	};
	printf("params_w_len %d\n", TOF_BW_NUM);
	for (i = 0; i < TOF_BW_NUM; i++) {
		printf("%li\n", (long)ltoh16(pHdr->params.w_len[i]));
	};
	printf("params_maxDT %li\n", (long)ltoh32(pHdr->params.maxDT));
	printf("params_minDT %li\n", (long)ltoh32(pHdr->params.minDT));
	printf("params_totalfrmcnt %lu\n", (unsigned long)pHdr->params.totalfrmcnt);
	printf("params_rsv_media %lu\n", (unsigned long)ltoh16(pHdr->params.rsv_media));
}

static void wlc_proxd_collec_data_dump(wl_proxd_collect_data_t *replay)
{
	int i, n;

	printf("info_type %lu\n", (unsigned long)ltoh16(replay->info.type));
	printf("info_index %lu\n", (unsigned long)ltoh16(replay->info.index));
	printf("info_tof_cmd %lu\n", (unsigned long)ltoh16(replay->info.tof_cmd));
	printf("info_tof_rsp %lu\n", (unsigned long)ltoh16(replay->info.tof_rsp));
	printf("info_tof_avb_rxl %lu\n", (unsigned long)ltoh16(replay->info.tof_avb_rxl));
	printf("info_tof_avb_rxh %lu\n", (unsigned long)ltoh16(replay->info.tof_avb_rxh));
	printf("info_tof_avb_txl %lu\n", (unsigned long)ltoh16(replay->info.tof_avb_txl));
	printf("info_tof_avb_txh %lu\n", (unsigned long)ltoh16(replay->info.tof_avb_txh));
	printf("info_tof_id %lu\n", (unsigned long)ltoh16(replay->info.tof_id));
	printf("info_tof_frame_type %lu\n", (unsigned long)replay->info.tof_frame_type);
	printf("info_tof_frame_bw %lu\n", (unsigned long)replay->info.tof_frame_bw);
	printf("info_tof_rssi %li\n", (long)replay->info.tof_rssi);
	printf("info_tof_cfo %li\n", (long)ltoh32(replay->info.tof_cfo));
	printf("info_gd_adj_ns %li\n", (long)ltoh32(replay->info.gd_adj_ns));
	printf("info_gd_h_adj_ns %li\n", (long)ltoh32(replay->info.gd_h_adj_ns));
	printf("info_nfft %li\n", (long)ltoh16(replay->info.nfft));
	n = (int)ltoh16(replay->info.nfft);
	printf("H %d\n", n);
	for (i = 0; i < n; i++) {
		printf("%lu\n", (unsigned long)ltoh32(replay->H[i]));
	};
}

static int
wl_proxd_get_collect_data(void *wl, cmd_t *cmd, FILE *fp, int index,
	wl_proxd_rssi_bias_avg_t *rssi_bias_avg)
{
	int ret, nbytes;
	void *buff;
	wl_proxd_collect_query_t query;
	wl_proxd_collect_data_t *replay;
	int nfft;
#ifdef RSSI_REFINE
	int rssi_dec;
#else
	/* rssi_bias_avg is unused under !RSSI_REFINE. */
	/* Macro to prevent compiler warning under some platforms */
	UNUSED_PARAMETER(rssi_bias_avg);
#endif

	bzero(&query, sizeof(query));
	query.method = htol32(PROXD_TOF_METHOD);
	query.request = PROXD_COLLECT_QUERY_DATA;
	query.index = htol16(index);

	ret = wlu_var_getbuf(wl, cmd->name, &query, sizeof(query), &buff);
	if (ret != BCME_OK)
		return ret;

	replay = (wl_proxd_collect_data_t *)buff;

	wlc_proxd_collec_data_dump(replay);

	nfft = (int)ltoh16(replay->info.nfft);

#ifdef RSSI_REFINE

	if (nfft > 0)
	{
		printf("}\nImpulse Response = {\n");
		for (i = 0; i < nfft; i++) {
		printf("%010d ", ltoh32(replay->info.rssi_bias.imp_resp[i]));
			if ((i & 7) == 7)
				printf("\n");
		}
		printf("RSSI_VERSION = %d\n", ltoh32(replay->info.rssi_bias.version));
		printf("PEAK_OFFSET = %d\n", ltoh32(replay->info.rssi_bias.peak_offset));
		rssi_bias_avg->avg_peak_offset += ltoh32(replay->info.rssi_bias.peak_offset);
		printf("PEAK_TO_AVG = %d", ltoh32(replay->info.rssi_bias.bias));
		rssi_bias_avg->avg_bias += ltoh32(replay->info.rssi_bias.bias);
		printf("\n");
		for (i = 0; i < 10; i++) {
			printf("THRESHOLD_%d = %u", i, ltoh32(replay->info.rssi_bias.threshold[i]));
			if ((i+1) % 5)
				printf(", ");
			else
				printf("\n");
		rssi_bias_avg->avg_threshold[i] += ltoh32(replay->info.rssi_bias.threshold[i]);
		}
		printf("SCALAR = %d", replay->info.rssi_bias.threshold[10]);
	}

	/* convert tof_status2 from hex to dec */
	rssi_dec = replay->info.tof_rssi;
	printf("\nRSSI10 = %d", rssi_dec);
	rssi_bias_avg->avg_rssi += rssi_dec;
	printf("\n\n");
#endif /* RSSI_REFINE */
	nbytes = sizeof(wl_proxd_collect_data_t) - (k_tof_collect_H_size - nfft) * sizeof(uint32);
	ret = fwrite(buff, 1, nbytes, fp);
	if (ret != nbytes) {
		fprintf(stderr, "Error writing %d bytes to file, rc %d!\n",
			nbytes, ret);
		return -1;
	}

	return BCME_OK;
}

static int
wl_proxd_collect(void *wl, cmd_t *cmd, char **argv)
{
	int ret;
	void *buff;
	wl_proxd_collect_query_t query, *pStatus;
	wl_proxd_collect_header_t *pHdr;
	const char *fname = "proxd_collect.dat";
	FILE *fp = NULL;
	int   i, total_frames, load_request = 0, remote_request = 0;
	char chspec_str[CHANSPEC_STR_LEN];
	chanspec_t chanspec;
	float d_ref = -1;
#ifdef RSSI_REFINE
	wl_proxd_rssi_bias_avg_t rssi_bias_avg;

	bzero(&rssi_bias_avg, sizeof(rssi_bias_avg));
#endif
	bzero(&query, sizeof(query));
	query.method = htol32(PROXD_TOF_METHOD);

	/* Skip the command name */
	argv++;
	while (*argv) {
		if (strcmp(argv[0], "disable") == 0 || *argv[0] == '0') {
			query.request = PROXD_COLLECT_SET_STATUS;
			query.status = 0;
			return wlu_var_getbuf(wl, cmd->name, &query, sizeof(query), &buff);
		}
		if (strcmp(argv[0], "enable") == 0 || *argv[0] == '1') {
			query.request = PROXD_COLLECT_SET_STATUS;
			query.status = 1;
			return wlu_var_getbuf(wl, cmd->name, &query, sizeof(query), &buff);
		}
		if (strcmp(argv[0], "debug") == 0 || *argv[0] == '2') {
			query.request = PROXD_COLLECT_SET_STATUS;
			query.status = 2;
			return wlu_var_getbuf(wl, cmd->name, &query, sizeof(query), &buff);
		}
		if (!strcmp(argv[0], "-l")) {
			load_request = 1;
			argv++;
		}
		else if (!strcmp(argv[0], "-r")) {
			remote_request = 1;
			argv++;
		}
		else if (!strcmp(argv[0], "-f")) {
			if (argv[1] == NULL)
				return -1;
			fname = argv[1];
			argv += 2;
		}
		else if (!strcmp(argv[0], "-d")) {
			if (argv[1] == NULL)
				return -1;
			sscanf((const char*)argv[1], "%f", &d_ref);
			argv += 2;
		} else
			return -1;
	}

	query.request = PROXD_COLLECT_GET_STATUS;
	ret = wlu_var_getbuf(wl, cmd->name, &query, sizeof(query), &buff);
	if (ret != BCME_OK)
		return ret;

	pStatus = (wl_proxd_collect_query_t *)buff;
	if (!pStatus->status) {
		printf("Disable\n");
		return BCME_OK;
	}

	if (pStatus->busy) {
		printf("Busy\n");
		return BCME_OK;
	}

	if ((pStatus->mode == WL_PROXD_MODE_TARGET) &&
		(remote_request || load_request)) {
		printf("Unsupport\n");
		return BCME_OK;
	}

	if (remote_request && !pStatus->remote) {
		printf("Remote data have not ready, please run this command again\n");
		load_request = 1;
		goto exit;
	}

	if (load_request && pStatus->remote) {
		printf("Local data have not ready, please run command 'proxd_find' to get it\n");
		goto exit;
	}

	query.request = PROXD_COLLECT_QUERY_HEADER;
	ret = wlu_var_getbuf(wl, cmd->name, &query, sizeof(query), &buff);
	if (ret != BCME_OK)
		return ret;

	pHdr = (wl_proxd_collect_header_t *)buff;
	total_frames = (int)ltoh32(pHdr->total_frames);
	if (!total_frames && pStatus->status == 1) {
		printf("Enable\n");
		goto exit;
	}

	chanspec = wl_chspec_from_driver(pHdr->chanspec);
	wf_chspec_ntoa(chanspec, chspec_str);

	printf("d_ref %5.1f\n", d_ref);
	wlc_proxd_collec_header_dump(pHdr);

	if ((fp = fopen(fname, "wb")) == NULL) {
		fprintf(stderr, "Problem opening file %s\n", fname);
		return 0;
	}

	ret = fwrite(buff, 1, sizeof(wl_proxd_collect_header_t), fp);
	if (ret != sizeof(wl_proxd_collect_header_t)) {
		fprintf(stderr, "Error writing to file rc %d\n", ret);
		ret = -1;
		goto exit;
	}

	for (i = 0; i < total_frames; i++) {
#ifdef RSSI_REFINE
		ret = wl_proxd_get_collect_data(wl, cmd, fp, i, &rssi_bias_avg);
#else
		ret = wl_proxd_get_collect_data(wl, cmd, fp, i, NULL);
#endif
		if (ret != BCME_OK)
			goto exit;
	}
#ifdef RSSI_REFINE
	if (total_frames > 0) {
		printf("avg_rssi = %d avg_peak_offset = %d\n",
			rssi_bias_avg.avg_rssi/total_frames,
			rssi_bias_avg.avg_peak_offset/total_frames);
		for (i = 0; i < 10; i++) {
			printf("avg_threshold_%d = %d",
				i, rssi_bias_avg.avg_threshold[i]/total_frames);
			if ((i+1) % 5)
				printf(", ");
			else
				printf("\n");
		}
		printf("avg_bias = %d\n", rssi_bias_avg.avg_bias/total_frames);
	}
#endif
	for (i = 0; i < 256; i++) {
		ret = wl_proxd_get_debug_data(wl, cmd, i);
		if (ret != BCME_OK)
			break;
	}
	ret = BCME_OK;
exit:
	if (ret == BCME_OK && load_request) {
		query.request = PROXD_COLLECT_REMOTE_REQUEST;
		ret = wlu_var_getbuf(wl, cmd->name, &query, sizeof(query), &buff);
	}
	if (fp) fclose(fp);
	return ret;
}

/* set measurement packet transmit rate */
static int proxd_method_set_vht_rate(miniopt_t *mopt)
{
	char *startp, *endp;
	char c;
	bool legacy_set = FALSE, ht_set = FALSE, vht_set = FALSE;
	int rate, mcs, Nss, tx_exp, bw, val;
	bool stbc, ldpc, sgi;
	uint32 rspec = 0;

	/* set default values */
	rate = 0;
	mcs = 0;
	Nss = 0;
	tx_exp = 0;
	stbc = FALSE;
	ldpc = FALSE;
	sgi = FALSE;
	bw = 0;

	startp = mopt->valstr;
	endp = NULL;
	if (*startp != 'h' && *startp != 'v') {
		if ((rate = (int)strtol(startp, &endp, 10)) == 0)
			return -1;

		rate *= 2;
		if (endp[0] == '.' && endp[1] == '5') {
			rate += 1;
			endp += 2;
		}
		startp = endp;
		legacy_set = TRUE;
	}

	while (startp && ((c = *startp++) != '\0')) {
		if (c == 'h') {
			ht_set = TRUE;
			mcs = (int)strtol(startp, &endp, 10);
			if (mcs < 0 || mcs > 23) {
				printf("HT MCS index %d out of range [0-23].\n", mcs);
				return -1;
			}
			startp = endp;
		}
		else if (c == 'v') {
			vht_set = TRUE;
			mcs = (int)strtol(startp, &endp, 10);
			if (mcs < 0 || mcs > 9) {
				printf("HT MCS index %d out of range [0-9].\n", mcs);
				return -1;
			}
			startp = endp;
		}
		else if (c == 'x') {
			Nss = (int)strtol(startp, &endp, 10);
			if (Nss < 1 || Nss > 8) {
				printf("Nss %d out of range [1-8].\n", Nss);
				return -1;
			}
			startp = endp;
		}
		else if (c == 'e') {
			tx_exp = (int)strtol(startp, &endp, 10);
			if (tx_exp < 0 || tx_exp > 3) {
				printf("tx expansion %d out of range [0-3].\n", tx_exp);
				return -1;
			}
			startp = endp;
		}
		else if (c == 's') {
			stbc = TRUE;
			continue;
		}
		else if (c == 'l') {
			ldpc = TRUE;
			continue;
		}
		else if (c == 'g') {
			sgi = TRUE;
			continue;
		}
		else if (c == 'b') {
			val = (int)strtol(startp, &endp, 10);
			if (val == 20) {
				bw = WL_RSPEC_BW_20MHZ;
			} else if (val == 40) {
				bw = WL_RSPEC_BW_40MHZ;
			} else if (val == 80) {
				bw = WL_RSPEC_BW_80MHZ;
			} else if (val == 160) {
				bw = WL_RSPEC_BW_160MHZ;
			} else {
				printf("unexpected bandwidth specified \"%d\", "
				        "expected 20, 40, 80, or 160\n", val);
				return -1;
			}
			startp = endp;
		}
	}

	if (!legacy_set && !ht_set && !vht_set) {
		printf("must specify one of legacy rate, HT (11n) rate hM, "
			"or VHT (11ac) rate vM[xS]\n");
		return -1;
	}

	if (legacy_set && (ht_set || vht_set)) {
		printf("cannot use legacy rate and HT rate or VHT rate at the same time\n");
		return -1;
	}

	if (ht_set && vht_set) {
		printf("cannot use HT rate hM and HT rate vM[xS] at the same time\n");
		return -1;
	}

	if (!vht_set && Nss != 0) {
		printf("cannot use xS option with non VHT rate\n");
		return -1;
	}

	if ((stbc || ldpc || sgi) && !(ht_set || vht_set)) {
		printf("cannot use STBC/LDPC/SGI options with non HT/VHT rates\n");
		return -1;
	}

	if (legacy_set) {
		rspec = WL_RSPEC_ENCODE_RATE;	/* 11abg */
		rspec |= rate;
	} else if (ht_set) {
		rspec = WL_RSPEC_ENCODE_HT; /* 11n HT */
		rspec |= mcs;
	} else {
		rspec = WL_RSPEC_ENCODE_VHT;	/* 11ac VHT */
		if (Nss == 0) {
			Nss = 1; /* default Nss = 1 if --ss option not given */
		}
		rspec |= (Nss << WL_RSPEC_VHT_NSS_SHIFT) | mcs;
	}

	/* set the other rspec fields */
	rspec |= (tx_exp << WL_RSPEC_TXEXP_SHIFT);
	rspec |= bw;
	rspec |= (stbc ? WL_RSPEC_STBC : 0);
	rspec |= (ldpc ? WL_RSPEC_LDPC : 0);
	rspec |= (sgi  ? WL_RSPEC_SGI  : 0);

	mopt->uval = rspec;

	return 0;
}

/* proxd set params common cmdl opts */
int proxd_method_set_common_param_from_opt(cmd_t *cmd,
	miniopt_t *mopt, wl_proxd_params_common_t *proxd_params)
{
	chanspec_t chanspec;

	if (mopt->opt == 'c') {
		/* chanspec iovar uses wl_chspec32_to_driver(chanspec), why ? */
		if ((chanspec = wf_chspec_aton(mopt->valstr)) == 0) {
			fprintf(stderr, "%s: could not parse \"%s\" as a channel\n",
				cmd->name, mopt->valstr);
			return BCME_BADARG;
		}

		proxd_params->chanspec
			= wl_chspec_to_driver(chanspec);

		if (proxd_params->chanspec == INVCHANSPEC) {
			fprintf(stderr,
				"%s: wl_chspec_to_driver() error \"%s\" \n",
				cmd->name, mopt->valstr);
			return BCME_BADARG;
		}
	} else if (mopt->opt == 't') {
		if (!mopt->good_int) {
			fprintf(stderr,
				"%s: could not parse \"%s\" as a timeout\n",
				cmd->name, mopt->valstr);
			return BCME_USAGE_ERROR;
		}
		proxd_params->timeout = htod16(mopt->val);
	}
	else
		return BCME_USAGE_ERROR;

	return BCME_OK;
}

/*  proxd  TOF cmdl ops  */
int proxd_method_tof_set_param_from_opt(cmd_t *cmd,
	miniopt_t *mopt, wl_proxd_params_tof_method_t *proxd_params)
{
	 if (mopt->opt == 'g') {
		/* this param is only valid for TOF method only */
		struct ether_addr ea;

		if (!wl_ether_atoe(mopt->valstr, &ea))  {
			fprintf(stderr,
				"%s: could not parse \"%s\" as MAC address\n",
			cmd->name, mopt->valstr);
			return BCME_USAGE_ERROR;
		}
		memcpy(&proxd_params->tgt_mac, &ea, 6);
	} else if (mopt->opt == 'f') {
		if (!mopt->good_int) {
			fprintf(stderr,
				"%s: could not parse \"%s\" as FTM frame count\n",
			cmd->name, mopt->valstr);
			return BCME_USAGE_ERROR;
		}
		proxd_params->ftm_cnt = htod16(mopt->val);
	} else if (mopt->opt == 'y') {
		if (!mopt->good_int) {
			fprintf(stderr,
				"%s: could not parse \"%s\" as Retry Count\n",
			cmd->name, mopt->valstr);
			return BCME_USAGE_ERROR;
		}
		proxd_params->retry_cnt = htod16(mopt->val);
	}  else if (mopt->opt == 'r') {
		if (!mopt->good_int) {
			/* special case check for "-r 5.5" */
			if (!strcmp(mopt->valstr, "5.5")) {
				mopt->uval = 11;
			} else if (proxd_method_set_vht_rate(mopt)) {
				fprintf(stderr,
					"%s: could not parse \"%s\" as a rate\n",
					cmd->name, mopt->valstr);
				return BCME_USAGE_ERROR;
			}
		} else
			 mopt->uval = mopt->uval*2;
		proxd_params->tx_rate = htod16((mopt->uval & 0xffff));
		proxd_params->vht_rate = htod16((mopt->uval >> 16));
	} else
		return BCME_USAGE_ERROR;

	return BCME_OK;
}

/*   RSSI method specific mdl opts   */
int proxd_method_rssi_set_param_from_opt(cmd_t *cmd,
	miniopt_t *mopt, wl_proxd_params_rssi_method_t *proxd_params)
{

	if (mopt->opt == 'i') {
		if (!mopt->good_int) {
			fprintf(stderr,
				"%s: could not parse \"%s\" as an interval\n",
				cmd->name, mopt->valstr);
			return BCME_USAGE_ERROR;
		}
		proxd_params->interval = htod16(mopt->val);
	} else if (mopt->opt == 'd') {
		if (!mopt->good_int) {
			fprintf(stderr,
				"%s: could not parse \"%s\" as a duration\n",
				cmd->name, mopt->valstr);
			return BCME_USAGE_ERROR;
		}
		proxd_params->duration = htod16(mopt->val);
	} else if (mopt->opt == 'p') {
		if (!mopt->good_int) {
			fprintf(stderr,
				"%s: could not parse \"%s\" as a power\n",
			cmd->name, mopt->valstr);
			return BCME_USAGE_ERROR;
		}
		proxd_params->tx_power = htod16(mopt->val);
	} else if (mopt->opt == 's') {
		if (!mopt->good_int) {
			fprintf(stderr,
				"%s: could not parse \"%s\" as a RSSI\n",
				cmd->name, mopt->valstr);
			return BCME_USAGE_ERROR;
		}
		proxd_params->rssi_thresh = htod16(mopt->val);
	} else if (mopt->opt == 'm') {
		if (!mopt->good_int) {
			fprintf(stderr,
				"%s: could not parse \"%s\" as a maxconvergetime\n",
				cmd->name, mopt->valstr);
			return BCME_USAGE_ERROR;
		}
		proxd_params->maxconvergtmo = htod16(mopt->val);
	} else if (mopt->opt == 'r') {
		if (!mopt->good_int) {
			/* special case check for "-r 5.5" */
			if (!strcmp(mopt->valstr, "5.5")) {
				mopt->val = 11;
			} else {
				fprintf(stderr,
					"%s: could not parse \"%s\" as a rate\n",
					cmd->name, mopt->valstr);
				return BCME_USAGE_ERROR;
			}
		} else
			mopt->val = mopt->val*2;
		proxd_params->tx_rate = htod16(mopt->val);
	}
	else
		return BCME_USAGE_ERROR;

	return BCME_OK;
}

static int
wl_proxd_params(void *wl, cmd_t *cmd, char **argv)
{
	wl_proxd_params_iovar_t proxd_params, *reply;
	uint16 method;
	void *ptr = NULL;
	int ret, opt_err;
	miniopt_t to;
	char chspec_str[CHANSPEC_STR_LEN];
	char rate_str[64];
	chanspec_t chanspec;
	uint16 interval, duration;
	uint32 tx_rate;

	/* skip the command name and check if mandatory exists */
	if (!*++argv) {
		fprintf(stderr, "missing mandatory parameter \'method\'\n");
		return BCME_USAGE_ERROR;
	}

	/* parse method */
	method = (uint16)atoi(argv[0]);
	if (method == 0) {
		fprintf(stderr, "invalid parameter \'method\'\n");
		return BCME_USAGE_ERROR;
	}

	bzero(&proxd_params, sizeof(proxd_params));

	/* set method to get/set */
	proxd_params.method = htod16(method);

	ret = wlu_var_getbuf_sm(wl, cmd->name, &proxd_params, sizeof(proxd_params), &ptr);
	if (ret != BCME_OK) {
		return ret;
	}

	if (!*++argv) {
		/* get */
		/* display proxd_params got */
		reply = (wl_proxd_params_iovar_t *)ptr;

		printf("bf proxd_params.method:%d\n", proxd_params.method);
		switch (proxd_params.method) {

		case PROXD_RSSI_METHOD:

			chanspec = wl_chspec_from_driver(reply->u.rssi_params.chanspec);
			tx_rate = dtoh16(reply->u.rssi_params.tx_rate);
			wf_chspec_ntoa(chanspec, chspec_str);

			printf("channel=%s\n", chspec_str);
			printf("interval=%d TU\n", dtoh16(reply->u.rssi_params.interval));
			printf("duration=%d ms\n", dtoh16(reply->u.rssi_params.duration));
			printf("rssi_thresh=%d dBm\n",
				(int16)dtoh16(reply->u.rssi_params.rssi_thresh));
			printf("maxconvergetime=%d ms\n\n",
				dtoh16(reply->u.rssi_params.maxconvergtmo));
			printf("tx_power=%d dBm\n",
				(int16)dtoh16(reply->u.rssi_params.tx_power));
			printf("tx_rate=%d%s Mbps\n",
				(tx_rate / 2), (tx_rate & 1) ? ".5" : "");
			printf("timeout=%d ms\n", dtoh16(reply->u.rssi_params.timeout));
			break;

		case PROXD_TOF_METHOD:

			chanspec = wl_chspec_from_driver(reply->u.tof_params.chanspec);
			tx_rate = dtoh16(reply->u.tof_params.tx_rate) |
				(dtoh16(reply->u.tof_params.vht_rate) << 16);
			wf_chspec_ntoa(chanspec, chspec_str);
			wl_rate_print(rate_str, tx_rate);

			printf("tgt_mac=%s \n",
				wl_ether_etoa(&reply->u.tof_params.tgt_mac));
			printf("ftm_cnt= %d\n", dtoh16(reply->u.tof_params.ftm_cnt));
			printf("channel=%s (0x%04x)\n", chspec_str, chanspec);
			printf("tx_rate=%s (0x%08x)\n", rate_str, tx_rate);
			printf("timeout=%d ms\n",
				dtoh16(reply->u.tof_params.timeout));
			printf("retry_cnt=%d \n", dtoh16(reply->u.tof_params.retry_cnt));
			break;

		default:
			fprintf(stderr,
				"%s: ERROR undefined method \n", cmd->name);
			return BCME_BADARG;
		}
	} else {  /* set */
		memcpy((void *)&proxd_params, (void *)ptr, sizeof(proxd_params));
		proxd_params.method = method;

		/* set */
		miniopt_init(&to, cmd->name, NULL, FALSE);
		while ((opt_err = miniopt(&to, argv)) != -1) {
			int com_res, meth_res;

			if (opt_err == 1) {
				return BCME_USAGE_ERROR;
			}
			argv += to.consumed;

			/*  process cmd opts common for all methods */
			com_res = proxd_method_set_common_param_from_opt(cmd,
				&to, &proxd_params.u.cmn_params);

			/* method specific opts */
			switch (method) {
				case PROXD_RSSI_METHOD:
					meth_res = proxd_method_rssi_set_param_from_opt(cmd,
						&to, &proxd_params.u.rssi_params);
				break;
				case PROXD_TOF_METHOD:
					meth_res = proxd_method_tof_set_param_from_opt(cmd,
						&to, &proxd_params.u.tof_params);
					if (meth_res == BCME_BADARG)
						return meth_res;
				break;
				default:
					printf("ERROR: unsupported method\n");
					return BCME_USAGE_ERROR;
			}

			/*  if option is unknown to both common and meth specific */
			if ((com_res != BCME_OK) && (meth_res != BCME_OK)) {
				printf(">>>> Method:%d doesn't support cmd option:'%c'\n",
					method, to.opt);
				return BCME_USAGE_ERROR;
			}
		}

		/* Sanity check of parameters against each other */
		interval = dtoh16(proxd_params.u.rssi_params.interval);
		duration = dtoh16(proxd_params.u.rssi_params.duration);

		if (interval < duration) {
			fprintf(stderr,
				"%s: \'interval\' cannot be shorter than \'duration\'\n",
				cmd->name);
			return BCME_BADARG;
		}

		ret = wlu_var_setbuf(wl, cmd->name, &proxd_params, sizeof(proxd_params));
	}

	return ret;
}

/* proxd parse mixed param: <str0><val0><str1><val1>... */
static void
proxd_method_tof_parse_mixed_param(char* str, const char** p_name, int* p_val, int* p_map)
{
	char* p;

	/* parse stuff of format <str0><val0><str1><val1>... */
	while (*p_name) {
		p = strstr((const char*)str, (const char*)*p_name);
		if (p) {
			p += strlen((const char*)*p_name);
			*p_map = 1;
			*p_val = strtol(p, NULL, 10);
		} else {
			*p_map = 0;
		}

		p_name++;
		p_map++;
		p_val++;
	}
}

/*  proxd  TOF tune ops  */
static int
proxd_tune_set_param_from_opt(cmd_t *cmd,
	miniopt_t *mopt, wl_proxd_params_tof_tune_t *proxd_tune)
{
	if (mopt->opt == 'k') {
		if (!mopt->good_int) {
			char *p = strstr(mopt->valstr, ",");
			if (p) {
				proxd_tune->Ki = htod32(atoi(mopt->valstr));
				proxd_tune->Kt = htod32(atoi(p+1));
			}
			else {
			fprintf(stderr,
					"%s: could not parse \"%s\" as K\n",
				cmd->name, mopt->valstr);
			return BCME_USAGE_ERROR;
		}
		}
		else {
			proxd_tune->Ki = htod32(mopt->val);
			proxd_tune->Kt = htod32(mopt->val);
		}
		proxd_tune->force_K = 1;
	} else if (mopt->opt == 'b') {
		if (!mopt->good_int) {
			fprintf(stderr,
				"%s: could not parse \"%s\" as bcm ack\n",
				cmd->name, mopt->valstr);
			return BCME_USAGE_ERROR;
		}
		proxd_tune->vhtack = htod16(mopt->val);
	} else if (mopt->opt == 'c') {
		if (!mopt->good_int) {
			fprintf(stderr,
				"%s: could not parse \"%s\" as core\n",
				cmd->name, mopt->valstr);
			return BCME_USAGE_ERROR;
		}
		proxd_tune->core = htod16(mopt->val);
	} else if (mopt->opt == 'A') {
		const char* n[4] = {"s", "h", "r", NULL};
		int v[3] = {0, 0, 0};
		int m[3] = {0, 0, 0};

		proxd_method_tof_parse_mixed_param(mopt->valstr, n, v, m);
		if (m[TOF_ADJ_SOFTWARE]) {
			/* sw adj */
			proxd_tune->sw_adj = (int16)v[TOF_ADJ_SOFTWARE];
		}
		if (m[TOF_ADJ_HARDWARE]) {
			/* hw adj */
			proxd_tune->hw_adj = (int16)v[TOF_ADJ_HARDWARE];
		}
		if (m[TOF_ADJ_SEQ]) {
			/* ranging sequence */
			proxd_tune->seq_en = (int16)v[TOF_ADJ_SEQ];
		}

		if ((m[TOF_ADJ_SOFTWARE] | m[TOF_ADJ_HARDWARE] | m[TOF_ADJ_SEQ]) == 0) {
			fprintf(stderr,
				"%s: could not parse \"%s\" as hw/sw adjustment enable params\n",
				cmd->name, mopt->valstr);
			return BCME_USAGE_ERROR;
		}
	} else if (mopt->opt == 'n') {
		if (!mopt->good_int) {
			fprintf(stderr,
				"%s: could not parse \"%s\" as min time difference limitation\n",
				cmd->name, mopt->valstr);
			return BCME_USAGE_ERROR;
		}
		proxd_tune->minDT = htod32(mopt->val);
	} else if (mopt->opt == 'x') {
		if (!mopt->good_int) {
			fprintf(stderr,
				"%s: could not parse \"%s\" as max time difference limitation\n",
				cmd->name, mopt->valstr);
			return BCME_USAGE_ERROR;
		}
		proxd_tune->maxDT = htod32(mopt->val);
	} else if (mopt->opt == 'N') {
		int i = 0;
		if (!mopt->good_int) {
			char *p = mopt->valstr;
			while (p && i < TOF_BW_SEQ_NUM) {
				if (htod16(atoi(p)))
					proxd_tune->N_log2[i] = htod16(atoi(p));
				i++;
				p = strstr(p, ",");
				if (p)
					p++;
			}
		} else {
			for (; i < TOF_BW_SEQ_NUM; i++) {
				proxd_tune->N_log2[i] = htod16(mopt->val);
			}
		}
	} else if (mopt->opt == 'S') {
		int i = 0;
		if (!mopt->good_int) {
			char *p = mopt->valstr;
			while (p && i < TOF_BW_SEQ_NUM) {
				if (htod16(atoi(p)))
					proxd_tune->N_scale[i] = htod16(atoi(p));
				i++;
				p = strstr(p, ",");
				if (p)
					p++;
			}
		} else {
			for (; i < TOF_BW_SEQ_NUM; i++) {
				proxd_tune->N_scale[i] = htod16(mopt->val);
			}
		}
	} else if (mopt->opt == 'F') {
		int i = 0;
		if (!mopt->good_int) {
			char *p = mopt->valstr;
			while (p && i < TOF_BW_SEQ_NUM) {
				if (htod16(atoi(p)))
					proxd_tune->ftm_cnt[i] = htod16(atoi(p));
				i++;
				p = strstr(p, ",");
				if (p)
					p++;
			}
		} else {
			for (; i < TOF_BW_SEQ_NUM; i++) {
				proxd_tune->ftm_cnt[i] = htod16(mopt->val);
			}
		}
	} else if (mopt->opt == 't') {
		if (!mopt->good_int) {
			fprintf(stderr,
				"%s: could not parse \"%s\" as total frmcnt\n",
				cmd->name, mopt->valstr);
			return BCME_USAGE_ERROR;
		}
		proxd_tune->totalfrmcnt = (mopt->val);
	} else if (mopt->opt == 'r') {
		if (!mopt->good_int) {
			fprintf(stderr,
				"%s: could not parse \"%s\" as media reserve value\n",
				cmd->name, mopt->valstr);
				return BCME_USAGE_ERROR;
			}
			proxd_tune->rsv_media = (mopt->val);
	} else if (mopt->opt == 'f') {
		if (!mopt->good_int) {
			fprintf(stderr,
				"%s: could not parse \"%s\" as flags\n",
				cmd->name, mopt->valstr);
			return BCME_USAGE_ERROR;
		}
		proxd_tune->flags = htod16(mopt->val);
	} else if (mopt->opt == 'W') {
		const char* n[4] = {"b", "l", "o", NULL};
		int v[TOF_BW_NUM] = {0, 0, 0};
		int m[TOF_BW_NUM] = {0, 0, 0};
		int i;

		proxd_method_tof_parse_mixed_param(mopt->valstr, n, v, m);
		if (m[0]) {
			/* Got bw */
			if (v[0] == TOF_BW_80MHZ)
				i = TOF_BW_80MHZ_INDEX;
			else if (v[0] == TOF_BW_40MHZ)
				i = TOF_BW_40MHZ_INDEX;
			else if (v[0] == TOF_BW_20MHZ)
				i = TOF_BW_20MHZ_INDEX;
			else {
				fprintf(stderr,
					"%s: could not parse \"%s\" as window params\n",
					cmd->name, mopt->valstr);
					return BCME_USAGE_ERROR;
			}
			if (m[1]) {
				/* Got length */
				proxd_tune->w_len[i] = (int16)v[1];
			}
			if (m[2]) {
				/* Got offset */
				proxd_tune->w_offset[i] = (int16)v[2];
			}
		}
	} else
		return BCME_USAGE_ERROR;

	return BCME_OK;
}

static int
wl_proxd_tune(void *wl, cmd_t *cmd, char **argv)
{
	wl_proxd_params_iovar_t proxd_tune, *reply;
	uint16 method;
	void *ptr = NULL;
	int ret, opt_err;
	miniopt_t to;
	int i;

	/* skip the command name and check if mandatory exists */
	if (!*++argv) {
		fprintf(stderr, "missing mandatory parameter \'method\'\n");
		return BCME_USAGE_ERROR;
	}

	/* parse method */
	method = (uint16)atoi(argv[0]);
	if (method == 0) {
		fprintf(stderr, "invalid parameter \'method\'\n");
		return BCME_USAGE_ERROR;
	}

	bzero(&proxd_tune, sizeof(proxd_tune));

	proxd_tune.method = htod16(method);
	ret = wlu_var_getbuf_sm(wl, cmd->name, &proxd_tune, sizeof(proxd_tune), &ptr);
	if (ret != BCME_OK) {
		return ret;
	}

	if (!*++argv) {
		/* get */
		/* display proxd_params got */
		reply = (wl_proxd_params_iovar_t *)ptr;

		printf("bf proxd_params.method:%d\n", proxd_tune.method);
		switch (proxd_tune.method) {
		case PROXD_RSSI_METHOD:
			break;

		case PROXD_TOF_METHOD:
			printf("Ki=%d \n", dtoh32(reply->u.tof_tune.Ki));
			printf("Kt=%d \n", dtoh32(reply->u.tof_tune.Kt));
			printf("bcmack=%d \n", dtoh16(reply->u.tof_tune.vhtack));
			printf("seq_en=%d\n", dtoh16(reply->u.tof_tune.seq_en));
			printf("core=%d\n", reply->u.tof_tune.core);
			printf("sw_adj=%d\n", dtoh16(reply->u.tof_tune.sw_adj));
			printf("hw_adj=%d\n", dtoh16(reply->u.tof_tune.hw_adj));
			printf("minDT = %d\n", reply->u.tof_tune.minDT);
			printf("maxDT = %d\n", reply->u.tof_tune.maxDT);
			printf("threshold_log2=%d %d %d seqtx %d seqrx %d\n",
				dtoh16(reply->u.tof_tune.N_log2[TOF_BW_20MHZ_INDEX]),
				dtoh16(reply->u.tof_tune.N_log2[TOF_BW_40MHZ_INDEX]),
				dtoh16(reply->u.tof_tune.N_log2[TOF_BW_80MHZ_INDEX]),
				dtoh16(reply->u.tof_tune.N_log2[TOF_BW_SEQTX_INDEX]),
				dtoh16(reply->u.tof_tune.N_log2[TOF_BW_SEQRX_INDEX]));
			printf("threshold_scale=%d %d %d seqtx %d seqrx %d\n",
				dtoh16(reply->u.tof_tune.N_scale[TOF_BW_20MHZ_INDEX]),
				dtoh16(reply->u.tof_tune.N_scale[TOF_BW_40MHZ_INDEX]),
				dtoh16(reply->u.tof_tune.N_scale[TOF_BW_80MHZ_INDEX]),
				dtoh16(reply->u.tof_tune.N_scale[TOF_BW_SEQTX_INDEX]),
				dtoh16(reply->u.tof_tune.N_scale[TOF_BW_SEQRX_INDEX]));
			printf("total_frmcnt=%d \n", reply->u.tof_tune.totalfrmcnt);
			printf("reserve_media=%d \n", reply->u.tof_tune.rsv_media);
			printf("flags=0x%x \n", dtoh16(reply->u.tof_tune.flags));
			for (i = 0; i < TOF_BW_NUM; i++) {
				printf("window length %dMHz = %d\n",
					(20 << i), reply->u.tof_tune.w_len[i]);
				printf("window offset %dMHz = %d\n",
					(20 << i), reply->u.tof_tune.w_offset[i]);
			}
			printf("frame count=%d %d %d seq %d\n",
				reply->u.tof_tune.ftm_cnt[TOF_BW_20MHZ_INDEX],
				reply->u.tof_tune.ftm_cnt[TOF_BW_40MHZ_INDEX],
				reply->u.tof_tune.ftm_cnt[TOF_BW_80MHZ_INDEX],
				reply->u.tof_tune.ftm_cnt[TOF_BW_SEQTX_INDEX]);
			break;

		default:
			fprintf(stderr,
				"%s: ERROR undefined method \n", cmd->name);
			return BCME_BADARG;
		}
	} else {
		/* set */
		memcpy((void *)&proxd_tune, (void *)ptr, sizeof(proxd_tune));
		proxd_tune.method = method;

		miniopt_init(&to, cmd->name, NULL, FALSE);
		while ((opt_err = miniopt(&to, argv)) != -1) {
			int meth_res = BCME_USAGE_ERROR;

			if (opt_err == 1) {
				return BCME_USAGE_ERROR;
			}
			argv += to.consumed;

			/* method specific opts */
			switch (method) {
				case PROXD_RSSI_METHOD:
					break;

				case PROXD_TOF_METHOD:
					meth_res = proxd_tune_set_param_from_opt(cmd,
						&to, &proxd_tune.u.tof_tune);
					break;

				default:
					printf("ERROR: unsupported method\n");
					return BCME_USAGE_ERROR;
			}

			/*  if option is unknown to tune specific */
			if (meth_res != BCME_OK) {
				printf(">>>> Method:%d doesn't support cmd option:'%c'\n",
					method, to.opt);
				return meth_res;
			}
		}
		ret = wlu_var_setbuf(wl, cmd->name, &proxd_tune, sizeof(proxd_tune));
	}

	return ret;
}

static const char *wl_proxd_mode_str(uint8 mode)
{
	static const char *proxd_mode[] = {"Undetected", "Neutral", "Initiator", "Target",
		"UNKNOWN"};

	if (mode > WL_PROXD_MODE_TARGET)
		mode = WL_PROXD_MODE_TARGET+1;

	return proxd_mode[mode];
}
static const char *wl_proxd_state_str(uint8 state)
{
	static const char *proxd_state[] = {"Poll", "Pairing", "Handshake", "Detected",
		"Pipeline", "NegMode", "Monitor", "Unknown"};

	if (state == RSSI_STATE_POLL)
		return proxd_state[0];
	if (state == RSSI_STATE_TPAIRING || state == RSSI_STATE_IPAIRING)
		return proxd_state[1];
	if (state == RSSI_STATE_THANDSHAKE || state == RSSI_STATE_IHANDSHAKE)
		return proxd_state[2];
	if (state == RSSI_STATE_CONFIRMED)
		return proxd_state[3];
	if (state == RSSI_STATE_PIPELINE)
		return proxd_state[4];
	if (state == RSSI_STATE_NEGMODE)
		return proxd_state[5];
	if (state == RSSI_STATE_MONITOR)
		return proxd_state[6];

	return proxd_state[7];
}

static const char *wl_proxd_tof_state_str(uint8 state)
{
	static const char *tof_proxd_state[] =
		{"Idle", "Wait", "LegacyWait", "Confirmed", "Unknown", "Report"};

	if (state == TOF_STATE_IDLE)
		return tof_proxd_state[0];
	if (state == TOF_STATE_IWAITM || state == TOF_STATE_TWAITM ||
		state == TOF_STATE_IWAITCL || state == TOF_STATE_TWAITCL)
		return tof_proxd_state[1];
	if (state == TOF_STATE_ILEGACY)
		return tof_proxd_state[2];
	if (state == TOF_STATE_ICONFIRM)
		return tof_proxd_state[3];
	if (state == TOF_STATE_IREPORT)
		return tof_proxd_state[5];

	return tof_proxd_state[4];
}

static const char *wl_proxd_tof_reason_str(uint8 reason)
{
	static const char *tof_proxd_reason[] = {"OK", "RxedReqEnd", "Timeout",
		"LostACK", "InvalidAVB"};

	if (reason > TOF_REASON_INVALIDAVB)
		reason = 0;

	return tof_proxd_reason[reason];
}

static const char *wl_proxd_reason_str(uint8 reason)
{
	static const char *proxd_reason[] = {"Unknown", "Low rssi", "State machine out of SYNC",
		"Timeout"};

	if (reason > RSSI_REASON_TIMEOUT)
		reason = 0;

	return proxd_reason[reason];
}

static int
wl_proxd_status(void *wl, cmd_t *cmd, char **argv)
{
	wl_proxd_status_iovar_t status, *statusp;
	int ret = BCME_BADARG;

	if (!*++argv) {
		/* Get */
		bzero(&status, sizeof(wl_proxd_status_iovar_t));
		if ((ret = wlu_iovar_get(wl, cmd->name, (void *) &status,
			(sizeof(wl_proxd_status_iovar_t)))) < 0)
			return (ret);

		statusp = &status;
		switch (statusp->method)
		{
			case PROXD_RSSI_METHOD:
				printf("mode=%s\n", wl_proxd_mode_str(statusp->mode));
				printf("state=%s\n", wl_proxd_state_str(statusp->state));
				printf("peer mode=%s\n", wl_proxd_mode_str(statusp->peermode));
				printf("peer=%s\n", wl_ether_etoa(&statusp->peer));
				printf("lowest rssi=%d\n", statusp->low_rssi);
				printf("highest rssi=%d\n", statusp->hi_rssi);
				printf("tx pkts=%d\n", statusp->txcnt);
				printf("rx pkts=%d\n", statusp->rxcnt);
				printf("reason=%s\n\n", wl_proxd_reason_str(statusp->reason));
				break;

			case PROXD_TOF_METHOD:
				printf("mode=%s\n", wl_proxd_mode_str(statusp->mode));
				printf("state=%s\n", wl_proxd_tof_state_str(statusp->state));
				if (statusp->distance == 0xffffffff)
					printf("distance=-1\n");
				else
					printf("distance=%d.%04d\n", statusp->distance >> 4,
						((statusp->distance & 0xf)*625));
				printf("peer=%s\n", wl_ether_etoa(&statusp->peer));
				printf("avg rssi=%d\n", statusp->avg_rssi);
				printf("tx pkts=%d\n", statusp->txcnt);
				printf("rx pkts=%d\n", statusp->rxcnt);
				printf("frame types = CCK %d OFDM %d 11N %d 11AC %d\n",
					statusp->frame_type_cnt[FRAME_TYPE_CCK],
					statusp->frame_type_cnt[FRAME_TYPE_OFDM],
					statusp->frame_type_cnt[FRAME_TYPE_11N],
					statusp->frame_type_cnt[FRAME_TYPE_11AC]);
				printf("adj types = SW %d HW %d SEQ %d NONE %d\n",
					statusp->adj_type_cnt[TOF_ADJ_SOFTWARE],
					statusp->adj_type_cnt[TOF_ADJ_HARDWARE],
					statusp->adj_type_cnt[TOF_ADJ_SEQ],
					statusp->adj_type_cnt[TOF_ADJ_NONE]);
				printf("report status= %d\n", statusp->dbgstatus);
				printf("reason=%s\n", wl_proxd_tof_reason_str(statusp->reason));
				printf("frmcnt=%d\n", statusp->low_rssi);
				if (statusp->hi_rssi == TOF_LEGACY_AP)
					printf("measure=OneSide\n\n");
				else
					printf("measure=TwoSide\n\n");
				break;

			default:
				printf("ERROR: unsupported method\n");
				return BCME_USAGE_ERROR;
		}
	}
	else
		printf("Cannot set proxd_status\n");

	return ret;
}
static int
wl_proxd_payload(void *wl, cmd_t *cmd, char **argv)
{
	char *buf;
	uint16 len, *reply;
	int ret;

	buf = malloc(WL_PROXD_PAYLOAD_LEN);
	if (buf == NULL) {
		fprintf(stderr, "Failed to allocate buffer of %d bytes\n", WL_PROXD_PAYLOAD_LEN);
		return -1;
	}
	bzero(buf, WL_PROXD_PAYLOAD_LEN);

	/* skip the command name and check if NULL */
	if (!*++argv) {
		/* Get */
		if ((ret = wlu_iovar_get(wl, cmd->name, (void *)buf, WL_PROXD_PAYLOAD_LEN)) < 0) {
			free(buf);
			return (ret);
		}
		reply = (uint16 *)buf;
		len = dtoh16(reply[0]);

		if (len > 0) {
			char *ptr = buf+sizeof(uint16);
			char *endptr = ptr+len;
			int num = 0;
			uint8 val;

			printf("Payload Length %d\n", len);
			while (ptr < endptr)
			{
				val = *(uint8 *)ptr++;
				printf("%02X", val);
				if (++num == 40)
				{
					printf("\n");
					num = 0;
				}
			}
			if (num) printf("\n");
		}
	} else {
		/* Set */
		len = (uint16)atoi(argv[0]);
		if (len > 0) {
			if (!argv[1]) {
				printf("Payload content is missing\n");
				free(buf);
				return -1;
			}
			else {
				char *ptr = argv[1];
				char *bufp = buf;
				char hex[] = "XX";

				if ((uint16)strlen(ptr) != len*2)
				{
					printf("Payload length mismatch %d %d\n", len,
						((int)strlen(ptr))/2);
					free(buf);
					return -1;
				}
				while (*ptr) {
					strncpy(hex, ptr, 2);
					*bufp++ = (char) strtoul(hex, NULL, 16);
					ptr += 2;
				}
			}
		}
		ret = wlu_var_setbuf(wl, cmd->name, buf, len);
	}
	free(buf);
	return ret;
}


/*   print or calculate & print location info   */
void wl_proxd_tof_host_calc(wl_proxd_event_data_t* evp)
{
	uint32 distance;
	uint32 meanrtt, modertt, medianrtt, dst_sigma;	/* standard deviation */
	int ftm_cnt;
	int16 avg_rssi, validfrmcnt;
	int32 var1, var2, var3;
	char diststr[40];

	distance = ntoh32(evp->distance);
	dst_sigma = ntoh32(evp->sdrtt);
	ftm_cnt = ntoh16(evp->ftm_cnt);
	avg_rssi = ntoh16(evp->avg_rssi);
	validfrmcnt = ntoh16(evp->validfrmcnt);
	meanrtt = ntoh32(evp->meanrtt);
	modertt = ntoh32(evp->modertt);
	medianrtt = ntoh32(evp->medianrtt);
	var1 = ntoh32(evp->var1);
	var2 = ntoh32(evp->var2);
	var3 = ntoh32(evp->var3);

	bzero(diststr, sizeof(diststr));
	if (distance == 0xffffffff)
		sprintf(diststr, "distance=-1m\n");
	else
		sprintf(diststr, "distance=%d.%04dm\n", distance>>4, (distance & 0xf) * 625);

	if (ntoh32(evp->mode) == WL_PROXD_MODE_INITIATOR) {
		printf("Target:(%s); %s; ", wl_ether_etoa(&evp->peer_mac), diststr);
		printf("mean %d mode %d median %d\n", meanrtt, modertt, medianrtt);
	}
	else
		printf("Initiator:(%s); %s; ", wl_ether_etoa(&evp->peer_mac), diststr);

	printf("sigma:%d.%d;", dst_sigma/10, dst_sigma % 10);
	printf("rssi:%d validfrmcnt %d\n", avg_rssi, validfrmcnt);
	printf("var: %d %d %d\n", var1, var2, var3);

	if (ftm_cnt > 1) {
		int i;
		printf("event contains %d rtd samples for host side calculation:\n",
			ftm_cnt);

		for (i = 0; i < ftm_cnt; i++) {
			printf("ftm[%d] --> value:%d rssi:%d\n", i,
				ntoh32(evp->ftm_buff[i].value), evp->ftm_buff[i].rssi);
		}

		printf("host side calculation result: TBD\n");
		/* TODO: process raw samples */
		/*  e.g:
			1)  mean Mn = (S1+S2+... Sn)/N
			2)  variatin: Xn = (Sn - M)^2;
			3)  sqrt((X1 + X2 + .. Xn)/N)
		*/
	}
}
#ifdef WL_NAN
static const char *wl_proxd_nan_status_str(uint8 status)
{
	static const char *proxd_nan_status[] = {"Unknown", "Success", "Fail", "Timeout", "Abort"};

	if (status > WL_NAN_RANGING_STATUS_ABORT)
		status = 0;

	return proxd_nan_status[status];
}

/*   print or calculate & print nan event   */
void wl_proxd_nan_host_calc(wl_nan_ranging_event_data_t* evp)
{
	wl_nan_ranging_result_t *rp;
	int i;
	uint32 distance;
	uint32 dst_sigma;	/* standard deviation */
	uint8 validfrmcnt;
	char dist[40];

	rp = evp->rr;
	for (i = 0; i < evp->count; i++, rp++) {
		distance = rp->distance;
		dst_sigma = rp->rtt_var;
		validfrmcnt = rp->sounding_count;

		bzero(dist, sizeof(dist));
		if (distance == 0xffffffff)
			sprintf(dist, "distance=-1m\n");
		else
			sprintf(dist, "distance=%d.%dm\n", distance>>4, ((distance&0xf)*125)>>1);

		if (evp->mode == WL_PROXD_MODE_INITIATOR) {
			printf("Target:(%s); %s", wl_ether_etoa(&rp->ea), dist);
		}
		else
			printf("Initiator:(%s); %s", wl_ether_etoa(&rp->ea), dist);

		printf("%s sigma:%d.%d validfrmcnt %d\n", wl_proxd_nan_status_str(rp->status),
			dst_sigma/10, dst_sigma % 10, validfrmcnt);
	}
}
#endif /* WL_NAN */

#define PROXD_EVENTS_BUFFER_SIZE 2048
static int
wl_proxd_event_check(void *wl, cmd_t *cmd, char **argv)
{
	bool exit_on1stresult = FALSE;
	int fd, err, octets;
	struct sockaddr_ll sll;
	struct ifreq ifr;
	char ifnames[IFNAMSIZ] = {"eth0"};
	bcm_event_t *event;
	uint32 reason;
	uint16 mode; /* target or initiator */
	char* data;
	int event_type;
	uint8 event_inds_mask[WL_EVENTING_MASK_LEN];	/* 128-bit mask */
	wl_proxd_event_data_t* evp;
#ifdef WL_NAN
	wl_nan_ranging_event_data_t *nanevp;
#endif


	UNUSED_PARAMETER(wl);
	UNUSED_PARAMETER(cmd);

	if (argv[1] == NULL) {
		printf("<ifname> param is missing\n");
		return -1;
	}

	if (*++argv) {
		strncpy(ifnames, *argv, (IFNAMSIZ - 1));
	}

	bzero(&ifr, sizeof(ifr));
	strncpy(ifr.ifr_name, ifnames, (IFNAMSIZ - 1));


	/*  read current mask state  */
	if ((err = wlu_iovar_get(wl, "event_msgs", &event_inds_mask, WL_EVENTING_MASK_LEN))) {
		printf("couldn't read event_msgs\n");
		return (err);
	}
	event_inds_mask[WLC_E_PROXD / 8] |= 1 << (WLC_E_PROXD % 8);
	if ((err = wlu_iovar_set(wl, "event_msgs", &event_inds_mask, WL_EVENTING_MASK_LEN)))
		return (err);

	if (*++argv) {
		if (strcmp(*argv, "osh") == 0) {
			/* exit after processing 1st proximity result */;
			exit_on1stresult = TRUE;
		}
	}

	fd = socket(PF_PACKET, SOCK_RAW, hton16(ETHER_TYPE_BRCM));
	if (fd < 0) {
		printf("Cannot create socket %d\n", fd);
		return -1;
	}

	err = ioctl(fd, SIOCGIFINDEX, &ifr);
	if (err < 0) {
		printf("Cannot get iface:%s index \n", ifr.ifr_name);
		goto exit1;
	}

	bzero(&sll, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = hton16(ETHER_TYPE_BRCM);
	sll.sll_ifindex = ifr.ifr_ifindex;
	err = bind(fd, (struct sockaddr *)&sll, sizeof(sll));
	if (err < 0) {
		printf("Cannot bind %d\n", err);
		goto exit1;
	}

	data = (char*)malloc(PROXD_EVENTS_BUFFER_SIZE);

	if (data == NULL) {
		printf("Cannot not allocate %d bytes for events receive buffer\n",
			PROXD_EVENTS_BUFFER_SIZE);
		goto exit1;
	}

	printf("wating for LBS events :%s\n", ifr.ifr_name);

	while (1) {
		fflush(stdout);
		octets = recv(fd, data, PROXD_EVENTS_BUFFER_SIZE, 0);

		if (octets <= 0)  {
			/* sigterm */
			err = -1;
			break;
		}

		event = (bcm_event_t *)data;
		event_type = ntoh32(event->event.event_type);
		reason = ntoh32(event->event.reason);


		if ((event_type != WLC_E_PROXD)) {
		/* may be other BCM events we are not interested in */
			printf("WARNING: not a proxd BCM_EVENT:%d\n", event_type);
				continue;
		}

#ifdef WL_NAN
		if (reason == WLC_E_PROXD_NAN_EVENT) {
			nanevp = (wl_nan_ranging_event_data_t *)&data[sizeof(bcm_event_t)];
			mode = nanevp->mode;
		}
		else
#endif
		{
		/* move to bcm event payload, which is proxd event structure */
		evp = (wl_proxd_event_data_t*)&data[sizeof(bcm_event_t)];
		mode = ntoh16(evp->mode);
		}

		printf("mode:%s; event:",
			(mode == WL_PROXD_MODE_INITIATOR)?"initiator":"target");

		switch (reason) {
		case WLC_E_PROXD_FOUND:
			printf("WLC_E_PROXD_FOUND; ");
			wl_proxd_tof_host_calc(evp); /* backward compatibility with RSSI method */
			break;
		case WLC_E_PROXD_GONE:
			printf("WLC_E_PROXD_GONE; ");
			break;
		case WLC_E_PROXD_START:
			/* event for targets / accesspoints  */
			printf("WLC_E_PROXD_START; ");
			break;
		case WLC_E_PROXD_STOP:
			printf("WLC_E_PROXD_STOP; ");
		break;
		case WLC_E_PROXD_COMPLETED:
			printf("WLC_E_PROXD_COMPLETED; ");
			/* all new method results should land here */
			wl_proxd_tof_host_calc(evp);
			if (exit_on1stresult)
				goto exit0;
			break;
		case WLC_E_PROXD_ERROR:
			printf("WLC_E_PROXD_ERROR:%d;", evp->err_code);
			/* all new method results should land here */
			wl_proxd_tof_host_calc(evp);
			if (exit_on1stresult)
				goto exit0;
			break;
		case WLC_E_PROXD_COLLECT_START:
			printf("WLC_E_PROXD_COLLECT_START; ");
			break;
		case WLC_E_PROXD_COLLECT_STOP:
			printf("WLC_E_PROXD_COLLECT_STOP; ");
			break;
		case WLC_E_PROXD_COLLECT_COMPLETED:
			printf("WLC_E_PROXD_COLLECT_COMPLETED; ");
			break;
		case WLC_E_PROXD_COLLECT_ERROR:
			printf("WLC_E_PROXD_COLLECT_ERROR; ");
			break;
#ifdef WL_NAN
		case WLC_E_PROXD_NAN_EVENT:
			wl_proxd_nan_host_calc(nanevp);
			break;
#endif
		default:
			printf("ERROR: unsupported EVENT reason code:%d; ",
				reason);
			err = -1;
			break;
		}

		printf("\n");
	}
exit0:
	/* if we ever reach here */
	free(data);
exit1:
	close(fd);

	/* Read the event mask from driver and mask the event WLC_E_PROXD */
	if (!(err = wlu_iovar_get(wl, "event_msgs", &event_inds_mask, WL_EVENTING_MASK_LEN))) {
		event_inds_mask[WLC_E_PROXD / 8] &= (~(1 << (WLC_E_PROXD % 8)));
		err = wlu_iovar_set(wl, "event_msgs", &event_inds_mask, WL_EVENTING_MASK_LEN);
	}

	fflush(stdout);
	return (err);
}

#if defined(WL_NAN)
int wl_nan_ranging_config(void *wl, cmd_t *cmd, char **argv)
{
	wl_nan_ranging_config_t	nanconfig, *pnan_config;
	char chspec_str[CHANSPEC_STR_LEN];
	int 	rc;
	void	*ptr = NULL;
	int	count;
	chanspec_t chanspec;

	count = ARGCNT(argv);

	/* GET operation */
	if (*++argv == NULL) {
		if ((rc = wlu_var_getbuf(wl, cmd->name, NULL, 0, &ptr)) < 0)
			return rc;
		pnan_config = (wl_nan_ranging_config_t *)ptr;
		wf_chspec_ntoa(pnan_config->chanspec, chspec_str);
		printf("chanspec:           %s(0x%04x)\n", chspec_str, pnan_config->chanspec);
		printf("timeslot:           %d\n", pnan_config->timeslot);
		printf("duration:           %d\n", pnan_config->duration);
		printf("allowed mac:        %02x:%02x:%02x:%02x:%02x:%02x\n",
			pnan_config->allow_mac.octet[0],
			pnan_config->allow_mac.octet[1],
			pnan_config->allow_mac.octet[2],
			pnan_config->allow_mac.octet[3],
			pnan_config->allow_mac.octet[4],
			pnan_config->allow_mac.octet[5]);
		printf("flags:              0x%04x\n", pnan_config->flags);
		return rc;
	}

	/*
	** Set the attributes.
	*/
	if (count < 4) {
		return BCME_USAGE_ERROR;
	}

	pnan_config = &nanconfig;

	if ((chanspec = wf_chspec_aton(*argv)) == 0) {
		fprintf(stderr, "%s: could not parse \"%s\" as a channel\n",
			cmd->name, *argv);
		return BCME_BADARG;
	}

	pnan_config->chanspec = wl_chspec_to_driver(chanspec);

	if (pnan_config->chanspec == INVCHANSPEC) {
		fprintf(stderr, "%s: wl_chspec_to_driver() error \"%s\" \n",
			cmd->name, *argv);
		return BCME_BADARG;
	}

	pnan_config->timeslot = strtoul(*++argv, NULL, 0);
	if (pnan_config->timeslot == 0 || pnan_config->timeslot >= 512) {
		fprintf(stderr, "Invalid timeslot \"%s\" \n", *argv);
		return BCME_BADARG;
	}

	pnan_config->duration = strtoul(*++argv, NULL, 0);
	if (pnan_config->duration == 0 || pnan_config->duration >= 512) {
		fprintf(stderr, "Invalid duration \"%s\" \n", *argv);
		return BCME_BADARG;
	}

	if (*++argv) {
		/* MAC address */
		if (!wl_ether_atoe(*argv, &pnan_config->allow_mac)) {
			fprintf(stderr, "nan ranging config mac addr err\n");
			return BCME_BADARG;
		}
		if (*++argv) {
			pnan_config->flags = strtoul(*argv, NULL, 0);
		} else
			pnan_config->flags = 0;
	} else {
		memcpy(&pnan_config->allow_mac, &ether_bcast, ETHER_ADDR_LEN);
		pnan_config->flags = 0;
	}

	rc = wlu_var_setbuf(wl, cmd->name, pnan_config, sizeof(wl_nan_ranging_config_t));

	return (rc);
}

int wl_nan_ranging_start(void *wl, cmd_t *cmd, char **argv)
{
	const char  *str;
	wl_nan_ranging_list_t *pnan_list;
	int	buf_len;
	int	str_len;
	int 	rc, i;
	void	*ptr = NULL;
	int count;
	chanspec_t chanspec;

	count = ARGCNT(argv);

	/* GET operation */
	if (*++argv == NULL) {
		if ((rc = wlu_var_getbuf(wl, cmd->name, NULL, 0, &ptr)) < 0)
			return rc;
		pnan_list = (wl_nan_ranging_list_t *)ptr;
		printf("num peers:       %d \n", pnan_list->count);
		printf("num peers done:  %d \n", pnan_list->num_peers_done);
		printf("num dws:         %d \n", pnan_list->num_dws);

		printf("----------------------------------------------------------------------\n");
		printf("Address \t\tchanspec\tcount\tretry\tabitmap\tflags\n");
		for (i = 0; i < pnan_list->count; i++) {
			printf("%02x:%02x:%02x:%02x:%02x:%02x\t0x%04x\t\t%d\t%d\t0x%x\t0x%x\n",
				pnan_list->rp[i].ea.octet[0],
				pnan_list->rp[i].ea.octet[1],
				pnan_list->rp[i].ea.octet[2],
				pnan_list->rp[i].ea.octet[3],
				pnan_list->rp[i].ea.octet[4],
				pnan_list->rp[i].ea.octet[5],
				pnan_list->rp[i].chanspec,
				pnan_list->rp[i].frmcnt,
				pnan_list->rp[i].retrycnt,
				pnan_list->rp[i].abitmap,
				pnan_list->rp[i].flags);
		}
		return rc;
	}

	/*
	** Set the attributes.
	*/
	if ((count % 6) != 2) {
		return BCME_USAGE_ERROR;
	}

	str = cmd->name;
	str_len = strlen(str);
	strncpy(buf, str, str_len);
	buf[ str_len ] = '\0';

	pnan_list = (wl_nan_ranging_list_t *) (buf + str_len + 1);
	pnan_list->count = count/6;
	pnan_list->num_peers_done = 0;
	pnan_list->num_dws =  strtoul(*argv++, NULL, 0);
	for (i = 0; i < pnan_list->count; i++, argv++) {
		if ((chanspec = wf_chspec_aton(*argv)) == 0) {
			fprintf(stderr, "%s: could not parse \"%s\" as a channel\n",
				cmd->name, *argv);
			return BCME_BADARG;
		}

		pnan_list->rp[i].chanspec = wl_chspec_to_driver(chanspec);

		if (pnan_list->rp[i].chanspec == INVCHANSPEC) {
			fprintf(stderr, "%s: wl_chspec_to_driver() error \"%s\" \n",
				cmd->name, *argv);
			return BCME_BADARG;
		}

		if (!wl_ether_atoe(*++argv, &pnan_list->rp[i].ea)) {
			fprintf(stderr, "ranging mac addr err\n");
			return BCME_BADADDR;
		}

		pnan_list->rp[i].abitmap = strtoul(*++argv, NULL, 0);
		pnan_list->rp[i].frmcnt = strtoul(*++argv, NULL, 0);
		if (pnan_list->rp[i].frmcnt >= 255) {
			fprintf(stderr, "Invalid frame count \"%s\" \n", *argv);
			return BCME_BADARG;
		}

		pnan_list->rp[i].retrycnt = strtoul(*++argv, NULL, 0);
		pnan_list->rp[i].flags = strtoul(*++argv, NULL, 0);
	}

	fprintf(stderr, "count %d\n", pnan_list->count);
	buf_len = str_len + 1 + sizeof(wl_nan_ranging_list_t) +
		sizeof(wl_nan_ranging_peer_t) * (pnan_list->count - 1);

	rc = wlu_set(wl, WLC_SET_VAR, buf, buf_len);

	return (rc);
}

int wl_nan_ranging_results_host(void *wl, cmd_t *cmd, char **argv)
{
	wl_nan_ranging_event_data_t *pnan_event;
	int rc, i;
	void *ptr = NULL;

	UNUSED_PARAMETER(argv);
	if ((rc = wlu_var_getbuf(wl, cmd->name, NULL, 0, &ptr)) < 0)
		return rc;
	pnan_event = (wl_nan_ranging_event_data_t *) ptr;
	printf("num results:       %d \n", pnan_event->count);
	printf("num good results:  %d \n", pnan_event->success_count);
	printf("------------------------------------------------------------------------------\n");
	printf("Address\t\t\tchanspec\tvalidcnt\tts\t\tdist\tstatus\n");
	for (i = 0; i < pnan_event->count; i++) {
		printf("%02x:%02x:%02x:%02x:%02x:%02x\t",
			pnan_event->rr[i].ea.octet[0],
			pnan_event->rr[i].ea.octet[1],
			pnan_event->rr[i].ea.octet[2],
			pnan_event->rr[i].ea.octet[3],
			pnan_event->rr[i].ea.octet[4],
			pnan_event->rr[i].ea.octet[5]);
		printf("%04x\t\t%d\t\t%u\t",
			pnan_event->rr[i].chanspec,
			pnan_event->rr[i].sounding_count,
			pnan_event->rr[i].timestamp);
		if (pnan_event->rr[i].distance == 0xffffffff)
			printf("-1\t");
		else
			printf("%d.%04d\t", pnan_event->rr[i].distance >> 4,
				(pnan_event->rr[i].distance & 0x0f) * 625);
		printf("%s\n", wl_proxd_nan_status_str(pnan_event->rr[i].status));
	}

	return (rc);
}
#endif /* WL_NAN */
