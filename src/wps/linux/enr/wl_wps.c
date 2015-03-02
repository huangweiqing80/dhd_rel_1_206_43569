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
 * $Id: wl_wps.c 368046 2012-11-11 00:40:51Z $
 */

#include <stdio.h>

#ifdef __linux__
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <errno.h>
#include <time.h>
#endif // __linux__

#include <portability.h>
#include <wps_enrapi.h>
#include <wps_sta.h>
#include "wlioctl.h"
#include <wps_staeapsm.h>
#include <wpserror.h>
#include <wpscommon.h>
#include <wps_enr_osl.h>
#include <reg_prototlv.h>
#include "bcmendian.h"

static bool wps_swap = false;

/* IOCTL swapping mode for Big Endian host with Little Endian dongle.  Default to off */
#define htod32(i) (wps_swap?bcmswap32(i):i)
#define htod16(i) (wps_swap?bcmswap16(i):i)
#define dtoh32(i) (wps_swap?bcmswap32(i):i)
#define dtoh16(i) (wps_swap?bcmswap16(i):i)
#define htodchanspec(i) htod16(i)
#define dtohchanspec(i) dtoh16(i)
#define htodenum(i) ((sizeof(i) == 4) ? htod32(i) : ((sizeof(i) == 2) ? htod16(i) : i))
#define dtohenum(i) ((sizeof(i) == 4) ? dtoh32(i) : ((sizeof(i) == 2) ? htod16(i) : i))

#if defined(D11AC_IOTYPES) && defined(BCM_WPS_IOTYPECOMPAT)
extern bool g_legacy_chanspec;
extern chanspec_t wps_wl_chspec_from_legacy(chanspec_t legacy_chspec);
extern chanspec_t wps_wl_chspec_to_legacy(chanspec_t chspec);

#define WPS_WL_CHSPEC_IOTYPE_HTOD(a) \
	((g_legacy_chanspec) ? wps_wl_chspec_to_legacy((a)):((a)))
#define WPS_WL_CHSPEC_IOTYPE_DTOH(a) \
	((g_legacy_chanspec) ? wps_wl_chspec_from_legacy((a)):((a)))

#else

#define WPS_WL_CHSPEC_IOTYPE_HTOD(a) ((a))
#define WPS_WL_CHSPEC_IOTYPE_DTOH(a) ((a))

#endif

extern char *ether_ntoa(const struct ether_addr *addr);
int tolower(int);
int wps_wl_ioctl(int cmd, void *buf, int len, bool set);
static int wl_iovar_get(char *iovar, void *bufptr, int buflen);
static int wps_iovar_set(const char *iovar, void *param, int paramlen);
static int wl_iovar_getbuf(char *iovar, void *param, int paramlen, void *bufptr, int buflen);
static int wps_iovar_setbuf(const char *iovar,
	void *param, int paramlen, void *bufptr, int buflen);
static uint wps_iovar_mkbuf(const char *name, char *data, uint datalen,
	char *iovar_buf, uint buflen, int *perr);
static int wps_ioctl_get(int cmd, void *buf, int len);
static int wps_ioctl_set(int cmd, void *buf, int len);
static char *get_scan_results();

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

#ifndef WL_SCAN_PARAMS_SSID_MAX
#define WL_SCAN_PARAMS_SSID_MAX         10
#endif

wps_ap_list_info_t ap_list[WPS_MAX_AP_SCAN_LIST_LEN];
static char scan_result[WPS_DUMP_BUF_LEN];
static uint8 wps_ie_setbuf[WPS_IE_BUF_LEN];

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
		printf("Please specify all the data bytes for this IE\n");
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
#ifdef _TUDEBUGTRACE
		printf( "Fail to get WLC_GET_MAGIC (%d)\n", ret);
#endif
		return ret;
	}

	/* Detect if IOCTL swapping is necessary */
	if (val == (int)bcmswap32(WLC_IOCTL_MAGIC))
	{
		val = bcmswap32(val);
		wps_swap = true;
	}
#ifdef _TUDEBUGTRACE
	printf( "val = %d(%d), swap=%d\n", val, WLC_IOCTL_MAGIC, wps_swap);
#endif
	if (val != WLC_IOCTL_MAGIC)
		return -1;
	if ((ret = wps_ioctl_get(WLC_GET_VERSION, &val, sizeof(int)) < 0))
	{
#ifdef _TUDEBUGTRACE
		printf( "Fail to get WLC_GET_VERSION (%d)\n", ret);
#endif
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

#ifdef ESCAN_REQ_VERSION
char *get_escan_results()
{
	#define ESCAN_BSS_FIXED_SIZE 		4
	#define ESCAN_EVENTS_BUFFER_SIZE 	2048
	struct escan_bss {
		struct escan_bss *next;
		wl_bss_info_t bss[1];
	};
	int params_size = (WL_SCAN_PARAMS_FIXED_SIZE +
		(uint)(uintptr)&((wl_escan_params_t *)0)->params) +
		(WL_NUMCHANNELS * sizeof(uint16));
	wl_escan_params_t *params;
	int fd, err, octets;
	struct sockaddr_ll sll;
	struct ifreq ifr;
	char if_name[IFNAMSIZ] = {"eth0"};
	bcm_event_t *event;
	uint32 reason, status;
	char *data;
	int event_type;
	struct ether_addr *addr;
	uint8 event_inds_mask[WL_EVENTING_MASK_LEN];    /* 128-bit mask */
	wl_escan_result_t *escan_data;
	struct escan_bss *escan_bss_head = NULL;
	struct escan_bss *escan_bss_tail = NULL;
	struct escan_bss *result;

	wl_scan_results_t *list = (wl_scan_results_t*)scan_result;
	wl_bss_info_t *scan_bss;
	params_size += WL_SCAN_PARAMS_SSID_MAX * sizeof(wlc_ssid_t);
	params = (wl_escan_params_t*)malloc(params_size);
	if (params == NULL) {
		fprintf(stderr, "Error allocating %d bytes for scan params\n", params_size);
		return 0;
	}
	memset(params, 0, params_size);
	params->params.bss_type = DOT11_BSSTYPE_ANY;
	memcpy(&params->params.bssid, &ether_bcast, ETHER_ADDR_LEN);
	params->params.scan_type = 0;
	params->params.nprobes = -1;
	params->params.active_time = -1;
	params->params.passive_time = -1;
	params->params.home_time = -1;
	params->params.channel_num = 0;

	memset(&ifr, 0, sizeof(ifr));
	wps_osl_get_ifname(if_name);
	strncpy(ifr.ifr_name, if_name, (IFNAMSIZ - 1));

	memset(event_inds_mask, '\0', WL_EVENTING_MASK_LEN);
	event_inds_mask[WLC_E_ESCAN_RESULT / 8] |= 1 << (WLC_E_ESCAN_RESULT % 8);
	if ((err = wps_iovar_set("event_msgs", &event_inds_mask, WL_EVENTING_MASK_LEN)))
		goto exit2;

	fd = socket(PF_PACKET, SOCK_RAW, htons(ETHER_TYPE_BRCM));
	if (fd < 0) {
		printf("Cannot create socket %d\n", fd);
		err = -1;
		goto exit2;
	}

	err = ioctl(fd, SIOCGIFINDEX, &ifr);
	if (err < 0) {
		printf("Cannot get index %d\n", err);
		close(fd);
		goto exit2;
	}

	/* bind the socket first before starting escan so we won't miss any event */
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETHER_TYPE_BRCM);
	sll.sll_ifindex = ifr.ifr_ifindex;
	err = bind(fd, (struct sockaddr *)&sll, sizeof(sll));
	if (err < 0) {
		printf("Cannot bind %d\n", err);
		close(fd);
		goto exit2;
	}

	params->version = htod32(ESCAN_REQ_VERSION);
	params->action = htod16(WL_SCAN_ACTION_START);
#ifdef __linux__
	srand((unsigned)time(NULL));
	params->sync_id = rand() & 0xffff;
#else
	params->sync_id = 4321;
#endif /* __linux__ */
	params->sync_id = htod16(params->sync_id);

	params_size += (uint)(uintptr)&((wl_escan_params_t *)0)->params;

	if ((err = wps_iovar_setbuf("escan", params, params_size, scan_result, sizeof(scan_result))) < 0 )
	{
		printf("Escan failed %d. Try scan process\n", err);
		close(fd);
		goto exit2;
	}
	data = (char*)malloc(ESCAN_EVENTS_BUFFER_SIZE);

	if (data == NULL) {
		printf("Cannot not allocate %d bytes for events receive buffer\n",
			ESCAN_EVENTS_BUFFER_SIZE);
		err = -1;
		close(fd);
		goto exit2;
	}

	list->count = 0;
	list->version = WL_BSS_INFO_VERSION;
	scan_bss = list->bss_info;

	/* receive scan result */
	while (1) {
		octets = recv(fd, data, ESCAN_EVENTS_BUFFER_SIZE, 0);
		if (octets < 0) {
			printf("escan result recv failed; recvBytes = %d\n", octets);
			goto exit1;
		}
		event = (bcm_event_t *)data;
		addr = (struct ether_addr *)&(event->event.addr);
		event_type = ntohl(event->event.event_type);

		if ((event_type == WLC_E_ESCAN_RESULT) && (octets > 0)) {
			escan_data = (wl_escan_result_t*)&data[sizeof(bcm_event_t)];
			reason = ntohl(event->event.reason);
			status = ntohl(event->event.status);
			if (status == WLC_E_STATUS_PARTIAL) {
				wl_bss_info_t *bi = &escan_data->bss_info[0];
				wl_bss_info_t *bss;

				/* check if we've received info of same BSSID */
				for (result = escan_bss_head; result; result = result->next) {
					bss = result->bss;

#define WLC_BSS_RSSI_ON_CHANNEL 0x0002 /* Copied from wlc.h. Is there a better way to do this? */

					if (!memcmp(&bi->BSSID, &bss->BSSID, ETHER_ADDR_LEN) &&
						CHSPEC_BAND(bi->chanspec) ==
						CHSPEC_BAND(bss->chanspec) &&
						bi->SSID_len == bss->SSID_len &&
						!memcmp(bi->SSID, bss->SSID, bi->SSID_len))
						break;
				}

				if (!result) {
					/* New BSS. Allocate memory and save it */
#ifdef _TUDEBUGTRACE
//					printf("bi->length = %d\n", dtoh32(bi->length));
#endif
					struct escan_bss *ebss = malloc(ESCAN_BSS_FIXED_SIZE
						+ dtoh32(bi->length));

					if (!ebss) {
						perror("can't allocate memory for bss");
						goto exit1;
					}

					ebss->next = NULL;
					memcpy(&ebss->bss, bi, dtoh32(bi->length));
					if (escan_bss_tail) {
						escan_bss_tail->next = ebss;
					} else {
						escan_bss_head = ebss;
					}
					escan_bss_tail = ebss;

					/* Copy bss info to scan buffer. */
					memcpy((int8*)scan_bss, (int8*)bi, dtoh32(bi->length));
					scan_bss = (wl_bss_info_t*)((int8*)scan_bss + dtoh32(bi->length));
					list->count++;
				} else {
					/* We've got this BSS. Update rssi if necessary */
					if ((bss->flags & WLC_BSS_RSSI_ON_CHANNEL) ==
						(bi->flags & WLC_BSS_RSSI_ON_CHANNEL)) {
						/* preserve max RSSI if the measurements are
						 * both on-channel or both off-channel
						 */
						bss->RSSI = (dtoh16(bss->RSSI) > dtoh16(bi->RSSI)) ? bss->RSSI : bi->RSSI;
					} else if ((bss->flags & WLC_BSS_RSSI_ON_CHANNEL) &&
						(bi->flags & WLC_BSS_RSSI_ON_CHANNEL) == 0) {
						/* preserve the on-channel rssi measurement
						 * if the new measurement is off channel
						*/
						bss->RSSI = bi->RSSI;
						bss->flags |= WLC_BSS_RSSI_ON_CHANNEL;
					}
				}
			} else if (status == WLC_E_STATUS_SUCCESS) {
				/* Escan finished. Let's go dump the results. */
				break;
			} else {
				printf("sync_id: %d, status:%d, misc. error/abort\n",
					dtoh16(escan_data->sync_id), status);
				goto exit1;
			}
		}
	}

	/* Revert back to match the results directly from WLC_SCAN */
	list->version = htod32(list->version);
	list->count = htod32(list->count);
	list->buflen = htod32(list->buflen);

exit1:
	/* free scan results */
	result = escan_bss_head;
	while (result) {
		struct escan_bss *tmp = result->next;
		free(result);
		result = tmp;
	}
	free(data);
	close(fd);

exit2:
	free(params);
	if (err < 0)
		return NULL;
	return scan_result;
}
#endif /* ESCAN_REQ_VERSION */


char *get_scan_results()
{
	int ret, retry;
	wl_scan_params_t* params;
	wl_scan_results_t *list = (wl_scan_results_t*)scan_result;
	int params_size = WL_SCAN_PARAMS_FIXED_SIZE + WL_NUMCHANNELS * sizeof(uint16);

#ifdef ESCAN_REQ_VERSION
	/* Use Escan */
	if (get_escan_results() != NULL)
		return scan_result;
#endif /* ESCAN_REQ_VERSION */

	/* Try scan process instead */

	params = (wl_scan_params_t*)malloc(params_size);
	if (params == NULL) {
		fprintf(stderr, "Error allocating %d bytes for scan params\n", params_size);
		return 0;
	}

	memset(params, 0, params_size);
	params->bss_type = DOT11_BSSTYPE_ANY;
	memcpy(&params->bssid, &ether_bcast, ETHER_ADDR_LEN);
	params->scan_type = -1;
	params->nprobes = -1;
	params->active_time = -1;
	params->passive_time = -1;
	params->home_time = -1;
	params->channel_num = 0;

	wps_ioctl_set(WLC_SCAN, params, params_size);

	/* Poll for the results once a second until the scan is done */
	for (retry = 0; retry < WPS_SCAN_MAX_WAIT_SEC; retry++) {
		WpsSleep(1);

		list->buflen = htod32(WPS_DUMP_BUF_LEN);
		ret = wps_ioctl_get(WLC_SCAN_RESULTS, scan_result, WPS_DUMP_BUF_LEN);

		/* break out if the scan result is ready */
		if (ret == 0)
			break;
	}

	free(params);
	if (ret < 0)
		return NULL;
	return scan_result;
}


wps_ap_list_info_t *wps_get_ap_list()
{
	return ap_list;
}
wps_ap_list_info_t *create_aplist()
{
	wl_scan_results_t *list = (wl_scan_results_t*)scan_result;
	wl_bss_info_t *bi;
	wl_bss_info_107_t *old_bi_107;
	uint i, wps_ap_count = 0;

	get_scan_results();

	list->version = dtoh32(list->version);
	list->count = dtoh32(list->count);
	list->buflen = dtoh32(list->buflen);

	memset(ap_list, 0, sizeof(ap_list));
	if (list->count == 0)
		return 0;

	if (list->version != WL_BSS_INFO_VERSION &&
	    list->version != LEGACY_WL_BSS_INFO_VERSION &&
#ifdef LEGACY2_WL_BSS_INFO_VERSION
	    list->version != LEGACY2_WL_BSS_INFO_VERSION &&
#endif
	    TRUE) {
		fprintf(stderr, "Sorry, your driver has bss_info_version %d "
			"but this program supports only version %d.\n",
			list->version, WL_BSS_INFO_VERSION);
		return 0;
	}

	if (list->version > WL_BSS_INFO_VERSION)
	{
		fprintf(stderr, "your driver has bss_info_version %d "
			"but this program supports only version %d.\n",
			list->version, WL_BSS_INFO_VERSION);
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
				wps_strncpy((char *)ap_list[wps_ap_count].ssid, (char *)bi->SSID,
					sizeof(ap_list[0].ssid));
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
				ap_list[wps_ap_count].channel = CHSPEC_CHANNEL(bi->chanspec) +
					chan_adj;
				ap_list[wps_ap_count].band = (CHSPEC_IS2G(bi->chanspec) ?
					WPS_RFBAND_24GHZ : WPS_RFBAND_50GHZ);
				ap_list[wps_ap_count].wep = bi->capability & DOT11_CAP_PRIVACY;
				wps_ap_count++;
			}

		}
		bi = (wl_bss_info_t*)((int8*)bi + bi->length);
	}
	return ap_list;
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

static int
_del_vndr_ie(char *bufaddr, int buflen, uint32 frametype)
{
	int iebuf_len;
	int iecount, err;
	vndr_ie_setbuf_t *ie_setbuf;
#ifdef _TUDEBUGTRACE
	int i;
	int frag_len = buflen - 6;
	unsigned char *frag = (unsigned char *)(bufaddr + 6);
#endif

	iebuf_len = buflen + sizeof(vndr_ie_setbuf_t) - sizeof(vndr_ie_t);
	ie_setbuf = (vndr_ie_setbuf_t *) malloc(iebuf_len);
	if (!ie_setbuf) {
		printf("memory alloc failure\n");
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
	printf("\n_del_vndr_ie (%s, frag_len=%d)\n", _pktflag_name(dtoh32(frametype)), frag_len);
	for (i = 0; i < frag_len; i++) {
		if (i && !(i%16))
			printf("\n");
		printf("%02x ", frag[i]);
	}
	printf("\n");
#endif

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
		printf("memory alloc failure\n");
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
	pktflag = htod32(pktflag);
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
	printf("\n_set_vndr_ie (%s, frag_len=%d)\n", _pktflag_name(dtoh32(pktflag)), frag_len);
	for (i = 0; i < frag_len; i++) {
		if (i && !(i%16))
			printf("\n");
		printf("%02x ", frag[i]);
	}
	printf("\n");
#endif
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
			printf("Error, there is a TLV length %d bigger than "
				"Max fragment length %d. Unable to fragment it.\n",
				next_tlv_len, max_frag_len);
			return NULL;
		}

		/* Abnormal IE check */
		if ((total_len + next_tlv_len) > length) {
			printf("Error, Abnormal WPS IE.\n");
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

int create_wps_ie(bool pbc, unsigned int pktflag)
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
	int frag_max = WPS_IE_FRAG_MAX;
#ifdef WFA_WPS_20_TESTBED
	uint8 *updie_setbuf;
	uint8 *updie_len;
#endif /* WFA_WPS_20_TESTBED */


	if (pktflag != VNDR_IE_PRBREQ_FLAG && pktflag != VNDR_IE_ASSOCREQ_FLAG) {
#ifdef _TUDEBUGTRACE
		printf("_add_wps_ie : unsupported pktflag 0x%x\n", pktflag);
#endif
		return -1;
	}

	/* Generate wps_ie_setbuf */
	if (create_wps_ie(pbc, pktflag) != 0) {
#ifdef _TUDEBUGTRACE
		printf("_add_wps_ie : Create WPS IE failed\n");
#endif
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
			printf("Failed to update partial WPS IE in %s\n",
				(pktflag == VNDR_IE_PRBREQ_FLAG) ? "probereq" : "assocreq");
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

/* add probe request for enrollee */
int add_wps_ie(unsigned char *p_data, int length, bool pbc, bool b_wps_version2)
{
	int err = 0;

	/* Add WPS IE in probe request */
	if ((err = _add_wps_ie(pbc, VNDR_IE_PRBREQ_FLAG)) != 0) {
#ifdef _TUDEBUGTRACE
		printf("add_wps_ie : Add WPS IE in probe request failed\n");
#endif
		return err;
	}

	/* Add WPS IE in associate request */
	if (b_wps_version2 && (err = _add_wps_ie(pbc, VNDR_IE_ASSOCREQ_FLAG)) != 0) {
#ifdef _TUDEBUGTRACE
		printf("add_wps_ie : Add WPS IE in associate request failed\n");
#endif
		return err;
	}

	return 0;
}

/* Remove probe request WPS IEs */
int rem_wps_ie(unsigned char *p_data, int length, unsigned int pktflag)
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
#ifdef _TUDEBUGTRACE
		printf("rem_wps_ie : unsupported pktflag 0x%x\n", pktflag);
#endif
		return -1;
	}

	/* Get all WPS IEs in probe request IE */
	if (wl_iovar_get("vndr_ie", getbuf, WPS_IE_BUF_LEN)) {
#ifdef _TUDEBUGTRACE
		printf("rem_wps_ie : No IE to remove\n");
#endif
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

int join_network(char* ssid, uint32 wsec)
{
	int ret = 0, retry;
	wlc_ssid_t ssid_t;
	int auth = 0, infra = 1;
	int wpa_auth = WPA_AUTH_DISABLED;
	char bssid[6];
	uint wsec_ext;

#ifdef _TUDEBUGTRACE
	printf("Joining network %s - %d\n", ssid, wsec);
#endif
	/*
	 * If wep bit is on,
	 * pick any WPA encryption type to allow association.
	 * Registration traffic itself will be done in clear (eapol).
	*/
	if (wsec)
		wsec = 4; /* AES */
	ssid_t.SSID_len = strlen(ssid);
	strncpy((char *)ssid_t.SSID, ssid, sizeof(ssid_t.SSID));

	/* set infrastructure mode */
	infra = htod32(infra);
	if ((ret = wps_ioctl_set(WLC_SET_INFRA, &infra, sizeof(int))) < 0)
		return ret;

	/* set authentication mode */
	auth = htod32(auth);
	if ((ret = wps_ioctl_set(WLC_SET_AUTH, &auth, sizeof(int))) < 0)
		return ret;

	/* set wsec mode */
	wsec_ext = (uint)wsec;
	wsec_ext = htod32(wsec_ext);
	if ((ret = wps_ioctl_set(WLC_SET_WSEC, &wsec_ext, sizeof(int))) < 0)
		return ret;

	/* set WPA_auth mode */
	wpa_auth = htod32(wpa_auth);
	if ((ret = wps_ioctl_set(WLC_SET_WPA_AUTH, &wpa_auth, sizeof(wpa_auth))) < 0)
		return ret;

	/* set ssid */
	ssid_t.SSID_len = htod32(ssid_t.SSID_len);
	if ((ret = wps_ioctl_set(WLC_SET_SSID, &ssid_t, sizeof(wlc_ssid_t))) == 0) {
		/* Poll for the results once a second until we got BSSID */
		for (retry = 0; retry < WPS_JOIN_MAX_WAIT_SEC; retry++) {
			WpsSleep(1);

			ret = wps_ioctl_get(WLC_GET_BSSID, bssid, 6);

			/* break out if the scan result is ready */
			if (ret == 0)
				break;

			if (retry != 0 && retry % 10 == 0) {
				if ((ret = wps_ioctl_set(WLC_SET_SSID, &ssid_t,
					sizeof(wlc_ssid_t))) < 0)
					return ret;
			}
		}
	}

	return ret;
}

int join_network_with_bssid(char* ssid, uint32 wsec, char *bssid)
{
#if !defined(WL_ASSOC_PARAMS_FIXED_SIZE) || !defined(WL_JOIN_PARAMS_FIXED_SIZE)
	return (join_network(ssid, wsec));
#else
	int ret = 0, retry;
	int auth = 0, infra = 1;
	int wpa_auth = WPA_AUTH_DISABLED;
	char associated_bssid[6];
	wl_join_params_t join_params;
	wlc_ssid_t *ssid_t = &join_params.ssid;
	wl_assoc_params_t *params_t = &join_params.params;
	uint wsec_ext;

	printf("Joining network %s - %d\n", ssid, wsec);

	memset(&join_params, 0, sizeof(join_params));

	/*
	 * If wep bit is on,
	 * pick any WPA encryption type to allow association.
	 * Registration traffic itself will be done in clear (eapol).
	*/
	if (wsec)
		wsec = 4; /* AES */

	/* ssid */
	ssid_t->SSID_len = strlen(ssid);
	strncpy((char *)ssid_t->SSID, ssid, sizeof(ssid_t->SSID));

	/* bssid (if any) */
	if (bssid)
		memcpy(&params_t->bssid, bssid, ETHER_ADDR_LEN);
	else
		memcpy(&params_t->bssid, &ether_bcast, ETHER_ADDR_LEN);

	/* set infrastructure mode */
	infra = htod32(infra);
	if ((ret = wps_ioctl_set(WLC_SET_INFRA, &infra, sizeof(int))) < 0)
		return ret;

	/* set authentication mode */
	auth = htod32(auth);
	if ((ret = wps_ioctl_set(WLC_SET_AUTH, &auth, sizeof(int))) < 0)
		return ret;

	/* set wsec mode */
	wsec_ext = (uint)wsec;
	wsec_ext = htod32(wsec_ext);
	if ((ret = wps_ioctl_set(WLC_SET_WSEC, &wsec_ext, sizeof(int))) < 0)
		return ret;

	/* set WPA_auth mode */
	wpa_auth = htod32(wpa_auth);
	if ((ret = wps_ioctl_set(WLC_SET_WPA_AUTH, &wpa_auth, sizeof(wpa_auth))) < 0)
		return ret;

	/* set ssid */
	join_params.params.chanspec_num = htod32(join_params.params.chanspec_num);
	/* if chanspec_num ==0, use all available channels,
		otherwise count of chanspecs in chanspec_list.
	 */
	if (join_params.params.chanspec_num) {
		join_params.params.chanspec_list[0] = 
			htodchanspec(WPS_WL_CHSPEC_IOTYPE_HTOD(join_params.params.chanspec_list[0]));
	}
	join_params.ssid.SSID_len = htod32(join_params.ssid.SSID_len);
	if ((ret = wps_ioctl_set(WLC_SET_SSID, &join_params, sizeof(wl_join_params_t))) == 0) {
		/* Poll for the results once a second until we got BSSID */
		for (retry = 0; retry < WPS_JOIN_MAX_WAIT_SEC; retry++) {
			WpsSleep(1);

			ret = wps_ioctl_get(WLC_GET_BSSID, associated_bssid, 6);

			/* break out if the scan result is ready */
			if (ret == 0)
				break;

			if (retry != 0 && retry % 10 == 0) {
				if ((ret = wps_ioctl_set(WLC_SET_SSID, &join_params,
					sizeof(wl_join_params_t))) < 0)
					return ret;
			}
		}
	}

	return ret;
#endif /* !defined(WL_ASSOC_PARAMS_FIXED_SIZE) || !defined(WL_JOIN_PARAMS_FIXED_SIZE) */
}

int leave_network()
{
	return wps_ioctl_set(WLC_DISASSOC, NULL, 0);
}

int wps_get_bssid(char *bssid)
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

int
do_wpa_psk(WpsEnrCred* credential)
{
	int ret = 0, retry;
	wlc_ssid_t ssid_t;
	int auth = 0, infra = 1;
	int wpa_auth = WPA_AUTH_DISABLED;
	char bssid[6];
	uint8 wsec = 0;
	int sup_wpa;
	wl_wsec_key_t wlkey;
	wsec_pmk_t pmk;
	unsigned char *data = wlkey.data;
	char hex[] = "XX";
	int i;
	char *keystr, keystr_buf[SIZE_64_BYTES+1];

	/* get SSID */
	/* Add in PF #3, zero padding in SSID */
	if (strlen(credential->ssid) == (credential->ssidLen - 1))
		credential->ssidLen--;

	ssid_t.SSID_len = credential->ssidLen;
	strncpy((char *)ssid_t.SSID, credential->ssid, sizeof(ssid_t.SSID));

	/* get auth */
	auth = (strstr(credential->keyMgmt, "SHARED")) ? 1 : 0;

	/* get wpa_auth */
	if (strstr(credential->keyMgmt, "WPA-PSK"))
		wpa_auth |= WPA_AUTH_PSK;

	if (strstr(credential->keyMgmt, "WPA2-PSK")) {
		/* Always use WPA2PSK when both WPAPSK and WPA2PSK enabled */
		if (wpa_auth & WPA_AUTH_PSK)
			wpa_auth &= ~WPA_AUTH_PSK;

		wpa_auth |= WPA2_AUTH_PSK;
	}

	/* get wsec */
	if (credential->encrType & ENCRYPT_WEP)
		wsec |= WEP_ENABLED;
	if (credential->encrType & ENCRYPT_TKIP)
		wsec |= TKIP_ENABLED;
	if (credential->encrType & ENCRYPT_AES)
		wsec |= AES_ENABLED;

	/* Add in PF#3, use AES when encryptoin type in mixed-mode */
	if (wsec == (TKIP_ENABLED | AES_ENABLED))
		wsec &= ~TKIP_ENABLED;

	/* set infrastructure mode */
	infra = htod32(infra);
	if ((ret = wps_ioctl_set(WLC_SET_INFRA, &infra, sizeof(int))) < 0)
		return ret;

	/* set mac-layer auth */
	auth = htod32(auth);
	if ((ret = wps_ioctl_set(WLC_SET_AUTH, &auth, sizeof(int))) < 0)
		return ret;

	/* set wsec */
	if ((ret = wps_ioctl_set(WLC_SET_WSEC, &wsec, sizeof(int))) < 0)
		return ret;

	/* set upper-layer auth */
	wpa_auth = htod32(wpa_auth);
	if ((ret = wps_ioctl_set(WLC_SET_WPA_AUTH, &wpa_auth, sizeof(wpa_auth))) < 0)
		return ret;

	/* set in-driver supplicant */
	sup_wpa = ((dtoh32(wpa_auth) & WPA_AUTH_PSK) == 0)? 0: 1;
	sup_wpa |= ((dtoh32(wpa_auth) & WPA2_AUTH_PSK) == 0)? 0: 1;

	sup_wpa = htod32(sup_wpa);
	if ((ret = wps_iovar_set("sup_wpa", &sup_wpa, sizeof(sup_wpa))) < 0)
		return ret;

	/* set the key if wsec */
	if (wsec == WEP_ENABLED) {
		memset(&wlkey, 0, sizeof(wl_wsec_key_t));
		if (credential->wepIndex)
			wlkey.index = credential->wepIndex - 1;
		switch (credential->nwKeyLen) {
		/* ASIC */
		case 5:
		case 13:
		case 16:
			wlkey.len = credential->nwKeyLen;
			memcpy(data, credential->nwKey, wlkey.len + 1);
			break;
		case 10:
		case 26:
		case 32:
		case 64:
			wlkey.len = (credential->nwKeyLen) / 2;
			memcpy(keystr_buf, credential->nwKey, credential->nwKeyLen);
			keystr_buf[credential->nwKeyLen] = '\0';
			keystr = keystr_buf;
			while (*keystr) {
				wps_strncpy(hex, keystr, sizeof(hex));
				*data++ = (char) strtoul(hex, NULL, 16);
				keystr += 2;
			}
			break;
		default:
			return -1;
		}

		switch (wlkey.len) {
		case 5:
			wlkey.algo = CRYPTO_ALGO_WEP1;
			break;
		case 13:
			wlkey.algo = CRYPTO_ALGO_WEP128;
			break;
		case 16:
			/* default to AES-CCM */
			wlkey.algo = CRYPTO_ALGO_AES_CCM;
			break;
		case 32:
			wlkey.algo = CRYPTO_ALGO_TKIP;
			break;
		default:
			return -1;
		}

		/* Set as primary key by default */
		wlkey.flags |= WL_PRIMARY_KEY;

		wlkey.algo = htod32(wlkey.algo);
		wlkey.flags = htod32(wlkey.flags);
		wlkey.index = htod32(wlkey.index);
		wlkey.iv_initialized = htod32(wlkey.iv_initialized);
		wlkey.len = htod32(wlkey.len);
		for (i=0;i<18;i++) {
			wlkey.pad_1[i] = htod32(wlkey.pad_1[i]);
		}
		for (i=0;i<2;i++) {
			wlkey.pad_2[i] = htod32(wlkey.pad_2[i]);
		}
		wlkey.pad_3 = htod32(wlkey.pad_3);
		wlkey.pad_4 = htod32(wlkey.pad_4);
		for (i=0;i<2;i++) {
			wlkey.pad_5[i] = htod32(wlkey.pad_5[i]);
		}
		wlkey.rxiv.hi = htod32(wlkey.rxiv.hi);
		wlkey.rxiv.lo = htod32(wlkey.rxiv.lo);

		if ((ret = wps_ioctl_set(WLC_SET_KEY, &wlkey, sizeof(wlkey))) < 0)
			return ret;
	}
	else if (wsec != 0) {
		memset(&pmk, 0, sizeof(wsec_pmk_t));
		if (credential->nwKeyLen < WSEC_MIN_PSK_LEN ||
			credential->nwKeyLen > WSEC_MAX_PSK_LEN) {
			printf("passphrase must be between %d and %d characters long\n",
				WSEC_MIN_PSK_LEN, WSEC_MAX_PSK_LEN);
			return -1;
		}

		if (strlen(credential->nwKey) == (credential->nwKeyLen - 1))
			credential->nwKeyLen--;

		pmk.key_len = credential->nwKeyLen;
		pmk.flags = WSEC_PASSPHRASE;
		strncpy((char *)pmk.key, credential->nwKey, sizeof(pmk.key));

		pmk.flags = htod16(pmk.flags);
		pmk.key_len = htod16(pmk.key_len);
		if ((ret = wps_ioctl_set(WLC_SET_WSEC_PMK, &pmk, sizeof(pmk))) < 0)
			return ret;
	}

	/* set ssid */
	ssid_t.SSID_len = htod32(ssid_t.SSID_len);
	if ((ret = wps_ioctl_set(WLC_SET_SSID, &ssid_t, sizeof(wlc_ssid_t))) == 0) {
		/* Poll for the results once a second until we got BSSID */
		for (retry = 0; retry < WPS_JOIN_MAX_WAIT_SEC; retry++) {
			WpsSleep(1);

			ret = wps_ioctl_get(WLC_GET_BSSID, bssid, 6);

			/* break out if the scan result is ready */
			if (ret == 0)
				break;

			if (retry != 0 && retry % 10 == 0) {
				if ((ret = wps_ioctl_set(WLC_SET_SSID, &ssid_t,
					sizeof(wlc_ssid_t))) < 0)
					return ret;
			}
		}
	}

	return ret;

}

int
wps_ioctl_get(int cmd, void *buf, int len)
{
	return wps_wl_ioctl(cmd, buf, len, FALSE);
}

int
wps_ioctl_set(int cmd, void *buf, int len)
{
	return wps_wl_ioctl(cmd, buf, len, TRUE);
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

static int
wl_iovar_get(char *iovar, void *bufptr, int buflen)
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

static int
wl_iovar_getbuf(char *iovar, void *param, int paramlen, void *bufptr, int buflen)
{
	int err;
	uint namelen;
	uint iolen;

	namelen = strlen(iovar) + 1;	 /* length of iovar name plus null */
	iolen = namelen + paramlen;

	/* check for overflow */
	if (iolen > buflen)
		return (-1);

	memcpy(bufptr, iovar, namelen);	/* copy iovar name including null */
	memcpy((int8*)bufptr + namelen, param, paramlen);

	err = wps_ioctl_get(WLC_GET_VAR, bufptr, buflen);

	return (err);
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
 * format an iovar buffer
 * iovar name is converted to lower case
 */
static uint
wps_iovar_mkbuf(const char *name, char *data, uint datalen, char *iovar_buf, uint buflen, int *perr)
{
	uint iovar_len;
	char *p;

	iovar_len = strlen(name) + 1;

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
