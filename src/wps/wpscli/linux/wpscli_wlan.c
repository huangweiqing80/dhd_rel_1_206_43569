/*
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wpscli_wlan.c 475022 2014-05-02 23:21:49Z $
 *
 * Description: Implement functions handling WLAN activities
 *
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <netpacket/packet.h>
#include <net/if.h>
#ifndef OFFSETOF
#define	OFFSETOF(type, member)	((uint)(uintptr)&((type *)0)->member)
#endif /* OFFSETOF */
#include <wpscli_osl.h>
#include <bcmutils.h>
#include <tutrace.h>

extern int g_bRequestAbort;


extern int wpscli_iovar_set(const char *iovar, void *param, uint paramlen);
extern int wpscli_iovar_setbuf(const char *iovar, void *param, uint paramlen, void *buf, int buf_len);
extern char *wpscli_get_interface_name();

#define WLAN_JOIN_ATTEMPTS	3
#define WLAN_POLLING_JOIN_COMPLETE_ATTEMPTS	20
#define WLAN_POLLING_JOIN_COMPLETE_SLEEP	100
#define WLAN_JOIN_SCAN_DEFAULT_ACTIVE_TIME 20
#define WLAN_JOIN_SCAN_ACTIVE_TIME 60
#define WLAN_JOIN_SCAN_PASSIVE_TIME 150
#define WLAN_JOIN_SCAN_PASSIVE_TIME_LONG 2000

#ifndef WL_SCAN_PARAMS_SSID_MAX
#define WL_SCAN_PARAMS_SSID_MAX         10
#endif

#if defined(D11AC_IOTYPES) && defined(BCM_P2P_IOTYPECOMPAT)
extern bool g_legacy_chanspec;
extern chanspec_t p2pwl_chspec_from_legacy(chanspec_t legacy_chspec);
extern chanspec_t p2pwl_chspec_to_legacy(chanspec_t chspec);
#define P2PWL_CHSPEC_IOTYPE_HTOD(a) \
	((g_legacy_chanspec) ? p2pwl_chspec_to_legacy((a)):((a)))
#define P2PWL_CHSPEC_IOTYPE_DTOH(a) \
	((g_legacy_chanspec) ? p2pwl_chspec_from_legacy((a)):((a)))
#else
#define P2PWL_CHSPEC_IOTYPE_HTOD(a) ((a))
#define P2PWL_CHSPEC_IOTYPE_DTOH(a) ((a))
#endif

#if !defined(WL_ASSOC_PARAMS_FIXED_SIZE) || !defined(WL_JOIN_PARAMS_FIXED_SIZE)
static int join_network(char* ssid, uint32 wsec);
#endif /* !defined(WL_ASSOC_PARAMS_FIXED_SIZE) || !defined(WL_JOIN_PARAMS_FIXED_SIZE) */
static int join_network_with_bssid_active(const char* ssid, uint32 wsec, const char *bssid,
	int num_chanspec, chanspec_t *chanspec);
static int join_network_with_bssid(const char* ssid, uint32 wsec, const char *bssid,
	int num_chanspec, chanspec_t *chanspec);
static int leave_network(void);
extern int brcm_wpscli_ioctl_err;

brcm_wpscli_status wpscli_wlan_open(void)
{
	return WPS_STATUS_SUCCESS;
}

brcm_wpscli_status wpscli_wlan_close(void)
{
	return WPS_STATUS_SUCCESS;
}

/* make a wlan connection. */
brcm_wpscli_status wpscli_wlan_connect(const char* ssid, uint32 wsec, const char *bssid,
	int num_chanspec, chanspec_t *chanspec)
{
	int ret = 0;
	int auth = 0, infra = 1;
	int wpa_auth = WPA_AUTH_DISABLED;

	/* clear abort flag */
	g_bRequestAbort = FALSE;

	/*
	 * If wep bit is on,
	 * pick any WPA encryption type to allow association.
	 * Registration traffic itself will be done in clear (eapol).
	*/
	if (wsec)
		wsec = 2; /* TKIP */

	/* set infrastructure mode */
	if ((ret = wpscli_wlh_ioctl_set(WLC_SET_INFRA,
		(const char *)&infra, sizeof(int))) < 0)
		return ret;

	/* set authentication mode */
	if ((ret = wpscli_wlh_ioctl_set(WLC_SET_AUTH,
		(const char *)&auth, sizeof(int))) < 0)
		return ret;

	/* set wsec mode */
	if ((ret = wpscli_wlh_ioctl_set(WLC_SET_WSEC,
		(const char *)&wsec, sizeof(int))) < 0)
		return ret;

	/* set WPA_auth mode */
	if ((ret = wpscli_wlh_ioctl_set(WLC_SET_WPA_AUTH,
		(const char *)&wpa_auth, sizeof(wpa_auth))) < 0)
		return ret;
#if !defined(WL_ASSOC_PARAMS_FIXED_SIZE) || !defined(WL_JOIN_PARAMS_FIXED_SIZE)
		if (!g_bRequestAbort)
		{
			if (join_network(ssid, wsec) == 0)
				return WPS_STATUS_SUCCESS;
		}
#else
		/* attempt join with first channel */
		if (!g_bRequestAbort)
		{
			if (join_network_with_bssid_active(ssid, wsec, bssid, num_chanspec ? 1 : 0, chanspec) == 0)
				return WPS_STATUS_SUCCESS;
		}
		if (!g_bRequestAbort)
		{
			if (join_network_with_bssid(ssid, wsec, bssid, num_chanspec ? 1 : 0, chanspec) == 0)
				return WPS_STATUS_SUCCESS;
		}
		
			if (num_chanspec > 1 && chanspec != NULL) {
				/* attempt join with remaining channels */
				if (!g_bRequestAbort)
				{
					if (join_network_with_bssid_active(ssid, wsec, bssid, num_chanspec - 1, &chanspec[1]) == 0)
						return WPS_STATUS_SUCCESS;
				}
				if (!g_bRequestAbort)
				{
					if (join_network_with_bssid(ssid, wsec, bssid, num_chanspec - 1, &chanspec[1]) == 0)
						return WPS_STATUS_SUCCESS;
				}
			}
#endif /* !defined(WL_ASSOC_PARAMS_FIXED_SIZE) || !defined(WL_JOIN_PARAMS_FIXED_SIZE) */
		
			/* clear abort flag */
			g_bRequestAbort = FALSE;

	return WPS_STATUS_WLAN_CONNECTION_ATTEMPT_FAIL;
}

/* disconnect wlan connection */
brcm_wpscli_status wpscli_wlan_disconnect(void)
{
	leave_network();

	return WPS_STATUS_SUCCESS;
}

#ifdef ESCAN_REQ_VERSION
brcm_wpscli_status wpscli_wlan_escan(wl_scan_results_t *ap_list, uint32 buf_size)
{
#define ESCAN_BSS_FIXED_SIZE 		4
#define ESCAN_EVENTS_BUFFER_SIZE 	2048
	struct escan_bss {
		struct escan_bss *next;
		wl_bss_info_t bss[1];
	};
	brcm_wpscli_status wpscli_status = WPS_STATUS_WLAN_NO_ANY_AP_FOUND;
	int params_size = (WL_SCAN_PARAMS_FIXED_SIZE +
		(uint)(uintptr)&((wl_escan_params_t *)0)->params) +
		(WL_NUMCHANNELS * sizeof(uint16));
	wl_escan_params_t *params;
	int fd, err, octets;
	struct sockaddr_ll sll;
	struct ifreq ifr;
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
	wl_bss_info_t *scan_bss;

	TUTRACE((TUTRACE_INFO, "Entered: wpscli_wlan_scan\n"));

	if (ap_list == NULL)
		return WPS_STATUS_INVALID_NULL_PARAM;

	params_size += WL_SCAN_PARAMS_SSID_MAX * sizeof(wlc_ssid_t);
	params = (wl_escan_params_t*)malloc(params_size);
	if (params == NULL) {
		printf("Error allocating %d bytes for scan params\n", params_size);
		return WPS_STATUS_SYSTEM_ERR;
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
	strncpy(ifr.ifr_name, wpscli_get_interface_name(), (IFNAMSIZ - 1));

	memset(event_inds_mask, '\0', WL_EVENTING_MASK_LEN);
	event_inds_mask[WLC_E_ESCAN_RESULT / 8] |= 1 << (WLC_E_ESCAN_RESULT % 8);
	if (!(err = wpscli_iovar_set("event_msgs", &event_inds_mask, WL_EVENTING_MASK_LEN))) {
		wpscli_status = WPS_STATUS_INVALID_NW_SETTINGS;
		goto exit2;
	}

	fd = socket(PF_PACKET, SOCK_RAW, htons(ETHER_TYPE_BRCM));
	if (fd < 0) {
		printf("Cannot create socket %d\n", fd);
		wpscli_status = WPS_STATUS_INVALID_NW_SETTINGS;
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
		wpscli_status = WPS_STATUS_INVALID_NW_SETTINGS;
		goto exit2;
	}

	params->version = ESCAN_REQ_VERSION;
	params->action = WL_SCAN_ACTION_START;
#ifdef __linux__
	srand((unsigned)time(NULL));
	params->sync_id = rand() & 0xffff;
#else
	params->sync_id = 4321;
#endif /* __linux__ */

	params_size += (uint)(uintptr)&((wl_escan_params_t *)0)->params;
	err = wpscli_iovar_setbuf("escan", params, params_size, ap_list, buf_size);
	if (err ==  0) {
		close(fd);
		wpscli_status = WPS_STATUS_IOCTL_SET_FAIL;
		/* Do not support escan, try scan instead */
		goto exit2;
	}

	data = (char*)malloc(ESCAN_EVENTS_BUFFER_SIZE);

	if (data == NULL) {
		printf("Cannot not allocate %d bytes for events receive buffer\n",
			ESCAN_EVENTS_BUFFER_SIZE);
		err = -1;
		wpscli_status = WPS_STATUS_NOT_ENOUGH_MEMORY;
		close(fd);
		goto exit2;
	}

	ap_list->count = 0;
	ap_list->version = WL_BSS_INFO_VERSION;
	scan_bss = ap_list->bss_info;

	/* receive scan result */
	while (1) {
		octets = recv(fd, data, ESCAN_EVENTS_BUFFER_SIZE, 0);
		if (octets < 0) {
			printf("escan result recv failed; recvBytes = %d\n", octets);
			wpscli_status = WPS_STATUS_INVALID_NW_SETTINGS;
			goto exit1;
		}
		event = (bcm_event_t *)data;
		addr = (struct ether_addr *)&(event->event.addr);
		event_type = ntohl(event->event.event_type);

		if ((event_type == WLC_E_ESCAN_RESULT) && (octets > 0)) {
			escan_data = (wl_escan_result_t*)&data[sizeof(bcm_event_t)];
			reason = ntohl(event->event.reason);
			status = ntohl(event->event.status);

#if defined(D11AC_IOTYPES) && defined(BCM_P2P_IOTYPECOMPAT)
		{
			int i;
			for (i=0; i < (escan_data->bss_count); i++) {
				wl_bss_info_t *bss_info = &escan_data->bss_info[i];
				bss_info->chanspec =
					P2PWL_CHSPEC_IOTYPE_DTOH(bss_info->chanspec);
			}
		}
#endif

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
					struct escan_bss *ebss = malloc(ESCAN_BSS_FIXED_SIZE
						+ bi->length);

					if (!ebss) {
						perror("can't allocate memory for bss");
						wpscli_status = WPS_STATUS_NOT_ENOUGH_MEMORY;
						goto exit1;
					}

					ebss->next = NULL;
					memcpy(&ebss->bss, bi, bi->length);
					if (escan_bss_tail) {
						escan_bss_tail->next = ebss;
					} else {
						escan_bss_head = ebss;
					}
					escan_bss_tail = ebss;

					/* Copy bss info to scan buffer. */
					memcpy((int8*)scan_bss, (int8*)bi, bi->length);
					scan_bss = (wl_bss_info_t*)((int8*)scan_bss + bi->length);
					ap_list->count++;
				} else {
					/* We've got this BSS. Update rssi if necessary */
					if ((bss->flags & WLC_BSS_RSSI_ON_CHANNEL) ==
						(bi->flags & WLC_BSS_RSSI_ON_CHANNEL)) {
						/* preserve max RSSI if the measurements are
						 * both on-channel or both off-channel
						 */
						bss->RSSI = (bss->RSSI > bi->RSSI) ? bss->RSSI : bi->RSSI;
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
					escan_data->sync_id, status);
				wpscli_status = WPS_STATUS_IOCTL_GET_FAIL;
				goto exit1;
			}
		}
 	}
 
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
	
	wpscli_status = (err < 0) ? wpscli_status : WPS_STATUS_SUCCESS;
 
	TUTRACE((TUTRACE_INFO, "Exit: wpscli_wlan_scan. status=%d\n", wpscli_status));
	return wpscli_status;

}
#endif /* ESCAN_REQ_VERSION */


brcm_wpscli_status wpscli_wlan_scan(wl_scan_results_t *ap_list, uint32 buf_size)
{
	brcm_wpscli_status status = WPS_STATUS_WLAN_NO_ANY_AP_FOUND;
	int retry;
	wl_scan_params_t* params;
	int params_size = WL_SCAN_PARAMS_FIXED_SIZE + WL_NUMCHANNELS * sizeof(uint16);

#ifdef ESCAN_REQ_VERSION
	if ((status = wpscli_wlan_escan(ap_list, buf_size)) != WPS_STATUS_IOCTL_SET_FAIL)
		return status;
#endif /* ESCAN_REQ_VERSION */

	/* Do not support escan, try scan instead */

	TUTRACE((TUTRACE_INFO, "Entered: wpscli_wlan_scan\n"));

	if (ap_list == NULL)
		return WPS_STATUS_INVALID_NULL_PARAM;

	params = (wl_scan_params_t*)malloc(params_size);

	if (params == NULL) {
		printf("Error allocating %d bytes for scan params\n", params_size);
		return WPS_STATUS_SYSTEM_ERR;
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

	wpscli_wlh_ioctl_set(WLC_SCAN, (const char *)params, params_size);

	/* Poll for the results once a second until the scan is done */
	for (retry = 0; retry < WLAN_SCAN_TIMEOUT; retry++) {
		wpscli_sleep(1000);

		ap_list->buflen = WPS_DUMP_BUF_LEN;

		status = wpscli_wlh_ioctl_get(WLC_SCAN_RESULTS, (char *)ap_list, buf_size);

		/* break out if the scan result is ready */
		if (status == WPS_STATUS_SUCCESS)
			break;
	}
#if defined(D11AC_IOTYPES) && defined(BCM_P2P_IOTYPECOMPAT)
		{
			int i;
			for (i=0; i < (ap_list->count); i++) {
				wl_bss_info_t *bss_info = &ap_list->bss_info[i];
				bss_info->chanspec =
					P2PWL_CHSPEC_IOTYPE_DTOH(bss_info->chanspec);
			}
		}
#endif

	free(params);

	TUTRACE((TUTRACE_INFO, "Exit: wpscli_wlan_scan. status=%d\n", status));
	return status;
}

#if !defined(WL_ASSOC_PARAMS_FIXED_SIZE) || !defined(WL_JOIN_PARAMS_FIXED_SIZE)
static int join_network(char* ssid, uint32 wsec)
{
	int ret = 0;
	wlc_ssid_t ssid_t;
	char associated_bssid[6];
	int auth = 0, infra = 1;
	int wpa_auth = WPA_AUTH_DISABLED;
	int i, j;

	TUTRACE((TUTRACE_INFO, "Entered: join_network. ssid=[%s] wsec=%d\n", ssid, wsec));

	printf("Joining network %s - %d\n", ssid, wsec);

	/*
	 * If wep bit is on,
	 * pick any WPA encryption type to allow association.
	 * Registration traffic itself will be done in clear (eapol).
	*/
	if (wsec)
		wsec = 2; /* TKIP */
	ssid_t.SSID_len = strlen(ssid);
	strncpy((char *)ssid_t.SSID, ssid, ssid_t.SSID_len);

	/* set infrastructure mode */
	if ((ret = wpscli_wlh_ioctl_set(WLC_SET_INFRA,
		(const char *)&infra, sizeof(int))) < 0)
		return ret;

	/* set authentication mode */
	if ((ret = wpscli_wlh_ioctl_set(WLC_SET_AUTH,
		(const char *)&auth, sizeof(int))) < 0)
		return ret;

	/* set wsec mode */
	if ((ret = wpscli_wlh_ioctl_set(WLC_SET_WSEC,
		(const char *)&wsec, sizeof(int))) < 0)
		return ret;

	/* set WPA_auth mode */
	if ((ret = wpscli_wlh_ioctl_set(WLC_SET_WPA_AUTH,
		(const char *)&wpa_auth, sizeof(wpa_auth))) < 0)
		return ret;

	for (i = 0; i < WLAN_JOIN_ATTEMPTS; i++) {
		TUTRACE((TUTRACE_INFO, "join_network: WLC_SET_SSID %d\n", i + 1));

		if ((ret = wpscli_wlh_ioctl_set(WLC_SET_SSID,
			(const char *)&ssid_t, sizeof(wlc_ssid_t))) < 0) {
			TUTRACE((TUTRACE_INFO,
				"join_network: WLC_SET_SSID ret=%d\n", ret));
			break;
		}

		/* poll for the results until we got BSSID */
		for (j = 0; j < WLAN_POLLING_JOIN_COMPLETE_ATTEMPTS; j++) {

			/* join time */
			wpscli_sleep(WLAN_POLLING_JOIN_COMPLETE_SLEEP);

			ret = wpscli_wlh_ioctl_get(WLC_GET_BSSID, associated_bssid, 6);

			/* exit if associated */
			if (ret == 0)
				goto exit;
			
			if(g_bRequestAbort)
				break;
		}
		if(g_bRequestAbort) {
			TUTRACE((TUTRACE_INFO, "join_network: abort requested\n"));
			break;
		}	
	}

exit:
	TUTRACE((TUTRACE_INFO, "join_network: Exiting. ret=%d\n", ret));
	return ret;
}
#endif /* !defined(WL_ASSOC_PARAMS_FIXED_SIZE) || !defined(WL_JOIN_PARAMS_FIXED_SIZE) */


/* Join a BSSID using the WLC_SET_SSID ioctl */
static int join_network_with_bssid_ioctl(const char* ssid, uint32 wsec, const char *bssid,
	int num_chanspec, chanspec_t *chanspec)
{
	int ret = 0;
	int auth = 0, infra = 1;
	int wpa_auth = WPA_AUTH_DISABLED;
	char associated_bssid[6];
	int join_params_size;
	wl_join_params_t *join_params;
	wlc_ssid_t *ssid_t;
	wl_assoc_params_t *params_t;
	int i, j;

	TUTRACE((TUTRACE_INFO,
		"Entered: join_network_with_bssid_ioctl. ssid=[%s] wsec=%d #ch=%d\n", ssid, wsec, num_chanspec));

	printf("Joining network %s - wsec %d\n", ssid, wsec);
	printf("BSSID: %02x-%02x-%02x-%02x-%02x-%02x\n",
		(unsigned char)bssid[0], (unsigned char)bssid[1], (unsigned char)bssid[2],
		(unsigned char)bssid[3], (unsigned char)bssid[4], (unsigned char)bssid[5]);

	join_params_size = WL_JOIN_PARAMS_FIXED_SIZE + num_chanspec * sizeof(chanspec_t);
	if ((join_params = malloc(join_params_size)) == NULL) {
		TUTRACE((TUTRACE_INFO, "Exit: join_network_with_bssid_ioctl: malloc failed"));
		return -1;
	}
	memset(join_params, 0, join_params_size);
	ssid_t = &join_params->ssid;
	params_t = &join_params->params;

	/*
	 * If wep bit is on,
	 * pick any WPA encryption type to allow association.
	 * Registration traffic itself will be done in clear (eapol).
	*/
	if (wsec)
		wsec = 2; /* TKIP */

	/* ssid */
	ssid_t->SSID_len = strlen(ssid);
	strncpy((char *)ssid_t->SSID, ssid, ssid_t->SSID_len);

	/* bssid (if any) */
	if (bssid)
		memcpy(&params_t->bssid, bssid, ETHER_ADDR_LEN);
	else
		memcpy(&params_t->bssid, &ether_bcast, ETHER_ADDR_LEN);

	/* channel spec */
	params_t->chanspec_num = num_chanspec;
	for (i = 0; i < params_t->chanspec_num; i++) {
#ifndef WL_EXTJOIN_PARAMS_FIXED_SIZE
		params_t->chanspec_list[i] = P2PWL_CHSPEC_IOTYPE_HTOD(chanspec[i]);
#else
		params_t->chanspec_list[i] = chanspec[i];
#endif
	}

	/* set infrastructure mode */
	if ((ret = wpscli_wlh_ioctl_set(WLC_SET_INFRA,
		(const char *)&infra, sizeof(int))) < 0)
		goto exit;

	/* set authentication mode */
	if ((ret = wpscli_wlh_ioctl_set(WLC_SET_AUTH,
		(const char *)&auth, sizeof(int))) < 0)
		goto exit;

	/* set wsec mode */
	if ((ret = wpscli_wlh_ioctl_set(WLC_SET_WSEC,
		(const char *)&wsec, sizeof(int))) < 0)
		goto exit;

	/* set WPA_auth mode */
	if ((ret = wpscli_wlh_ioctl_set(WLC_SET_WPA_AUTH,
		(const char *)&wpa_auth, sizeof(wpa_auth))) < 0)
		goto exit;

	/* set ssid */
	for (i = 0; i < WLAN_JOIN_ATTEMPTS; i++) {
		TUTRACE((TUTRACE_INFO, "join_network_with_bssid_ioctl: WLC_SET_SSID %d\n", i + 1));

		if ((ret = wpscli_wlh_ioctl_set(WLC_SET_SSID,
			(const char *)join_params, join_params_size)) < 0) {
			TUTRACE((TUTRACE_INFO,
				"join_network_with_bssid_ioctl: WLC_SET_SSID ret=%d\n", ret));
			goto exit;
		}

		/* join scan time */
		TUTRACE((TUTRACE_INFO,
			"join_network_with_bssid_ioctl: sleep %d ms\n", 40 * num_chanspec));
		wpscli_sleep(40 * num_chanspec);

		/* poll for the results until we got BSSID */
		for (j = 0; j < WLAN_POLLING_JOIN_COMPLETE_ATTEMPTS; j++) {

			/* join time */
			wpscli_sleep(100);

			ret = wpscli_wlh_ioctl_get(WLC_GET_BSSID, associated_bssid, 6);

			/* exit if associated */
			if (ret == 0)
				goto exit;
			
			if(g_bRequestAbort)
				break;
		}
		if(g_bRequestAbort) {
			TUTRACE((TUTRACE_INFO, "join_network_with_bssid_ioctl: abort requested\n"));
			break;
		}
	}

exit:
	TUTRACE((TUTRACE_INFO, "Exit: join_network_with_bssid_ioctl: ret=%d\n", ret));
	free(join_params);
	return ret;
}

/* Applies security settings and join a BSSID using a passive join scan.
 * First tries using the "join" iovar.  If that is unsupported by the driver
 * then use the WLC_SET_SSID ioctl.
 */
static int join_network_with_bssid(const char* ssid, uint32 wsec, const char *bssid,
	int num_chanspec, chanspec_t *chanspec)
{
#ifdef WL_EXTJOIN_PARAMS_FIXED_SIZE  /* if driver has "join" iovar */
	int ret = 0;
	int auth = 0, infra = 1;
	int wpa_auth = WPA_AUTH_DISABLED;
	char associated_bssid[6];
	int join_params_size;
	wl_extjoin_params_t *join_params;
	wlc_ssid_t *ssid_t;
	wl_join_scan_params_t *scan_t;
	wl_join_assoc_params_t *params_t;
	int i, j;
	int join_scan_time;

	TUTRACE((TUTRACE_INFO,
		"Entered: join_network_with_bssid. ssid=[%s] wsec=%d #ch=%d\n", ssid, wsec, num_chanspec));

	printf("Joining network %s - wsec %d (passive scan)\n", ssid, wsec);
	printf("BSSID: %02x-%02x-%02x-%02x-%02x-%02x\n",
		(unsigned char)bssid[0], (unsigned char)bssid[1], (unsigned char)bssid[2],
		(unsigned char)bssid[3], (unsigned char)bssid[4], (unsigned char)bssid[5]);
	printf("chanspec[%d] =", num_chanspec);
	for (i = 0; i < num_chanspec; i++)
		printf(" 0x%04x", chanspec[i]);
	printf("\n");

	join_params_size = WL_EXTJOIN_PARAMS_FIXED_SIZE + num_chanspec * sizeof(chanspec_t);
	if ((join_params = malloc(join_params_size)) == NULL) {
		TUTRACE((TUTRACE_INFO, "Exit: join_network_with_bssid: malloc failed"));
		return -1;
	}
	memset(join_params, 0, join_params_size);
	ssid_t = &join_params->ssid;
	scan_t = &join_params->scan;
	params_t = &join_params->assoc;

	/*
	 * If wep bit is on,
	 * pick any WPA encryption type to allow association.
	 * Registration traffic itself will be done in clear (eapol).
	*/
	if (wsec)
		wsec = 2; /* TKIP */

	/* ssid */
	ssid_t->SSID_len = strlen(ssid);
	strncpy((char *)ssid_t->SSID, ssid, ssid_t->SSID_len);

	/* join scan params */
	scan_t->scan_type = 1;
	scan_t->nprobes = -1;
	scan_t->active_time = -1;
	if (num_chanspec == 1)
		scan_t->passive_time = WLAN_JOIN_SCAN_PASSIVE_TIME_LONG;
	else
		scan_t->passive_time = WLAN_JOIN_SCAN_PASSIVE_TIME;
	scan_t->home_time = -1;
	join_scan_time = num_chanspec *
		(scan_t->passive_time + WLAN_JOIN_SCAN_DEFAULT_ACTIVE_TIME);

	/* bssid (if any) */
	if (bssid)
		memcpy(&params_t->bssid, bssid, ETHER_ADDR_LEN);
	else
		memcpy(&params_t->bssid, &ether_bcast, ETHER_ADDR_LEN);

	/* channel spec */
	params_t->chanspec_num = num_chanspec;
	for (i = 0; i < params_t->chanspec_num; i++) {
		params_t->chanspec_list[i] = P2PWL_CHSPEC_IOTYPE_HTOD(chanspec[i]);
	}

	/* set infrastructure mode */
	if ((ret = wpscli_wlh_ioctl_set(WLC_SET_INFRA,
		(const char *)&infra, sizeof(int))) < 0)
		goto exit;

	/* set authentication mode */
	if ((ret = wpscli_wlh_ioctl_set(WLC_SET_AUTH,
		(const char *)&auth, sizeof(int))) < 0)
		goto exit;

	/* set wsec mode */
	if ((ret = wpscli_wlh_ioctl_set(WLC_SET_WSEC,
		(const char *)&wsec, sizeof(int))) < 0)
		goto exit;

	/* set WPA_auth mode */
	if ((ret = wpscli_wlh_ioctl_set(WLC_SET_WPA_AUTH,
		(const char *)&wpa_auth, sizeof(wpa_auth))) < 0)
		goto exit;

	/* do join */
	for (i = 0; i < WLAN_JOIN_ATTEMPTS; i++) {

		/* Start the join */
		TUTRACE((TUTRACE_INFO, "join_network_with_bssid: join iovar %d\n", i + 1));
		if (!wpscli_iovar_set("join", join_params, join_params_size)) {
			TUTRACE((TUTRACE_INFO, "join_network_with_bssid: 'join' iovar ret=%d\n",
				brcm_wpscli_ioctl_err));
			/* If the "join" iovar is unsupported by the driver
			 *     Retry the join using the WLC_SET_SSID ioctl.
			 */
			if (brcm_wpscli_ioctl_err == BCME_UNSUPPORTED) {
				return join_network_with_bssid_ioctl(ssid, wsec, bssid,
					num_chanspec, chanspec);
			}
			goto exit;
		}

		/* wait for the join scan time */
		TUTRACE((TUTRACE_INFO,
			"join_network_with_bssid: sleep %d ms\n", join_scan_time));
		wpscli_sleep(join_scan_time);

		/* poll for the results until we got BSSID */
		for (j = 0; j < WLAN_POLLING_JOIN_COMPLETE_ATTEMPTS; j++) {

			/* join time */
			wpscli_sleep(WLAN_POLLING_JOIN_COMPLETE_SLEEP);

			ret = wpscli_wlh_ioctl_get(WLC_GET_BSSID, associated_bssid, 6);

			/* exit if associated */
			if (ret == 0)
				goto exit;
			
			if(g_bRequestAbort)
				break;
		}
		if(g_bRequestAbort) {
			TUTRACE((TUTRACE_INFO, "join_network_with_bssid: abort requested\n"));
			break;
		}

	}

exit:
	TUTRACE((TUTRACE_INFO, "Exit: join_network_with_bssid: ret=%d\n", ret));
	free(join_params);
	return ret;
#else /* no "join" iovar */
	return join_network_with_bssid_ioctl(ssid, wsec, bssid, num_channels,
		channels);
#endif /* WL_EXTJOIN_PARAMS_FIXED_SIZE */
}

/* Applies security settings and join a BSSID using an active join scan.
 * First tries using the "join" iovar.  If that is unsupported by the driver
 * then use the WLC_SET_SSID ioctl.
 */
/* TODO: factor out common code between join_network_with_bssid() and
 * join_network_with_bssid_active()
 */
static int join_network_with_bssid_active(const char* ssid, uint32 wsec,
	const char *bssid, int num_chanspec, chanspec_t *chanspec)
{
#ifdef WL_EXTJOIN_PARAMS_FIXED_SIZE  /* if driver has "join" iovar */
	int ret = 0;
	int auth = 0, infra = 1;
	int wpa_auth = WPA_AUTH_DISABLED;
	char associated_bssid[6];
	int join_params_size;
	wl_extjoin_params_t *join_params;
	wlc_ssid_t *ssid_t;
	wl_join_scan_params_t *scan_t;
	wl_join_assoc_params_t *params_t;
	int i, j;
	int join_scan_time;

	TUTRACE((TUTRACE_INFO,
		"Entered: join_network_with_bssid_active. ssid=[%s] wsec=%d #ch=%d\n", ssid, wsec, num_chanspec));

	printf("Joining network %s - wsec %d (active scan)\n", ssid, wsec);
	printf("BSSID: %02x-%02x-%02x-%02x-%02x-%02x\n",
		(unsigned char)bssid[0], (unsigned char)bssid[1], (unsigned char)bssid[2],
		(unsigned char)bssid[3], (unsigned char)bssid[4], (unsigned char)bssid[5]);
	printf("chanspec[%d] =", num_chanspec);
	for (i = 0; i < num_chanspec; i++)
		printf(" 0x%04x", chanspec[i]);
	printf("\n");

	join_params_size = WL_EXTJOIN_PARAMS_FIXED_SIZE + num_chanspec * sizeof(chanspec_t);
	if ((join_params = malloc(join_params_size)) == NULL) {
		TUTRACE((TUTRACE_INFO, "Exit: join_network_with_bssid_active: malloc failed"));
		return -1;
	}
	memset(join_params, 0, join_params_size);
	ssid_t = &join_params->ssid;
	scan_t = &join_params->scan;
	params_t = &join_params->assoc;

	/*
	 * If wep bit is on,
	 * pick any WPA encryption type to allow association.
	 * Registration traffic itself will be done in clear (eapol).
	*/
	if (wsec)
		wsec = 2; /* TKIP */

	/* ssid */
	ssid_t->SSID_len = strlen(ssid);
	strncpy((char *)ssid_t->SSID, ssid, ssid_t->SSID_len);

	/* join scan params */
	scan_t->scan_type = DOT11_SCANTYPE_ACTIVE;
	scan_t->nprobes = -1;
	scan_t->active_time = WLAN_JOIN_SCAN_ACTIVE_TIME;
	scan_t->home_time = -1;
	join_scan_time = num_chanspec *
		(scan_t->active_time + WLAN_JOIN_SCAN_DEFAULT_ACTIVE_TIME);

	/* bssid (if any) */
	if (bssid)
		memcpy(&params_t->bssid, bssid, ETHER_ADDR_LEN);
	else
		memcpy(&params_t->bssid, &ether_bcast, ETHER_ADDR_LEN);

	/* channel spec */
	params_t->chanspec_num = num_chanspec;
	for (i = 0; i < params_t->chanspec_num; i++) {
		params_t->chanspec_list[i] = P2PWL_CHSPEC_IOTYPE_HTOD(chanspec[i]);
	}

	/* set infrastructure mode */
	if ((ret = wpscli_wlh_ioctl_set(WLC_SET_INFRA,
		(const char *)&infra, sizeof(int))) < 0)
		goto exit;

	/* set authentication mode */
	if ((ret = wpscli_wlh_ioctl_set(WLC_SET_AUTH,
		(const char *)&auth, sizeof(int))) < 0)
		goto exit;

	/* set wsec mode */
	if ((ret = wpscli_wlh_ioctl_set(WLC_SET_WSEC,
		(const char *)&wsec, sizeof(int))) < 0)
		goto exit;

	/* set WPA_auth mode */
	if ((ret = wpscli_wlh_ioctl_set(WLC_SET_WPA_AUTH,
		(const char *)&wpa_auth, sizeof(wpa_auth))) < 0)
		goto exit;

	/* do join */
	for (i = 0; i < WLAN_JOIN_ATTEMPTS; i++) {

		/* Start the join */
		TUTRACE((TUTRACE_INFO, "join_network_with_bssid_active: join iovar %d\n", i + 1));
		if (!wpscli_iovar_set("join", join_params, join_params_size)) {
			TUTRACE((TUTRACE_INFO, "join_network_with_bssid_active: 'join' iovar ret=%d\n",
				brcm_wpscli_ioctl_err));
			/* If the "join" iovar is unsupported by the driver
			 *     Retry the join using the WLC_SET_SSID ioctl.
			 */
			if (brcm_wpscli_ioctl_err == BCME_UNSUPPORTED) {
				return join_network_with_bssid_ioctl(ssid, wsec, bssid,
					num_chanspec, chanspec);
			}
			goto exit;
		}

		/* wait for the join scan time */
		TUTRACE((TUTRACE_INFO,
			"join_network_with_bssid_active: sleep %d ms\n", join_scan_time));
		wpscli_sleep(join_scan_time);

		/* poll for the results until we got BSSID */
		for (j = 0; j < WLAN_POLLING_JOIN_COMPLETE_ATTEMPTS; j++) {

			/* join time */
			wpscli_sleep(WLAN_POLLING_JOIN_COMPLETE_SLEEP);

			ret = wpscli_wlh_ioctl_get(WLC_GET_BSSID, associated_bssid, 6);

			/* exit if associated */
			if (ret == 0)
				goto exit;
			
			if(g_bRequestAbort)
				break;
		}
		if(g_bRequestAbort) {
			TUTRACE((TUTRACE_INFO, "join_network_with_bssid_active: abort requested\n"));
			break;
		}		
	}

exit:
	TUTRACE((TUTRACE_INFO, "Exit: join_network_with_bssid_active: ret=%d\n", ret));
	free(join_params);
	return ret;
#else /* no "join" iovar */
	return join_network_with_bssid_ioctl(ssid, wsec, bssid, num_chanspec,
		chanspec);
#endif /* WL_EXTJOIN_PARAMS_FIXED_SIZE */
}

static int leave_network(void)
{
	return wpscli_wlh_ioctl_set(WLC_DISASSOC, NULL, 0);
}

#if defined(D11AC_IOTYPES) && defined(BCM_P2P_IOTYPECOMPAT)
bool g_legacy_chanspec = FALSE;
/* 80MHz channels in 5GHz band */
static const uint8 wf_5g_80m_chans[] =
{42, 58, 106, 122, 138, 155};
#define WF_NUM_5G_80M_CHANS \
	(sizeof(wf_5g_80m_chans)/sizeof(uint8))

static bool
p2pwf_chspec_malformed(chanspec_t chanspec)
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
p2pwl_chspec_from_legacy(chanspec_t legacy_chspec)
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

	if (p2pwf_chspec_malformed(chspec)) {
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
p2pwl_chspec_to_legacy(chanspec_t chspec)
{
	chanspec_t lchspec;

	if (p2pwf_chspec_malformed(chspec)) {
		fprintf(stderr, "wl_chspec_to_legacy: input chanspec (0x%04X) malformed\n",
		        chspec);
		return INVCHANSPEC;
	}

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
		char chanbuf[CHANSPEC_STR_LEN];
		fprintf(stderr,
		        "wl_chspec_to_legacy: unable to convert chanspec (0x%04X) "
		        "to pre-11ac format\n",
		        chspec);
		return INVCHANSPEC;
	}

	return lchspec;
}
#endif /* defined(D11AC_IOTYPES) && defined(BCM_P2P_IOTYPECOMPAT) */
