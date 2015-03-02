/*
 * WPS API tester ui
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wps_api_ui.c 470127 2014-04-14 04:14:51Z $
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <typedefs.h>

#include <wps_sdk.h>
#include <wps_api_osl.h>
#include "wps_api_tester.h"
#include <wpscommon.h>


/* WPS UI STUFF  */
#define WPS_PRINT_USAGE()	wps_print_usage(base)
#define WPS_ARGC_CHECK()	\
	if (argc <= 0) { \
		WPS_PRINT(("Need argument for %s\n", cmd)); \
		wps_print_usage(base); \
		return FALSE; \
	}

#define REMOVE_NEWLINE(buf)	{ \
	int i; \
	for (i = 0; i < sizeof(buf); i++) { \
		if (buf[i] == '\n') \
		buf[i] = '\0'; \
	} \
}

uint8 empty_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
char wps_def_pin[9] = "12345670\0";


#ifndef WPSENR_BINARY_SINGLE
int
set_mac_address(char *mac_string, char *mac_bin)
{
	int i = 0;
	char *endptr, *nptr;
	long val;

	nptr = mac_string;

	do {
		val = strtol(nptr, &endptr, 16);
		if (val > 255) {
			WPS_PRINT(("invalid MAC address\n"));
			return -1;
		}

		if (endptr == nptr) {
			/* no more digits. */
			if (i != 6) {
				WPS_PRINT(("invalid MAC address\n"));
				return -1;
			}
			return 0;
		}

		if (i >= 6) {
			WPS_PRINT(("invalid MAC address\n"));
			return -1;
		}

		mac_bin[i++] = val;
		nptr = endptr+1;
	} while (nptr[0]);

	if (i != 6) {
		WPS_PRINT(("invalid MAC address\n"));
		return -1;
	}

	return 0;
}
#endif /* WPSENR_BINARY_SINGLE */

#ifdef WFA_WPS_20_TESTBED
static int
new_tlv_convert(TESTER_WPS_T *wps, uint8 *new_tlv_str)
{
	uchar *src, *dest;
	uchar val;
	int idx, len;
	char hexstr[3];
	wps20_testbed_inf *wps20_tbinf = &wps->wps20_tbinf;

	/* reset first */
	wps20_tbinf->nattr_len = 0;

	if (!new_tlv_str)
		return 0;

	/* Ensure in 2 characters long */
	len = strlen((char*)new_tlv_str);
	if (len % 2) {
		WPS_PRINT(("Please specify all the data bytes for this TLV\n"));
		return -1;
	}
	wps20_tbinf->nattr_len = (uint8) (len / 2);

	/* string to hex */
	src = new_tlv_str;
	dest = (uchar*)wps20_tbinf->nattr_tlv;
	for (idx = 0; idx < len; idx++) {
		hexstr[0] = src[0];
		hexstr[1] = src[1];
		hexstr[2] = '\0';

		val = (uchar) strtoul(hexstr, NULL, 16);

		*dest++ = val;
		src += 2;
	}

	/* TODO, can add TLV parsing here */
	return 0;
}
#endif /* WFA_WPS_20_TESTBED */

static int
wps_print_usage(char *base)
{
	if (strcmp(base, "wpsenr") == 0) {
	WPS_PRINT(("Usage : \n\n"));
	WPS_PRINT(("    Interactive mode : \n"));
	WPS_PRINT(("       wpsenr <-if eth_name> <-ip addr>/<-dhcp [command]> <-v1>\n\n"));
	WPS_PRINT(("    Command line mode (pin) : \n"));
	WPS_PRINT(("       wpsenr <-if eth_name> <-sec 0|1> -ssid ssid -pin pin "
		"<-ip addr>/<-dhcp [command]> <-v1>\n\n"));
	WPS_PRINT(("    Command line mode (push button) : \n"));
	WPS_PRINT(("       wpsenr <-if eth_name> -pb <-ip addr>/<-dhcp [command]> <-v1>\n\n"));
	WPS_PRINT(("    Command line mode (Authorized MAC) : \n"));
	WPS_PRINT(("       wpsenr <-if eth_name> -amac [wc] <-pin pin> "
		"<-ip addr>/<-dhcp [command]>\n\n"));
	WPS_PRINT(("    Command line mode (Automatically WPS in PIN mode) : \n"));
	WPS_PRINT(("       wpsenr <-if eth_name> -auto <-pin pin>\n\n"));
	WPS_PRINT(("    Scan only :\n"));
	WPS_PRINT(("       wpsenr -scan <-v1>\n\n"));
	WPS_PRINT(("    Default values :\n"));
	WPS_PRINT(("       eth_name :  eth0\n"));
	WPS_PRINT(("       sec : 1 \n"));
	WPS_PRINT(("       pin : 12345670\n"));
	WPS_PRINT(("       v1 (version 1 only) : false\n\n"));
	WPS_PRINT(("       fb (fallback support v1 WEP AP) : false\n\n"));
#ifdef WFA_WPS_20_TESTBED
	WPS_PRINT(("    Internal testing arguments :\n"));
	WPS_PRINT(("       <-v2 number>: Version2 Number\n"));
	WPS_PRINT(("       <-ifrag threshold>: WPS IE fragment threshold\n"));
	WPS_PRINT(("       <-efrag threshold>: EAP fragment threshold\n"));
	WPS_PRINT(("       <-zpadding>: Do zero padding\n"));
	WPS_PRINT(("       <-zlength>: Zero length in mandatory string attributes\n"));
	WPS_PRINT(("       <-nattr tlv>: Add new attribute\n"));
	WPS_PRINT(("         ex. <-nattr 2001000411223344> add type 0x2001 length is 4\n"));
	WPS_PRINT(("       <-prbreq ie>: Update partial embedded WPS probe request IE\n"));
	WPS_PRINT(("         ex. <-prbreq 104a000111> replace version value with 0x11\n"));
	WPS_PRINT(("       <-assocreq ie>: Update partial embedded WPS associate request IE\n"));
	WPS_PRINT(("         ex. <-assocreq 104a000111> replace version value with 0x11\n"));
#endif /* WFA_WPS_20_TESTBED */
	} else if (strcmp(base, "wpsreg") == 0) {
	WPS_PRINT(("Usage : \n\n"));
	WPS_PRINT(("    Interactive mode : \n"));
	WPS_PRINT(("       wpsreg <-if eth_name> <-ip addr>/<-dhcp [command]> <-v1>\n\n"));
	WPS_PRINT(("    Command line mode (pin) : \n"));
	WPS_PRINT(("       wpsreg <-if eth_name> <-sec 0|1> -mode (1:reg-join|2:config) "
	       "-cred (1:random|2:user input) -ssid ssid -pin ap_pin "
	       "<-ip addr>/<-dhcp [command]> <-v1>\n\n"));
	WPS_PRINT(("    Scan only :\n"));
	WPS_PRINT(("       wpsreg -scan <-v1>\n\n"));
	WPS_PRINT(("    Default values :\n"));
	WPS_PRINT(("       eth_name :  eth0\n"));
	WPS_PRINT(("       sec : 1 \n"));
	WPS_PRINT(("       mode : 1 reg-join \n"));
	WPS_PRINT(("       cred : 1 random \n"));
	WPS_PRINT(("       v1 (version 1 only) : false\n\n"));
	WPS_PRINT(("       fb (fallback support v1 WEP AP) : false\n\n"));
#ifdef WFA_WPS_20_TESTBED
	WPS_PRINT(("    Internal testing arguments :\n"));
	WPS_PRINT(("       <-v2 number>: Version2 Number\n"));
	WPS_PRINT(("       <-ifrag threshold>: WPS IE fragment threshold\n"));
	WPS_PRINT(("       <-efrag threshold>: EAP fragment threshold\n"));
	WPS_PRINT(("       <-zpadding>: Do zero padding\n"));
	WPS_PRINT(("       <-zlength>: Zero length in mandatory string attributes\n"));
	WPS_PRINT(("       <-mca>: Multiple Credential Attributes\n"));
	WPS_PRINT(("       <-nattr tlv>: Add new attribute\n"));
	WPS_PRINT(("         ex. <-nattr 2001000411223344> add type 0x2001 length is 4\n"));
	WPS_PRINT(("       <-prbreq ie>: Update partial embedded WPS probe request IE\n"));
	WPS_PRINT(("         ex. <-prbreq 104a000111> replace version value with 0x11\n"));
	WPS_PRINT(("       <-assocreq ie>: Update partial embedded WPS associate request IE\n"));
	WPS_PRINT(("         ex. <-assocreq 104a000111> replace version value with 0x11\n"));
#endif /* WFA_WPS_20_TESTBED */
	} else {
	WPS_PRINT(("Usage : \n\n"));
	WPS_PRINT(("    Interactive mode : \n"));
	WPS_PRINT(("       %s <-async>\n", base));
	WPS_PRINT(("          -async : asyn mode\n"));
	}

	return 0;
}

static void
_ui_wps_build_manual_cred(TESTER_WPS_T *wps)
{
	char inp[8];
	bool b_tryAgain = TRUE;
	wps_credentials *cred = &wps->cred;

	WPS_PRINT(("\n Input new configuration manually\n"));

	/* ssid */
	while (b_tryAgain) {
		WPS_PRINT(("SSID (Max 32 character): "));
		fgets(cred->ssid, sizeof(cred->ssid), stdin);
		fflush(stdin);
		REMOVE_NEWLINE(cred->ssid);

		if (STRP(cred->ssid) == NULL) {
			WPS_PRINT(("\tERROR: Invalid input.\n"));
			continue;
		}

		b_tryAgain = FALSE;
		WPS_PRINT(("SSID: [%s]\n", cred->ssid));
	}

	/* keyMgmt */
	WPS_PRINT(("\nKey Management"));
	b_tryAgain = TRUE;
	while (b_tryAgain) {
keyMgmt:
		WPS_PRINT(("\n\tOptions:\n"));
		WPS_PRINT(("\t0. None (OPEN)\n"));
		if (wps->b_v2 == FALSE)
			WPS_PRINT(("\t1. WPA-PSK\n"));
		WPS_PRINT(("\t2. WPA2-PSK\n"));
		WPS_PRINT(("\t3. Both WPA-PSK, WPA2-PSK\n"));
		WPS_PRINT(("\tEnter selection: "));
		fgets(inp, sizeof(inp), stdin);
		fflush(stdin);
		REMOVE_NEWLINE(inp);

		if (STRP(inp) == NULL) {
			/* We got no input */
			WPS_PRINT(("\tError: Invalid input.\n"));
			continue;
		}

		switch (inp[0]) {
		case '0': /* OPEN */
			/* Prompt a warning message when new credential is open */
			while (b_tryAgain) {
				WPS_PRINT(("\nWarning:\n"));
				WPS_PRINT(("Security is not set for the network. Are you sure"
					" you want to continue? [y/n]:"));
				fgets(inp, sizeof(inp), stdin);
				fflush(stdin);
				REMOVE_NEWLINE(inp);

				if (STRP(inp) == NULL) {
					/* We got no input */
					continue;
				}

				switch (inp[0]) {
				case 'y':
				case 'Y':
					b_tryAgain = FALSE;
					break;
				case 'n':
				case 'N':
					goto keyMgmt;
					break;
				default:
					break;
				}
			}

			cred->keyMgmt[0] = '\0';
			cred->encrType = 0;
			memset(cred->nwKey, 0, SIZE_64_BYTES);
			return;

		case '1':
			if (wps->b_v2 == FALSE) {
				strcpy(cred->keyMgmt, "WPA-PSK");
				b_tryAgain = FALSE;
			} else
				WPS_PRINT(("\tERROR: Invalid input.\n"));
			break;

		case '2':
			strcpy(cred->keyMgmt, "WPA2-PSK");
			b_tryAgain = FALSE;
			break;

		case '3':
			strcpy(cred->keyMgmt, "WPA-PSK WPA2-PSK");
			b_tryAgain = FALSE;
			break;

		default:
			WPS_PRINT(("\tERROR: Invalid input.\n"));
			break;
		}
	}

	/* crypto */
	cred->encrType = 0;
	WPS_PRINT(("\nCrypto Type"));
	b_tryAgain = TRUE;
	while (b_tryAgain) {
		WPS_PRINT(("\n\tOptions:\n"));
		if (wps->b_v2 == FALSE)
			WPS_PRINT(("\t0. TKIP\n"));
		WPS_PRINT(("\t1. AES\n"));
		WPS_PRINT(("\t2. Both TKIP, AES\n"));
		WPS_PRINT(("\tEnter selection: "));
		fgets(inp, sizeof(inp), stdin);
		fflush(stdin);
		REMOVE_NEWLINE(inp);

		if (STRP(inp) == NULL) {
			/* We got no input */
			WPS_PRINT(("\tError: Invalid input.\n"));
			continue;
		}

		switch (inp[0]) {
		case '0':
			if (wps->b_v2 == FALSE) {
				cred->encrType |= ENCRYPT_TKIP;
				b_tryAgain = FALSE;
			} else {
				WPS_PRINT(("\tERROR: Invalid input.\n"));
			}
			break;

		case '1':
			cred->encrType |= ENCRYPT_AES;
			b_tryAgain = FALSE;
			break;

		case '2':
			cred->encrType = (ENCRYPT_TKIP | ENCRYPT_AES);
			b_tryAgain = FALSE;
			break;

		default:
			WPS_PRINT(("\tERROR: Invalid input.\n"));
			break;
		}
	}

	/* nwKey */
	b_tryAgain = TRUE;
	while (b_tryAgain) {
		WPS_PRINT(("Network Key: "));
		fgets(cred->nwKey, sizeof(cred->nwKey), stdin);
		fflush(stdin);
		REMOVE_NEWLINE(cred->nwKey);

		if (STRP(cred->nwKey) == NULL) {
			WPS_PRINT(("\tERROR: Invalid input.\n"));
			continue;
		}

		b_tryAgain = FALSE;
		WPS_PRINT(("Network Key: [%s]\n", cred->nwKey));
	}
}

static wps_credentials *
_ui_wps_build_new_cred(TESTER_WPS_T *wps)
{
	char option[10];

	if (wps->b_tester || (wps->b_wpsreg && wps->reg_mode == 0)) {
		WPS_PRINT(("\nDo you want to configure AP [N/Y]:"));
		fgets(option, sizeof(option), stdin);
		fflush(stdin);
		REMOVE_NEWLINE(option);

		if (option[0] == 'y' || option[0] == 'Y') {
			WPS_PRINT(("\nDo you want to generate new credential "
				"automatically [Y/N]:"));
			fgets(option, sizeof(option), stdin);
			fflush(stdin);
			REMOVE_NEWLINE(option);

			memset(&wps->cred, 0, sizeof(wps->cred));
			if (option[0] != 'n' && option[0] != 'N')
				wps_api_generate_cred(&wps->cred);
			else
				_ui_wps_build_manual_cred(wps);
			return &wps->cred;
		}
	} else  if (wps->b_wpsreg && wps->reg_mode == STA_REG_CONFIG_NW) {
		if (wps->reg_cred == 1) /* random */
			wps_api_generate_cred(&wps->cred);
		else
			_ui_wps_build_manual_cred(wps);
		return &wps->cred;
	}

	return NULL;
}

static bool
_ui_find_ap_wsec(TESTER_WPS_T *wps, wps_apinf *apinf, char *bssid, char *ssid)
{
#define UI_FIND_AP_WSEC_MAX 5

	int retry = 0;
	struct wps_ap_list_info *aplist;

	if (!apinf || !ssid)
		return FALSE;

	aplist = wps_api_surveying(wps->b_pbc, wps->b_v2, wps->b_v2);
	while (retry < UI_FIND_AP_WSEC_MAX) {
		if (wps->b_abort) {
			WPS_PRINT(("Could not find a specified AP \"%s\", user abort\n", ssid));
			return FALSE;
		}

		if (aplist) {
			int i = 0;
			while (wps_api_get_ap(i, apinf)) {
				if (strcmp(ssid, apinf->ssid) == 0 &&
				    (!bssid || memcmp(bssid, apinf->bssid, 6) == 0)) {
					return TRUE;
				}
				i++;
			}
		}

		sleep(1);
		aplist = wps_api_surveying(wps->b_pbc, wps->b_v2, FALSE);
		retry++;
	}

	if (retry == UI_FIND_AP_WSEC_MAX) {
		WPS_PRINT(("Could not find a specified AP \"%s\"\n", ssid));
		return FALSE;
	}

	return TRUE;
}

static bool
_ui_find_pbc_ap(TESTER_WPS_T *wps, wps_apinf *apinf, int *nAP)
{
#define UI_FIND_PBC_AP_WALK_TIME 120

	struct wps_ap_list_info *aplist;
	unsigned long start = wps_osl_get_current_time();


	*nAP = 0;
	aplist = wps_api_surveying(TRUE, wps->b_v2, TRUE);
	while (1) {
		if (wps->b_abort) {
			WPS_PRINT(("Could not find a PBC enabled AP, user abort\n"));
			return FALSE;
		}

		if (aplist && wps_api_find_ap(aplist, nAP, TRUE, NULL, FALSE, NULL, FALSE))
			break;

		sleep(1);
		if ((wps_osl_get_current_time() - start) > UI_FIND_PBC_AP_WALK_TIME) {
			WPS_PRINT(("Could not find a PBC enabled AP, TIMEOUT\n"));
			return FALSE;
		}

		aplist = wps_api_surveying(TRUE, wps->b_v2, FALSE);
	}

	if (*nAP > 1) {
		WPS_PRINT(("Could not find a PBC enabled AP, OVERLAP\n"));
		return FALSE;
	}

	/* Get AP info */
	return wps_api_get_ap(0, apinf);
}

static int
_ui_find_amac_ap(TESTER_WPS_T *wps, wps_apinf *apinf, int *nAP)
{
#define UI_FIND_AMAC_AP_WALK_TIME 120

	uint8 mac[6];
	struct wps_ap_list_info *aplist;
	unsigned long start = wps_osl_get_current_time();


	/* Get my MAC */
	wps_osl_get_mac(mac);

	aplist = wps_api_surveying(FALSE, wps->b_v2, TRUE);
	while (1) {
		if (wps->b_abort) {
			WPS_PRINT(("No any APs have my MAC in AuthorizedMACs list, user abort\n"));
			return FALSE;
		}

		if (aplist &&
		    wps_api_find_ap(aplist, nAP, FALSE, mac, wps->b_amac_wc, &wps->b_pbc, FALSE))
			break;

		sleep(1);
		if ((wps_osl_get_current_time() - start) > UI_FIND_AMAC_AP_WALK_TIME) {
			WPS_PRINT(("No any APs have my MAC in AuthorizedMACs list, TIMEOUT\n"));
			return FALSE;
		}

		aplist = wps_api_surveying(FALSE, wps->b_v2, FALSE);
	}

	/* Get AP info */
	return wps_api_get_ap(0, apinf);
}

/* find all APs which has PIN my MAC in AuthorizedMACs */
static bool
_ui_find_pin_aps(TESTER_WPS_T *wps, wps_apinf *apinf, int *nAP)
{
	struct wps_ap_list_info *aplist;

	*nAP = 0;
	aplist = wps_api_surveying(FALSE, wps->b_v2, TRUE);

	/* filter with PIN */
	if (wps_api_find_ap(aplist, nAP, FALSE, NULL, FALSE, NULL, TRUE) == FALSE)
		return FALSE;

	/* return first AP info. */
	return wps_api_get_ap(0, apinf);
}

static bool
_ui_wps_find_sepcific_ap(TESTER_WPS_T *wps, wps_apinf *apinf, bool *b_user_sel, int *nAP)
{
	if (wps->b_tester) {
		*b_user_sel = TRUE;
		return FALSE;
	}

	/* Clear needed user further selection */
	*b_user_sel = FALSE;

	if (wps->b_ssid) {
		if (wps->b_pbc) {
			wps->pin[0] = '\0';
		}
		else if (STRP(wps->pin) == NULL) {
			/* Should not happen, ui_wps_select_mode will handle it */
			strncpy(wps->pin, wps_def_pin, sizeof(wps->pin));
			WPS_PRINT(("\n\nStation Pin not specified, use default Pin %s\n\n",
				wps_def_pin));
		}

		/* Get wsec */
		if (wps->b_wsec == FALSE &&
		    _ui_find_ap_wsec(wps, apinf, STRP(wps->bssid), wps->ssid) == FALSE) {
			*nAP = 0;
			return FALSE;
		}
	}
	else if (wps->b_pbc) {
		/* ui_find_pbc_ap will keep the WPS IE in probe request */
		if (_ui_find_pbc_ap(wps, apinf, nAP) == FALSE)
			return FALSE;

		wps->pin[0] = '\0';
	}
	else if (wps->b_amac) {
		/* Try to find a AP which has my MAC in AuthorizedMACs */
		if (_ui_find_amac_ap(wps, apinf, nAP) == FALSE)
		    return FALSE;

		if (wps->b_pbc)
			wps->pin[0] = '\0';
		else if (STRP(wps->pin) == NULL)
			strncpy(wps->pin, wps_def_pin, sizeof(wps->pin));
	}
	else if (wps->b_auto) {
		/* Try to collect all SSR is TRUE APs */
		if (_ui_find_pin_aps(wps, apinf, nAP) == FALSE) {
			WPS_PRINT(("No any WPS PIN Enabled AP exist\n"));
			return FALSE;
		}
		wps->ap_count = *nAP;
		WPS_PRINT(("WPS PIN Enabled AP list :\n"));
		ui_display_aplist(wps->b_v2);

		if (STRP(wps->pin) == NULL) {
			strncpy(wps->pin, wps_def_pin, sizeof(wps->pin));
			WPS_PRINT(("Use defualt device PIN!\n"));
		}
	}
	else {
		/* Need user further selection */
		*b_user_sel = TRUE;
		return FALSE;
	}

	return TRUE;
}

void
ui_display_aplist(bool b_v2)
{
	int i, j;
	uint8 *mac;
	wps_apinf apinf;

	i = 0;
	WPS_PRINT(("\n------------------------------------\n"));
	/* Retrieve index i AP info for display all WPS APs */
	while (wps_api_get_ap(i, &apinf)) {
		WPS_PRINT((" %-2d :  ", i+1));
		WPS_PRINT(("SSID:%-16s  ", apinf.ssid));
		WPS_PRINT(("BSSID:%02x:%02x:%02x:%02x:%02x:%02x  ",
			apinf.bssid[0], apinf.bssid[1], apinf.bssid[2],
			apinf.bssid[3], apinf.bssid[4], apinf.bssid[5]));
		WPS_PRINT(("Channel:%-3d  ", apinf.channel));
		if (apinf.wep)
			WPS_PRINT(("WEP  "));
		if (b_v2 && apinf.version2 != 0) {
			WPS_PRINT(("V2(0x%02X)  ", apinf.version2));

			mac = apinf.authorizedMACs;
			WPS_PRINT(("AuthorizedMACs:"));
			for (j = 0; j < 5; j++) {
				if (memcmp(mac, empty_mac, 6) == 0)
					break;

				WPS_PRINT((" %02x:%02x:%02x:%02x:%02x:%02x",
					mac[0], mac[1], mac[2], mac[3],
					mac[4], mac[5]));
				mac += 6;
			}
		}
		WPS_PRINT(("\n"));
		i++;
	}
}

wps_credentials *
ui_wps_select_mode(TESTER_WPS_T *wps)
{
	wps_credentials *new_cred = NULL;

	if (wps->b_scan)
		return NULL;

enter_ap_pin:
	wps->b_appin = FALSE;
	if (wps->b_tester || (wps->b_wpsreg && !wps->b_pin)) {
		/* wpsreg WPS through AP's PIN */
		WPS_PRINT(("\nIf you have an AP's pin, enter it now, otherwise press ENTER:"));
		fgets(wps->pin, sizeof(wps->pin), stdin);
		fflush(stdin);
		REMOVE_NEWLINE(wps->pin);
	}

	/* wpsreg use default pin */
	if (wps->b_wpsreg && STRP(wps->pin) == NULL) {
		WPS_PRINT(("\nAP's Pin not specified, use default Pin %s\n", wps_def_pin));
		strncpy(wps->pin, wps_def_pin, sizeof(wps->pin));
	}

	if (STRP(wps->pin)) {
		if (wps_api_validate_checksum(wps->pin) == FALSE) {
			WPS_PRINT(("\nInvalid AP's pin %s!\n", wps->pin));
			wps->pin[0] = '\0';
			goto enter_ap_pin;
		}

		wps->b_pin = TRUE;
		if (wps->b_tester || wps->b_wpsreg)
			wps->b_appin = TRUE;
		new_cred = _ui_wps_build_new_cred(wps);
		WPS_PRINT(("\nLooking for a WPS PIN AP with AP's pin %s.\n", wps->pin));
	}
	else {
enter_pin:
		if (wps->b_tester || (wps->b_wpsenr && !wps->b_pin && !wps->b_auto)) {
			/* wpsenr WPS through STA's PIN */
			WPS_PRINT(("\nIf you have a pin, enter it now, otherwise press ENTER:"));
			fgets(wps->pin, sizeof(wps->pin), stdin);
			fflush(stdin);
			REMOVE_NEWLINE(wps->pin);
		}

		if (STRP(wps->pin)) {
			if (wps_api_validate_checksum(wps->pin) == FALSE) {
				WPS_PRINT(("\nInvalid pin %s!\n", wps->pin));
				wps->pin[0] = '\0';
				goto enter_pin;
			}
			wps->b_pin = TRUE;
			WPS_PRINT(("\nLooking for a WPS PIN AP with pin %s.\n", wps->pin));
		}
		else if (wps->b_auto) {
			strncpy(wps->pin, wps_def_pin, sizeof(wps->pin));
			wps->b_pin = TRUE;
			WPS_PRINT(("Use defualt device PIN!\n"));
		}
		else {
			wps->b_pin = TRUE;
			wps->b_pbc = TRUE;
			WPS_PRINT(("\nLooking for a WPS PBC AP.\n"));
		}
	}

	return new_cred;
}

bool
ui_wps_find_ap(TESTER_WPS_T *wps, enum eWPS_MODE mode, int *nAP, bool b_v2)
{
	uint8 *mac;
	char option[10];
	bool bFoundAP = FALSE;
	bool b_user_sel = FALSE;
	int i, j, valc, valc1;
	wps_apinf apinf;
	struct wps_ap_list_info *aplist;

	if (wps == NULL|| nAP == NULL)
		return FALSE;

	memset(&apinf, 0, sizeof(apinf));

	/* for old wpsenr/wpsreg commands, find specific AP w/o user selection */
	bFoundAP = _ui_wps_find_sepcific_ap(wps, &apinf, &b_user_sel, nAP);
	if (bFoundAP) {
		/* Add confirmation check if AP is configured */
		if (mode == STA_REG_CONFIG_NW && apinf.configured) {
			WPS_PRINT(("\n%s is a configured network."
				" Are you sure you want to "
				"overwrite existing network"
				" settings? [Y/N]:", apinf.ssid));
			fgets(option, 10, stdin);
			fflush(stdin);
			REMOVE_NEWLINE(option);

			if (option[0] == 'n' || option[0] == 'N') {
				*nAP = -1;
				return FALSE;
			}
		}
		goto found;
	}
	else if (b_user_sel == FALSE)
		return FALSE; /* Timeout or error */

	memset(&apinf, 0, sizeof(apinf));

scan:
	i = 20;
	*nAP = 0;
	bFoundAP = FALSE;

	while (bFoundAP == FALSE && i) {
		/* Get all APs */
		aplist = wps_api_surveying(PBC_MODE(mode), b_v2, TRUE);

		/* Try to find:
		* 1. A PBC enabled AP when we WPS through PBC
		* 2. Collect all WPS APs when we WPS through AP's PIN or PIN
		*/
		bFoundAP = wps_api_find_ap(aplist, nAP, PBC_MODE(mode), NULL, FALSE, NULL, FALSE);

		if (bFoundAP) {
			/* AP's PIN or PIN */
			if (PIN_MODE(mode) && *nAP > 0) {
				i = 0;
				WPS_PRINT(("\n-----------------------------------------------\n"));
				/* Retrieve index i AP info for display all WPS APs */
				while (wps_api_get_ap(i, &apinf)) {
					WPS_PRINT((" %-2d :  ", i+1));
					WPS_PRINT(("SSID:%-16s  ", apinf.ssid));
					WPS_PRINT(("BSSID:%02x:%02x:%02x:%02x:%02x:%02x  ",
						apinf.bssid[0], apinf.bssid[1], apinf.bssid[2],
						apinf.bssid[3], apinf.bssid[4], apinf.bssid[5]));
					WPS_PRINT(("Channel:%-3d  ", apinf.channel));
					if (apinf.wep)
						WPS_PRINT(("WEP  "));
					if (wps->b_v2 && apinf.version2 != 0) {
						WPS_PRINT(("V2(0x%02X)  ", apinf.version2));

						mac = apinf.authorizedMACs;
						WPS_PRINT(("AuthorizedMACs:"));
						for (j = 0; j < 5; j++) {
							if (memcmp(mac, empty_mac, 6) == 0)
								break;

							WPS_PRINT((" %02x:%02x:%02x:%02x:%02x:%02x",
								mac[0], mac[1], mac[2], mac[3],
								mac[4], mac[5]));
							mac += 6;
						}
					}
					WPS_PRINT(("\n"));
					i++;
				}
				/* Select one to WPS */
				WPS_PRINT(("-----------------------------------------------\n"));
				WPS_PRINT(("\nPlease enter the AP number you wish to connect to.\n"
					"Or enter 0 to search again or x to quit:"));
				fgets(option, sizeof(option), stdin);
				fflush(stdin);
				REMOVE_NEWLINE(option);

				if (option[0] == 'x' || option[0] == 'X') {
					bFoundAP = FALSE;
					*nAP = -1;
					break;
				}

				if (option[0] < '0' || option[0] > '9')
					goto scan;

				valc = option[0] - '0';
				if ('0' <= option[1] && '9' >= option[1]) {
					valc1 = option[1] - '0';
					valc = valc * 10;
					valc += valc1;
				}

				if (valc > *nAP)
					goto scan;

				/* Retrieve PIN index valc AP info for WPS */
				if (wps_api_get_ap(valc - 1, &apinf) == FALSE) {
					WPS_PRINT(("Error, wrong number entered!\n"));
					goto scan;
				}

				/* Add confirmation check if AP is configured */
				if (mode == STA_REG_CONFIG_NW && apinf.configured) {
					WPS_PRINT(("\nDo you want to configure AP [Y/N]:"));
					WPS_PRINT(("\n%s is a configured network."
						" Are you sure you want to "
						"overwrite existing network"
						" settings? [Y/N]:", apinf.ssid));
					fgets(option, 10, stdin);
					fflush(stdin);
					REMOVE_NEWLINE(option);

					if (option[0] == 'n' || option[0] == 'N') {
						bFoundAP = FALSE;
						*nAP = -1;
						break;
					}
				}
			}
			/* PBC */
			else if (PBC_MODE(mode) && *nAP > 0) {
				if (*nAP > 1) {
					WPS_PRINT(("More than one PBC AP found. "
						"Restarting scanning\n"));
					bFoundAP = FALSE;
				} else {
					/* Retrieve PBC index 0 AP info for WPS */
					wps_api_get_ap(0, &apinf);
				}
			}
		} else {
			WPS_PRINT(("Did not find a WPS AP.\nPress X to quit, "
				"<Enter> to continue\n"));
			fgets(option, 10, stdin);
			fflush(stdin);
			REMOVE_NEWLINE(option);

			if (option[0] == 'x' || option[0] == 'X') {
				WPS_PRINT(("\nCANCEL REQUESTED BY USER. CANCELING, "
					"PLEASE WAIT...\n"));
				bFoundAP = FALSE;
				*nAP = -1;
				break;
			}
		}

		i--;
	}
	WPS_PRINT(("\n"));

found:
	/* Copy found ap info to wps */
	if (bFoundAP) {
		memcpy(wps->bssid, apinf.bssid, 6);
		wps_strncpy(wps->ssid, apinf.ssid, sizeof(wps->ssid));
		wps->wsec = apinf.wep;
	}

	return bFoundAP;
}

bool
ui_wps_parse_args(TESTER_WPS_T *wps, bool *b_async, int argc, char* argv[])
{
	int index;
	char *cmd, *val, *base;
	/* int ap_index = 1, apcount = 1; */

	if (wps == NULL)
		return FALSE;

	/* default settings */
	memset(wps, 0, sizeof(TESTER_WPS_T));
	wps->wsec = 1; /* assume wep is ON */
	wps->b_v2 = TRUE;
	wps->ap_index = 1;

	base = strrchr(argv[0], '/');
	base = base ? base + 1 : argv[0];

	if (strstr(base, "wpsenr"))
		wps->b_wpsenr = TRUE;
	else if (strstr(base, "wpsreg"))
		wps->b_wpsreg = TRUE;
	else {
		/* for wpsapitester only support async argument and use interactive mode */
		wps->b_tester = TRUE;
		if (argc > 2 ||
		    (argc == 2 && strcmp(argv[1], "-async"))) {
			WPS_PRINT_USAGE();
			return FALSE;
		}
	}

	/* decount the prog name */
	argc--;
	index = 1;
	while (argc) {
		cmd = argv[index++]; argc--;
		if (!strcmp(cmd, "-help")) {
			WPS_PRINT_USAGE();
			return FALSE;
		}
		else if (wps->b_tester && !strcmp(cmd, "-async")) {
			*b_async = TRUE;
		}
		else if (!strcmp(cmd, "-scan")) {
			wps->b_scan = TRUE;
		}
		else if (!strcmp(cmd, "-ssid")) {
			WPS_ARGC_CHECK();
			val = argv[index++]; argc--;
			wps_strncpy(wps->ssid, val, sizeof(wps->ssid));
			wps->b_ssid = TRUE;
			WPS_PRINT(("SSID : %s", wps->ssid));
		}
		else if (!strcmp(cmd, "-if")) {
			WPS_ARGC_CHECK();
			val = argv[index++]; argc--;
			wps_strncpy(wps->ifname, val, sizeof(wps->ifname));
		}
		else if (!strcmp(cmd, "-bssid")) {
			WPS_ARGC_CHECK();
			/*
			 * WARNING : this "bssid" is used only to create an 802.1X socket.
			 * Normally, it should be the bssid of the AP we will associate to.
			 * Setting this manually means that we might be proceeding to
			 * eapol exchange with a different AP than the one we are associated to,
			 * which might work ... or not.
			 *
			 * When implementing an application, one might want to enforce association
			 * with the AP with that particular BSSID. In case of multiple AP
			 * on the ESS, this might not be stable with roaming enabled.
			 */
			 val = argv[index++]; argc--;
			if (!set_mac_address(val, wps->bssid)) {
				WPS_PRINT(("\n*** WARNING : Setting 802.1X destination manually to:"
					"  %s ***\n\n", val));
				wps->b_bssid = TRUE;
			}
		}
		else if (!strcmp(cmd, "-pin")) {
			WPS_ARGC_CHECK();
			val = argv[index++]; argc--;
			wps_strncpy(wps->pin, val, sizeof(wps->pin));

			/* Allow 4-digit PIN, we should add numeric checking for 4-digit PIN */
			if (strlen(wps->pin) != 4 && !wps_api_validate_checksum(wps->pin)) {
				WPS_PRINT(("\tInvalid PIN number parameter: %s\n", wps->pin));
				WPS_PRINT_USAGE();
				return FALSE;
			}

			wps->b_pin = TRUE;
		}
		else if (wps->b_wpsenr && !strcmp(cmd, "-pb")) {
			wps->pin[0] = '\0';
			wps->b_pin = TRUE;
			wps->b_pbc = TRUE;
		}
		else if (!strcmp(cmd, "-sec")) {
			WPS_ARGC_CHECK();
			val = argv[index++]; argc--;
			wps->wsec = atoi(val);
			wps->b_wsec = TRUE;
		}
		else if (wps->b_wpsreg && !strcmp(cmd, "-mode")) {
			/* For registrar */
			WPS_ARGC_CHECK();
			val = argv[index++]; argc--;
			wps->reg_mode = atoi(val);
			if (wps->reg_mode == 1)
				wps->reg_mode = STA_REG_JOIN_NW;
			else if (wps->reg_mode == 2)
				wps->reg_mode = STA_REG_CONFIG_NW;
			else {
				WPS_PRINT(("Invalid parameter for registrar \"mode\": %s\n", val));
				WPS_PRINT_USAGE();
				return FALSE;
			}
		}
		else if (wps->b_wpsreg && !strcmp(cmd, "-cred")) {
			/* For registrar */
			WPS_ARGC_CHECK();
			val = argv[index++]; argc--;
			wps->reg_cred = atoi(val);
			if (wps->reg_mode != 1 || wps->reg_mode != 2) {
				WPS_PRINT(("Invalid parameter for registrar \"cred\": %s\n", val));
				WPS_PRINT_USAGE();
				return FALSE;
			}
		}
		else if (!strcmp(cmd, "-v1")) {
			/* WSC V1 only */
			wps->b_v2 = FALSE;
		}
		else if (!strcmp(cmd, "-ip")) {
			WPS_ARGC_CHECK();
			/* Static IP address */
			val = argv[index++]; argc--;

			wps_strncpy(wps->ip_addr, val, sizeof(wps->ip_addr));
			wps->run_ip = "ip";
		}
		else if (!strcmp(cmd, "-dhcp")) {
			wps->b_def_dhclient = TRUE;

			/* Dhcp client */
			val = argv[index];
			if (argc && val && val[0] != '-') {
				/* Use user specified */
				wps_strncpy(wps->dhcp_cmd, val, sizeof(wps->dhcp_cmd));
				wps->b_def_dhclient = FALSE;
				index++;
				argc--;
			}

			wps->run_ip = "dhcp";
		}
		else if (!strcmp(cmd, "-amac")) {
			/* Connet to the AP which has my MAC in its AuthorizedMASc list */
			wps->b_amac = TRUE;
			val = argv[index];
			if (argc && val && val[0] != '-') {
				/* check wildcard */
				if (!strcmp(val, "wc"))
					wps->b_amac_wc = TRUE;
				else {
					WPS_PRINT(("Invalid parameter for \"amac\": %s\n", val));
					WPS_PRINT_USAGE();
					return FALSE;
				}

				index++;
				argc--;
			}
		}
		else if (!strcmp(cmd, "-auto")) {
			wps->b_auto = TRUE;
		}
#ifdef WFA_WPS_20_TESTBED
		else if (!strcmp(cmd, "-v2")) {
			WPS_ARGC_CHECK();
			/* version2 number */
			val = argv[index++]; argc--;

			wps->wps20_tbinf.v2_num = (uint8)strtoul(val, NULL, 16);
		}
		else if (!strcmp(cmd, "-nattr")) {
			WPS_ARGC_CHECK();
			/* add a new attribute at the end of every messages */
			val = argv[index++]; argc--;

			/* TLV convert */
			if (new_tlv_convert(wps, (uint8*)val) == -1) {
				WPS_PRINT(("\nInvalid new attribute TLV value\n"));
				WPS_PRINT_USAGE();
				return FALSE;
			}
		}
		else if (!strcmp(cmd, "-zpadding")) {
			/* do zero padding */
			wps->wps20_tbinf.b_zpadding = TRUE;
		}
		else if (!strcmp(cmd, "-zlength")) {
			/* do zero length */
			wps->wps20_tbinf.b_zlength = TRUE;
		}
		else if (wps->b_wpsreg && !strcmp(cmd, "-mca")) {
			/* for registrar, Multiple Credential Attributes */
			wps->wps20_tbinf.b_mca = TRUE;
		}
		else if (!strcmp(cmd, "-ifrag")) {
			WPS_ARGC_CHECK();
			/* WPS IE fragment threshold */
			val = argv[index++]; argc--;

			wps->ifrag = atoi(val);
			if (wps_api_set_wps_ie_frag_threshold(wps->ifrag) == FALSE) {
				WPS_PRINT(("\nInvalid WPS IE fragment threshold %s\n", val));
				WPS_PRINT_USAGE();
				return FALSE;
			}
		}
		else if (!strcmp(cmd, "-efrag")) {
			WPS_ARGC_CHECK();
			/* EAP fragment threshold */
			val = argv[index++]; argc--;

			wps->efrag = atoi(val);
			if (wps_api_set_sta_eap_frag_threshold(wps->efrag) == FALSE) {
				WPS_PRINT(("\nInvalid EAP fragment threshold %s\n", val));
				WPS_PRINT_USAGE();
				return FALSE;
			}
		}
		else if (!strcmp(cmd, "-prbreq")) {
			WPS_ARGC_CHECK();
			/* Update partial embedded WPS probe request IE */
			val = argv[index++]; argc--;

			if (wps_api_update_prbreq_ie((uint8 *)val) == FALSE) {
				WPS_PRINT(("\nInvalid updating WPS IE in probe request IE\n"));
				WPS_PRINT_USAGE();
				return FALSE;
			}
		}
		else if (!strcmp(cmd, "-assocreq")) {
			WPS_ARGC_CHECK();
			/* Update partial embedded WPS assoc request IE */
			val = argv[index++]; argc--;

			if (wps_api_update_assocreq_ie((uint8 *)val) == FALSE) {
				WPS_PRINT(("\nInvalid updating WPS IE in associate request IE\n"));
				WPS_PRINT_USAGE();
				return FALSE;
			}
		}
#endif /* WFA_WPS_20_TESTBED */
		else if (!strcmp(cmd, "-transport_uuid")) {
			int i = 0;
			char cByte[3] = {0, 0, 0};
			WPS_ARGC_CHECK();
			val = argv[index++]; argc--;
			WPS_PRINT(("Transport UUID is:"));

			if (strlen(val) != 32) {
				WPS_PRINT(("Transport UUID format (16 bytes): "
					"000102030405060708090a0b0c0d0e0f\n"));
				return FALSE;
			}

			while ((val != NULL) && ((val+2) != NULL) && (i < 16)) {
				memcpy(cByte, val, 2);
				wps->transport_uuid[i] = strtol(cByte, NULL, 16);
				WPS_PRINT(("[%02x] ", wps->transport_uuid[i]));
				val += 2;
				i++;
			}
			WPS_PRINT(("\n"));
		}
		else if (!strcmp(cmd, "-fb")) {
			/* Enabled fallback support an WEP V1 AP */
			wps->b_fb = TRUE;
		}
		else {
			WPS_PRINT(("Invalid parameter : %s\n", cmd));
			WPS_PRINT_USAGE();
			return FALSE;
		}
	}

	/* Disable auto mode when PBC and AuthorizedMAC enalbed */
	if (wps->b_pbc || wps->b_amac)
		wps->b_auto = FALSE;

	/* Argumetns compability checking */
	if (wps->b_amac && !wps->b_v2) {
		WPS_PRINT(("Conflict arguments \"amac\" and \"v1\"\n"));
		WPS_PRINT_USAGE();
		return FALSE;
	}

	return TRUE;
}

void
ui_wps_wep_incompatible_notify(TESTER_WPS_T *wps)
{
	char inp[8];
	bool b_tryAgain = TRUE;

	if (wps == NULL || wps->b_fb == FALSE)
		return;

	/* Clear it, because we have ran WPS again in v1 */
	if (wps->b_force_v1 == TRUE) {
		wps->b_force_v1 = FALSE;
		return;
	}

	/* Select Accept or Cancel */
	WPS_PRINT(("\nYour AP/Router is using a security format no longer supported by WSP 2.0\n"
		"Select Accept to connect anyways or "
		"Cancel to change the AP/Router to a supported format like WPA/WPA2:"));

	while (b_tryAgain) {
		WPS_PRINT(("\n\tOptions:\n"));
		WPS_PRINT(("\t1. Accept%s\n", wps->b_appin ?
			"" : " (You need to start WPS again on AP/Router !!)"));
		WPS_PRINT(("\t2. Cancel\n"));
		WPS_PRINT(("\tEnter selection: "));
		fgets(inp, sizeof(inp), stdin);
		fflush(stdin);
		REMOVE_NEWLINE(inp);

		if (STRP(inp) == NULL) {
			/* We got no input */
			WPS_PRINT(("\tError: Invalid input.\n"));
			continue;
		}

		switch (inp[0]) {
		case '1': /* Accept */
			wps->b_force_v1 = TRUE;
			b_tryAgain = FALSE;
			break;

		case '2': /* Cancel */
			wps->b_force_v1 = FALSE;
			b_tryAgain = FALSE;
			break;

		default:
			WPS_PRINT(("\tERROR: Invalid input.\n"));
			break;
		}
	}

	return;
}
