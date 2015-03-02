/*
 * WPS app utilies
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: $
 */

#include <stdio.h>
#include <string.h>
#include <wpstypes.h>
#include <tutrace.h>
#include <wps.h>
#include <wps_apputils.h>
#include <wlif_utils.h>

int
wpsapp_utils_update_custom_cred(char *ssid, char *key, char *akm, char *crypto, int oob_addenr,
	bool b_wps_Version2)
{
	/*
	 * WSC 1.0 Old design : Because WSC 1.0 did not support Mix mode, in default
	 * we pick WPA2-PSK/AES up in Mix mode.  If NVRAM "wps_mixedmode" is "1"
	 * than change to pick WPA-PSK/TKIP up.
	 */

	/*
	 * WSC 2.0 support Mix mode and says "WPA-PSK and TKIP only allowed in
	 * Mix mode".  So in default we use Mix mode and if  NVRMA "wps_mixedmode"
	 * is "1" than change to pick WPA2-PSK/AES up.
	 */
	int mix_mode = 2;

	if (!strcmp(wps_safe_get_conf("wps_mixedmode"), "1"))
		mix_mode = 1;

	if (!strcmp(akm, "WPA-PSK WPA2-PSK")) {
		if (b_wps_Version2) {
				strcpy(akm, "WPA2-PSK");
		} else {
			if (mix_mode == 1)
				strcpy(akm, "WPA-PSK");
			else
				strcpy(akm, "WPA2-PSK");
		}
		TUTRACE((TUTRACE_INFO, "Update customized Key Mode : %s, ", akm));
	}

	if (!strcmp(crypto, "AES+TKIP")) {
		if (b_wps_Version2) {
				strcpy(crypto, "AES");
		} else {
			if (mix_mode == 1)
				strcpy(crypto, "TKIP");
			else
				strcpy(crypto, "AES");
		}
		TUTRACE((TUTRACE_INFO, "Update customized encrypt mode = %s\n", crypto));
	}

	if (oob_addenr) {
		char *p;

		/* get randomssid */
		if ((p = wps_get_conf("wps_randomssid"))) {
			strncpy(ssid, p, MAX_SSID_LEN);
			TUTRACE((TUTRACE_INFO, "Update customized SSID : %s\n", ssid));
		}

		/* get randomkey */
		if ((p = wps_get_conf("wps_randomkey")) && (strlen (p) >= 8)) {
			strncpy(key, p, SIZE_64_BYTES);
			TUTRACE((TUTRACE_INFO, "Update customized Key : %s\n", key));
		}

		/* Modify the crypto, if the station is legacy */
	}

	return 0;
}
