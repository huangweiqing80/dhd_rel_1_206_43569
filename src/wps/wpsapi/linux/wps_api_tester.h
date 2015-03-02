/*
 * WPS API tester header file
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wps_api_tester.h 283412 2011-09-14 05:52:39Z $
 */

#ifndef __WPS_API_TESTER_H__
#define __WPS_API_TESTER_H__

#ifdef __cplusplus
extern "C" {
#endif

#define STRP(s) (strlen((s)) ? (s) : NULL)
#define ARRAYSIZE(a)	(sizeof(a) / sizeof(a[0]))


typedef struct TESTER_WPS_S {
	char pin[12];
	char *run_ip;

	char bssid[6];
	char ssid[33];
	char ifname[16];
	char def_dhclient_pf[256];
	char ip_addr[16];
	char dhcp_cmd[256];
	char run_ip_cmd[256];

	bool b_abort;	/* indecate user abort happened */
	bool b_wpsenr;	/* Using old wpsenr style commands */
	bool b_wpsreg;	/* Using old wpsreg style commands */
	bool b_tester;	/* wps api tester */
	bool b_force_v1; /* wep incompatible happen force to v1 */

	bool b_ssid;	/* user specified ssid */
	bool b_bssid;	/* user specified bssid */
	bool b_pbc;	/* user specified pbc method */
	bool b_pin;	/* user specified pin */
	bool b_wsec;	/* user specified AP security enabled */
	bool b_amac;	/* Authorized MAC */
	bool b_amac_wc;	/* include wildcard Authorized MAC  */
	bool b_auto;	/* Automatically WPS each PIN mode APs */
	bool b_scan;
	bool b_appin;	/* is the pin beloneg to AP or STA */
	bool b_v2;
	bool b_def_dhclient;
	bool b_fb;	/* user specified fallback support V1 WEP AP */

	uint8 wsec;

	int ap_index;
	int ap_count;
	int ifrag;
	int efrag;
	int reg_mode;	/* registrar command line mode */
	int reg_cred;	/* registrar command line credential mode */

	wps_credentials cred; /* for registrar */
	char transport_uuid[16];
#ifdef WFA_WPS_20_TESTBED
	wps20_testbed_inf wps20_tbinf;
#endif /* WFA_WPS_20_TESTBED */
} TESTER_WPS_T;

/* UI */
extern void ui_display_aplist(bool b_v2);
extern bool ui_wps_parse_args(TESTER_WPS_T *wps, bool *b_async, int argc, char* argv[]);
extern wps_credentials *ui_wps_select_mode(TESTER_WPS_T *wps);
extern bool ui_wps_find_ap(TESTER_WPS_T *wps, enum eWPS_MODE mode, int *nAP, bool b_v2);
extern void ui_wps_wep_incompatible_notify(TESTER_WPS_T *wps);


#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* __WPS_API_TESTER_H__ */
