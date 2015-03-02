/*
 * wl pfn command module
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wluc_pfn.c 458728 2014-02-27 18:15:25Z $
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

static cmd_func_t wl_pfn_set;
static cmd_func_t wl_pfn_add;
static cmd_func_t wl_pfn_add_bssid;
static cmd_func_t wl_pfn_cfg;
static cmd_func_t wl_pfn;
static cmd_func_t wl_pfnbest;
static cmd_func_t wl_pfn_suspend;
static cmd_func_t wl_pfnlbest;
static cmd_func_t wl_pfn_mem;
static cmd_func_t wl_pfn_event_check;
static cmd_func_t wl_event_filter;
static cmd_func_t wl_pfn_roam_alert_thresh;

static cmd_t wl_pfn_cmds[] = {
	{ "pfnset", wl_pfn_set, -1, -1,
	"Configures preferred network offload parameter\n"
	"\tpfnset syntax is: pfnset [scanfrq xxxxx(30 sec)] [netimeout xxxx(60 sec)]"
	"[slowfrq xxxx(180 sec)] [bestn (2)|[1-BESTN_MAX]] [mscan (0)|[0-MSCAN_MAX]]"
	"[bdscan (0)|1] [adapt (off)|[smart, strict, slow]]"
	"[rssi_delta xxxx(30 dBm)] [sort (listorder)|rssi] [bkgscan (0)|1] [immediateevent (0)|1]"
	"[immediate 0|(1)] [repeat (10)|[1-20]] [exp (2)|[1-5]] [separate 0|(1)]"},
	{ "pfnadd", wl_pfn_add, -1, -1,
	"Adding SSID based preferred networks to monitor and connect\n"
	"\tpfnadd syntax is: pfnadd ssid <SSID> [hidden (0)|1]"
	"[imode (bss)|ibss]"
	"[amode (open)|shared] [wpa_auth (wpadisabled)|wpapsk|wpa2psk|wpanone|any]"
	"[wsec WEP|TKIP|AES|TKIPAES] [suppress (neither)|found|lost] [rssi <rssi>(0 dBm)]\n"
	"Up to 16 SSID networks can be added together in one pfnadd\n"
	"\tTo specify more than one WPA methods, use a number (same format as wpa_auth iovar) "
	"as the parameter of wpa_auth (e.g. 0x84 for wpapsk and wpa2psk.)"},
	{ "pfnadd_bssid", wl_pfn_add_bssid, -1, -1,
	"Adding BSSID based preferred networks to monitor and connect\n"
	"\tpfnadd_bssid syntax is: pfnadd_bssid bssid <BSSID> [suppress (neither)|found|lost]"
	"[rssi <rssi>(0 dBm)]\n"
	"\tUp to 150 BSSIDs can be added together in one pfnadd_bssid"},
	{ "pfncfg", wl_pfn_cfg, -1, -1,
	"Configures channel list and report type\n"
	"Usage: pfncfg [channel <list>] [report <type>] [prohibited 1|0]\n"
	"\treport <type> is ssidonly, bssidonly, or both (default: both)\n"
	"\tprohibited flag 1: allow and (passively) scan any channel (default 0)"},
	{ "pfn", wl_pfn, -1, -1,
	"Enable/disable preferred network off load monitoring\n"
	"\tpfn syntax is: pfn 0|1"},
	{ "pfnclear", wl_var_void, -1, WLC_SET_VAR,
	"Clear the preferred network list\n"
	"\tpfnclear syntax is: pfnclear"},
	{ "pfnbest", wl_pfnbest, -1, -1,
	"Get the best n networks in each of up to m scans, with 16bit timestamp\n"
	"\tpfnbest syntax is: pfnbest"},
	{ "pfnlbest", wl_pfnlbest, -1, -1,
	"Get the best n networks in each scan, up to m scans, with 32bit timestmp\n"
	"\tpfnbest syntax is: pfnlbest"},
	{ "pfnsuspend", wl_pfn_suspend, -1, -1,
	"Suspend/resume pno scan\n"
	"\tpfnsuspend syntax is: pfnsuspend 0|1"},
	{ "pfnmem", wl_pfn_mem, -1, -1,
	"Get supported mscan with given bestn\n"
	"\tpfnmem syntax is: pfnmscan bestn [1-BESTN_MAX]"},
	{ "pfneventchk", wl_pfn_event_check, -1, -1,
	"Listen and prints the preferred network off load event from dongle\n"
	"\tpfneventchk syntax is: pfneventchk [ifname]"},
	{ "event_filter", wl_event_filter, -1, -1,
	"Set/get event filter\n"
	"\tevent_filter syntax is: event_filter [value]"},
	{ "pfn_roam_alert_thresh", wl_pfn_roam_alert_thresh, WLC_GET_VAR, WLC_SET_VAR,
	"Get/Set PFN and roam alert threshold\n"
	"\tUsage: wl pfn_roam_alert_thresh [pfn_alert_thresh] [roam_alert_thresh]"
	},
	{ NULL, NULL, 0, 0, NULL }
};

static char *buf;

/* module initialization */
void
wluc_pfn_module_init(void)
{
	/* get the global buf */
	buf = wl_get_buf();

	/* register pfn commands */
	wl_module_cmds_register(wl_pfn_cmds);
}

static int
wl_pfn_set(void *wl, cmd_t *cmd, char **argv)
{
	int err;
	wl_pfn_param_t pfn_param;

	UNUSED_PARAMETER(cmd);

	/* Setup default values */
	pfn_param.version = PFN_VERSION;
	/* Sorting based on list order, no back ground scan, no autoswitch,
	  * no immediate event report, no adaptvie scan, but immediate scan
	  */
	pfn_param.flags = (PFN_LIST_ORDER << SORT_CRITERIA_BIT | ENABLE << IMMEDIATE_SCAN_BIT);
	/* Scan frequency of 30 sec */
	pfn_param.scan_freq = 30;
	/* slow adapt scan is off by default */
	pfn_param.slow_freq = 0;
	/* RSSI margin of 30 dBm */
	pfn_param.rssi_margin = 30;
	/* Network timeout 60 sec */
	pfn_param.lost_network_timeout = 60;
	/* best n = 2 by default */
	pfn_param.bestn = DEFAULT_BESTN;
	/* mscan m=0 by default, so not record best networks by default */
	pfn_param.mscan = DEFAULT_MSCAN;
	/*  default repeat = 10 */
	pfn_param.repeat = DEFAULT_REPEAT;
	/* by default, maximum scan interval = 2^2*scan_freq when adaptive scan is turned on */
	pfn_param.exp = DEFAULT_EXP;

	while (*++argv) {
		if (!stricmp(*argv, "scanfrq")) {
			if (*++argv)
				pfn_param.scan_freq = atoi(*argv);
			else {
				fprintf(stderr, "Missing scanfrq option\n");
				return BCME_USAGE_ERROR;
			}
		} else if (!stricmp(*argv, "netimeout")) {
			if (*++argv)
				pfn_param.lost_network_timeout = atoi(*argv);
			else {
				fprintf(stderr, "Missing netimeout option\n");
				return BCME_USAGE_ERROR;
			}
		} else if (!stricmp(*argv, "rssi_delta")) {
			if (*++argv)
				pfn_param.rssi_margin = atoi(*argv);
			else {
				fprintf(stderr, "Missing rssi_delta option\n");
				return BCME_USAGE_ERROR;
			}
		} else if (!stricmp(*argv, "sort")) {
			if (*++argv) {
				pfn_param.flags &= ~SORT_CRITERIA_MASK;
				if (!stricmp(*argv, "listorder"))
					pfn_param.flags |= (PFN_LIST_ORDER << SORT_CRITERIA_BIT);
				else if (!stricmp(*argv, "rssi"))
					pfn_param.flags |= (PFN_RSSI << SORT_CRITERIA_BIT);
				else {
					fprintf(stderr, "Invalid sort option %s\n", *argv);
					return BCME_USAGE_ERROR;
				}
			} else {
				fprintf(stderr, "Missing sort option\n");
				return BCME_USAGE_ERROR;
			}
		} else if (!stricmp(*argv, "immediateevent")) {
			if (*++argv) {
				if (!stricmp(*argv, "1")) {
					pfn_param.flags |= IMMEDIATE_EVENT_MASK;
				} else if (!stricmp(*argv, "0")) {
					pfn_param.flags &= ~IMMEDIATE_EVENT_MASK;
				} else {
					fprintf(stderr, "Invalid immediateevent option\n");
					return BCME_USAGE_ERROR;
				}
			} else {
				fprintf(stderr, "Missing immediateevent option\n");
				return BCME_USAGE_ERROR;
			}
		} else if (!stricmp(*argv, "bkgscan")) {
			if (*++argv) {
				pfn_param.flags &= ~ENABLE_BKGRD_SCAN_MASK;
				if (atoi(*argv))
					pfn_param.flags |= (ENABLE << ENABLE_BKGRD_SCAN_BIT);
				else
					pfn_param.flags |= (DISABLE << ENABLE_BKGRD_SCAN_BIT);
			} else {
				fprintf(stderr, "Missing bkgscan option\n");
				return BCME_USAGE_ERROR;
			}
		} else if (!stricmp(*argv, "immediate")) {
			pfn_param.flags &= ~IMMEDIATE_SCAN_MASK;
			if (*++argv) {
				if (atoi(*argv))
					pfn_param.flags |= (ENABLE << IMMEDIATE_SCAN_BIT);
				else
					pfn_param.flags |= (DISABLE << IMMEDIATE_SCAN_BIT);
			} else {
				fprintf(stderr, "Missing immediate option\n");
				return BCME_USAGE_ERROR;
			}
		} else if (!stricmp(*argv, "bdscan")) {
			if (*++argv) {
				pfn_param.flags &= ~ENABLE_BD_SCAN_MASK;
				if (atoi(*argv))
					pfn_param.flags |= (ENABLE << ENABLE_BD_SCAN_BIT);
				else
					pfn_param.flags |= (DISABLE << ENABLE_BD_SCAN_BIT);
			} else {
				fprintf(stderr, "Missing bdscan option\n");
				return BCME_USAGE_ERROR;
			}
		} else if (!stricmp(*argv, "separate")) {
			if (*++argv) {
				pfn_param.flags &= ~REPORT_SEPERATELY_MASK;
				if (atoi(*argv))
					pfn_param.flags |= (ENABLE << REPORT_SEPERATELY_BIT);
				else
					pfn_param.flags |= (DISABLE << REPORT_SEPERATELY_BIT);
			} else {
				fprintf(stderr, "Missing seperate option\n");
				return -1;
			}
		} else if (!stricmp(*argv, "adapt")) {
			if (*++argv) {
				pfn_param.flags &= ~ENABLE_ADAPTSCAN_MASK;
				if (!stricmp(*argv, "off")) {
					pfn_param.flags |= (OFF_ADAPT << ENABLE_ADAPTSCAN_BIT);
				} else if (!stricmp(*argv, "smart")) {
					pfn_param.flags |= (SMART_ADAPT << ENABLE_ADAPTSCAN_BIT);
				} else if (!stricmp(*argv, "strict")) {
					pfn_param.flags |= (STRICT_ADAPT << ENABLE_ADAPTSCAN_BIT);
				} else if (!stricmp(*argv, "slow")) {
					pfn_param.flags |= (SLOW_ADAPT << ENABLE_ADAPTSCAN_BIT);
				} else {
					fprintf(stderr, "Invalid adaptive scan option %s\n", *argv);
					return BCME_USAGE_ERROR;
				}
			} else {
				fprintf(stderr, "Missing adaptive scan option\n");
				return BCME_USAGE_ERROR;
			}
		} else if (!stricmp(*argv, "bestn")) {
			pfn_param.bestn = atoi(*++argv);
		} else if (!stricmp(*argv, "mscan")) {
			pfn_param.mscan = atoi(*++argv);
		} else if (!stricmp(*argv, "repeat")) {
			pfn_param.repeat = atoi(*++argv);
			if (pfn_param.repeat < 1 || pfn_param.repeat > 20) {
				fprintf(stderr, "repeat %d out of range (1-20)\n",
					pfn_param.repeat);
				return BCME_USAGE_ERROR;
			}
		} else if (!stricmp(*argv, "exp")) {
			pfn_param.exp = atoi(*++argv);
			if (pfn_param.exp < 1 || pfn_param.exp > 5) {
				fprintf(stderr, "exp %d out of range (1-5)\n",
					pfn_param.exp);
				return BCME_BADARG;
			}
		} else if (!stricmp(*argv, "slowfrq")) {
			if (*++argv)
				pfn_param.slow_freq = atoi(*argv);
			else {
				fprintf(stderr, "Missing slowfrq option\n");
				return BCME_USAGE_ERROR;
			}
		}  else {
			fprintf(stderr, "Invalid parameter %s\n", *argv);
			return BCME_USAGE_ERROR;
		}
	}

	if ((((pfn_param.flags & ENABLE_ADAPTSCAN_MASK) ==
	    (SLOW_ADAPT << ENABLE_ADAPTSCAN_BIT)) &&
	    !pfn_param.slow_freq) ||
	    (((pfn_param.flags & ENABLE_ADAPTSCAN_MASK) !=
	    (SLOW_ADAPT << ENABLE_ADAPTSCAN_BIT)) &&
	    pfn_param.slow_freq)) {
		fprintf(stderr, "SLOW_ADAPT flag and slowfrq value not match\n");
		return BCME_BADARG;
	}
	pfn_param.version = htod32(pfn_param.version);
	pfn_param.scan_freq = htod32(pfn_param.scan_freq);
	pfn_param.lost_network_timeout = htod32(pfn_param.lost_network_timeout);
	pfn_param.flags = htod16(pfn_param.flags);
	pfn_param.rssi_margin = htod16(pfn_param.rssi_margin);
	pfn_param.slow_freq = htod32(pfn_param.slow_freq);

	if ((err = wlu_iovar_set(wl, "pfn_set", &pfn_param, sizeof(wl_pfn_param_t))))
		return (err);

	return (0);
}

static bool
validate_hex(char hexchar)
{
	if ((hexchar >= '0' && hexchar <= '9') ||
		(hexchar >= 'a' || hexchar <= 'z') ||
		(hexchar >= 'A' || hexchar <= 'Z'))
		return TRUE;
	else
		return FALSE;
}

static uint8
char2hex(char hexchar)
{
	if (hexchar >= '0' && hexchar <= '9')
		return (hexchar - '0');
	else if (hexchar >= 'a' && hexchar <= 'f')
		return (hexchar - 'a' + 10);
	else if (hexchar >= 'A' && hexchar <= 'F')
		return (hexchar - 'A' + 10);
	else
	{
		fprintf(stderr, "non-hex\n");
		return 0xff;
	}
}

#define MAXNUM_SSID_PER_ADD	16

static int
wl_pfn_add(void *wl, cmd_t *cmd, char **argv)
{
	int         err;
	wl_pfn_t    *p_pfn_element = NULL;
	int         i, pfn_element_len, cnt;
	wl_pfn_t    *pssidnet = NULL;
	int32       hidden;

	UNUSED_PARAMETER(cmd);

	pfn_element_len = MAXNUM_SSID_PER_ADD * sizeof(wl_pfn_t);
	p_pfn_element = (wl_pfn_t *)malloc(pfn_element_len);
	if (p_pfn_element == NULL) {
		fprintf(stderr, "Failed to allocate buffer for %d bytes\n", pfn_element_len);
		return BCME_NOMEM;
	}
	memset(p_pfn_element, '\0', pfn_element_len);

	pssidnet = p_pfn_element;
	for (i = 0; i < MAXNUM_SSID_PER_ADD; i++) {
		/* Default setting, open, no WPA, no WEP and bss */
		pssidnet->auth = DOT11_OPEN_SYSTEM;
		pssidnet->wpa_auth = WPA_AUTH_DISABLED;
		pssidnet->wsec = 0;
		pssidnet->infra = 1;
		pssidnet->flags = 0;
		pssidnet++;
	}
	cnt = -1;
	pssidnet = p_pfn_element;
	while (*++argv) {
		if (!stricmp(*argv, "ssid")) {
			if (*++argv) {
				if (++cnt >= MAXNUM_SSID_PER_ADD) {
					fprintf(stderr, "exceed max 16 SSID per pfn_add\n");
					err = BCME_BADARG;
					goto error;
				}
				if (cnt > 0) {
					pssidnet->flags = htod32(pssidnet->flags);
					pssidnet++;
				}
				strncpy((char *)pssidnet->ssid.SSID, *argv,
				        sizeof(pssidnet->ssid.SSID));
				pssidnet->ssid.SSID_len =
				   strlen((char *)pssidnet->ssid.SSID);
				if (pssidnet->ssid.SSID_len > 32) {
					fprintf(stderr, "SSID too long: %s\n", *argv);
					err = BCME_BADARG;
					goto error;
				}
				pssidnet->ssid.SSID_len = htod32(pssidnet->ssid.SSID_len);
			} else {
				fprintf(stderr, "no value for ssid\n");
				err = BCME_USAGE_ERROR;
				goto error;
			}
		}
		else if (!stricmp(*argv, "hidden")) {
			if (pssidnet->ssid.SSID_len == 0) {
				fprintf(stderr, "Wrong! Start with SSID\n");
				err = BCME_USAGE_ERROR;
				goto error;
			}
			if (*++argv) {
				hidden = **argv - '0';
				if (hidden != ENABLE && hidden != DISABLE) {
					fprintf(stderr, "invalid hidden setting, use 0/1\n");
					err = BCME_USAGE_ERROR;
					goto error;
				}
				pssidnet->flags |= hidden << WL_PFN_HIDDEN_BIT;
			} else {
				fprintf(stderr, "no value for hidden\n");
				err = BCME_USAGE_ERROR;
				goto error;
			}
		}  else if (!stricmp(*argv, "imode")) {
			if (*++argv) {
				if (pssidnet->ssid.SSID_len == 0) {
					fprintf(stderr, "Wrong! Start with SSID\n");
					err = BCME_USAGE_ERROR;
					goto error;
				}
				if (!stricmp(*argv, "bss")) {
					pssidnet->infra = 1;
				} else if (!stricmp(*argv, "ibss")) {
					pssidnet->infra = 0;
				} else {
					fprintf(stderr, "Invalid imode arg %s\n", *argv);
					err = BCME_USAGE_ERROR;
					goto error;
				}
				pssidnet->infra = htod32(pssidnet->infra);
			} else {
				fprintf(stderr, "Missing option for imode\n");
				err = BCME_USAGE_ERROR;
				goto error;
			}
		} else if (!stricmp(*argv, "amode")) {
			if (*++argv) {
				if (pssidnet->ssid.SSID_len == 0) {
					fprintf(stderr, "Wrong! Start with SSID\n");
					err = BCME_USAGE_ERROR;
					goto error;
				}
				if (!stricmp(*argv, "open"))
					pssidnet->auth = DOT11_OPEN_SYSTEM;
				else if (!stricmp(*argv, "shared"))
					pssidnet->auth = DOT11_SHARED_KEY;
				else {
					fprintf(stderr, "Invalid imode arg %s\n", *argv);
					err = BCME_USAGE_ERROR;
					goto error;
				}
				pssidnet->auth = htod32(pssidnet->auth);
			} else {
				fprintf(stderr, "Missing option for amode\n");
				err = BCME_USAGE_ERROR;
				goto error;
			}
		} else if (!stricmp(*argv, "wpa_auth")) {
			if (*++argv) {
				uint32 wpa_auth;
				if (pssidnet->ssid.SSID_len == 0) {
					fprintf(stderr, "Wrong! Start with SSID\n");
					err = BCME_USAGE_ERROR;
					goto error;
				}

				/* figure requested auth, allow "any" */
				if (!stricmp(*argv, "wpapsk"))
					pssidnet->wpa_auth = WPA_AUTH_PSK;
				else if (!stricmp(*argv, "wpa2psk"))
					pssidnet->wpa_auth = WPA2_AUTH_PSK;
				else if (!stricmp(*argv, "wpadisabled"))
					pssidnet->wpa_auth = WPA_AUTH_DISABLED;
				else if (!stricmp(*argv, "any"))
					pssidnet->wpa_auth = WPA_AUTH_PFN_ANY;
				else if ((wpa_auth = strtoul(*argv, 0, 0)))
					pssidnet->wpa_auth = wpa_auth;
				else {
					fprintf(stderr, "Invalid wpa_auth option %s\n", *argv);
					err = BCME_USAGE_ERROR;
					goto error;
				}
				pssidnet->wpa_auth = htod32(pssidnet->wpa_auth);
			} else {
				fprintf(stderr, "Missing option for wpa_auth\n");
				err = BCME_USAGE_ERROR;
				goto error;
			}
		} else if (!stricmp(*argv, "wsec")) {
			if (*++argv) {
				if (pssidnet->ssid.SSID_len == 0) {
					fprintf(stderr, "Wrong! Start with SSID\n");
					err = BCME_USAGE_ERROR;
					goto error;
				}
				if (!stricmp(*argv, "WEP")) {
					pssidnet->wsec = WEP_ENABLED;
				} else if (!stricmp(*argv, "TKIP"))
					pssidnet->wsec = TKIP_ENABLED;
				else if (!stricmp(*argv, "AES"))
					pssidnet->wsec = AES_ENABLED;
				else if (!stricmp(*argv, "TKIPAES"))
					pssidnet->wsec = TKIP_ENABLED | AES_ENABLED;
				else {
					fprintf(stderr, "Invalid wsec option %s\n", *argv);
					err = BCME_USAGE_ERROR;
					goto error;
				}
				pssidnet->wsec = htod32(pssidnet->wsec);
			} else {
				fprintf(stderr, "Missing option for wsec\n");
				err = BCME_USAGE_ERROR;
				goto error;
			}
		} else if (!stricmp(*argv, "suppress")) {
			if (*++argv) {
				if (pssidnet->ssid.SSID_len == 0) {
					fprintf(stderr, "Wrong! Start with SSID\n");
					err = BCME_USAGE_ERROR;
					goto error;
				}
				if (!stricmp(*argv, "found")) {
					pssidnet->flags |= WL_PFN_SUPPRESSFOUND_MASK;
				} else if (!stricmp(*argv, "lost")) {
					pssidnet->flags |= WL_PFN_SUPPRESSLOST_MASK;
				} else if (!stricmp(*argv, "neither")) {
					pssidnet->flags &=
					 ~(WL_PFN_SUPPRESSLOST_MASK | WL_PFN_SUPPRESSFOUND_MASK);
				} else {
					fprintf(stderr, "Invalid suppress option %s\n", *argv);
					err = BCME_USAGE_ERROR;
					goto error;
				}
			} else {
				fprintf(stderr, "Missing option for suppress\n");
				err = BCME_USAGE_ERROR;
				goto error;
			}
		} else if (!stricmp(*argv, "rssi")) {
			if (*++argv) {
				int rssi = atoi(*argv);
				if (pssidnet->ssid.SSID_len == 0) {
					fprintf(stderr, "Wrong! Start with SSID\n");
					err = BCME_USAGE_ERROR;
					goto error;
				}
				if (rssi >= -128 && rssi <= 0) {
					pssidnet->flags |= (rssi << WL_PFN_RSSI_SHIFT)
						& WL_PFN_RSSI_MASK;
				} else {
					fprintf(stderr, "Invalid rssi option %s\n", *argv);
					err = BCME_BADARG;
					goto error;
				}
			} else {
				fprintf(stderr, "Missing option for rssi\n");
				err = BCME_USAGE_ERROR;
				goto error;
			}
		}	else {
			fprintf(stderr, "Invalid parameter %s\n", *argv);
			err = BCME_USAGE_ERROR;
			goto error;
		}
	}
	pssidnet->flags = htod32(pssidnet->flags);

	pfn_element_len = (cnt + 1) * sizeof(wl_pfn_t);
	if ((err = wlu_iovar_set(wl, "pfn_add", p_pfn_element,
	     pfn_element_len))) {
		fprintf(stderr, "pfn_add fail\n");
		goto error;
	}
	free(p_pfn_element);
	return (0);

error:
	free(p_pfn_element);
	return err;
}

#define MAXNUM_BSSID_PER_ADD	150

static int
wl_pfn_add_bssid(void *wl, cmd_t *cmd, char **argv)
{
	int                 err;
	uint8               *ptr;
	int                 i, bssidlistlen, cnt;
	wl_pfn_bssid_t      *bssidlist;
	wl_pfn_bssid_t      *pbssid = NULL;

	UNUSED_PARAMETER(cmd);

	if (!*(argv + 1)) {
		fprintf(stderr, "Invalid command\n");
		return BCME_USAGE_ERROR;
	}

	bssidlistlen = MAXNUM_BSSID_PER_ADD * sizeof(wl_pfn_bssid_t);
	bssidlist = (wl_pfn_bssid_t *)malloc(bssidlistlen);
	if (bssidlist == NULL) {
		fprintf(stderr, "Failed to allocate buffer for %d bytes\n", bssidlistlen);
		return BCME_NOMEM;
	}
	memset(bssidlist, '\0', bssidlistlen);

	cnt = 0;
	while (*++argv) {
		if (!stricmp(*argv, "bssid")) {
			if (*++argv) {
				if (cnt >= MAXNUM_BSSID_PER_ADD) {
					fprintf(stderr, "exceed max 150 BSSID per pfn_add_bssid\n");
					err = BCME_BADARG;
					goto error;
				}
				if (!cnt)
					pbssid = bssidlist;
				else {
					pbssid->flags = htod16(pbssid->flags);
					pbssid++;
				}

				ptr = (uint8 *)*argv;
				for (i = 0; i < ETHER_ADDR_LEN; i++)
				{
					if (!validate_hex(*ptr) || !validate_hex(*(ptr + 1)))
					{
						fprintf(stderr, "non-hex in BSSID\n");
						err = BCME_BADARG;
						goto error;
					}
					pbssid->macaddr.octet[i] =
					      char2hex(*ptr) << 4 | char2hex(*(ptr+1));
					ptr += 3;
				}
				cnt++;
			} else {
				fprintf(stderr, "Missing option for bssid\n");
				err = BCME_USAGE_ERROR;
				goto error;
			}
		} else if (!stricmp(*argv, "suppress")) {
			if (!pbssid || ETHER_ISNULLADDR(pbssid->macaddr.octet)) {
				fprintf(stderr, "Wrong! Start with BSSID\n");
				err = BCME_BADARG;
				goto error;
			}
			if (*++argv) {
				if (!stricmp(*argv, "found")) {
					pbssid->flags |= WL_PFN_SUPPRESSFOUND_MASK;
				} else if (!stricmp(*argv, "lost")) {
					pbssid->flags |= WL_PFN_SUPPRESSLOST_MASK;
				} else if (!stricmp(*argv, "neither")) {
					pbssid->flags &=
					 ~(WL_PFN_SUPPRESSFOUND_MASK | WL_PFN_SUPPRESSLOST_MASK);
				} else {
					fprintf(stderr, "Invalid suppress option %s\n", *argv);
					err = BCME_USAGE_ERROR;
					goto error;
				}
			} else {
				fprintf(stderr, "Missing option for suppress\n");
				err = BCME_USAGE_ERROR;
				goto error;
			}
		} else if (!stricmp(*argv, "rssi")) {
			if (*++argv) {
				int rssi = atoi(*argv);
				if (!pbssid || ETHER_ISNULLADDR(pbssid->macaddr.octet)) {
					fprintf(stderr, "Wrong! Start with BSSID\n");
					err = BCME_BADARG;
					goto error;
				}
				if (rssi >= -128 && rssi <= 0) {
					pbssid->flags |= (rssi << WL_PFN_RSSI_SHIFT)
						& WL_PFN_RSSI_MASK;
				} else {
					fprintf(stderr, "Invalid rssi option %s\n", *argv);
					err = BCME_BADARG;
					goto error;
				}
			} else {
				fprintf(stderr, "Missing option for rssi\n");
				err = BCME_USAGE_ERROR;
				goto error;
			}
		} else {
			fprintf(stderr, "Invalid parameter %s\n", *argv);
			err = BCME_USAGE_ERROR;
			goto error;
		}
	}
	pbssid->flags = htod16(pbssid->flags);

	bssidlistlen = cnt * sizeof(wl_pfn_bssid_t);
	if ((err = wlu_iovar_set(wl, "pfn_add_bssid", bssidlist,
	     bssidlistlen))) {
		fprintf(stderr, "pfn_add_bssid fail\n");
		goto error;
	}
	free(bssidlist);
	return 0;

error:
	free(bssidlist);
	return err;
}

static int
wl_pfn_cfg(void *wl, cmd_t *cmd, char **argv)
{
	wl_pfn_cfg_t pfncfg_param;
	int          nchan = 0;
	int          err;

	UNUSED_PARAMETER(cmd);

	memset(&pfncfg_param, '\0', sizeof(wl_pfn_cfg_t));

	/* Setup default values */
	pfncfg_param.reporttype = WL_PFN_REPORT_ALLNET;
	pfncfg_param.channel_num = 0;

	while (*++argv) {
		if (!stricmp(*argv, "report")) {
			if (*++argv) {
				if (!stricmp(*argv, "all")) {
					pfncfg_param.reporttype = WL_PFN_REPORT_ALLNET;
				} else if (!stricmp(*argv, "ssidonly")) {
					pfncfg_param.reporttype = WL_PFN_REPORT_SSIDNET;
				} else if (!stricmp(*argv, "bssidonly")) {
					pfncfg_param.reporttype = WL_PFN_REPORT_BSSIDNET;
				} else {
					fprintf(stderr, "Invalid report option %s\n", *argv);
					return BCME_USAGE_ERROR;
				}
			} else {
				fprintf(stderr, "no value for report\n");
				return BCME_USAGE_ERROR;
			}
		} else if (!stricmp(*argv, "channel")) {
			if (*++argv) {
				nchan = wl_parse_channel_list(*argv, pfncfg_param.channel_list,
				                              WL_NUMCHANNELS);
				if (nchan < 0) {
					fprintf(stderr, "error parsing channel\n");
					return BCME_BADARG;
				}
			} else {
				fprintf(stderr, "Missing option for channel\n");
				return BCME_USAGE_ERROR;
			}
		} else if (!stricmp(*argv, "prohibited")) {
			if (*++argv) {
				pfncfg_param.flags &= ~WL_PFN_CFG_FLAGS_PROHIBITED;
				if (atoi(*argv))
					pfncfg_param.flags |= WL_PFN_CFG_FLAGS_PROHIBITED;
			} else {
				fprintf(stderr, "Missing prohibited option value\n");
				return BCME_USAGE_ERROR;
			}
		} else {
			fprintf(stderr, "Invalid parameter %s\n", *argv);
			return BCME_USAGE_ERROR;
		}
	}

	pfncfg_param.reporttype = htod32(pfncfg_param.reporttype);
	pfncfg_param.channel_num = htod32(nchan);
	pfncfg_param.flags = htod32(pfncfg_param.flags);

	if ((err = wlu_iovar_set(wl, "pfn_cfg", &pfncfg_param,
	     sizeof(wl_pfn_cfg_t)))) {
		fprintf(stderr, "pfn_cfg fail\n");
		return err;
	}

	return 0;
}

static int
wl_pfn(void *wl, cmd_t *cmd, char **argv)
{
	int err, val;

	UNUSED_PARAMETER(cmd);

	if (*++argv) {
		val = atoi(*argv);
		err = wlu_iovar_setint(wl, "pfn", (val ? 1 : 0));
	} else {
		err = wlu_iovar_getint(wl, "pfn", &val);
		if (!err)
			wl_printint(val);
	}

	return err;
}
#define WL_PFN_BESTNET_LEN	1024

static int
wl_pfnbest(void *wl, cmd_t *cmd, char **argv)
{
	int	err;
	wl_pfn_scanresults_t *bestnet;
	wl_pfn_net_info_t *netinfo;
	uint32 i, j;

	UNUSED_PARAMETER(cmd);

	if (*++argv) {
		fprintf(stderr, "Invalid parameter %s\n", *argv);
		return BCME_USAGE_ERROR;
	}
	bestnet = (wl_pfn_scanresults_t *)malloc(WL_PFN_BESTNET_LEN);
	if (bestnet == NULL) {
		fprintf(stderr, "Failed to allocate buffer of %d bytes\n", WL_PFN_BESTNET_LEN);
		return BCME_NOMEM;
	}

	bzero(bestnet, WL_PFN_BESTNET_LEN);
	while (bestnet->status != PFN_COMPLETE) {
		if ((err = wlu_iovar_get(wl, "pfnbest", (void *)bestnet, WL_PFN_BESTNET_LEN))) {
			fprintf(stderr, "pfnbest fail\n");
			free(bestnet);
			return err;
		}
		if (bestnet->count >
		    (WL_PFN_BESTNET_LEN / sizeof(wl_pfn_net_info_t)))
		{
			fprintf(stderr, "invalid data\n");
			free(bestnet);
			return -1;
		}

		printf("ver %d, status %d, count %d\n",
		 bestnet->version, bestnet->status, bestnet->count);
		netinfo = bestnet->netinfo;
		for (i = 0; i < bestnet->count; i++) {
			for (j = 0; j < netinfo->pfnsubnet.SSID_len; j++)
				printf("%c", netinfo->pfnsubnet.SSID[j]);
			printf("\n");
			printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
			        netinfo->pfnsubnet.BSSID.octet[0],
			        netinfo->pfnsubnet.BSSID.octet[1],
			        netinfo->pfnsubnet.BSSID.octet[2],
			        netinfo->pfnsubnet.BSSID.octet[3],
			        netinfo->pfnsubnet.BSSID.octet[4],
			        netinfo->pfnsubnet.BSSID.octet[5]);
			printf("channel: %d, RSSI: %d, timestamp: %d\n",
			 netinfo->pfnsubnet.channel, netinfo->RSSI, netinfo->timestamp);
			netinfo++;
		}
	}

	free(bestnet);
	return 0;
}

static int
wl_pfnlbest(void *wl, cmd_t *cmd, char **argv)
{
	int	err;
	wl_pfn_lscanresults_t *bestnet;
	wl_pfn_lnet_info_t *netinfo;
	uint32 i, j;

	UNUSED_PARAMETER(cmd);

	if (*++argv) {
		fprintf(stderr, "Invalid parameter %s\n", *argv);
		return -1;
	}
	bestnet = (wl_pfn_lscanresults_t *)malloc(WL_PFN_BESTNET_LEN);
	if (bestnet == NULL) {
		fprintf(stderr, "Failed to allocate buffer of %d bytes\n", WL_PFN_BESTNET_LEN);
		return -1;
	}
	bzero(bestnet, WL_PFN_BESTNET_LEN);
	while (bestnet->status == PFN_INCOMPLETE) {
		if ((err = wlu_iovar_get(wl, "pfnlbest", (void *)bestnet, WL_PFN_BESTNET_LEN))) {
			fprintf(stderr, "pfnbest fail\n");
			return err;
		}
		printf("ver %d, status %d, count %d\n",
		 bestnet->version, bestnet->status, bestnet->count);
		netinfo = bestnet->netinfo;
		for (i = 0; i < bestnet->count; i++) {
			for (j = 0; j < netinfo->pfnsubnet.SSID_len; j++)
				printf("%c", netinfo->pfnsubnet.SSID[j]);
			printf("\n");
			printf("%02x:%02x:%02x:%02x:%02x:%02x\n",
			        netinfo->pfnsubnet.BSSID.octet[0],
			        netinfo->pfnsubnet.BSSID.octet[1],
			        netinfo->pfnsubnet.BSSID.octet[2],
			        netinfo->pfnsubnet.BSSID.octet[3],
			        netinfo->pfnsubnet.BSSID.octet[4],
			        netinfo->pfnsubnet.BSSID.octet[5]);
			printf("channel: %d, flags: %d, RSSI: %d, timestamp: %d\n",
			 netinfo->pfnsubnet.channel, netinfo->flags,
			 netinfo->RSSI, netinfo->timestamp);
			printf("RTT0: %d, RTT1: %d\n", netinfo->rtt0, netinfo->rtt1);
			netinfo++;
		}
	}

	free(bestnet);
	return 0;
}

static int
wl_pfn_suspend(void *wl, cmd_t *cmd, char **argv)
{
	int	err, val;

	UNUSED_PARAMETER(cmd);

	if (*++argv) {
		val = atoi(*argv);
		err = wlu_iovar_setint(wl, "pfn_suspend", (val ? 1 : 0));
	} else {
		err = wlu_iovar_getint(wl, "pfn_suspend", &val);
		if (!err)
			wl_printint(val);
	}

	return err;
}

static int
wl_pfn_mem(void *wl, cmd_t *cmd, char **argv)
{
	int	err, val;

	UNUSED_PARAMETER(cmd);

	if (*++argv && !stricmp(*argv, "bestn")) {
		if (*++argv)
			val = atoi(*argv);
		else {
			fprintf(stderr, "Missing bestn value\n");
			return -1;
		}
	} else {
		fprintf(stderr, "Missing bestn option\n");
		return -1;
	}

	err = wlu_iovar_setint(wl, "pfnmem", val);
	if (err) {
		fprintf(stderr, "pfnmem set wrong!\n");
		return err;
	}

	err = wlu_iovar_getint(wl, "pfnmem", &val);
	if (!err)
		wl_printint(val);
	else
		fprintf(stderr, "pfnmem get wrong!\n");
	return err;
}

static void
wl_pfn_printnet(wl_pfn_scanresults_t *ptr, int event_type)
{
	wl_pfn_net_info_t *netinfo = ptr->netinfo;
	uint32 i, j;

	if (WLC_E_PFN_NET_FOUND == event_type) {
		printf("WLC_E_PFN_NET_FOUND:\n");
	} else if (WLC_E_PFN_NET_LOST == event_type) {
		printf("WLC_E_PFN_NET_LOST:\n");
	} else if (WLC_E_PFN_BSSID_NET_FOUND == event_type) {
		printf("WLC_E_PFN_BSSID_NET_FOUND:\n");
	} else if (WLC_E_PFN_BSSID_NET_LOST == event_type) {
		printf("WLC_E_PFN_BSSID_NET_LOST:\n");
	} else {
		return;
	}
	printf("ver %d, status %d, count %d\n",
	        ptr->version, ptr->status, ptr->count);
	for (i = 0; i < ptr->count; i++) {
		printf("%d. ", i + 1);
		for (j = 0; j < netinfo->pfnsubnet.SSID_len; j++)
			printf("%c", netinfo->pfnsubnet.SSID[j]);
		printf("\n");
		printf("BSSID %02x:%02x:%02x:%02x:%02x:%02x\n",
		        netinfo->pfnsubnet.BSSID.octet[0],
		        netinfo->pfnsubnet.BSSID.octet[1],
		        netinfo->pfnsubnet.BSSID.octet[2],
		        netinfo->pfnsubnet.BSSID.octet[3],
		        netinfo->pfnsubnet.BSSID.octet[4],
		        netinfo->pfnsubnet.BSSID.octet[5]);
		printf("channel %d, RSSI %d, timestamp %d\n",
		      netinfo->pfnsubnet.channel, netinfo->RSSI, netinfo->timestamp);

		netinfo++;
	}
}

static int
wl_pfn_event_check(void *wl, cmd_t *cmd, char **argv)
{
	int                 fd, err;
	struct sockaddr_ll	sll;
	struct ifreq        ifr;
	char                ifnames[IFNAMSIZ] = {"eth1"};
	bcm_event_t         * event;
	char                data[512];
	int                 event_type;
	struct ether_addr   *addr;
	char                eabuf[ETHER_ADDR_STR_LEN];
	wl_pfn_scanresults_t *ptr;
	wl_pfn_net_info_t   *info;
	uint32              i, j;
	uint32              foundcnt, lostcnt;

	UNUSED_PARAMETER(wl);
	UNUSED_PARAMETER(cmd);

	/* Override default ifname explicitly or implicitly */
	if (*++argv) {
		if (strlen(*argv) >= IFNAMSIZ) {
			printf("Interface name %s too long\n", *argv);
			return -1;
		}
		strncpy(ifnames, *argv, IFNAMSIZ);
	} else if (wl) {
		strncpy(ifnames, ((struct ifreq *)wl)->ifr_name, (IFNAMSIZ - 1));
	}
	ifnames[IFNAMSIZ - 1] = '\0';

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifnames, IFNAMSIZ);

	fd = socket(PF_PACKET, SOCK_RAW, hton16(ETHER_TYPE_BRCM));
	if (fd < 0) {
		printf("Cannot create socket %d\n", fd);
		return -1;
	}

	err = ioctl(fd, SIOCGIFINDEX, &ifr);
	if (err < 0) {
		printf("Cannot get index %d\n", err);
		return -1;
	}

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = hton16(ETHER_TYPE_BRCM);
	sll.sll_ifindex = ifr.ifr_ifindex;
	err = bind(fd, (struct sockaddr *)&sll, sizeof(sll));
	if (err < 0) {
		printf("Cannot get index %d\n", err);
		return -1;
	}

	while (1) {
		recv(fd, data, sizeof(data), 0);
		event = (bcm_event_t *)data;
		addr = (struct ether_addr *)&(event->event.addr);

		event_type = ntoh32(event->event.event_type);

		if (addr != NULL) {
			sprintf(eabuf, "%02x:%02x:%02x:%02x:%02x:%02x",
				(uchar)addr->octet[0]&0xff,
				(uchar)addr->octet[1]&0xff,
				(uchar)addr->octet[2]&0xff,
				(uchar)addr->octet[3]&0xff,
				(uchar)addr->octet[4]&0xff,
				(uchar)addr->octet[5]&0xff);
		}

		if (ntoh32(event->event.datalen)) {
			if (WLC_E_PFN_SCAN_COMPLETE == event_type) {
				ptr = (wl_pfn_scanresults_t *)(data + sizeof(bcm_event_t));
				info = ptr->netinfo;
				foundcnt = ptr->count & 0xffff;
				lostcnt = ptr->count >> 16;
				printf("ver %d, status %d, found %d, lost %d\n",
				        ptr->version, ptr->status, foundcnt, lostcnt);
				if (foundcnt)
					printf("Network found:\n");
				for (i = 0; i < foundcnt; i++) {
					printf("%d. ", i + 1);
					for (j = 0; j < info->pfnsubnet.SSID_len; j++)
						printf("%c", info->pfnsubnet.SSID[j]);
					printf("\n");
					printf("BSSID %02x:%02x:%02x:%02x:%02x:%02x\n",
					        info->pfnsubnet.BSSID.octet[0],
					        info->pfnsubnet.BSSID.octet[1],
					        info->pfnsubnet.BSSID.octet[2],
					        info->pfnsubnet.BSSID.octet[3],
					        info->pfnsubnet.BSSID.octet[4],
					        info->pfnsubnet.BSSID.octet[5]);
					printf("channel %d, RSSI %d, timestamp %d\n",
					 info->pfnsubnet.channel, info->RSSI, info->timestamp);
					info++;
				}
				if (lostcnt)
					printf("Network lost:\n");
				for (i = 0; i < lostcnt; i++) {
					printf("%d. ", i + 1);
					for (j = 0; j < info->pfnsubnet.SSID_len; j++)
						printf("%c", info->pfnsubnet.SSID[j]);
					printf("\n");
					printf("BSSID %02x:%02x:%02x:%02x:%02x:%02x\n",
					        info->pfnsubnet.BSSID.octet[0],
					        info->pfnsubnet.BSSID.octet[1],
					        info->pfnsubnet.BSSID.octet[2],
					        info->pfnsubnet.BSSID.octet[3],
					        info->pfnsubnet.BSSID.octet[4],
					        info->pfnsubnet.BSSID.octet[5]);
					printf("channel %d, RSSI %d, timestamp %d\n",
					 info->pfnsubnet.channel, info->RSSI, info->timestamp);
					info++;
				}
			} else if ((WLC_E_PFN_NET_FOUND == event_type) ||
			           (WLC_E_PFN_NET_LOST == event_type) ||
			           (WLC_E_PFN_BSSID_NET_FOUND == event_type) ||
			           (WLC_E_PFN_BSSID_NET_LOST == event_type)) {
				wl_pfn_printnet(
				   (wl_pfn_scanresults_t *)(data + sizeof(bcm_event_t)),
				                            event_type);
			}

			if (WLC_E_LINK == event_type || WLC_E_NDIS_LINK == event_type) {
				if (ntoh16(event->event.flags) & WLC_EVENT_MSG_LINK)
					printf("MACEVENT Link up :%s\n", eabuf);
				else
					printf("MACEVENT Link down :%s\n", eabuf);
			}
		} else {
			if (WLC_E_PFN_SCAN_NONE == event_type) {
				printf("Got WLC_E_PFN_SCAN_NONE\n");
			}
			if (WLC_E_PFN_SCAN_ALLGONE == event_type) {
				printf("Got WLC_E_PFN_SCAN_ALLGONE\n");
			}
			if (WLC_E_PFN_BEST_BATCHING == event_type) {
				printf("Got WLC_E_PFN_BEST_BATCHING\n");
			}
		}
	}
	return (0);
}

static int
wl_event_filter(void *wl, cmd_t *cmd, char **argv)
{
	int     err;
	uint8   event_inds_mask[WL_EVENTING_MASK_LEN];  /* event bit mask */

	UNUSED_PARAMETER(cmd);
	UNUSED_PARAMETER(argv);

	memset(event_inds_mask, '\0', WL_EVENTING_MASK_LEN);

	/* Register for following event for pfn */
	event_inds_mask[WLC_E_LINK / 8] |= 1 << (WLC_E_LINK % 8);
	event_inds_mask[WLC_E_PFN_NET_FOUND / 8] |= 1 << (WLC_E_PFN_NET_FOUND % 8);
	event_inds_mask[WLC_E_PFN_NET_LOST / 8] |= 1 << (WLC_E_PFN_NET_LOST % 8);
	event_inds_mask[WLC_E_PFN_SCAN_NONE/ 8] |= 1 << (WLC_E_PFN_SCAN_NONE % 8);
	event_inds_mask[WLC_E_PFN_SCAN_ALLGONE/ 8] |= 1 << (WLC_E_PFN_SCAN_ALLGONE % 8);

	if ((err = wlu_iovar_set(wl, "event_msgs", &event_inds_mask, WL_EVENTING_MASK_LEN)))
		return (err);

	return (0);
}

static int
wl_pfn_roam_alert_thresh(void *wl, cmd_t *cmd, char **argv)
{
	int err, buflen;
	wl_pfn_roam_thresh_t *pfn_roam_alert;

	buflen = sprintf(buf, "%s", *argv) + 1;

	if (*++(argv) == NULL) {
		buf[buflen] = '\0';
		err = wlu_get(wl, cmd->get, buf, WLC_IOCTL_MAXLEN);
		if (err < 0)
			return err;

		pfn_roam_alert = (wl_pfn_roam_thresh_t *)buf;
		printf("pfn_alert_thresh %u\n", pfn_roam_alert->pfn_alert_thresh);
		printf("roam_alert_thresh %u\n", pfn_roam_alert->roam_alert_thresh);
		return 0;

	} else {
		pfn_roam_alert = (wl_pfn_roam_thresh_t *) (buf + buflen);
		buflen += sizeof(wl_pfn_roam_thresh_t);

		pfn_roam_alert->pfn_alert_thresh = (uint32) strtoul(*argv, NULL, 0);

		if (*++(argv) == NULL) {
			printf("Incorrect number of arguments\n");
			return BCME_ERROR;
		}
		pfn_roam_alert->roam_alert_thresh = (uint32) strtoul(*argv, NULL, 0);

		if (*++(argv)) {
			printf("extra arguments\n");
			return BCME_ERROR;
		}
		err = wlu_set(wl, WLC_SET_VAR, buf, buflen);

		return err;
	}
	return 0;
}
