/*
 * wl p2p command module
 *
 * Copyright (C) 2014, Broadcom Corporation
 * All Rights Reserved.
 * 
 * This is UNPUBLISHED PROPRIETARY SOURCE CODE of Broadcom Corporation;
 * the contents of this file may not be disclosed to third parties, copied
 * or duplicated in any form, in whole or in part, without the prior
 * written permission of Broadcom Corporation.
 *
 * $Id: wluc_p2p.c 458728 2014-02-27 18:15:25Z $
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

#include <time.h>

static cmd_func_t wl_p2p_state;
static cmd_func_t wl_p2p_scan;
static cmd_func_t wl_p2p_ifadd;
static cmd_func_t wl_p2p_ifdel;
static cmd_func_t wl_p2p_ifupd;
static cmd_func_t wl_p2p_if;
static cmd_func_t wl_p2p_ops;
static cmd_func_t wl_p2p_noa;

static cmd_t wl_p2p_cmds[] = {
	{ "p2p_ssid", wl_ssid, WLC_GET_VAR, WLC_SET_VAR,
	"set WiFi P2P wildcard ssid.\n"
	"\tUsage: wl p2p_ssid <ssid>"
	},
	{ "p2p_state", wl_p2p_state, -1, WLC_SET_VAR,
	"set WiFi P2P discovery state.\n"
	"\tUsage: wl p2p_state <state> [<chanspec> <dwell time>]"
	},
	{ "p2p_scan", wl_p2p_scan, -1, WLC_SET_VAR,
	"initiate WiFi P2P scan.\n"
	"\tUsage: wl p2p_scan S|E <scan parms>\n"
	SCAN_USAGE
	},
	{ "p2p_ifadd", wl_p2p_ifadd, -1, WLC_SET_VAR,
	"add WiFi P2P interface\n"
	"\tUsage: wl p2p_ifadd <MAC-address> go|client|dyngo [chanspec]\n"
	"MAC-address: xx:xx:xx:xx:xx:xx"
	},
	{ "p2p_ifdel", wl_p2p_ifdel, -1, WLC_SET_VAR,
	"delete WiFi P2P interface\n"
	"\tUsage: wl p2p_ifdel <MAC-address>\n"
	"MAC-address: xx:xx:xx:xx:xx:xx"
	},
	{ "p2p_ifupd", wl_p2p_ifupd, -1, WLC_SET_VAR,
	"update an interface to WiFi P2P interface\n"
	"\tUsage: wl p2p_ifupd <MAC-address> go|client\n"
	"MAC-address: xx:xx:xx:xx:xx:xx"
	},
	{ "p2p_if", wl_p2p_if, WLC_GET_VAR, -1,
	"query WiFi P2P interface bsscfg index\n"
	"\tUsage: wl p2p_if <MAC-address>\n"
	"MAC-address: xx:xx:xx:xx:xx:xx"
	},
	{ "p2p_noa", wl_p2p_noa, WLC_GET_VAR, WLC_SET_VAR,
	"set/get WiFi P2P NoA schedule\n"
	"\tUsage: wl p2p_noa <type> <type-specific-params>\n"
	"\t\ttype 0: Scheduled Absence (on GO): <type> <action> <action-specific-params>\n"
	"\t\t\taction -1: Cancel the schedule: <type> <action>\n"
	"\t\t\taction 0,1,2: <type> <action> <option> <option-specific-params>\n"
	"\t\t\t\taction 0: Do nothing during absence periods\n"
	"\t\t\t\taction 1: Sleep during absence periods\n"
	"\t\t\t\toption 0: <start:tsf> <interval> <duration> <count> ...\n"
	"\t\t\t\toption 1 [<start-percentage>] <duration-percentage>\n"
	"\t\t\t\toption 2 <start:tsf-offset> <interval> <duration> <count>\n"
	"\t\ttype 1: Requested Absence (on GO): \n"
	"\t\t\taction -1: Cancel the schedule: <type> <action>\n"
	"\t\t\taction 2: <type> <action> <option> <option-specific-params>\n"
	"\t\t\t\taction 2: Turn off GO beacons and probe responses during absence period\n"
	"\t\t\t\toption 2 <start:tsf-offset> <interval> <duration> <count>"
	},
	{ "p2p_ops", wl_p2p_ops, WLC_GET_VAR, WLC_SET_VAR,
	"set/get WiFi P2P OppPS and CTWindow\n"
	"\tUsage: wl p2p_ops <ops> [<ctw>]\n"
	"\t\t<ops>:\n"
	"\t\t\t0: Disable OppPS\n"
	"\t\t\t1: Enable OppPS\n"
	"\t\t<ctw>:\n"
	"\t\t\t10 and up to beacon interval"
	},
	{ "p2p_da_override", wl_iov_mac, WLC_GET_VAR, WLC_SET_VAR,
	"Get/Set WiFi P2P device interface addr\n"
	"\tUsage: wl p2p_da_override <MAC-address>\n"
	"MAC-address: xx:xx:xx:xx:xx:xx\n"
	"(When MAC-address is set to 00:00:00:00:00:00, default da restored)"
	},
	{ NULL, NULL, 0, 0, NULL }
};

static char *buf;

/* module initialization */
void
wluc_p2p_module_init(void)
{
	/* get the global buf */
	buf = wl_get_buf();

	/* register p2p commands */
	wl_module_cmds_register(wl_p2p_cmds);
}

static int
wl_p2p_state(void *wl, cmd_t *cmd, char **argv)
{
	wl_p2p_disc_st_t st;
	int count;
	char *endptr;

	argv++;

	count = ARGCNT(argv);
	if (count < 1)
		return BCME_USAGE_ERROR;

	st.state = (uint8) strtol(argv[0], &endptr, 0);
	if (st.state == WL_P2P_DISC_ST_LISTEN) {
		if (count != 3)
			return BCME_USAGE_ERROR;
		if ((st.chspec = wf_chspec_aton(argv[1])) == 0) {
			fprintf(stderr, "error parsing chanspec arg \"%s\"\n", argv[1]);
			return BCME_BADARG;
		}
		st.chspec = wl_chspec_to_driver(st.chspec);
		if (st.chspec == INVCHANSPEC) {
			return BCME_USAGE_ERROR;
		}
		st.dwell = (uint16) strtol(argv[2], &endptr, 0);
	}

	return wlu_var_setbuf(wl, cmd->name, &st, sizeof(st));
}

static int
wl_p2p_scan(void *wl, cmd_t *cmd, char **argv)
{
	wl_p2p_scan_t *params = NULL;
	int params_size = 0;
	int malloc_size = 0;
	int sparams_size = 0;
	int err = 0;

	if (*(argv + 1) != NULL) {
		malloc_size = sizeof(wl_p2p_scan_t);
		switch (toupper(**(argv + 1))) {
		case 'S':
			malloc_size += WL_SCAN_PARAMS_FIXED_SIZE + WL_NUMCHANNELS * sizeof(uint16);
			break;
		case 'E':
			malloc_size += OFFSETOF(wl_escan_params_t, params) +
			        WL_SCAN_PARAMS_FIXED_SIZE + WL_NUMCHANNELS * sizeof(uint16);
			break;
		}
	}
	if (malloc_size == 0) {
		fprintf(stderr, "wrong syntax, need 'S' or 'E'\n");
		return BCME_BADARG;
	}

	malloc_size += WL_SCAN_PARAMS_SSID_MAX * sizeof(wlc_ssid_t);
	params = (wl_p2p_scan_t *)malloc(malloc_size);
	if (params == NULL) {
		fprintf(stderr, "Error allocating %d bytes for scan params\n", malloc_size);
		return BCME_NOMEM;
	}
	memset(params, 0, malloc_size);

	switch (toupper(**(argv + 1))) {
	case 'S': {
		wl_scan_params_t *sparams = (wl_scan_params_t *)(params+1);
		sparams_size = malloc_size - sizeof(wl_p2p_scan_t);

		params->type = 'S';

		if ((err = wl_scan_prep(wl, cmd, argv + 1, sparams, &sparams_size)) == 0)
			params_size = sizeof(wl_p2p_scan_t) + sparams_size;
		break;
	}

	case 'E': {
		wl_escan_params_t *eparams = (wl_escan_params_t *)(params+1);
		sparams_size = malloc_size - sizeof(wl_p2p_scan_t) - sizeof(wl_escan_params_t);

		params->type = 'E';

		eparams->version = htod32(ESCAN_REQ_VERSION);
		eparams->action = htod16(WL_SCAN_ACTION_START);

		srand((unsigned)time(NULL));
		eparams->sync_id = htod16(rand() & 0xffff);

		if ((err = wl_scan_prep(wl, cmd, argv + 1, &eparams->params, &sparams_size)) == 0)
			params_size = sizeof(wl_p2p_scan_t) + sizeof(wl_escan_params_t) +
				sparams_size;
		break;
	}
	}

	if (!err)
		err = wlu_iovar_setbuf(wl, cmd->name, params, params_size, buf, WLC_IOCTL_MAXLEN);

	free(params);
	return err;
}

static int
wl_p2p_ifadd(void *wl, cmd_t *cmd, char **argv)
{
	wl_p2p_if_t ifreq;
	int count;

	argv++;

	count = ARGCNT(argv);
	if (count < 2)
		return BCME_USAGE_ERROR;

	if (!wl_ether_atoe(argv[0], &ifreq.addr))
		return BCME_USAGE_ERROR;

	if (stricmp(argv[1], "go") == 0)
		ifreq.type = WL_P2P_IF_GO;
	else if (stricmp(argv[1], "client") == 0)
		ifreq.type = WL_P2P_IF_CLIENT;
	else if (stricmp(argv[1], "dyngo") == 0)
		ifreq.type = WL_P2P_IF_DYNBCN_GO;
	else
		return BCME_USAGE_ERROR;

	if (ifreq.type == WL_P2P_IF_GO || ifreq.type == WL_P2P_IF_DYNBCN_GO) {
		if (count > 2) {
			if ((ifreq.chspec = wf_chspec_aton(argv[2])) == 0) {
				fprintf(stderr, "error parsing chanspec arg \"%s\"\n", argv[2]);
				return BCME_BADARG;
			}
			ifreq.chspec = wl_chspec_to_driver(ifreq.chspec);
			if (ifreq.chspec == INVCHANSPEC) {
				return BCME_BADARG;
			}
		}
		else
			ifreq.chspec = 0;
	}

	return wlu_var_setbuf(wl, cmd->name, &ifreq, sizeof(ifreq));
}

static int
wl_p2p_ifdel(void *wl, cmd_t *cmd, char **argv)
{
	struct ether_addr addr;
	int count;

	argv++;

	count = ARGCNT(argv);
	if (count != 1)
		return BCME_USAGE_ERROR;

	if (!wl_ether_atoe(argv[0], &addr))
		return BCME_USAGE_ERROR;

	return wlu_var_setbuf(wl, cmd->name, &addr, sizeof(addr));
}

static int
wl_p2p_ifupd(void *wl, cmd_t *cmd, char **argv)
{
	wl_p2p_if_t ifreq;
	int count;
	int ret;
	int bsscfg_idx = 0;
	int consumed = 0;

	argv++;

	/* parse a bsscfg_idx option if present */
	if ((ret = wl_cfg_option(argv, cmd->name, &bsscfg_idx, &consumed)) != 0)
		return ret;
	argv += consumed;
	if (consumed == 0)
		bsscfg_idx = -1;

	count = ARGCNT(argv);
	if (count < 2)
		return BCME_USAGE_ERROR;

	if (!wl_ether_atoe(argv[0], &ifreq.addr))
		return BCME_USAGE_ERROR;

	if (stricmp(argv[1], "go") == 0)
		ifreq.type = WL_P2P_IF_GO;
	else if (stricmp(argv[1], "client") == 0)
		ifreq.type = WL_P2P_IF_CLIENT;
	else
		return BCME_USAGE_ERROR;

	ifreq.chspec = 0;

	if (bsscfg_idx == -1)
		return wlu_var_setbuf(wl, cmd->name, &ifreq, sizeof(ifreq));
	return wlu_bssiovar_setbuf(wl, cmd->name, bsscfg_idx,
	                          &ifreq, sizeof(ifreq),
	                          buf, WLC_IOCTL_MAXLEN);
}

static int
wl_p2p_if(void *wl, cmd_t *cmd, char **argv)
{
	struct ether_addr addr;
	int count;
	wl_p2p_ifq_t *ptr;
	int err;

	argv++;

	count = ARGCNT(argv);
	if (count != 1)
		return BCME_USAGE_ERROR;

	if (!wl_ether_atoe(argv[0], &addr))
		return BCME_USAGE_ERROR;

	err = wlu_var_getbuf(wl, cmd->name, &addr, sizeof(addr), (void*)&ptr);
	if (err >= 0)
		printf("%u %s\n", dtoh32(ptr->bsscfgidx), (ptr->ifname));

	return err;
}

static int
wl_p2p_ops(void *wl, cmd_t *cmd, char **argv)
{
	wl_p2p_ops_t ops;
	int count;
	char *endptr;

	argv++;

	count = ARGCNT(argv);
	if (count < 1) {
		wl_p2p_ops_t *ops;
		int err;

		err = wlu_var_getbuf(wl, cmd->name, NULL, 0, (void *)&ops);
		if (err != BCME_OK) {
			fprintf(stderr, "%s: error %d\n", cmd->name, err);
			return err;
		}

		printf("ops: %u ctw: %u\n", ops->ops, ops->ctw);

		return BCME_OK;
	}

	ops.ops = (uint8) strtol(argv[0], &endptr, 0);
	if (ops.ops != 0) {
		if (count != 2)
			return BCME_USAGE_ERROR;
		ops.ctw = (uint8) strtol(argv[1], &endptr, 0);
	}
	else
		ops.ctw = 0;

	return wlu_var_setbuf(wl, cmd->name, &ops, sizeof(ops));
}

static int
wl_p2p_noa(void *wl, cmd_t *cmd, char **argv)
{
	int count;
	wl_p2p_sched_t *noa;
	int len;
	int i;
	char *endptr;

	argv ++;

	strcpy(buf, cmd->name);

	count = ARGCNT(argv);
	if (count < 2) {
		int err = wlu_get(wl, WLC_GET_VAR, buf, WLC_IOCTL_MAXLEN);
		wl_p2p_sched_t *sched;
		int i;

		if (err != BCME_OK) {
			fprintf(stderr, "%s: error %d\n", cmd->name, err);
			return err;
		}

		sched = (wl_p2p_sched_t *)buf;
		for (i = 0; i < 16; i ++) {
			if (sched->desc[i].count == 0)
				break;
			printf("start: %u interval: %u duration: %u count: %u\n",
			       sched->desc[i].start, sched->desc[i].interval,
			       sched->desc[i].duration, sched->desc[i].count);
		}

		return BCME_OK;
	}

	len = strlen(buf);

	noa = (wl_p2p_sched_t *)&buf[len + 1];
	len += 1;

	noa->type = (uint8)strtol(argv[0], &endptr, 0);
	len += sizeof(noa->type);
	noa->action = (uint8)strtol(argv[1], &endptr, 0);
	len += sizeof(noa->action);

	argv += 2;
	count -= 2;

	/* action == -1 is to cancel the current schedule */
	if (noa->action == WL_P2P_SCHED_ACTION_RESET) {
		/* the fixed portion of wl_p2p_sched_t with action == WL_P2P_SCHED_ACTION_RESET
		 * is required to cancel the curret schedule.
		 */
		len += (char *)&noa->desc[0] - ((char *)buf + len);
	}
	/* Take care of any special cases only and let all other cases fall through
	 * as normal 'start/interval/duration/count' descriptions.
	 * All cases start with 'type' 'action' 'option'.
	 * Any count value greater than 255 is to repeat unlimited.
	 */
	else {
		switch (noa->type) {
		case WL_P2P_SCHED_TYPE_ABS:
		case WL_P2P_SCHED_TYPE_REQ_ABS:
			if (count < 1)
				return BCME_USAGE_ERROR;
			noa->option = (uint8)strtol(argv[0], &endptr, 0);
			len += sizeof(noa->option);
			argv += 1;
			count -= 1;
			break;
		}

		/* add any paddings before desc field */
		len += (char *)&noa->desc[0] - ((char *)buf + len);

		switch (noa->type) {
		case WL_P2P_SCHED_TYPE_ABS:
			switch (noa->option) {
			case WL_P2P_SCHED_OPTION_BCNPCT:
				if (count == 1) {
					noa->desc[0].duration = htod32(strtol(argv[0], &endptr, 0));
					noa->desc[0].start = 100 - noa->desc[0].duration;
				}
				else if (count == 2) {
					noa->desc[0].start = htod32(strtol(argv[0], &endptr, 0));
					noa->desc[0].duration = htod32(strtol(argv[1], &endptr, 0));
				}
				else {
					fprintf(stderr, "Usage: wl p2p_noa 0 %d 1 "
					        "<start-pct> <duration-pct>\n",
					        noa->action);
					return BCME_USAGE_ERROR;
				}
				len += sizeof(wl_p2p_sched_desc_t);
				break;

			default:
				if (count < 4 || (count % 4) != 0) {
					fprintf(stderr, "Usage: wl p2p_noa 0 %d 0 "
					        "<start> <interval> <duration> <count> ...\n",
					        noa->action);
					return BCME_USAGE_ERROR;
				}
				goto normal;
			}
			break;

		default:
			if (count != 4) {
				fprintf(stderr, "Usage: wl p2p_noa 1 %d "
				        "<start> <interval> <duration> <count> ...\n",
				        noa->action);
				return BCME_USAGE_ERROR;
			}
			/* fall through... */
		normal:
			for (i = 0; i < count; i += 4) {
				noa->desc[i / 4].start = htod32(strtoul(argv[i], &endptr, 0));
				noa->desc[i / 4].interval = htod32(strtol(argv[i + 1], &endptr, 0));
				noa->desc[i / 4].duration = htod32(strtol(argv[i + 2], &endptr, 0));
				noa->desc[i / 4].count = htod32(strtol(argv[i + 3], &endptr, 0));
				len += sizeof(wl_p2p_sched_desc_t);
			}
			break;
		}
	}

	return wlu_set(wl, WLC_SET_VAR, buf, len);
}
